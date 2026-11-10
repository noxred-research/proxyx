use std::sync::Arc;

use crate::db::{Db, SessionInsert};
use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use prost::Message;
use uuid::Uuid;

use common::log::CaptureLogProducer;
use common::types::{
    CreateSessionRequest, CreateSessionResponse, EgressProxy, ProxyType, SessionConfig,
};
use common::wire::{self, request_log_message};

#[derive(Debug, thiserror::Error)]
#[error("active session has different upstream_overrides")]
pub struct UpstreamOverridesConflict;

/// Build an authenticated proxy URL from a `host:port` and scheme.
fn build_authenticated_url(scheme: &str, host_port: &str, session_id: Uuid) -> String {
    format!("{}://{}:password@{}", scheme, session_id, host_port)
}

/// Row returned from the `orgs` table for session creation.
#[derive(sqlx::FromRow)]
pub(crate) struct OrgRow {
    pub(crate) id: String,
    pub(crate) rate_limit_rpm: Option<i32>,
    pub(crate) rate_limit_burst: Option<i32>,
    pub(crate) proxy_type: Option<String>,
    pub(crate) proxy_address: Option<String>,
    pub(crate) proxy_username: Option<String>,
    pub(crate) proxy_password: Option<String>,
}

impl OrgRow {
    /// Convert into rate-limit settings and egress proxy.
    /// `default_rpm`/`default_burst` are used when the DB columns are NULL.
    pub(crate) fn into_parts(
        self,
        org_id: &str,
        default_rpm: u32,
        default_burst: u32,
    ) -> Result<(
        Option<common::types::RateLimitSettings>,
        Option<EgressProxy>,
    )> {
        let rpm = db_rate_limit_or_default(self.rate_limit_rpm, default_rpm, "rate_limit_rpm")?;
        let burst =
            db_rate_limit_or_default(self.rate_limit_burst, default_burst, "rate_limit_burst")?;
        let rate_limit = if rpm > 0 || burst > 0 {
            Some(common::types::RateLimitSettings {
                requests_per_minute: rpm,
                burst,
            })
        } else {
            None
        };

        let egress_proxy = match (self.proxy_type.as_deref(), self.proxy_address) {
            (Some(pt), Some(addr)) => {
                let proxy_type = match pt {
                    "socks5" => ProxyType::Socks5,
                    "http" => ProxyType::Http,
                    other => {
                        tracing::warn!(
                            proxy_type = other,
                            org_id,
                            "unknown proxy type, skipping proxy"
                        );
                        return Ok((rate_limit, None));
                    }
                };
                Some(EgressProxy {
                    proxy_type,
                    address: addr,
                    username: self.proxy_username,
                    password: self.proxy_password,
                })
            }
            _ => None,
        };

        Ok((rate_limit, egress_proxy))
    }
}
fn db_rate_limit_or_default(value: Option<i32>, default: u32, field: &str) -> Result<u32> {
    match value {
        Some(value) => {
            u32::try_from(value).map_err(|_| anyhow!("{field} contains a negative rate limit"))
        }
        None => Ok(default),
    }
}

/// Replicate org rate-limit settings into Redis so the proxy can enforce them.
pub(crate) async fn replicate_ratelimit(
    redis: &mut redis::aio::ConnectionManager,
    org_id: &str,
    burst: u32,
    rpm: u32,
    redis_key_prefix: &str,
) -> anyhow::Result<()> {
    let key = format!("{}:ratelimit:{}:config", redis_key_prefix, org_id);
    redis::cmd("HMSET")
        .arg(&key)
        .arg("burst")
        .arg(burst)
        .arg("rpm")
        .arg(rpm)
        .query_async::<()>(redis)
        .await?;
    Ok(())
}

/// Live rate-limit state of an org as the session proxy keeps it in Redis:
/// the token bucket (`{prefix}:ratelimit:{org}`: `tokens`, `last_ms`) and the
/// replicated limits (`{prefix}:ratelimit:{org}:config`: `burst`, `rpm`).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct RateLimitState {
    /// Either hash exists.
    pub exists: bool,
    pub tokens: f64,
    pub last_refill_ms: i64,
    pub burst: u32,
    pub rpm: u32,
}

/// Read [`RateLimitState`] of `org_id` (two `HMGET`s in one pipeline).
pub async fn read_ratelimit_state(
    redis: &mut redis::aio::ConnectionManager,
    org_id: &str,
    redis_key_prefix: &str,
) -> anyhow::Result<RateLimitState> {
    let state_key = format!("{redis_key_prefix}:ratelimit:{org_id}");
    let config_key = format!("{state_key}:config");
    type Pair = (Option<String>, Option<String>);
    let ((tokens, last_ms), (burst, rpm)): (Pair, Pair) = redis::pipe()
        .cmd("HMGET")
        .arg(&state_key)
        .arg("tokens")
        .arg("last_ms")
        .cmd("HMGET")
        .arg(&config_key)
        .arg("burst")
        .arg("rpm")
        .query_async(redis)
        .await?;
    Ok(RateLimitState {
        exists: tokens.is_some() || burst.is_some(),
        tokens: tokens.and_then(|s| s.parse().ok()).unwrap_or(0.0),
        last_refill_ms: last_ms.and_then(|s| s.parse().ok()).unwrap_or(0),
        burst: burst.and_then(|s| s.parse().ok()).unwrap_or(0),
        rpm: rpm.and_then(|s| s.parse().ok()).unwrap_or(0),
    })
}

/// Manages session lifecycle in Redis.
pub struct SessionManager {
    redis: redis::aio::ConnectionManager,
    db: Db,
    ca_cert_pem: String,
    default_ttl_secs: u32,
    default_rate_limit_rpm: u32,
    default_rate_limit_burst: u32,
    log_producer: Arc<dyn CaptureLogProducer>,
    proxy_public_host: String,
    proxy_public_host_socks5: String,
    redis_key_prefix: String,
}

impl SessionManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        redis: redis::aio::ConnectionManager,
        db: Db,
        ca_cert_pem: String,
        default_ttl_secs: u32,
        default_rate_limit_rpm: u32,
        default_rate_limit_burst: u32,
        log_producer: Arc<dyn CaptureLogProducer>,
        proxy_public_host: String,
        proxy_public_host_socks5: String,
        redis_key_prefix: String,
    ) -> Self {
        Self {
            redis,
            db,
            ca_cert_pem,
            default_ttl_secs,
            default_rate_limit_rpm,
            default_rate_limit_burst,
            log_producer,
            proxy_public_host,
            proxy_public_host_socks5,
            redis_key_prefix,
        }
    }

    /// Create a new session, or attach to an existing active session with the
    /// same `(org_id, source, source_id)`.
    ///
    /// When an active session already exists for the triple, the reference
    /// count is incremented, the Redis TTL is extended if the new request's
    /// deadline is later, and the existing session is returned. A `warning`
    /// field is set on the response if the caller's capture config differs
    /// from the existing session's config.
    pub async fn create(&self, req: CreateSessionRequest) -> Result<CreateSessionResponse> {
        let ttl_secs = if req.ttl_secs > 0 {
            req.ttl_secs
        } else {
            self.default_ttl_secs
        };

        let now_ms = time::OffsetDateTime::now_utc().unix_timestamp() * 1000;
        let expires_at_ms = now_ms + (ttl_secs as i64) * 1000;
        let expires_at = ms_to_offset_dt(expires_at_ms);

        // ----------------------------------------------------------
        // Fast path: try to attach to an existing active session
        // ----------------------------------------------------------
        if let Some(existing) = self.try_attach(&req, expires_at_ms, expires_at).await? {
            return Ok(existing);
        }

        // ----------------------------------------------------------
        // Slow path: create a brand-new session
        // ----------------------------------------------------------
        let session_id = Uuid::new_v4();

        // Resolve org from Postgres
        let org_row = self
            .db
            .org(&req.org_id)
            .await
            .context("failed to query org from the database")?;

        let (rate_limit, egress_proxy) = match org_row {
            Some(row) => row.into_parts(
                &req.org_id,
                self.default_rate_limit_rpm,
                self.default_rate_limit_burst,
            )?,
            None => {
                tracing::info!(org_id = %req.org_id, "org not found, using defaults");
                let rate_limit =
                    if self.default_rate_limit_rpm > 0 || self.default_rate_limit_burst > 0 {
                        Some(common::types::RateLimitSettings {
                            requests_per_minute: self.default_rate_limit_rpm,
                            burst: self.default_rate_limit_burst,
                        })
                    } else {
                        None
                    };
                (rate_limit, None)
            }
        };

        // Replicate rate limit to Redis if we have settings
        if let Some(ref settings) = rate_limit
            && let Err(e) = replicate_ratelimit(
                &mut self.redis.clone(),
                &req.org_id,
                settings.burst,
                settings.requests_per_minute,
                &self.redis_key_prefix,
            )
            .await
        {
            tracing::warn!(
                error = %e,
                org_id = %req.org_id,
                "failed to replicate rate limit settings to Redis"
            );
        }

        // Keep a copy for the rare race-retry path (unique violation).
        let req_clone = req.clone();
        let session_config = SessionConfig {
            session_id,
            org_id: req.org_id,
            source: req.source,
            source_id: req.source_id,
            agent: req.agent,
            captured_hosts: req.captured_hosts,
            excluded_hosts: req.excluded_hosts,
            upstream_overrides: req.upstream_overrides,
            inject_headers: req.inject_headers,
            serialize: req.serialize,
            expires_at_ms,
            egress_proxy,
            rate_limit,
        };

        let data_key = format!("{}:session:{}:data", self.redis_key_prefix, session_id);
        let value =
            serde_json::to_string(&session_config).context("failed to serialize session config")?;

        let mut conn = self.redis.clone();
        redis::cmd("SET")
            .arg(&data_key)
            .arg(&value)
            .arg("EX")
            .arg(ttl_secs as i64)
            .query_async::<()>(&mut conn)
            .await
            .context("failed to write session data to Redis")?;

        // Lifecycle row in Postgres — source of truth for session state.
        // The partial unique index on (org_id, source, source_id) WHERE
        // state='active' prevents duplicate active sessions.  If a
        // concurrent request raced us past the try_attach check, this
        // INSERT fails and we retry the attach path once.
        let insert_result = self
            .db
            .insert_session(
                session_id,
                &session_config.org_id,
                &session_config.source,
                &session_config.source_id,
                expires_at,
            )
            .await;

        // The lifecycle row (source of truth) was not created in the other two
        // cases, so the Redis key written above is orphaned: a proxy would
        // authenticate from it and capture traffic for a session with no
        // lifecycle row, no reaper coverage, and no SessionEnd. Remove it on
        // every insert failure, not just a lost race.
        match insert_result {
            Ok(SessionInsert::Inserted) => {}
            Ok(SessionInsert::AlreadyActive) => {
                let _ = redis::cmd("DEL")
                    .arg(&data_key)
                    .query_async::<i64>(&mut conn)
                    .await;
                // A concurrent create won the race; attach to the winner instead.
                if let Some(existing) = self
                    .try_attach(&req_clone, expires_at_ms, expires_at)
                    .await?
                {
                    return Ok(existing);
                }
                // The attach failed (session closed between attempts) →
                // surface the error; caller should retry.
                return Err(anyhow!(
                    "failed to insert session_lifecycle row: an active session holds the slot"
                ));
            }
            Err(e) => {
                let _ = redis::cmd("DEL")
                    .arg(&data_key)
                    .query_async::<i64>(&mut conn)
                    .await;
                return Err(e).context("failed to insert session_lifecycle row");
            }
        }

        tracing::info!(
            session_id = %session_id,
            org_id = %session_config.org_id,
            ttl_secs,
            "session created (ref_count=1)"
        );

        let proxy_url = build_authenticated_url("http", &self.proxy_public_host, session_id);
        let proxy_url_socks5 =
            build_authenticated_url("socks5", &self.proxy_public_host_socks5, session_id);

        Ok(CreateSessionResponse {
            session_id,
            ca_cert_pem: self.ca_cert_pem.clone(),
            expires_at_ms,
            proxy_url,
            proxy_url_socks5,
            attached: false,
            success: true,
            error: None,
            warning: None,
            upstream_overrides: session_config.upstream_overrides.clone(),
        })
    }

    /// Release one reference to a session. When the reference count reaches
    /// zero, the session is fully torn down: proxies are notified via pubsub
    /// and a `SessionEnd` event is pushed to the request log stream. The
    /// Redis key is left to expire naturally via its TTL.
    ///
    /// Returns `true` if the session existed (regardless of whether this call
    /// was the final release or just a decrement).
    pub async fn delete(&self, session_id: Uuid) -> Result<bool> {
        let data_key = format!("{}:session:{}:data", self.redis_key_prefix, session_id);
        let mut conn = self.redis.clone();

        let raw: Option<String> = redis::cmd("GET")
            .arg(&data_key)
            .query_async(&mut conn)
            .await
            .context("failed to GET session data")?;

        let Some(raw) = raw else {
            return Ok(false);
        };

        // Atomically decrement ref_count and transition to 'consuming' only
        // when this is the last reference.  Returns the new ref_count so we
        // know whether to proceed with teardown.
        let new_ref_count = self
            .db
            .release_session(session_id)
            .await
            .context("failed to decrement session ref_count")?;

        let Some(new_ref_count) = new_ref_count else {
            // Row missing or already past 'active' — treat as "existed"
            // since we found the Redis key. Teardown was already initiated.
            return Ok(true);
        };

        if new_ref_count > 0 {
            tracing::info!(
                session_id = %session_id,
                ref_count = new_ref_count,
                "session reference released (still active)"
            );
            return Ok(true);
        }

        // ref_count == 0 → full teardown path (same as before).

        // Notify proxies that this session is invalidated.
        if let Err(e) = redis::cmd("PUBLISH")
            .arg(format!("{}:session_invalidations", self.redis_key_prefix))
            .arg(session_id.to_string())
            .query_async::<i64>(&mut conn)
            .await
        {
            tracing::warn!(
                session_id = %session_id,
                error = %e,
                "failed to publish session invalidation"
            );
        }

        // Build and push SessionEnd event (protobuf wire format).
        match serde_json::from_str::<SessionConfig>(&raw) {
            Ok(config) => {
                let timestamp_nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64;
                let key = config.source_id.clone();
                let event = wire::SessionEndEvent {
                    session_id: Bytes::copy_from_slice(session_id.as_bytes()),
                    org_id: config.org_id,
                    source: config.source,
                    source_id: config.source_id,
                    timestamp_nanos,
                };
                let envelope = wire::RequestLogMessage {
                    kind: Some(request_log_message::Kind::SessionEnd(event)),
                };
                let payload = Bytes::from(envelope.encode_to_vec());
                if let Err(e) = self.log_producer.publish(key.as_bytes(), payload).await {
                    tracing::warn!(
                        session_id = %session_id,
                        error = %e,
                        "failed to publish SessionEnd event"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    session_id = %session_id,
                    error = %e,
                    "failed to deserialize session config during delete"
                );
            }
        }

        tracing::info!(session_id = %session_id, "session closed (last reference released)");
        Ok(true)
    }

    /// Extend a session's TTL. Returns the new expires_at_ms.
    ///
    /// - `additional_secs`: add this many seconds to the current expiry
    /// - `new_ttl_secs`: set the TTL to exactly this many seconds from now
    pub async fn extend(
        &self,
        session_id: Uuid,
        additional_secs: Option<u32>,
        new_ttl_secs: Option<u32>,
    ) -> Result<i64> {
        // Guard: only extend sessions that are still 'active' in Postgres.
        // Sessions in 'consuming' or 'closed' state must not be extended.
        let pg_state = self
            .db
            .session_state(session_id)
            .await
            .context("failed to query session_lifecycle state")?;

        match pg_state.as_deref() {
            Some("active") => { /* ok, proceed */ }
            Some(state) => {
                return Err(anyhow!(
                    "session {} is in '{}' state and cannot be extended",
                    session_id,
                    state,
                ));
            }
            None => {
                return Err(anyhow!("session not found or already expired"));
            }
        }

        let data_key = format!("{}:session:{}:data", self.redis_key_prefix, session_id);
        let mut conn = self.redis.clone();

        let raw: Option<String> = redis::cmd("GET")
            .arg(&data_key)
            .query_async(&mut conn)
            .await
            .context("failed to GET session data")?;
        let raw = raw.ok_or_else(|| anyhow!("session not found or already expired"))?;

        let mut config: SessionConfig =
            serde_json::from_str(&raw).context("failed to deserialize session config")?;

        let now_ms = time::OffsetDateTime::now_utc().unix_timestamp() * 1000;

        let new_expires_ms = if let Some(new_ttl) = new_ttl_secs {
            now_ms + (new_ttl as i64) * 1000
        } else if let Some(additional) = additional_secs {
            config.expires_at_ms + (additional as i64) * 1000
        } else {
            return Err(anyhow!(
                "either additional_secs or new_ttl_secs must be provided"
            ));
        };

        let remaining_secs = ((new_expires_ms - now_ms) / 1000).max(1) as u64;
        config.expires_at_ms = new_expires_ms;

        let value = serde_json::to_string(&config).context("failed to serialize session config")?;

        redis::cmd("SET")
            .arg(&data_key)
            .arg(&value)
            .arg("EX")
            .arg(remaining_secs as i64)
            .query_async::<()>(&mut conn)
            .await
            .context("failed to write extended session to Redis")?;

        // Mirror the new expiry into Postgres so the phantom-active reaper
        // sees the extended deadline. Best-effort: a Redis-only extend is
        // still observed by the proxy via its Redis re-read on cache miss;
        // the worst case if this fails is the reaper closing the session
        // earlier than intended, which we tolerate as a soft inconsistency.
        if let Err(e) = self
            .db
            .set_session_expiry(session_id, ms_to_offset_dt(new_expires_ms))
            .await
        {
            tracing::warn!(
                session_id = %session_id,
                error = %e,
                "failed to update session_lifecycle.expires_at after extend"
            );
        }
        tracing::info!(
            session_id = %session_id,
            new_expires_ms,
            remaining_secs,
            "session extended"
        );

        Ok(new_expires_ms)
    }

    /// Get a session config from Redis.
    pub async fn get(&self, session_id: Uuid) -> Result<Option<SessionConfig>> {
        let data_key = format!("{}:session:{}:data", self.redis_key_prefix, session_id);
        let mut conn = self.redis.clone();
        let raw: Option<String> = redis::cmd("GET")
            .arg(&data_key)
            .query_async(&mut conn)
            .await
            .context("failed to GET session data")?;
        match raw {
            Some(data) => {
                let config: SessionConfig =
                    serde_json::from_str(&data).context("failed to deserialize session")?;
                Ok(Some(config))
            }
            None => Ok(None),
        }
    }

    /// Close sessions whose Redis TTL elapsed without an explicit DELETE.
    ///
    /// Without this, sessions whose clients never call `DELETE /sessions/{id}`
    /// leak as `state='active'` rows in `session_lifecycle` forever and
    /// pollute the `(org_id, state)` index. The reaper publishes a
    /// `SessionEnd` event for each expired-but-active row — the consumer
    /// then closes the row once the captures read before it are stored,
    /// exactly the same way as for an explicit DELETE.
    ///
    /// `grace` is the buffer past `expires_at` before a session is
    /// considered abandoned; it should comfortably exceed the worst-case
    /// consumer lag so any in-flight captures are read before the
    /// SessionEnd.
    ///
    /// Returns the number of sessions emitted in this pass.
    pub async fn reap_expired_sessions(&self, grace: std::time::Duration) -> Result<usize> {
        const REAP_BATCH: i64 = 1000;

        let cutoff = time::OffsetDateTime::now_utc() - grace;
        let rows = self
            .db
            .claim_expired_sessions(cutoff, REAP_BATCH)
            .await
            .context("failed to claim expired sessions")?;

        let timestamp_nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64;
        let mut emitted = 0_usize;

        for (session_id, org_id, source, source_id) in rows {
            let Some(source_id) = source_id.filter(|value| !value.is_empty()) else {
                tracing::error!(%session_id, "reaper: claimed session without source_id");
                continue;
            };
            let event = wire::SessionEndEvent {
                session_id: Bytes::copy_from_slice(session_id.as_bytes()),
                org_id,
                source,
                source_id: source_id.clone(),
                timestamp_nanos,
            };
            let envelope = wire::RequestLogMessage {
                kind: Some(request_log_message::Kind::SessionEnd(event)),
            };

            if let Err(e) = self
                .log_producer
                .publish(source_id.as_bytes(), Bytes::from(envelope.encode_to_vec()))
                .await
            {
                tracing::warn!(
                    %session_id,
                    error = %e,
                    "reaper: failed to publish claimed SessionEnd; will retry after grace"
                );
                continue;
            }
            emitted += 1;
        }

        if emitted > 0 {
            tracing::info!(emitted, "reaper: emitted SessionEnd for expired sessions");
        }
        Ok(emitted)
    }

    /// Atomically claim and re-drive sessions stranded in `consuming`.
    /// Refreshing `closing_at` in the claim gives each row a new lease, so
    /// concurrent API replicas cannot publish it during the same grace window.
    /// Failed publishes remain `consuming` and become eligible again later.
    ///
    /// Returns the number of SessionEnd events published.
    pub async fn reap_stuck_consuming(&self, grace: std::time::Duration) -> Result<usize> {
        const REAP_BATCH: i64 = 500;

        let cutoff = time::OffsetDateTime::now_utc() - grace;
        let rows = self
            .db
            .claim_stuck_sessions(cutoff, REAP_BATCH)
            .await
            .context("failed to claim stuck consuming sessions")?;

        let timestamp_nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64;
        let mut redriven = 0_usize;

        for (session_id, org_id, source, source_id) in rows {
            let Some(source_id) = source_id.filter(|value| !value.is_empty()) else {
                tracing::error!(%session_id, "reaper: claimed session without source_id");
                continue;
            };
            let event = wire::SessionEndEvent {
                session_id: Bytes::copy_from_slice(session_id.as_bytes()),
                org_id,
                source,
                source_id: source_id.clone(),
                timestamp_nanos,
            };
            let envelope = wire::RequestLogMessage {
                kind: Some(request_log_message::Kind::SessionEnd(event)),
            };

            if let Err(e) = self
                .log_producer
                .publish(source_id.as_bytes(), Bytes::from(envelope.encode_to_vec()))
                .await
            {
                tracing::warn!(
                    %session_id,
                    error = %e,
                    "reaper: failed to re-publish claimed SessionEnd"
                );
                continue;
            }
            redriven += 1;
        }

        if redriven > 0 {
            tracing::info!(redriven, "reaper: re-drove stuck consuming sessions");
        }
        Ok(redriven)
    }

    /// Try to attach to an existing active session with the same
    /// `(org_id, source, source_id)`. On success, bumps the reference
    /// count, extends the Redis TTL if the new deadline is later, and
    /// returns the response. Returns `None` if no matching active
    /// session exists.
    async fn try_attach(
        &self,
        req: &CreateSessionRequest,
        new_expires_at_ms: i64,
        new_expires_at: time::OffsetDateTime,
    ) -> Result<Option<CreateSessionResponse>> {
        // Find a candidate first; only increment its reference after Redis config
        // confirms this caller cannot attach to a different private route map.
        let session_id = self
            .db
            .active_session(&req.org_id, &req.source, &req.source_id)
            .await
            .context("failed to query active session")?;

        let Some(session_id) = session_id else {
            return Ok(None);
        };

        // Fetch existing config from Redis to build the response and
        // detect config mismatches.
        let data_key = format!("{}:session:{}:data", self.redis_key_prefix, session_id);
        let mut conn = self.redis.clone();

        let raw: Option<String> = redis::cmd("GET")
            .arg(&data_key)
            .query_async(&mut conn)
            .await
            .context("failed to GET session data for attach")?;

        let Some(raw) = raw else {
            // Redis key expired but the PG row is still active. Close the stale
            // row now rather than waiting for the reaper — leaving it state='active'
            // holds the unique index slot and will cause the caller's INSERT to
            // hit a unique violation it cannot recover from.
            let _ = self.db.abandon_active_session(session_id).await;
            return Ok(None);
        };

        let existing: SessionConfig =
            serde_json::from_str(&raw).context("failed to deserialize existing session config")?;

        if req.upstream_overrides != existing.upstream_overrides {
            return Err(UpstreamOverridesConflict.into());
        }

        let effective_expires_at_ms = self
            .db
            .attach_session(session_id, new_expires_at)
            .await
            .context("failed to attach active session")?;
        let Some(effective_expires_at_ms) = effective_expires_at_ms else {
            return Ok(None);
        };

        // Extend Redis TTL if the new deadline is later than the current one.
        if new_expires_at_ms > existing.expires_at_ms {
            let now_ms = time::OffsetDateTime::now_utc().unix_timestamp() * 1000;
            let remaining_secs = ((new_expires_at_ms - now_ms) / 1000).max(1);

            // Re-serialize with updated expires_at_ms.
            let mut updated = existing.clone();
            updated.expires_at_ms = new_expires_at_ms;
            if let Ok(value) = serde_json::to_string(&updated) {
                let _ = redis::cmd("SET")
                    .arg(&data_key)
                    .arg(&value)
                    .arg("EX")
                    .arg(remaining_secs)
                    .query_async::<()>(&mut conn)
                    .await;
            }
        }

        // Detect config mismatches and produce a warning.
        let warning = detect_config_mismatch(req, &existing);

        tracing::info!(
            session_id = %session_id,
            org_id = %req.org_id,
            source_id = %req.source_id,
            warning = warning.as_deref().unwrap_or("none"),
            "attached to existing session (ref_count incremented)"
        );

        let proxy_url = build_authenticated_url("http", &self.proxy_public_host, session_id);
        let proxy_url_socks5 =
            build_authenticated_url("socks5", &self.proxy_public_host_socks5, session_id);

        Ok(Some(CreateSessionResponse {
            session_id,
            ca_cert_pem: self.ca_cert_pem.clone(),
            expires_at_ms: effective_expires_at_ms,
            proxy_url,
            proxy_url_socks5,
            attached: true,
            success: true,
            error: None,
            warning,
            upstream_overrides: existing.upstream_overrides.clone(),
        }))
    }
}

/// Convert a UNIX-epoch milliseconds value to `OffsetDateTime`.
/// Falls back to `now_utc` on overflow — only reachable for nonsense input.
fn ms_to_offset_dt(ms: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp_nanos((ms as i128) * 1_000_000)
        .unwrap_or_else(|_| time::OffsetDateTime::now_utc())
}

/// Compare the incoming request's capture config against the existing
/// session and return a human-readable warning if they differ.
fn detect_config_mismatch(req: &CreateSessionRequest, existing: &SessionConfig) -> Option<String> {
    let mut diffs = Vec::new();

    if req.captured_hosts != existing.captured_hosts {
        diffs.push("captured_hosts");
    }
    if req.excluded_hosts != existing.excluded_hosts {
        diffs.push("excluded_hosts");
    }
    if req.inject_headers != existing.inject_headers {
        diffs.push("inject_headers");
    }
    if req.serialize != existing.serialize {
        diffs.push("serialize");
    }
    if req.agent != existing.agent {
        diffs.push("agent");
    }

    if diffs.is_empty() {
        None
    } else {
        Some(format!(
            "attached to existing session but config differs on: {}; existing config is used",
            diffs.join(", ")
        ))
    }
}
