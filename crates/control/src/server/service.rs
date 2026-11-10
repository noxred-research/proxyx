use std::sync::Arc;

use uuid::Uuid;

use crate::auth::UserPrincipal;
use crate::capture_store::{ConversationQuery, TimeSeriesQuery};
use crate::models::{HttpCapture, SearchResponse, WsCapture, WsSearchResponse};
use crate::policy::{PolicyError, require_superuser, resolve_user_org};
use crate::query::ws::{WsQueryBranch, WsTrafficQuery};
use crate::query::{
    IntFilter, NonEmpty, QueryBranch, SortField, SortOrder, StringFilter, TrafficQuery,
};
use crate::server::AppState;
use proxyx_control_graphql::*;

#[derive(Clone)]
pub struct ControllerApiService {
    state: Arc<AppState>,
}

impl ControllerApiService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    pub async fn organization_settings(
        &self,
        principal: &UserPrincipal,
        requested_org_id: Option<String>,
    ) -> anyhow::Result<Option<OrgSettingsDto>> {
        let org_id =
            resolve_user_org(principal, requested_org_id)?.ok_or(PolicyError::Forbidden)?;
        self.load_org_settings(org_id).await
    }

    pub async fn upsert_organization_settings(
        &self,
        principal: &UserPrincipal,
        input: UpsertOrgSettings,
    ) -> anyhow::Result<OrgSettingsDto> {
        require_superuser(principal)?;
        validate_org_settings_input(&input)?;

        self.state
            .db
            .set_org_settings(&crate::db::OrgSettingsWrite {
                id: &input.org_id,
                rpm: rate_limit_to_db(input.requests_per_minute, "requests_per_minute")?,
                burst: rate_limit_to_db(input.burst, "burst")?,
                proxy_type: input.proxy_type.as_deref(),
                proxy_address: input.proxy_address.as_deref(),
                proxy_username: input.proxy_username.as_deref(),
                proxy_password: input.proxy_password.as_deref(),
            })
            .await?;

        let effective_rpm = input
            .requests_per_minute
            .unwrap_or(self.state.default_rate_limit_rpm);
        let effective_burst = input.burst.unwrap_or(self.state.default_rate_limit_burst);
        if let Err(e) = crate::session::replicate_ratelimit(
            &mut self.state.redis.clone(),
            &input.org_id,
            effective_burst,
            effective_rpm,
            &self.state.config.redis_key_prefix,
        )
        .await
        {
            tracing::warn!(error = %e, org_id = %input.org_id, "failed to replicate rate limit to Redis");
        }

        self.load_org_settings(input.org_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("organization settings were not persisted"))
    }

    pub async fn upsert_organization_rate_limit(
        &self,
        principal: &UserPrincipal,
        org_id: String,
        requests_per_minute: Option<u32>,
        burst: Option<u32>,
    ) -> anyhow::Result<OrgSettingsDto> {
        require_superuser(principal)?;
        if org_id.trim().is_empty() {
            anyhow::bail!("org_id is required and must be non-empty");
        }

        self.state
            .db
            .set_org_rate_limit(
                &org_id,
                rate_limit_to_db(requests_per_minute, "requests_per_minute")?,
                rate_limit_to_db(burst, "burst")?,
            )
            .await?;

        let effective_rpm = requests_per_minute.unwrap_or(self.state.default_rate_limit_rpm);
        let effective_burst = burst.unwrap_or(self.state.default_rate_limit_burst);
        if let Err(e) = crate::session::replicate_ratelimit(
            &mut self.state.redis.clone(),
            &org_id,
            effective_burst,
            effective_rpm,
            &self.state.config.redis_key_prefix,
        )
        .await
        {
            tracing::warn!(error = %e, org_id, "failed to replicate rate limit to Redis");
        }

        self.load_org_settings(org_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("organization rate limit was not persisted"))
    }

    pub async fn search_http_traffic(
        &self,
        principal: &UserPrincipal,
        input: HttpTrafficSearch,
    ) -> anyhow::Result<SearchResponse> {
        let org_id = resolve_user_org(principal, input.org_id.clone())?;
        let mut query = traffic_query_from_input(org_id, input)?;
        crate::query::validate_regex_patterns(&query)?;
        crate::query::bound_to_sessions(&self.state.db, &mut query).await?;
        let store = &self.state.capture_store;
        store.check_http_query(&query)?;
        let (search_res, count_res) =
            tokio::try_join!(store.search_requests(&query), store.count_requests(&query),)?;
        Ok(SearchResponse {
            total_count: Some(count_res),
            ..search_res
        })
    }

    pub async fn http_request(
        &self,
        principal: &UserPrincipal,
        requested_org_id: Option<String>,
        id: Uuid,
    ) -> anyhow::Result<Option<HttpCapture>> {
        let org_id = resolve_user_org(principal, requested_org_id)?
            .ok_or_else(|| anyhow::anyhow!("org_id is required for single-record lookup"))?;
        self.state.capture_store.get_request(&org_id, id).await
    }

    pub async fn search_ws_traffic(
        &self,
        principal: &UserPrincipal,
        input: WsTrafficSearch,
    ) -> anyhow::Result<WsSearchResponse> {
        let org_id = resolve_user_org(principal, input.org_id.clone())?;
        let query = ws_traffic_query_from_input(org_id, input);
        crate::query::ws::validate_regex_patterns(&query)?;
        let store = &self.state.capture_store;
        store.check_ws_query(&query)?;
        let (search_res, count_res) =
            tokio::try_join!(store.search_ws(&query), store.count_ws(&query))?;
        Ok(WsSearchResponse {
            total_count: Some(count_res),
            ..search_res
        })
    }

    pub async fn ws_message(
        &self,
        principal: &UserPrincipal,
        requested_org_id: Option<String>,
        id: Uuid,
    ) -> anyhow::Result<Option<WsCapture>> {
        let org_id = resolve_user_org(principal, requested_org_id)?
            .ok_or_else(|| anyhow::anyhow!("org_id is required for single-record lookup"))?;
        self.state.capture_store.get_ws_message(&org_id, id).await
    }

    /// Unified, time-ordered HTTP+WS feed. Both tables share the
    /// `(timestamp, session_offset, id)` sort key and cursor space, so we
    /// run the existing HTTP and WS searches under one cursor and k-way
    /// merge their pages. Over-fetched rows that fall past `limit` simply
    /// re-page on the next request (the cursor is exclusive), so no row is
    /// dropped or duplicated.
    pub async fn search_traffic(
        &self,
        principal: &UserPrincipal,
        input: TrafficSearch,
    ) -> anyhow::Result<TrafficSearchResponse> {
        let org_id = resolve_user_org(principal, input.org_id.clone())?;
        let limit = input
            .limit
            .unwrap_or(crate::query::DEFAULT_LIMIT)
            .min(crate::query::MAX_LIMIT);
        let want_http = !matches!(input.kind, TrafficKind::Ws);
        let want_ws = !matches!(input.kind, TrafficKind::Http);

        let mut events: Vec<TrafficEventDto> = Vec::new();
        let mut more = false;
        let mut total: u64 = 0;

        if want_http {
            let mut q = traffic_query_from_input(
                org_id.clone(),
                HttpTrafficSearch {
                    org_id: org_id.clone(),
                    filter: HttpTrafficFilter {
                        source_id: input.filter.source_id.clone(),
                        source: input.filter.source.clone(),
                        host: input.filter.host.clone(),
                        method: input.filter.method.clone(),
                        path: input.filter.path.clone(),
                        search: input.filter.search.clone(),
                        correlation_id: input.filter.correlation_id.clone(),
                        parent_correlation_id: None,
                        account_id: None,
                        tool_call_id: input.filter.tool_call_id.clone(),
                        status_code: input.filter.status_code,
                        request: HttpRequestFilter::default(),
                        response: HttpResponseFilter::default(),
                    },
                    cursor: input.cursor.clone(),
                    limit: Some(limit),
                    descending: input.descending,
                    // The k-way merge below interleaves on capture time.
                    order_by: HttpTrafficOrderField::Timestamp,
                },
            )?;
            crate::query::validate_regex_patterns(&q)?;
            crate::query::bound_to_sessions(&self.state.db, &mut q).await?;
            let store = &self.state.capture_store;
            store.check_http_query(&q)?;
            let (res, count) =
                tokio::try_join!(store.search_requests(&q), store.count_requests(&q))?;
            more = more || res.next_cursor.is_some();
            total += count;
            events.extend(
                res.items
                    .into_iter()
                    .map(|capture| TrafficEventDto::Http(capture.into())),
            );
        }

        if want_ws {
            let q = ws_traffic_query_from_input(
                org_id.clone(),
                WsTrafficSearch {
                    org_id: org_id.clone(),
                    filter: WsTrafficFilter {
                        source_id: input.filter.source_id.clone(),
                        source: input.filter.source.clone(),
                        session_id: input.filter.session_id.clone(),
                        parent_event_id: input.filter.parent_event_id.clone(),
                        host: input.filter.host.clone(),
                        direction: input.filter.direction.clone(),
                        opcode: input.filter.opcode.clone(),
                        payload: None,
                        search: input.filter.search.clone(),
                    },
                    cursor: input.cursor.clone(),
                    limit: Some(limit),
                    descending: input.descending,
                    payload_max_bytes: input.payload_max_bytes,
                },
            );
            crate::query::ws::validate_regex_patterns(&q)?;
            let store = &self.state.capture_store;
            store.check_ws_query(&q)?;
            let (res, count) = tokio::try_join!(store.search_ws(&q), store.count_ws(&q))?;
            more = more || res.next_cursor.is_some();
            total += count;
            events.extend(
                res.items
                    .into_iter()
                    .map(|capture| TrafficEventDto::Ws(capture.into())),
            );
        }

        if input.descending {
            events.sort_by_key(|e| std::cmp::Reverse(e.sort_key()));
        } else {
            events.sort_by_key(|e| e.sort_key());
        }
        let had_more = more || events.len() as u32 > limit;
        events.truncate(limit as usize);
        let next_cursor = if had_more {
            events.last().map(|e| {
                let (ts, off, id) = e.sort_key();
                crate::query::cursor::encode_cursor(ts, off, id)
            })
        } else {
            None
        };
        Ok(TrafficSearchResponse {
            items: events,
            next_cursor,
            total_count: Some(total),
        })
    }

    /// Discovery primitive: aggregate `ws_messages` into one row per
    /// conversation (`parent_event_id`), joining the handshake host/path from
    /// `http_captures`. Backed by the `ws_messages_by_parent` MV. Capped at
    /// `MAX_LIMIT` conversations (no cursor in v1).
    pub async fn ws_conversations(
        &self,
        principal: &UserPrincipal,
        input: WsConversationSearch,
    ) -> anyhow::Result<WsConversationSearchResponse> {
        let org_id = resolve_user_org(principal, input.org_id)?.ok_or(PolicyError::Forbidden)?;
        let limit = input
            .limit
            .unwrap_or(crate::query::DEFAULT_LIMIT)
            .min(crate::query::MAX_LIMIT);
        self.state
            .capture_store
            .ws_conversations(&ConversationQuery {
                org_id: &org_id,
                source_ids: input.filter.source_id.as_deref(),
                source: input.filter.source.as_deref(),
                host: input.filter.host.as_deref(),
                limit,
                descending: input.descending,
            })
            .await
    }

    pub async fn rate_limit_state(
        &self,
        principal: &UserPrincipal,
        requested_org_id: Option<String>,
    ) -> anyhow::Result<RateLimitStateDto> {
        let org_id =
            resolve_user_org(principal, requested_org_id)?.ok_or(PolicyError::Forbidden)?;
        let mut conn = self.state.redis.clone();
        let live = crate::session::read_ratelimit_state(
            &mut conn,
            &org_id,
            &self.state.config.redis_key_prefix,
        )
        .await?;
        Ok(RateLimitStateDto {
            org_id,
            exists: live.exists,
            tokens: live.tokens,
            burst: live.burst,
            rpm: live.rpm,
            last_refill_ms: live.last_refill_ms,
        })
    }

    pub async fn request_rate_series(
        &self,
        principal: &UserPrincipal,
        input: RequestRateSeriesInput,
    ) -> anyhow::Result<Vec<RequestRatePointDto>> {
        let org_id = resolve_user_org(principal, input.org_id)?.ok_or(PolicyError::Forbidden)?;
        if input.end <= input.start {
            anyhow::bail!("end must be after start");
        }

        self.state
            .capture_store
            .request_rate_series(&org_id, input.start, input.end)
            .await
    }

    pub async fn http_traffic_time_series(
        &self,
        principal: &UserPrincipal,
        input: HttpTrafficTimeSeriesInput,
    ) -> anyhow::Result<Vec<TrafficTimeSeriesPointDto>> {
        // Mirror search_http_traffic: a superadmin without an org scope resolves
        // to None and aggregates across orgs (the source_id filter still scopes
        // it to this scan). Only constrain org_id when one is resolved.
        let org_id = resolve_user_org(principal, input.org_id)?;
        if input.end <= input.start {
            anyhow::bail!("end must be after start");
        }
        if input.bucket_seconds == 0 {
            anyhow::bail!("bucket_seconds must be a positive integer");
        }

        // Restrict to the requested scanners when the caller supplies a
        // non-empty source_id filter; otherwise aggregate across all.
        let source_ids = input.filter.source_id.filter(|ids| !ids.is_empty());
        self.state
            .capture_store
            .http_traffic_time_series(&TimeSeriesQuery {
                org_id: org_id.as_deref(),
                source_ids: source_ids.as_deref(),
                start: input.start,
                end: input.end,
                bucket_seconds: input.bucket_seconds,
            })
            .await
    }

    /// Aggregate request traffic for a set of scanner-run sources in one API
    /// call: summed per time bucket (the requests-over-time chart) and totaled
    /// per source (the per-scan column). Large source sets are split into
    /// parser-safe ClickHouse queries and folded here rather than over the wire.
    pub async fn scan_traffic_summary(
        &self,
        principal: &UserPrincipal,
        input: ScanTrafficSummaryInput,
    ) -> anyhow::Result<ScanTrafficSummaryDto> {
        // Superadmin without an org scope resolves to None; the source_id
        // filter still scopes the result to the requested scans.
        let org_id = resolve_user_org(principal, input.org_id)?;
        if input.end <= input.start {
            anyhow::bail!("end must be after start");
        }
        if input.bucket_seconds == 0 {
            anyhow::bail!("bucket_seconds must be a positive integer");
        }
        // No sources -> nothing to aggregate. Never fall through to an
        // unscoped scan of every capture.
        if input.source_ids.is_empty() {
            return Ok(ScanTrafficSummaryDto {
                buckets: Vec::new(),
                by_source: Vec::new(),
                total: 0,
            });
        }

        self.state
            .capture_store
            .scan_traffic_summary(&TimeSeriesQuery {
                org_id: org_id.as_deref(),
                source_ids: Some(input.source_ids.as_slice()),
                start: input.start,
                end: input.end,
                bucket_seconds: input.bucket_seconds,
            })
            .await
    }

    async fn load_org_settings(&self, org_id: String) -> anyhow::Result<Option<OrgSettingsDto>> {
        let row = self.state.db.org_settings(&org_id).await?;

        let settings = match row {
            Some(row) => OrgSettingsDto {
                org_id,
                requests_per_minute: db_rate_limit_or_default(
                    row.rate_limit_rpm,
                    self.state.default_rate_limit_rpm,
                    "rate_limit_rpm",
                )?,
                burst: db_rate_limit_or_default(
                    row.rate_limit_burst,
                    self.state.default_rate_limit_burst,
                    "rate_limit_burst",
                )?,
                proxy_type: row.proxy_type,
                proxy_address: row.proxy_address,
            },
            None => OrgSettingsDto {
                org_id,
                requests_per_minute: self.state.default_rate_limit_rpm,
                burst: self.state.default_rate_limit_burst,
                proxy_type: None,
                proxy_address: None,
            },
        };

        Ok(Some(settings))
    }
}

impl ControllerApiService {
    pub async fn create_traffic_view(
        &self,
        principal: &UserPrincipal,
        input: CreateTrafficViewInput,
    ) -> anyhow::Result<TrafficViewDto> {
        let org_id = resolve_user_org(principal, input.org_id)?
            .ok_or_else(|| anyhow::anyhow!("org_id is required for traffic view creation"))?;
        if input.branches.is_empty() {
            anyhow::bail!("branches must not be empty");
        }
        let branches: Vec<QueryBranch> = input
            .branches
            .into_iter()
            .map(branch_from_view_input)
            .collect();
        let query = TrafficQuery {
            org_id: Some(org_id.clone()),
            branches: NonEmpty(branches),
            cursor: None,
            end_cursor: None,
            limit: None,
            order: SortOrder::default(),
            order_by: SortField::Timestamp,
            request_body_max_fetch_size: None,
            response_body_max_fetch_size: None,
        };
        crate::query::validate_regex_patterns(&query)?;

        let exporter = self.state.capture_store.require_view_exporter()?;
        let result = crate::views::create_view(
            &self.state.config,
            &self.state.view_store,
            exporter,
            &self.state.db,
            &org_id,
            query,
        )
        .await?;

        let signed_url = match result.s3_key.as_deref() {
            Some(key) if result.status == "completed" => {
                self.state.view_store.download_url(key).await
            }
            _ => None,
        };

        Ok(TrafficViewDto {
            view_id: result.view_id,
            status: result.status,
            s3_key: result.s3_key,
            signed_url,
            error: result.error,
            read_rows: None,
            written_rows: None,
            total_rows: None,
        })
    }

    pub async fn get_traffic_view(
        &self,
        principal: &UserPrincipal,
        view_id: Uuid,
        org_id: Option<String>,
    ) -> anyhow::Result<Option<TrafficViewDto>> {
        let org_id = resolve_user_org(principal, org_id)?
            .ok_or_else(|| anyhow::anyhow!("org_id is required for traffic view lookup"))?;

        let exporter = self.state.capture_store.require_view_exporter()?;
        let result = crate::views::poll_view_status(
            &self.state.view_store,
            exporter,
            &self.state.db,
            &org_id,
            view_id,
        )
        .await?;

        let Some(r) = result else {
            return Ok(None);
        };
        let signed_url = match r.s3_key.as_deref() {
            Some(key) if r.status == "completed" => self.state.view_store.download_url(key).await,
            _ => None,
        };
        Ok(Some(TrafficViewDto {
            view_id: r.view_id,
            status: r.status,
            s3_key: r.s3_key,
            signed_url,
            error: r.error,
            read_rows: r.read_rows,
            written_rows: r.written_rows,
            total_rows: r.total_rows,
        }))
    }
}

fn rate_limit_to_db(value: Option<u32>, field: &str) -> anyhow::Result<Option<i32>> {
    value
        .map(|value| {
            i32::try_from(value)
                .map_err(|_| anyhow::anyhow!("{field} must be at most {}", i32::MAX))
        })
        .transpose()
}

fn db_rate_limit_or_default(value: Option<i32>, default: u32, field: &str) -> anyhow::Result<u32> {
    match value {
        Some(value) => u32::try_from(value)
            .map_err(|_| anyhow::anyhow!("{field} contains a negative rate limit")),
        None => Ok(default),
    }
}

fn validate_org_settings_input(input: &UpsertOrgSettings) -> anyhow::Result<()> {
    if input.org_id.trim().is_empty() {
        anyhow::bail!("org_id is required and must be non-empty");
    }

    if input.proxy_type.is_some() != input.proxy_address.is_some() {
        anyhow::bail!("proxy_type and proxy_address must be provided together");
    }
    if let Some(proxy_type) = input.proxy_type.as_deref() {
        match proxy_type {
            "socks5" | "http" => {}
            _ => anyhow::bail!("proxy_type must be \"socks5\" or \"http\""),
        }
    }
    Ok(())
}

fn traffic_query_from_input(
    org_id: Option<String>,
    input: HttpTrafficSearch,
) -> anyhow::Result<TrafficQuery> {
    let filter = input.filter;
    let request = filter.request;
    let response = filter.response;
    let methods = request.methods.and_then(|methods| {
        combine(
            methods.into_iter().map(exact_string_filter).collect(),
            |filters| StringFilter::Any { filters },
        )
    });
    // Classes and codes form one "any of" status selection: `2xx` + `404`
    // matches either.
    let classes = response.status_classes.into_iter().flatten().map(|class| {
        let low = i64::from(class) * 100;
        IntFilter::All {
            filters: NonEmpty(vec![
                IntFilter::Gte { value: low },
                IntFilter::Lt { value: low + 100 },
            ]),
        }
    });
    let codes = response
        .status_codes
        .into_iter()
        .flatten()
        .map(|code| IntFilter::Exact { value: code.into() });
    let response_status = combine(classes.chain(codes).collect(), |filters| IntFilter::Any {
        filters,
    });
    let branch = QueryBranch {
        source_id: filter.source_id,
        source: filter.source,
        host: filter.host.map(exact_string_filter),
        method: combine(
            [filter.method.map(exact_string_filter), methods]
                .into_iter()
                .flatten()
                .collect(),
            |filters| StringFilter::All { filters },
        ),
        path: filter.path.map(contains_string_filter),
        request_body: None,
        response_body: None,
        correlation_id: filter.correlation_id.map(exact_string_filter),
        parent_correlation_id: filter.parent_correlation_id.map(exact_string_filter),
        account_id: filter.account_id.map(exact_string_filter),
        tool_call_id: filter.tool_call_id.map(exact_string_filter),
        status_code: combine(
            [
                filter.status_code.map(|value| IntFilter::Exact {
                    value: value.into(),
                }),
                response_status,
            ]
            .into_iter()
            .flatten()
            .collect(),
            |filters| IntFilter::All { filters },
        ),
        response_size: int_range(response.min_length, response.max_length),
        duration_ms: int_range(response.min_duration_ms, response.max_duration_ms),
        mime_type: response
            .mime_type
            .map(|m| m.trim().to_string())
            .filter(|m| !m.is_empty())
            .map(contains_string_filter),
        request_sends_cookies: request.sends_cookies,
        response_sets_cookies: response.sets_cookies,
        request_header: None,
        response_header: None,
        time_window: None,
    };
    // `search` and `url_contains` each match the host OR the path, so each
    // splits every branch into a host branch and a path branch.
    let mut branches = vec![branch];
    for term in [filter.search, request.url_contains].into_iter().flatten() {
        let term = term.trim();
        if term.is_empty() {
            continue;
        }
        branches = branches
            .into_iter()
            .flat_map(|branch| {
                [
                    QueryBranch {
                        host: search_string_filter(branch.host.clone(), term.to_string()),
                        ..branch.clone()
                    },
                    QueryBranch {
                        path: search_string_filter(branch.path.clone(), term.to_string()),
                        ..branch
                    },
                ]
            })
            .collect();
    }
    Ok(TrafficQuery {
        org_id,
        branches: NonEmpty(branches),
        cursor: input.cursor,
        end_cursor: None,
        limit: input.limit,
        order: if input.descending {
            SortOrder::Desc
        } else {
            SortOrder::Asc
        },
        order_by: match input.order_by {
            HttpTrafficOrderField::Timestamp => SortField::Timestamp,
            HttpTrafficOrderField::Method => SortField::Method,
            HttpTrafficOrderField::Url => SortField::Url,
            HttpTrafficOrderField::StatusCode => SortField::StatusCode,
            HttpTrafficOrderField::ResponseSize => SortField::ResponseSize,
            HttpTrafficOrderField::MimeType => SortField::MimeType,
            HttpTrafficOrderField::Cookies => SortField::Cookies,
            HttpTrafficOrderField::DurationMs => SortField::DurationMs,
        },
        request_body_max_fetch_size: None,
        response_body_max_fetch_size: None,
    })
}

/// `None` for no filters, the filter itself for one, `join` for several.
fn combine<T>(mut filters: Vec<T>, join: fn(NonEmpty<T>) -> T) -> Option<T> {
    match filters.len() {
        0 => None,
        1 => filters.pop(),
        _ => Some(join(NonEmpty(filters))),
    }
}

fn int_range(min: Option<u32>, max: Option<u32>) -> Option<IntFilter> {
    combine(
        [
            min.map(|value| IntFilter::Gte {
                value: value.into(),
            }),
            max.map(|value| IntFilter::Lte {
                value: value.into(),
            }),
        ]
        .into_iter()
        .flatten()
        .collect(),
        |filters| IntFilter::All { filters },
    )
}

fn ws_traffic_query_from_input(org_id: Option<String>, input: WsTrafficSearch) -> WsTrafficQuery {
    let filter = input.filter;
    let branch_for = |source_id: Option<String>| WsQueryBranch {
        source_id,
        source: filter.source.clone(),
        session_id: filter.session_id.clone(),
        parent_event_id: filter.parent_event_id.clone(),
        host: filter.host.clone().map(exact_string_filter),
        payload: filter.payload.clone().map(contains_string_filter),
        direction: filter.direction.clone().map(exact_string_filter),
        opcode: filter.opcode.clone().map(exact_string_filter),
        close_reason: None,
        close_code: None,
        payload_size: None,
        was_compressed: None,
        payload_is_text: None,
        payload_truncated: None,
    };
    let branches = match filter.source_id.clone() {
        Some(ids) if !ids.is_empty() => ids.into_iter().map(|id| branch_for(Some(id))).collect(),
        _ => vec![branch_for(None)],
    };
    let branches = match filter.search {
        Some(search) if !search.trim().is_empty() => {
            let search = search.trim().to_string();
            branches
                .into_iter()
                .flat_map(|branch| {
                    [
                        WsQueryBranch {
                            host: search_string_filter(branch.host.clone(), search.clone()),
                            ..branch.clone()
                        },
                        WsQueryBranch {
                            payload: search_string_filter(branch.payload.clone(), search.clone()),
                            ..branch
                        },
                    ]
                })
                .collect()
        }
        _ => branches,
    };
    WsTrafficQuery {
        org_id,
        branches: NonEmpty(branches),
        cursor: input.cursor,
        limit: input.limit,
        order: if input.descending {
            SortOrder::Desc
        } else {
            SortOrder::Asc
        },
        payload_max_fetch_size: input.payload_max_bytes,
    }
}

fn exact_string_filter(value: String) -> StringFilter {
    StringFilter::Exact { value }
}

fn contains_string_filter(value: String) -> StringFilter {
    StringFilter::Contains { value }
}

fn search_string_filter(existing: Option<StringFilter>, search: String) -> Option<StringFilter> {
    let contains = contains_string_filter(search);
    Some(match existing {
        Some(existing) => StringFilter::All {
            filters: NonEmpty(vec![existing, contains]),
        },
        None => contains,
    })
}

fn branch_from_view_input(input: TrafficViewBranchInput) -> QueryBranch {
    QueryBranch {
        source_id: input.source_id,
        source: input.source,
        host: input.host.map(exact_string_filter),
        method: input.method.map(exact_string_filter),
        path: input.path.map(exact_string_filter),
        request_body: None,
        response_body: None,
        correlation_id: input.correlation_id.map(exact_string_filter),
        parent_correlation_id: input.parent_correlation_id.map(exact_string_filter),
        account_id: input.account_id.map(exact_string_filter),
        tool_call_id: input.tool_call_id.map(exact_string_filter),
        status_code: input.status_code.map(|value| IntFilter::Exact { value }),
        response_size: None,
        duration_ms: None,
        mime_type: None,
        request_sends_cookies: None,
        response_sets_cookies: None,
        request_header: None,
        response_header: None,
        time_window: None,
    }
}

fn header_pair((name, value): (String, String)) -> HeaderPairDto {
    HeaderPairDto { name, value }
}

impl From<crate::models::HttpCaptureSummary> for HttpTrafficSummaryDto {
    fn from(capture: crate::models::HttpCaptureSummary) -> Self {
        Self {
            id: capture.id,
            org_id: capture.org_id,
            timestamp: capture.timestamp,
            session_offset: capture.session_offset,
            method: capture.method,
            path: capture.path,
            host: capture.host,
            scheme: capture.scheme,
            request_headers: capture
                .request_headers
                .into_iter()
                .map(header_pair)
                .collect(),
            request_size: capture.request_size,
            status_code: capture.status_code,
            response_headers: capture
                .response_headers
                .into_iter()
                .map(header_pair)
                .collect(),
            response_size: capture.response_size,
            duration_ms: capture.duration_ms,
            ratelimit_wait_ms: capture.ratelimit_wait_ms,
            source: capture.source,
            source_id: capture.source_id,
            correlation_id: capture.correlation_id,
            parent_correlation_id: capture.parent_correlation_id,
            account_id: capture.account_id,
            tool_call_id: capture.tool_call_id,
        }
    }
}

impl From<crate::models::HttpCapture> for HttpTrafficDetailDto {
    fn from(capture: crate::models::HttpCapture) -> Self {
        Self {
            id: capture.id,
            org_id: capture.org_id,
            timestamp: capture.timestamp,
            method: capture.method,
            path: capture.path,
            host: capture.host,
            scheme: capture.scheme,
            request_headers: capture
                .request_headers
                .into_iter()
                .map(header_pair)
                .collect(),
            request_body: capture.request_body,
            request_size: capture.request_size,
            status_code: capture.status_code,
            response_headers: capture
                .response_headers
                .into_iter()
                .map(header_pair)
                .collect(),
            response_body: capture.response_body,
            response_size: capture.response_size,
            duration_ms: capture.duration_ms,
            ratelimit_wait_ms: capture.ratelimit_wait_ms,
            source: capture.source,
            source_id: capture.source_id,
            correlation_id: capture.correlation_id,
            parent_correlation_id: capture.parent_correlation_id,
            account_id: capture.account_id,
            tool_call_id: capture.tool_call_id,
        }
    }
}

impl From<crate::models::BodyFetch> for BodyFetchDto {
    fn from(body: crate::models::BodyFetch) -> Self {
        match body {
            crate::models::BodyFetch::Body { value } => Self::Body { value },
            crate::models::BodyFetch::TooLarge { size } => Self::TooLarge { size },
        }
    }
}

impl From<crate::models::WsCaptureSummary> for WsTrafficSummaryDto {
    fn from(c: crate::models::WsCaptureSummary) -> Self {
        Self {
            id: c.id,
            parent_event_id: c.parent_event_id,
            org_id: c.org_id,
            timestamp: c.timestamp,
            session_offset: c.session_offset,
            direction: c.direction,
            opcode: c.opcode,
            host: c.host,
            payload_size: c.payload_size,
            payload_truncated: c.payload_truncated,
            payload_is_text: c.payload_is_text,
            was_compressed: c.was_compressed,
            close_code: c.close_code,
            close_reason: c.close_reason,
            source: c.source,
            source_id: c.source_id,
            session_id: c.session_id,
            payload: c.payload.map(BodyFetchDto::from),
        }
    }
}

impl From<crate::models::WsCapture> for WsMessageDetailDto {
    fn from(c: crate::models::WsCapture) -> Self {
        Self {
            id: c.id,
            parent_event_id: c.parent_event_id,
            org_id: c.org_id,
            timestamp: c.timestamp,
            direction: c.direction,
            opcode: c.opcode,
            host: c.host,
            payload: c.payload,
            payload_size: c.payload_size,
            payload_truncated: c.payload_truncated,
            payload_is_text: c.payload_is_text,
            was_compressed: c.was_compressed,
            close_code: c.close_code,
            close_reason: c.close_reason,
            source: c.source,
            source_id: c.source_id,
            session_id: c.session_id,
        }
    }
}

#[async_trait::async_trait]
impl TrafficGraphqlService for ControllerApiService {
    type Principal = UserPrincipal;

    async fn organization_settings(
        &self,
        principal: &Self::Principal,
        org_id: Option<String>,
    ) -> anyhow::Result<Option<OrgSettingsDto>> {
        ControllerApiService::organization_settings(self, principal, org_id).await
    }

    async fn upsert_organization_settings(
        &self,
        principal: &Self::Principal,
        input: UpsertOrgSettings,
    ) -> anyhow::Result<OrgSettingsDto> {
        ControllerApiService::upsert_organization_settings(self, principal, input).await
    }

    async fn upsert_organization_rate_limit(
        &self,
        principal: &Self::Principal,
        org_id: String,
        requests_per_minute: Option<u32>,
        burst: Option<u32>,
    ) -> anyhow::Result<OrgSettingsDto> {
        ControllerApiService::upsert_organization_rate_limit(
            self,
            principal,
            org_id,
            requests_per_minute,
            burst,
        )
        .await
    }

    async fn rate_limit_state(
        &self,
        principal: &Self::Principal,
        org_id: Option<String>,
    ) -> anyhow::Result<RateLimitStateDto> {
        ControllerApiService::rate_limit_state(self, principal, org_id).await
    }

    async fn request_rate_series(
        &self,
        principal: &Self::Principal,
        input: RequestRateSeriesInput,
    ) -> anyhow::Result<Vec<RequestRatePointDto>> {
        ControllerApiService::request_rate_series(self, principal, input).await
    }

    async fn http_traffic_time_series(
        &self,
        principal: &Self::Principal,
        input: HttpTrafficTimeSeriesInput,
    ) -> anyhow::Result<Vec<TrafficTimeSeriesPointDto>> {
        ControllerApiService::http_traffic_time_series(self, principal, input).await
    }

    async fn scan_traffic_summary(
        &self,
        principal: &Self::Principal,
        input: ScanTrafficSummaryInput,
    ) -> anyhow::Result<ScanTrafficSummaryDto> {
        ControllerApiService::scan_traffic_summary(self, principal, input).await
    }

    async fn search_http_traffic(
        &self,
        principal: &Self::Principal,
        input: HttpTrafficSearch,
    ) -> anyhow::Result<HttpTrafficSearchResponse> {
        let response = ControllerApiService::search_http_traffic(self, principal, input).await?;
        Ok(HttpTrafficSearchResponse {
            items: response
                .items
                .into_iter()
                .map(HttpTrafficSummaryDto::from)
                .collect(),
            next_cursor: response.next_cursor,
            total_count: response.total_count,
        })
    }

    async fn http_request(
        &self,
        principal: &Self::Principal,
        org_id: Option<String>,
        id: Uuid,
    ) -> anyhow::Result<Option<HttpTrafficDetailDto>> {
        Ok(
            ControllerApiService::http_request(self, principal, org_id, id)
                .await?
                .map(HttpTrafficDetailDto::from),
        )
    }

    async fn search_ws_traffic(
        &self,
        principal: &Self::Principal,
        input: WsTrafficSearch,
    ) -> anyhow::Result<WsTrafficSearchResponse> {
        let response = ControllerApiService::search_ws_traffic(self, principal, input).await?;
        Ok(WsTrafficSearchResponse {
            items: response
                .items
                .into_iter()
                .map(WsTrafficSummaryDto::from)
                .collect(),
            next_cursor: response.next_cursor,
            total_count: response.total_count,
        })
    }

    async fn ws_message(
        &self,
        principal: &Self::Principal,
        org_id: Option<String>,
        id: Uuid,
    ) -> anyhow::Result<Option<WsMessageDetailDto>> {
        Ok(
            ControllerApiService::ws_message(self, principal, org_id, id)
                .await?
                .map(WsMessageDetailDto::from),
        )
    }

    async fn search_traffic(
        &self,
        principal: &Self::Principal,
        input: TrafficSearch,
    ) -> anyhow::Result<TrafficSearchResponse> {
        ControllerApiService::search_traffic(self, principal, input).await
    }

    async fn ws_conversations(
        &self,
        principal: &Self::Principal,
        input: WsConversationSearch,
    ) -> anyhow::Result<WsConversationSearchResponse> {
        ControllerApiService::ws_conversations(self, principal, input).await
    }

    async fn get_traffic_view(
        &self,
        principal: &Self::Principal,
        view_id: Uuid,
        org_id: Option<String>,
    ) -> anyhow::Result<Option<TrafficViewDto>> {
        ControllerApiService::get_traffic_view(self, principal, view_id, org_id).await
    }

    async fn create_traffic_view(
        &self,
        principal: &Self::Principal,
        input: CreateTrafficViewInput,
    ) -> anyhow::Result<TrafficViewDto> {
        ControllerApiService::create_traffic_view(self, principal, input).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_search(request: HttpRequestFilter, response: HttpResponseFilter) -> HttpTrafficSearch {
        HttpTrafficSearch {
            org_id: None,
            filter: HttpTrafficFilter {
                source_id: Some(vec!["run-1".into()]),
                request,
                response,
                ..Default::default()
            },
            cursor: None,
            limit: None,
            descending: true,
            order_by: HttpTrafficOrderField::StatusCode,
        }
    }

    fn where_sql(query: &TrafficQuery) -> (String, Vec<String>) {
        crate::query::build_where(query, &Default::default())
    }

    #[test]
    fn request_and_response_filter_groups_lower_to_one_query() {
        let query = traffic_query_from_input(
            Some("org-1".into()),
            scan_search(
                HttpRequestFilter {
                    methods: Some(vec!["GET".into(), "POST".into()]),
                    url_contains: Some(" api ".into()),
                    sends_cookies: Some(true),
                },
                HttpResponseFilter {
                    status_classes: Some(vec![4, 5]),
                    mime_type: Some(" json ".into()),
                    min_length: Some(100),
                    max_duration_ms: Some(2000),
                    ..Default::default()
                },
            ),
        )
        .unwrap();

        assert_eq!(query.order_by, SortField::StatusCode);
        assert_eq!(query.order, SortOrder::Desc);
        // url_contains matches the host OR the path.
        assert_eq!(query.branches.0.len(), 2);
        let (sql, binds) = where_sql(&query);
        // One branch per side of the URL match; every other filter in both.
        for fragment in ["lower(host) LIKE lower(?)", "lower(path) LIKE lower(?)"] {
            assert_eq!(sql.matches(fragment).count(), 1, "{fragment} in {sql}");
        }
        for fragment in [
            "(method = ? OR method = ?)",
            "((status_code >= 400 AND status_code < 500) OR (status_code >= 500 AND status_code < 600))",
            "response_size >= 100",
            "duration_ms <= 2000",
            "arrayExists(k -> lower(k) = 'cookie', mapKeys(request_headers)) = 1",
        ] {
            assert_eq!(sql.matches(fragment).count(), 2, "{fragment} in {sql}");
        }
        assert_eq!(binds.iter().filter(|b| *b == "%json%").count(), 2);
        assert_eq!(binds.iter().filter(|b| *b == "%api%").count(), 2);
    }

    #[test]
    fn empty_filter_groups_add_no_conditions() {
        let query = traffic_query_from_input(
            Some("org-1".into()),
            scan_search(
                HttpRequestFilter {
                    methods: Some(vec![]),
                    url_contains: Some("  ".into()),
                    sends_cookies: None,
                },
                HttpResponseFilter {
                    status_classes: Some(vec![]),
                    mime_type: Some(" ".into()),
                    ..Default::default()
                },
            ),
        )
        .unwrap();
        assert_eq!(where_sql(&query).0, "org_id = ? AND source_id = ?");
    }

    #[test]
    fn flat_status_code_and_response_codes_both_apply() {
        let mut search = scan_search(
            HttpRequestFilter::default(),
            HttpResponseFilter {
                status_codes: Some(vec![401, 403]),
                ..Default::default()
            },
        );
        search.filter.status_code = Some(403);
        let query = traffic_query_from_input(Some("org-1".into()), search).unwrap();
        assert_eq!(
            where_sql(&query).0,
            "org_id = ? AND (source_id = ? AND (status_code = 403 AND (status_code = 401 OR status_code = 403)))"
        );
    }

    #[test]
    fn response_status_classes_and_codes_match_either() {
        // The console's Status chip mixes `2xx` and `404` in one selection.
        let query = traffic_query_from_input(
            Some("org-1".into()),
            scan_search(
                HttpRequestFilter::default(),
                HttpResponseFilter {
                    status_classes: Some(vec![2]),
                    status_codes: Some(vec![404]),
                    ..Default::default()
                },
            ),
        )
        .unwrap();
        assert_eq!(
            where_sql(&query).0,
            "org_id = ? AND (source_id = ? AND ((status_code >= 200 AND status_code < 300) OR status_code = 404))"
        );
    }
}
