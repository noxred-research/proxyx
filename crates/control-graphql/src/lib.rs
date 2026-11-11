use std::marker::PhantomData;

use async_graphql::{
    Context, EmptySubscription, Enum, InputObject, Object, SDLExportOptions, Schema, SimpleObject,
    Union,
};
use async_trait::async_trait;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

pub type TrafficSchema<S> = Schema<Query<S>, Mutation<S>, EmptySubscription>;

#[derive(Clone)]
pub struct Query<S>(PhantomData<S>);

impl<S> Default for Query<S> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

#[derive(Clone)]
pub struct Mutation<S>(PhantomData<S>);

impl<S> Default for Mutation<S> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

pub fn build_schema<S>(service: S) -> TrafficSchema<S>
where
    S: TrafficGraphqlService,
{
    Schema::build(Query::default(), Mutation::default(), EmptySubscription)
        .enable_federation()
        .data(service)
        .finish()
}

pub fn federation_sdl() -> String {
    build_schema(NoopTrafficService).sdl_with_options(SDLExportOptions::new().federation())
}

#[async_trait]
pub trait TrafficGraphqlService: Clone + Send + Sync + 'static {
    type Principal: Clone + Send + Sync + 'static;

    async fn organization_settings(
        &self,
        principal: &Self::Principal,
        org_id: Option<String>,
    ) -> anyhow::Result<Option<OrgSettingsDto>>;

    async fn upsert_organization_settings(
        &self,
        principal: &Self::Principal,
        input: UpsertOrgSettings,
    ) -> anyhow::Result<OrgSettingsDto>;

    async fn upsert_organization_rate_limit(
        &self,
        principal: &Self::Principal,
        org_id: String,
        requests_per_minute: Option<u32>,
        burst: Option<u32>,
    ) -> anyhow::Result<OrgSettingsDto>;

    async fn rate_limit_state(
        &self,
        principal: &Self::Principal,
        org_id: Option<String>,
    ) -> anyhow::Result<RateLimitStateDto>;

    async fn request_rate_series(
        &self,
        principal: &Self::Principal,
        input: RequestRateSeriesInput,
    ) -> anyhow::Result<Vec<RequestRatePointDto>>;

    async fn http_traffic_time_series(
        &self,
        principal: &Self::Principal,
        input: HttpTrafficTimeSeriesInput,
    ) -> anyhow::Result<Vec<TrafficTimeSeriesPointDto>>;

    async fn scan_traffic_summary(
        &self,
        principal: &Self::Principal,
        input: ScanTrafficSummaryInput,
    ) -> anyhow::Result<ScanTrafficSummaryDto>;

    async fn search_http_traffic(
        &self,
        principal: &Self::Principal,
        input: HttpTrafficSearch,
    ) -> anyhow::Result<HttpTrafficSearchResponse>;

    async fn http_request(
        &self,
        principal: &Self::Principal,
        org_id: Option<String>,
        id: Uuid,
    ) -> anyhow::Result<Option<HttpTrafficDetailDto>>;

    async fn search_ws_traffic(
        &self,
        principal: &Self::Principal,
        input: WsTrafficSearch,
    ) -> anyhow::Result<WsTrafficSearchResponse>;

    async fn ws_message(
        &self,
        principal: &Self::Principal,
        org_id: Option<String>,
        id: Uuid,
    ) -> anyhow::Result<Option<WsMessageDetailDto>>;

    async fn search_traffic(
        &self,
        principal: &Self::Principal,
        input: TrafficSearch,
    ) -> anyhow::Result<TrafficSearchResponse>;

    async fn ws_conversations(
        &self,
        principal: &Self::Principal,
        input: WsConversationSearch,
    ) -> anyhow::Result<WsConversationSearchResponse>;

    async fn get_traffic_view(
        &self,
        principal: &Self::Principal,
        view_id: Uuid,
        org_id: Option<String>,
    ) -> anyhow::Result<Option<TrafficViewDto>>;

    async fn create_traffic_view(
        &self,
        principal: &Self::Principal,
        input: CreateTrafficViewInput,
    ) -> anyhow::Result<TrafficViewDto>;
}

#[derive(Clone)]
struct NoopTrafficService;

#[async_trait]
impl TrafficGraphqlService for NoopTrafficService {
    type Principal = ();

    async fn organization_settings(
        &self,
        _: &(),
        _: Option<String>,
    ) -> anyhow::Result<Option<OrgSettingsDto>> {
        unreachable!("schema export does not execute resolvers")
    }
    async fn upsert_organization_settings(
        &self,
        _: &(),
        _: UpsertOrgSettings,
    ) -> anyhow::Result<OrgSettingsDto> {
        unreachable!("schema export does not execute resolvers")
    }
    async fn upsert_organization_rate_limit(
        &self,
        _: &(),
        _: String,
        _: Option<u32>,
        _: Option<u32>,
    ) -> anyhow::Result<OrgSettingsDto> {
        unreachable!("schema export does not execute resolvers")
    }
    async fn rate_limit_state(
        &self,
        _: &(),
        _: Option<String>,
    ) -> anyhow::Result<RateLimitStateDto> {
        unreachable!("schema export does not execute resolvers")
    }
    async fn request_rate_series(
        &self,
        _: &(),
        _: RequestRateSeriesInput,
    ) -> anyhow::Result<Vec<RequestRatePointDto>> {
        unreachable!("schema export does not execute resolvers")
    }
    async fn http_traffic_time_series(
        &self,
        _: &(),
        _: HttpTrafficTimeSeriesInput,
    ) -> anyhow::Result<Vec<TrafficTimeSeriesPointDto>> {
        unreachable!("schema export does not execute resolvers")
    }
    async fn scan_traffic_summary(
        &self,
        _: &(),
        _: ScanTrafficSummaryInput,
    ) -> anyhow::Result<ScanTrafficSummaryDto> {
        unreachable!("schema export does not execute resolvers")
    }
    async fn search_http_traffic(
        &self,
        _: &(),
        _: HttpTrafficSearch,
    ) -> anyhow::Result<HttpTrafficSearchResponse> {
        unreachable!("schema export does not execute resolvers")
    }
    async fn http_request(
        &self,
        _: &(),
        _: Option<String>,
        _: Uuid,
    ) -> anyhow::Result<Option<HttpTrafficDetailDto>> {
        unreachable!("schema export does not execute resolvers")
    }
    async fn search_ws_traffic(
        &self,
        _: &(),
        _: WsTrafficSearch,
    ) -> anyhow::Result<WsTrafficSearchResponse> {
        unreachable!("schema export does not execute resolvers")
    }
    async fn ws_message(
        &self,
        _: &(),
        _: Option<String>,
        _: Uuid,
    ) -> anyhow::Result<Option<WsMessageDetailDto>> {
        unreachable!("schema export does not execute resolvers")
    }
    async fn search_traffic(
        &self,
        _: &(),
        _: TrafficSearch,
    ) -> anyhow::Result<TrafficSearchResponse> {
        unreachable!("schema export does not execute resolvers")
    }
    async fn ws_conversations(
        &self,
        _: &(),
        _: WsConversationSearch,
    ) -> anyhow::Result<WsConversationSearchResponse> {
        unreachable!("schema export does not execute resolvers")
    }
    async fn get_traffic_view(
        &self,
        _: &(),
        _: Uuid,
        _: Option<String>,
    ) -> anyhow::Result<Option<TrafficViewDto>> {
        unreachable!("schema export does not execute resolvers")
    }
    async fn create_traffic_view(
        &self,
        _: &(),
        _: CreateTrafficViewInput,
    ) -> anyhow::Result<TrafficViewDto> {
        unreachable!("schema export does not execute resolvers")
    }
}

#[derive(Debug, Clone)]
pub struct OrgSettingsDto {
    pub org_id: String,
    pub requests_per_minute: u32,
    pub burst: u32,
    pub proxy_type: Option<String>,
    pub proxy_address: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpsertOrgSettings {
    pub org_id: String,
    pub requests_per_minute: Option<u32>,
    pub burst: Option<u32>,
    pub proxy_type: Option<String>,
    pub proxy_address: Option<String>,
    pub proxy_username: Option<String>,
    pub proxy_password: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct HttpTrafficFilter {
    pub source_id: Option<Vec<String>>,
    pub source: Option<String>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub search: Option<String>,
    pub correlation_id: Option<String>,
    pub parent_correlation_id: Option<String>,
    pub account_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub status_code: Option<i32>,
    pub request: HttpRequestFilter,
    pub response: HttpResponseFilter,
}

/// Filters on what the client sent.
#[derive(Debug, Clone, Default)]
pub struct HttpRequestFilter {
    pub methods: Option<Vec<String>>,
    /// Case-insensitive substring of the host or the path.
    pub url_contains: Option<String>,
    pub sends_cookies: Option<bool>,
}

/// Filters on what the server answered.
#[derive(Debug, Clone, Default)]
pub struct HttpResponseFilter {
    /// Leading status digit, e.g. `4` for 4xx. Together with
    /// `status_codes`, a row matches any listed class or code.
    pub status_classes: Option<Vec<u16>>,
    pub status_codes: Option<Vec<u16>>,
    /// Case-insensitive substring of the `Content-Type` media type.
    pub mime_type: Option<String>,
    pub sets_cookies: Option<bool>,
    pub min_length: Option<u32>,
    pub max_length: Option<u32>,
    pub min_duration_ms: Option<u32>,
    pub max_duration_ms: Option<u32>,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum HttpTrafficOrderField {
    #[default]
    Timestamp,
    Method,
    Url,
    StatusCode,
    ResponseSize,
    MimeType,
    Cookies,
    DurationMs,
}

#[derive(Debug, Clone)]
pub struct HttpTrafficSearch {
    pub org_id: Option<String>,
    pub filter: HttpTrafficFilter,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub descending: bool,
    pub order_by: HttpTrafficOrderField,
}

#[derive(Debug, Clone, Default)]
pub struct WsTrafficFilter {
    pub source_id: Option<Vec<String>>,
    pub source: Option<String>,
    pub session_id: Option<String>,
    pub parent_event_id: Option<String>,
    pub host: Option<String>,
    pub direction: Option<String>,
    pub opcode: Option<String>,
    pub payload: Option<String>,
    pub search: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WsTrafficSearch {
    pub org_id: Option<String>,
    pub filter: WsTrafficFilter,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub descending: bool,
    pub payload_max_bytes: Option<u32>,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum TrafficKind {
    #[default]
    All,
    Http,
    Ws,
}

#[derive(Debug, Clone, Default)]
pub struct TrafficFilter {
    pub source_id: Option<Vec<String>>,
    pub source: Option<String>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub search: Option<String>,
    pub status_code: Option<i32>,
    pub correlation_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub direction: Option<String>,
    pub opcode: Option<String>,
    pub session_id: Option<String>,
    pub parent_event_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TrafficSearch {
    pub org_id: Option<String>,
    pub filter: TrafficFilter,
    pub kind: TrafficKind,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub descending: bool,
    pub payload_max_bytes: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct HeaderPairDto {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct HttpTrafficSummaryDto {
    pub id: Uuid,
    pub org_id: String,
    pub timestamp: OffsetDateTime,
    pub session_offset: u64,
    pub method: String,
    pub path: String,
    pub host: String,
    pub scheme: String,
    pub request_headers: Vec<HeaderPairDto>,
    pub request_size: u32,
    pub status_code: u16,
    pub response_headers: Vec<HeaderPairDto>,
    pub response_size: u32,
    pub duration_ms: u32,
    pub ratelimit_wait_ms: u32,
    pub source: String,
    pub source_id: String,
    pub correlation_id: Option<String>,
    pub parent_correlation_id: Option<String>,
    pub account_id: Option<String>,
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpTrafficDetailDto {
    pub id: Uuid,
    pub org_id: String,
    pub timestamp: OffsetDateTime,
    pub method: String,
    pub path: String,
    pub host: String,
    pub scheme: String,
    pub request_headers: Vec<HeaderPairDto>,
    pub request_body: String,
    pub request_size: u32,
    pub status_code: u16,
    pub response_headers: Vec<HeaderPairDto>,
    pub response_body: String,
    pub response_size: u32,
    pub duration_ms: u32,
    pub ratelimit_wait_ms: u32,
    pub source: String,
    pub source_id: String,
    pub correlation_id: Option<String>,
    pub parent_correlation_id: Option<String>,
    pub account_id: Option<String>,
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Clone)]
pub enum BodyFetchDto {
    Body { value: String },
    TooLarge { size: u32 },
}

#[derive(Debug, Clone)]
pub struct WsTrafficSummaryDto {
    pub id: Uuid,
    pub parent_event_id: Uuid,
    pub org_id: String,
    pub timestamp: OffsetDateTime,
    pub session_offset: u64,
    pub direction: String,
    pub opcode: String,
    pub host: String,
    pub payload_size: u32,
    pub payload_truncated: bool,
    pub payload_is_text: bool,
    pub was_compressed: bool,
    pub close_code: u16,
    pub close_reason: String,
    pub source: String,
    pub source_id: String,
    pub session_id: String,
    pub payload: Option<BodyFetchDto>,
}

#[derive(Debug, Clone)]
pub struct WsMessageDetailDto {
    pub id: Uuid,
    pub parent_event_id: Uuid,
    pub org_id: String,
    pub timestamp: OffsetDateTime,
    pub direction: String,
    pub opcode: String,
    pub host: String,
    pub payload: String,
    pub payload_size: u32,
    pub payload_truncated: bool,
    pub payload_is_text: bool,
    pub was_compressed: bool,
    pub close_code: u16,
    pub close_reason: String,
    pub source: String,
    pub source_id: String,
    pub session_id: String,
}

#[derive(Debug, Clone)]
pub struct HttpTrafficSearchResponse {
    pub items: Vec<HttpTrafficSummaryDto>,
    pub next_cursor: Option<String>,
    pub total_count: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct WsTrafficSearchResponse {
    pub items: Vec<WsTrafficSummaryDto>,
    pub next_cursor: Option<String>,
    pub total_count: Option<u64>,
}

/// One row in the unified, time-ordered HTTP+WS feed.
#[derive(Debug, Clone)]
pub enum TrafficEventDto {
    Http(HttpTrafficSummaryDto),
    Ws(WsTrafficSummaryDto),
}

impl TrafficEventDto {
    /// Shared ordering key — both tables sort by
    /// `(timestamp, session_offset, id)`, so a merge over this key
    /// reproduces exact wire order across the two streams.
    pub fn sort_key(&self) -> (OffsetDateTime, u64, Uuid) {
        match self {
            TrafficEventDto::Http(c) => (c.timestamp, c.session_offset, c.id),
            TrafficEventDto::Ws(c) => (c.timestamp, c.session_offset, c.id),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrafficSearchResponse {
    pub items: Vec<TrafficEventDto>,
    pub next_cursor: Option<String>,
    pub total_count: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct WsConversationFilter {
    pub source_id: Option<Vec<String>>,
    pub source: Option<String>,
    pub host: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WsConversationSearch {
    pub org_id: Option<String>,
    pub filter: WsConversationFilter,
    pub limit: Option<u32>,
    pub descending: bool,
}

/// One WebSocket conversation (all frames sharing a `parent_event_id`),
/// aggregated for the discovery view.
#[derive(Debug, Clone)]
pub struct WsConversationDto {
    pub parent_event_id: Uuid,
    pub host: String,
    /// Handshake request path (from the parent http_captures row); `None`
    /// when the handshake itself was not captured.
    pub path: Option<String>,
    pub source: String,
    pub source_id: String,
    pub session_id: String,
    pub message_count: u64,
    pub client_to_server: u64,
    pub server_to_client: u64,
    pub first_at: OffsetDateTime,
    pub last_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct WsConversationSearchResponse {
    pub items: Vec<WsConversationDto>,
    pub total_count: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct RateLimitStateDto {
    pub org_id: String,
    pub exists: bool,
    pub tokens: f64,
    pub burst: u32,
    pub rpm: u32,
    pub last_refill_ms: i64,
}

#[derive(Debug, Clone)]
pub struct RequestRatePointDto {
    pub minute: OffsetDateTime,
    pub requests: u64,
}

#[derive(Debug, Clone)]
pub struct RequestRateSeriesInput {
    pub org_id: Option<String>,
    pub start: OffsetDateTime,
    pub end: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct TrafficTimeSeriesPointDto {
    pub bucket_start: String,
    pub source_id: String,
    pub source: String,
    pub count: u64,
}

#[derive(Debug, Clone)]
pub struct HttpTrafficTimeSeriesInput {
    pub org_id: Option<String>,
    pub filter: HttpTrafficFilter,
    pub start: OffsetDateTime,
    pub end: OffsetDateTime,
    pub bucket_seconds: u32,
}

#[derive(Debug, Clone)]
pub struct ScanTrafficSummaryInput {
    pub org_id: Option<String>,
    pub source_ids: Vec<String>,
    pub start: OffsetDateTime,
    pub end: OffsetDateTime,
    pub bucket_seconds: u32,
}

#[derive(Debug, Clone)]
pub struct TrafficBucketDto {
    pub bucket_start: String,
    pub count: u64,
}

#[derive(Debug, Clone)]
pub struct SourceTrafficTotalDto {
    pub source_id: String,
    pub count: u64,
}

#[derive(Debug, Clone)]
pub struct ScanTrafficSummaryDto {
    pub buckets: Vec<TrafficBucketDto>,
    pub by_source: Vec<SourceTrafficTotalDto>,
    pub total: u64,
}

#[derive(Debug, Clone)]
pub struct TrafficViewDto {
    pub view_id: Uuid,
    pub status: String,
    pub s3_key: Option<String>,
    pub signed_url: Option<String>,
    pub error: Option<String>,
    pub read_rows: Option<i64>,
    pub written_rows: Option<i64>,
    pub total_rows: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct CreateTrafficViewInput {
    pub org_id: Option<String>,
    pub branches: Vec<TrafficViewBranchInput>,
}

#[derive(Debug, Clone)]
pub struct TrafficViewBranchInput {
    pub source_id: Option<Vec<String>>,
    pub source: Option<String>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub correlation_id: Option<String>,
    pub parent_correlation_id: Option<String>,
    pub account_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub status_code: Option<i64>,
}

#[derive(SimpleObject)]
pub struct TrafficView {
    pub view_id: Uuid,
    pub status: String,
    pub s3_key: Option<String>,
    /// CloudFront signed URL, valid for 1 hour. Only present when status = completed
    /// and CloudFront is configured.
    pub signed_url: Option<String>,
    pub error: Option<String>,
    /// Number of rows read from ClickHouse so far (while running).
    pub read_rows: Option<i64>,
    /// Number of rows written to S3 so far (while running).
    pub written_rows: Option<i64>,
    /// Approximate total number of rows to export.
    pub total_rows: Option<i64>,
}

#[derive(InputObject)]
pub struct CreateTrafficViewGqlInput {
    pub org_id: Option<String>,
    pub branches: Vec<TrafficViewBranchGqlInput>,
}

#[derive(InputObject)]
pub struct TrafficViewBranchGqlInput {
    pub source_id: Option<String>,
    pub source_ids: Option<Vec<String>>,
    pub source: Option<String>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub correlation_id: Option<String>,
    pub parent_correlation_id: Option<String>,
    pub account_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub status_code: Option<i64>,
}

impl From<TrafficViewDto> for TrafficView {
    fn from(dto: TrafficViewDto) -> Self {
        Self {
            view_id: dto.view_id,
            status: dto.status,
            s3_key: dto.s3_key,
            signed_url: dto.signed_url,
            error: dto.error,
            read_rows: dto.read_rows,
            written_rows: dto.written_rows,
            total_rows: dto.total_rows,
        }
    }
}

impl From<CreateTrafficViewGqlInput> for CreateTrafficViewInput {
    fn from(input: CreateTrafficViewGqlInput) -> Self {
        Self {
            org_id: input.org_id,
            branches: input
                .branches
                .into_iter()
                .map(|b| {
                    let source_id = match (b.source_id, b.source_ids) {
                        (None, None) => None,
                        (Some(s), None) => Some(vec![s]),
                        (None, Some(v)) if v.is_empty() => None,
                        (None, Some(v)) => Some(v),
                        (Some(s), Some(mut v)) => {
                            if !v.contains(&s) {
                                v.push(s);
                            }
                            Some(v)
                        }
                    };
                    TrafficViewBranchInput {
                        source_id,
                        source: b.source,
                        host: b.host,
                        method: b.method,
                        path: b.path,
                        correlation_id: b.correlation_id,
                        parent_correlation_id: b.parent_correlation_id,
                        account_id: b.account_id,
                        tool_call_id: b.tool_call_id,
                        status_code: b.status_code,
                    }
                })
                .collect(),
        }
    }
}
#[derive(SimpleObject)]
pub struct OrgSettings {
    pub org_id: String,
    pub requests_per_minute: u32,
    pub burst: u32,
    pub proxy_type: Option<String>,
    pub proxy_address: Option<String>,
}

#[derive(InputObject)]
pub struct UpsertOrgSettingsInput {
    pub org_id: String,
    pub requests_per_minute: Option<u32>,
    pub burst: Option<u32>,
    pub proxy_type: Option<String>,
    pub proxy_address: Option<String>,
    pub proxy_username: Option<String>,
    pub proxy_password: Option<String>,
}

#[derive(SimpleObject)]
pub struct RateLimitSettings {
    pub org_id: String,
    pub requests_per_minute: u32,
    pub burst: u32,
}

#[derive(InputObject)]
pub struct UpsertRateLimitSettingsInput {
    pub org_id: String,
    pub requests_per_minute: Option<u32>,
    pub burst: Option<u32>,
}

#[derive(SimpleObject)]
pub struct RateLimitState {
    pub org_id: String,
    pub exists: bool,
    pub tokens: f64,
    pub burst: u32,
    pub rpm: u32,
    pub last_refill_ms: i64,
}

#[derive(InputObject)]
pub struct RequestRateSeriesGqlInput {
    pub org_id: Option<String>,
    /// Inclusive RFC3339 start timestamp.
    pub start: String,
    /// Exclusive RFC3339 end timestamp.
    pub end: String,
}

#[derive(SimpleObject)]
pub struct RequestRatePoint {
    pub minute: String,
    pub requests: u64,
}

#[derive(InputObject)]
#[graphql(name = "HttpTrafficTimeSeriesInput")]
pub struct HttpTrafficTimeSeriesGqlInput {
    pub org_id: Option<String>,
    #[graphql(default)]
    pub filter: HttpTrafficFilterInput,
    /// Inclusive RFC3339 start timestamp.
    pub start: String,
    /// Exclusive RFC3339 end timestamp.
    pub end: String,
    /// Bucket width in seconds.
    #[graphql(default = 60)]
    pub bucket_seconds: u32,
}

/// One (time-bucket x scanner) request count for the requests-over-time chart.
#[derive(SimpleObject)]
pub struct TrafficTimeSeriesPoint {
    pub bucket_start: String,
    pub source_id: String,
    pub source: String,
    pub count: u64,
}

#[derive(InputObject)]
#[graphql(name = "ScanTrafficSummaryInput")]
pub struct ScanTrafficSummaryGqlInput {
    pub org_id: Option<String>,
    /// Scanner-run source IDs to aggregate over.
    pub source_ids: Vec<String>,
    /// Inclusive RFC3339 start timestamp.
    pub start: String,
    /// Exclusive RFC3339 end timestamp.
    pub end: String,
    /// Bucket width in seconds.
    #[graphql(default = 60)]
    pub bucket_seconds: u32,
}

/// One time bucket of total requests across the requested sources.
#[derive(SimpleObject)]
pub struct TrafficBucket {
    pub bucket_start: String,
    pub count: u64,
}

/// Total requests for one source over the window.
#[derive(SimpleObject)]
pub struct SourceTrafficTotal {
    pub source_id: String,
    pub count: u64,
}

/// Server-side aggregate for the agents list: requests bucketed over time
/// (chart) plus per-source totals (per-scan column) in one round trip.
#[derive(SimpleObject)]
pub struct ScanTrafficSummary {
    pub buckets: Vec<TrafficBucket>,
    pub by_source: Vec<SourceTrafficTotal>,
    pub total: u64,
}

#[derive(InputObject, Default)]
pub struct HttpTrafficFilterInput {
    /// Filter by one or more source IDs. When a single value is given
    /// it produces `source_id = ?`; multiple values produce `IN (...)`.
    pub source_id: Option<String>,
    pub source_ids: Option<Vec<String>>,
    pub source: Option<String>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub search: Option<String>,
    pub correlation_id: Option<String>,
    pub parent_correlation_id: Option<String>,
    pub account_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub status_code: Option<i32>,
    /// Burp-style filters on the request side.
    pub request: Option<HttpRequestFilterInput>,
    /// Burp-style filters on the response side.
    pub response: Option<HttpResponseFilterInput>,
}

#[derive(InputObject)]
pub struct HttpRequestFilterInput {
    /// Any of these methods (exact, as captured).
    pub methods: Option<Vec<String>>,
    /// Case-insensitive substring of the host or the path.
    pub url_contains: Option<String>,
    /// Whether the request sent a `Cookie` header.
    pub sends_cookies: Option<bool>,
}

#[derive(InputObject)]
pub struct HttpResponseFilterInput {
    /// Status classes by leading digit (`4` = 4xx). A response matches any
    /// of the listed classes or `statusCodes`.
    pub status_classes: Option<Vec<u16>>,
    /// Exact status codes. A response matches any of the listed codes or
    /// `statusClasses`.
    pub status_codes: Option<Vec<u16>>,
    /// Case-insensitive substring of the `Content-Type` media type.
    pub mime_type: Option<String>,
    /// Whether the response sent a `Set-Cookie` header.
    pub sets_cookies: Option<bool>,
    /// Inclusive bounds on the response body size in bytes.
    pub min_length: Option<u32>,
    pub max_length: Option<u32>,
    /// Inclusive bounds on the response time in milliseconds.
    pub min_duration_ms: Option<u32>,
    pub max_duration_ms: Option<u32>,
}

/// Sort column for `httpTraffic`; `descending` sets the direction. Ties
/// break on capture time.
#[derive(Enum, Copy, Clone, Eq, PartialEq, Default)]
#[graphql(name = "HttpTrafficOrderField")]
pub enum HttpTrafficOrderFieldGql {
    #[default]
    Timestamp,
    Method,
    /// Host followed by path.
    Url,
    StatusCode,
    ResponseSize,
    MimeType,
    /// Number of cookie-carrying sides (request `Cookie`, response `Set-Cookie`).
    Cookies,
    DurationMs,
}

#[derive(InputObject)]
pub struct HttpTrafficQueryInput {
    pub org_id: Option<String>,
    #[graphql(default)]
    pub filter: HttpTrafficFilterInput,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    #[graphql(default)]
    pub descending: bool,
    #[graphql(default)]
    pub order_by: HttpTrafficOrderFieldGql,
}

#[derive(SimpleObject)]
pub struct HttpTrafficSearchResult {
    pub items: Vec<HttpTrafficSummary>,
    pub next_cursor: Option<String>,
    pub total_count: Option<u64>,
}

#[derive(SimpleObject)]
pub struct HttpTrafficSummary {
    pub id: Uuid,
    pub org_id: String,
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub host: String,
    pub scheme: String,
    pub request_headers: Vec<HeaderPair>,
    pub request_size: u32,
    pub status_code: u16,
    pub response_headers: Vec<HeaderPair>,
    pub response_size: u32,
    pub duration_ms: u32,
    pub ratelimit_wait_ms: u32,
    pub source: String,
    pub source_id: String,
    pub correlation_id: Option<String>,
    pub parent_correlation_id: Option<String>,
    pub account_id: Option<String>,
    pub tool_call_id: Option<String>,
    /// `Content-Type` media type without parameters, lower-cased; empty
    /// when the response had none or the row was read without headers.
    pub mime_type: String,
    /// The request sent a `Cookie` header.
    pub request_sends_cookies: bool,
    /// The response sent a `Set-Cookie` header.
    pub response_sets_cookies: bool,
}

#[derive(SimpleObject)]
pub struct HeaderPair {
    pub name: String,
    pub value: String,
}

#[derive(SimpleObject)]
pub struct HttpTrafficDetail {
    pub id: Uuid,
    pub org_id: String,
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub host: String,
    pub scheme: String,
    pub request_headers: Vec<HeaderPair>,
    pub request_body: String,
    pub request_size: u32,
    pub status_code: u16,
    pub response_headers: Vec<HeaderPair>,
    pub response_body: String,
    pub response_size: u32,
    pub duration_ms: u32,
    pub ratelimit_wait_ms: u32,
    pub source: String,
    pub source_id: String,
    pub correlation_id: Option<String>,
    pub parent_correlation_id: Option<String>,
    pub account_id: Option<String>,
    pub tool_call_id: Option<String>,
}

#[derive(InputObject, Default)]
pub struct WsTrafficFilterInput {
    pub source_id: Option<String>,
    pub source_ids: Option<Vec<String>>,
    pub source: Option<String>,
    pub session_id: Option<String>,
    pub parent_event_id: Option<String>,
    pub host: Option<String>,
    pub direction: Option<String>,
    pub opcode: Option<String>,
    pub payload: Option<String>,
}

#[derive(InputObject)]
pub struct WsTrafficQueryInput {
    pub org_id: Option<String>,
    #[graphql(default)]
    pub filter: WsTrafficFilterInput,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub payload_max_bytes: Option<u32>,
    #[graphql(default)]
    pub descending: bool,
}

#[derive(SimpleObject)]
pub struct WsTrafficSearchResult {
    pub items: Vec<WsTrafficSummary>,
    pub next_cursor: Option<String>,
    pub total_count: Option<u64>,
}

#[derive(SimpleObject)]
pub struct WsTrafficSummary {
    pub id: Uuid,
    pub parent_event_id: Uuid,
    pub org_id: String,
    pub timestamp: String,
    pub direction: String,
    pub opcode: String,
    pub host: String,
    pub payload_size: u32,
    pub payload_truncated: bool,
    pub payload_is_text: bool,
    pub was_compressed: bool,
    pub close_code: u16,
    pub close_reason: String,
    pub source: String,
    pub source_id: String,
    pub session_id: String,
    pub payload: Option<String>,
}

#[derive(SimpleObject)]
pub struct WsMessageDetail {
    pub id: Uuid,
    pub parent_event_id: Uuid,
    pub org_id: String,
    pub timestamp: String,
    pub direction: String,
    pub opcode: String,
    pub host: String,
    pub payload: String,
    pub payload_size: u32,
    pub payload_truncated: bool,
    pub payload_is_text: bool,
    pub was_compressed: bool,
    pub close_code: u16,
    pub close_reason: String,
    pub source: String,
    pub source_id: String,
    pub session_id: String,
}

#[derive(InputObject, Default)]
pub struct WsConversationFilterInput {
    pub source_id: Option<String>,
    pub source_ids: Option<Vec<String>>,
    pub source: Option<String>,
    pub host: Option<String>,
}

#[derive(InputObject)]
pub struct WsConversationQueryInput {
    pub org_id: Option<String>,
    #[graphql(default)]
    pub filter: WsConversationFilterInput,
    pub limit: Option<u32>,
    #[graphql(default = true)]
    pub descending: bool,
}

/// One WebSocket conversation (frames sharing a parent handshake).
#[derive(SimpleObject)]
pub struct WsConversation {
    pub parent_event_id: Uuid,
    pub host: String,
    pub path: Option<String>,
    pub message_count: u64,
    pub client_to_server: u64,
    pub server_to_client: u64,
    pub first_at: String,
    pub last_at: String,
    pub source: String,
    pub source_id: String,
    pub session_id: String,
}

#[derive(SimpleObject)]
pub struct WsConversationSearchResult {
    pub items: Vec<WsConversation>,
    pub total_count: Option<u64>,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq, Default)]
#[graphql(name = "TrafficKind")]
pub enum TrafficKindGql {
    #[default]
    All,
    Http,
    Ws,
}

#[derive(InputObject, Default)]
pub struct TrafficFilterInput {
    pub source_id: Option<String>,
    pub source_ids: Option<Vec<String>>,
    pub source: Option<String>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub search: Option<String>,
    pub status_code: Option<i32>,
    pub correlation_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub direction: Option<String>,
    pub opcode: Option<String>,
    pub session_id: Option<String>,
    pub parent_event_id: Option<String>,
}

#[derive(InputObject)]
pub struct TrafficQueryInput {
    pub org_id: Option<String>,
    #[graphql(default)]
    pub filter: TrafficFilterInput,
    #[graphql(default)]
    pub kind: TrafficKindGql,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub payload_max_bytes: Option<u32>,
    #[graphql(default)]
    pub descending: bool,
}

/// A single row in the unified, time-ordered HTTP + WS feed.
#[derive(Union)]
pub enum TrafficEvent {
    Http(HttpTrafficSummary),
    Ws(WsTrafficSummary),
}

#[derive(SimpleObject)]
pub struct TrafficSearchResult {
    pub items: Vec<TrafficEvent>,
    pub next_cursor: Option<String>,
    pub total_count: Option<u64>,
}

#[Object]
impl<S> Query<S>
where
    S: TrafficGraphqlService,
{
    async fn organization_settings(
        &self,
        ctx: &Context<'_>,
        org_id: Option<String>,
    ) -> async_graphql::Result<Option<OrgSettings>> {
        let (service, principal) = context_parts::<S>(ctx)?;
        Ok(service
            .organization_settings(&principal, org_id)
            .await?
            .map(OrgSettings::from))
    }

    async fn organization_rate_limit(
        &self,
        ctx: &Context<'_>,
        org_id: Option<String>,
    ) -> async_graphql::Result<Option<RateLimitSettings>> {
        let (service, principal) = context_parts::<S>(ctx)?;
        Ok(service
            .organization_settings(&principal, org_id)
            .await?
            .map(RateLimitSettings::from))
    }

    async fn rate_limit_state(
        &self,
        ctx: &Context<'_>,
        org_id: Option<String>,
    ) -> async_graphql::Result<RateLimitState> {
        let (service, principal) = context_parts::<S>(ctx)?;
        Ok(service.rate_limit_state(&principal, org_id).await?.into())
    }

    async fn request_rate_series(
        &self,
        ctx: &Context<'_>,
        input: RequestRateSeriesGqlInput,
    ) -> async_graphql::Result<Vec<RequestRatePoint>> {
        let (service, principal) = context_parts::<S>(ctx)?;
        let input = RequestRateSeriesInput::try_from(input)?;
        Ok(service
            .request_rate_series(&principal, input)
            .await?
            .into_iter()
            .map(RequestRatePoint::from)
            .collect())
    }

    async fn http_traffic_time_series(
        &self,
        ctx: &Context<'_>,
        input: HttpTrafficTimeSeriesGqlInput,
    ) -> async_graphql::Result<Vec<TrafficTimeSeriesPoint>> {
        let (service, principal) = context_parts::<S>(ctx)?;
        let input = HttpTrafficTimeSeriesInput::try_from(input)?;
        Ok(service
            .http_traffic_time_series(&principal, input)
            .await?
            .into_iter()
            .map(TrafficTimeSeriesPoint::from)
            .collect())
    }

    async fn scan_traffic_summary(
        &self,
        ctx: &Context<'_>,
        input: ScanTrafficSummaryGqlInput,
    ) -> async_graphql::Result<ScanTrafficSummary> {
        let (service, principal) = context_parts::<S>(ctx)?;
        let input = ScanTrafficSummaryInput::try_from(input)?;
        Ok(service
            .scan_traffic_summary(&principal, input)
            .await?
            .into())
    }

    async fn http_traffic(
        &self,
        ctx: &Context<'_>,
        input: HttpTrafficQueryInput,
    ) -> async_graphql::Result<HttpTrafficSearchResult> {
        let (service, principal) = context_parts::<S>(ctx)?;
        let results = service
            .search_http_traffic(&principal, HttpTrafficSearch::from(input))
            .await?;
        Ok(HttpTrafficSearchResult {
            items: results
                .items
                .into_iter()
                .map(HttpTrafficSummary::from)
                .collect(),
            next_cursor: results.next_cursor,
            total_count: results.total_count,
        })
    }

    async fn http_request(
        &self,
        ctx: &Context<'_>,
        id: Uuid,
        org_id: Option<String>,
    ) -> async_graphql::Result<Option<HttpTrafficDetail>> {
        let (service, principal) = context_parts::<S>(ctx)?;
        Ok(service
            .http_request(&principal, org_id, id)
            .await?
            .map(HttpTrafficDetail::from))
    }

    async fn ws_traffic(
        &self,
        ctx: &Context<'_>,
        input: WsTrafficQueryInput,
    ) -> async_graphql::Result<WsTrafficSearchResult> {
        let (service, principal) = context_parts::<S>(ctx)?;
        let results = service
            .search_ws_traffic(&principal, WsTrafficSearch::from(input))
            .await?;
        Ok(WsTrafficSearchResult {
            items: results
                .items
                .into_iter()
                .map(WsTrafficSummary::from)
                .collect(),
            next_cursor: results.next_cursor,
            total_count: results.total_count,
        })
    }

    async fn ws_message(
        &self,
        ctx: &Context<'_>,
        id: Uuid,
        org_id: Option<String>,
    ) -> async_graphql::Result<Option<WsMessageDetail>> {
        let (service, principal) = context_parts::<S>(ctx)?;
        Ok(service
            .ws_message(&principal, org_id, id)
            .await?
            .map(WsMessageDetail::from))
    }

    async fn traffic(
        &self,
        ctx: &Context<'_>,
        input: TrafficQueryInput,
    ) -> async_graphql::Result<TrafficSearchResult> {
        let (service, principal) = context_parts::<S>(ctx)?;
        let results = service
            .search_traffic(&principal, TrafficSearch::from(input))
            .await?;
        Ok(TrafficSearchResult {
            items: results.items.into_iter().map(TrafficEvent::from).collect(),
            next_cursor: results.next_cursor,
            total_count: results.total_count,
        })
    }

    async fn ws_conversations(
        &self,
        ctx: &Context<'_>,
        input: WsConversationQueryInput,
    ) -> async_graphql::Result<WsConversationSearchResult> {
        let (service, principal) = context_parts::<S>(ctx)?;
        let results = service
            .ws_conversations(&principal, WsConversationSearch::from(input))
            .await?;
        Ok(WsConversationSearchResult {
            items: results
                .items
                .into_iter()
                .map(WsConversation::from)
                .collect(),
            total_count: results.total_count,
        })
    }

    async fn traffic_view(
        &self,
        ctx: &Context<'_>,
        view_id: Uuid,
        org_id: Option<String>,
    ) -> async_graphql::Result<Option<TrafficView>> {
        let (service, principal) = context_parts::<S>(ctx)?;
        Ok(service
            .get_traffic_view(&principal, view_id, org_id)
            .await?
            .map(TrafficView::from))
    }
}

#[Object]
impl<S> Mutation<S>
where
    S: TrafficGraphqlService,
{
    async fn upsert_organization_settings(
        &self,
        ctx: &Context<'_>,
        input: UpsertOrgSettingsInput,
    ) -> async_graphql::Result<OrgSettings> {
        let (service, principal) = context_parts::<S>(ctx)?;
        Ok(service
            .upsert_organization_settings(&principal, UpsertOrgSettings::from(input))
            .await?
            .into())
    }

    async fn upsert_organization_rate_limit(
        &self,
        ctx: &Context<'_>,
        input: UpsertRateLimitSettingsInput,
    ) -> async_graphql::Result<RateLimitSettings> {
        let (service, principal) = context_parts::<S>(ctx)?;
        let settings = service
            .upsert_organization_rate_limit(
                &principal,
                input.org_id,
                input.requests_per_minute,
                input.burst,
            )
            .await?;
        Ok(RateLimitSettings::from(settings))
    }

    async fn create_traffic_view(
        &self,
        ctx: &Context<'_>,
        input: CreateTrafficViewGqlInput,
    ) -> async_graphql::Result<TrafficView> {
        let (service, principal) = context_parts::<S>(ctx)?;
        Ok(service
            .create_traffic_view(&principal, CreateTrafficViewInput::from(input))
            .await?
            .into())
    }
}

fn context_parts<S>(ctx: &Context<'_>) -> async_graphql::Result<(S, S::Principal)>
where
    S: TrafficGraphqlService,
{
    let service = ctx.data::<S>()?.clone();
    let principal = ctx.data::<S::Principal>()?.clone();
    Ok((service, principal))
}
impl From<OrgSettingsDto> for OrgSettings {
    fn from(settings: OrgSettingsDto) -> Self {
        Self {
            org_id: settings.org_id,
            requests_per_minute: settings.requests_per_minute,
            burst: settings.burst,
            proxy_type: settings.proxy_type,
            proxy_address: settings.proxy_address,
        }
    }
}

impl From<OrgSettingsDto> for RateLimitSettings {
    fn from(settings: OrgSettingsDto) -> Self {
        Self {
            org_id: settings.org_id,
            requests_per_minute: settings.requests_per_minute,
            burst: settings.burst,
        }
    }
}

impl From<RateLimitStateDto> for RateLimitState {
    fn from(state: RateLimitStateDto) -> Self {
        Self {
            org_id: state.org_id,
            exists: state.exists,
            tokens: state.tokens,
            burst: state.burst,
            rpm: state.rpm,
            last_refill_ms: state.last_refill_ms,
        }
    }
}

impl TryFrom<RequestRateSeriesGqlInput> for RequestRateSeriesInput {
    type Error = async_graphql::Error;

    fn try_from(input: RequestRateSeriesGqlInput) -> Result<Self, Self::Error> {
        Ok(Self {
            org_id: input.org_id,
            start: parse_rfc3339("start", &input.start)?,
            end: parse_rfc3339("end", &input.end)?,
        })
    }
}

impl From<RequestRatePointDto> for RequestRatePoint {
    fn from(point: RequestRatePointDto) -> Self {
        Self {
            minute: point.minute.format(&Rfc3339).unwrap_or_default(),
            requests: point.requests,
        }
    }
}

impl TryFrom<HttpTrafficTimeSeriesGqlInput> for HttpTrafficTimeSeriesInput {
    type Error = async_graphql::Error;

    fn try_from(input: HttpTrafficTimeSeriesGqlInput) -> Result<Self, Self::Error> {
        Ok(Self {
            org_id: input.org_id,
            filter: HttpTrafficFilter::from(input.filter),
            start: parse_rfc3339("start", &input.start)?,
            end: parse_rfc3339("end", &input.end)?,
            bucket_seconds: input.bucket_seconds,
        })
    }
}

impl From<TrafficTimeSeriesPointDto> for TrafficTimeSeriesPoint {
    fn from(point: TrafficTimeSeriesPointDto) -> Self {
        Self {
            bucket_start: point.bucket_start,
            source_id: point.source_id,
            source: point.source,
            count: point.count,
        }
    }
}

impl TryFrom<ScanTrafficSummaryGqlInput> for ScanTrafficSummaryInput {
    type Error = async_graphql::Error;

    fn try_from(input: ScanTrafficSummaryGqlInput) -> Result<Self, Self::Error> {
        Ok(Self {
            org_id: input.org_id,
            source_ids: input.source_ids,
            start: parse_rfc3339("start", &input.start)?,
            end: parse_rfc3339("end", &input.end)?,
            bucket_seconds: input.bucket_seconds,
        })
    }
}

impl From<ScanTrafficSummaryDto> for ScanTrafficSummary {
    fn from(dto: ScanTrafficSummaryDto) -> Self {
        Self {
            buckets: dto.buckets.into_iter().map(TrafficBucket::from).collect(),
            by_source: dto
                .by_source
                .into_iter()
                .map(SourceTrafficTotal::from)
                .collect(),
            total: dto.total,
        }
    }
}

impl From<TrafficBucketDto> for TrafficBucket {
    fn from(dto: TrafficBucketDto) -> Self {
        Self {
            bucket_start: dto.bucket_start,
            count: dto.count,
        }
    }
}

impl From<SourceTrafficTotalDto> for SourceTrafficTotal {
    fn from(dto: SourceTrafficTotalDto) -> Self {
        Self {
            source_id: dto.source_id,
            count: dto.count,
        }
    }
}

fn parse_rfc3339(field: &str, value: &str) -> async_graphql::Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| async_graphql::Error::new(format!("{field} must be an RFC3339 timestamp")))
}

impl From<UpsertOrgSettingsInput> for UpsertOrgSettings {
    fn from(input: UpsertOrgSettingsInput) -> Self {
        Self {
            org_id: input.org_id,
            requests_per_minute: input.requests_per_minute,
            burst: input.burst,
            proxy_type: input.proxy_type,
            proxy_address: input.proxy_address,
            proxy_username: input.proxy_username,
            proxy_password: input.proxy_password,
        }
    }
}

impl From<UpsertRateLimitSettingsInput> for UpsertOrgSettings {
    fn from(input: UpsertRateLimitSettingsInput) -> Self {
        Self {
            org_id: input.org_id,
            requests_per_minute: input.requests_per_minute,
            burst: input.burst,
            proxy_type: None,
            proxy_address: None,
            proxy_username: None,
            proxy_password: None,
        }
    }
}

impl From<HttpTrafficQueryInput> for HttpTrafficSearch {
    fn from(input: HttpTrafficQueryInput) -> Self {
        Self {
            org_id: input.org_id,
            filter: HttpTrafficFilter::from(input.filter),
            cursor: input.cursor,
            limit: input.limit,
            descending: input.descending,
            order_by: match input.order_by {
                HttpTrafficOrderFieldGql::Timestamp => HttpTrafficOrderField::Timestamp,
                HttpTrafficOrderFieldGql::Method => HttpTrafficOrderField::Method,
                HttpTrafficOrderFieldGql::Url => HttpTrafficOrderField::Url,
                HttpTrafficOrderFieldGql::StatusCode => HttpTrafficOrderField::StatusCode,
                HttpTrafficOrderFieldGql::ResponseSize => HttpTrafficOrderField::ResponseSize,
                HttpTrafficOrderFieldGql::MimeType => HttpTrafficOrderField::MimeType,
                HttpTrafficOrderFieldGql::Cookies => HttpTrafficOrderField::Cookies,
                HttpTrafficOrderFieldGql::DurationMs => HttpTrafficOrderField::DurationMs,
            },
        }
    }
}

impl From<HttpTrafficFilterInput> for HttpTrafficFilter {
    fn from(input: HttpTrafficFilterInput) -> Self {
        // Merge `source_id` (singular, backward-compat) and `source_ids`
        // (plural) into a single Vec. Either or both may be provided.
        let source_id = match (input.source_id, input.source_ids) {
            (None, None) => None,
            (Some(single), None) => Some(vec![single]),
            (None, Some(many)) if many.is_empty() => None,
            (None, Some(many)) => Some(many),
            (Some(single), Some(mut many)) => {
                if !many.contains(&single) {
                    many.push(single);
                }
                Some(many)
            }
        };
        Self {
            source_id,
            source: input.source,
            host: input.host,
            method: input.method,
            path: input.path,
            search: input.search,
            correlation_id: input.correlation_id,
            parent_correlation_id: input.parent_correlation_id,
            account_id: input.account_id,
            tool_call_id: input.tool_call_id,
            status_code: input.status_code,
            request: input
                .request
                .map(|r| HttpRequestFilter {
                    methods: r.methods,
                    url_contains: r.url_contains,
                    sends_cookies: r.sends_cookies,
                })
                .unwrap_or_default(),
            response: input
                .response
                .map(|r| HttpResponseFilter {
                    status_classes: r.status_classes,
                    status_codes: r.status_codes,
                    mime_type: r.mime_type,
                    sets_cookies: r.sets_cookies,
                    min_length: r.min_length,
                    max_length: r.max_length,
                    min_duration_ms: r.min_duration_ms,
                    max_duration_ms: r.max_duration_ms,
                })
                .unwrap_or_default(),
        }
    }
}

fn has_header(headers: &[HeaderPairDto], name: &str) -> bool {
    headers.iter().any(|h| h.name.eq_ignore_ascii_case(name))
}

/// Mirrors the API's ClickHouse `MIME_TYPE` expression so the displayed
/// value matches what the filter and sort see.
fn mime_type(headers: &[HeaderPairDto]) -> String {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-type"))
        .and_then(|h| h.value.split(';').next())
        .unwrap_or_default()
        .trim_matches(' ')
        .to_ascii_lowercase()
}

impl From<HttpTrafficSummaryDto> for HttpTrafficSummary {
    fn from(capture: HttpTrafficSummaryDto) -> Self {
        let mime_type = mime_type(&capture.response_headers);
        let request_sends_cookies = has_header(&capture.request_headers, "cookie");
        let response_sets_cookies = has_header(&capture.response_headers, "set-cookie");
        Self {
            id: capture.id,
            org_id: capture.org_id,
            timestamp: capture.timestamp.format(&Rfc3339).unwrap_or_default(),
            method: capture.method,
            path: capture.path,
            host: capture.host,
            scheme: capture.scheme,
            request_headers: capture
                .request_headers
                .into_iter()
                .map(|pair| HeaderPair {
                    name: pair.name,
                    value: pair.value,
                })
                .collect(),
            request_size: capture.request_size,
            status_code: capture.status_code,
            response_headers: capture
                .response_headers
                .into_iter()
                .map(|pair| HeaderPair {
                    name: pair.name,
                    value: pair.value,
                })
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
            mime_type,
            request_sends_cookies,
            response_sets_cookies,
        }
    }
}
impl From<HttpTrafficDetailDto> for HttpTrafficDetail {
    fn from(capture: HttpTrafficDetailDto) -> Self {
        Self {
            id: capture.id,
            org_id: capture.org_id,
            timestamp: capture.timestamp.format(&Rfc3339).unwrap_or_default(),
            method: capture.method,
            path: capture.path,
            host: capture.host,
            scheme: capture.scheme,
            request_headers: capture
                .request_headers
                .into_iter()
                .map(|pair| HeaderPair {
                    name: pair.name,
                    value: pair.value,
                })
                .collect(),
            request_body: capture.request_body,
            request_size: capture.request_size,
            status_code: capture.status_code,
            response_headers: capture
                .response_headers
                .into_iter()
                .map(|pair| HeaderPair {
                    name: pair.name,
                    value: pair.value,
                })
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

impl From<WsTrafficQueryInput> for WsTrafficSearch {
    fn from(input: WsTrafficQueryInput) -> Self {
        Self {
            org_id: input.org_id,
            filter: WsTrafficFilter::from(input.filter),
            cursor: input.cursor,
            limit: input.limit,
            descending: input.descending,
            payload_max_bytes: input.payload_max_bytes,
        }
    }
}

impl From<WsTrafficFilterInput> for WsTrafficFilter {
    fn from(input: WsTrafficFilterInput) -> Self {
        let source_id = match (input.source_id, input.source_ids) {
            (None, None) => None,
            (Some(single), None) => Some(vec![single]),
            (None, Some(many)) if many.is_empty() => None,
            (None, Some(many)) => Some(many),
            (Some(single), Some(mut many)) => {
                if !many.contains(&single) {
                    many.push(single);
                }
                Some(many)
            }
        };
        Self {
            source_id,
            source: input.source,
            session_id: input.session_id,
            parent_event_id: input.parent_event_id,
            host: input.host,
            direction: input.direction,
            opcode: input.opcode,
            payload: input.payload,
            search: None,
        }
    }
}

impl From<WsTrafficSummaryDto> for WsTrafficSummary {
    fn from(c: WsTrafficSummaryDto) -> Self {
        Self {
            id: c.id,
            parent_event_id: c.parent_event_id,
            org_id: c.org_id,
            timestamp: c.timestamp.format(&Rfc3339).unwrap_or_default(),
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
            payload: match c.payload {
                Some(BodyFetchDto::Body { value }) => Some(value),
                _ => None,
            },
        }
    }
}

impl From<WsMessageDetailDto> for WsMessageDetail {
    fn from(c: WsMessageDetailDto) -> Self {
        Self {
            id: c.id,
            parent_event_id: c.parent_event_id,
            org_id: c.org_id,
            timestamp: c.timestamp.format(&Rfc3339).unwrap_or_default(),
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

impl From<TrafficQueryInput> for TrafficSearch {
    fn from(input: TrafficQueryInput) -> Self {
        Self {
            org_id: input.org_id,
            filter: TrafficFilter::from(input.filter),
            kind: match input.kind {
                TrafficKindGql::All => TrafficKind::All,
                TrafficKindGql::Http => TrafficKind::Http,
                TrafficKindGql::Ws => TrafficKind::Ws,
            },
            cursor: input.cursor,
            limit: input.limit,
            descending: input.descending,
            payload_max_bytes: input.payload_max_bytes,
        }
    }
}

impl From<TrafficFilterInput> for TrafficFilter {
    fn from(input: TrafficFilterInput) -> Self {
        let source_id = match (input.source_id, input.source_ids) {
            (None, None) => None,
            (Some(single), None) => Some(vec![single]),
            (None, Some(many)) if many.is_empty() => None,
            (None, Some(many)) => Some(many),
            (Some(single), Some(mut many)) => {
                if !many.contains(&single) {
                    many.push(single);
                }
                Some(many)
            }
        };
        Self {
            source_id,
            source: input.source,
            host: input.host,
            method: input.method,
            path: input.path,
            search: input.search,
            status_code: input.status_code,
            correlation_id: input.correlation_id,
            tool_call_id: input.tool_call_id,
            direction: input.direction,
            opcode: input.opcode,
            session_id: input.session_id,
            parent_event_id: input.parent_event_id,
        }
    }
}

impl From<TrafficEventDto> for TrafficEvent {
    fn from(e: TrafficEventDto) -> Self {
        match e {
            TrafficEventDto::Http(c) => TrafficEvent::Http(HttpTrafficSummary::from(c)),
            TrafficEventDto::Ws(c) => TrafficEvent::Ws(WsTrafficSummary::from(c)),
        }
    }
}

impl From<WsConversationQueryInput> for WsConversationSearch {
    fn from(input: WsConversationQueryInput) -> Self {
        Self {
            org_id: input.org_id,
            filter: WsConversationFilter::from(input.filter),
            limit: input.limit,
            descending: input.descending,
        }
    }
}

impl From<WsConversationFilterInput> for WsConversationFilter {
    fn from(input: WsConversationFilterInput) -> Self {
        let source_id = match (input.source_id, input.source_ids) {
            (None, None) => None,
            (Some(single), None) => Some(vec![single]),
            (None, Some(many)) if many.is_empty() => None,
            (None, Some(many)) => Some(many),
            (Some(single), Some(mut many)) => {
                if !many.contains(&single) {
                    many.push(single);
                }
                Some(many)
            }
        };
        Self {
            source_id,
            source: input.source,
            host: input.host,
        }
    }
}

impl From<WsConversationDto> for WsConversation {
    fn from(c: WsConversationDto) -> Self {
        Self {
            parent_event_id: c.parent_event_id,
            host: c.host,
            path: c.path,
            message_count: c.message_count,
            client_to_server: c.client_to_server,
            server_to_client: c.server_to_client,
            first_at: c.first_at.format(&Rfc3339).unwrap_or_default(),
            last_at: c.last_at.format(&Rfc3339).unwrap_or_default(),
            source: c.source,
            source_id: c.source_id,
            session_id: c.session_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exports_federation_sdl() {
        assert!(federation_sdl().contains("type Query"));
    }
}
