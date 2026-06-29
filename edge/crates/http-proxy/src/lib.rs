use anyhow::Context;
use arc_swap::ArcSwap;
use base64::Engine;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use flate2::{write::GzEncoder, Compression};
use http::{
    header::{
        HeaderMap, HeaderName, HeaderValue, ACCEPT_ENCODING, ACCESS_CONTROL_REQUEST_METHOD,
        AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE,
        COOKIE, HOST, LOCATION, ORIGIN, SET_COOKIE, UPGRADE, VARY, WWW_AUTHENTICATE,
    },
    Method, Request, Response, StatusCode, Uri, Version,
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{body::Incoming, service::service_fn};
use hyper_rustls::HttpsConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder as AutoBuilder,
};
use ipnet::IpNet;
use parking_lot::Mutex;
use pxxl_common::{
    canonicalize_request_path, ip_allowed_for_upstream, normalize_domain, parse_ip_net,
    BasicAuthConfig, BufferingConfig, CircuitBreakerConfig, ClientCertForwardingConfig,
    CompressionConfig, ContentTypeAutoDetectConfig, DigestAuthConfig, DomainRateLimit, DomainRules,
    ForwardAuthConfig, GeoLocation, InFlightLimitConfig, InFlightLimitScope, MiddlewareDefinition,
    PassiveHealthConfig, PxxlError, RateLimitScope, RetryConfig, RouteMatch, RouteSource,
    StickySessionConfig, TrafficMirrorConfig, TrafficSplitRule, Upstream,
};
use pxxl_core::{EdgeState, RequestObservation};
use pxxl_ddos::{RequestObservationInput, SecurityDecision};
use pxxl_geo::GeoIpResolver;
use pxxl_redis_sync::RedisBandwidthTracker;
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    convert::Infallible,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::{watch, Semaphore},
    time,
};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type BoxBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;
const REQUEST_ID_HEADER: &str = "x-request-id";
const EDGE_CONNECTION_TIMEOUT_SECONDS: u64 = 120;
const EDGE_MAX_CONNECTIONS: usize = 8192;
const POLICY_RATE_BUCKET_TTL_SECONDS: u64 = 600;
const POLICY_RATE_BUCKET_EVICT_AT: usize = 100_000;
const DIGEST_NONCE_TTL_MS: u64 = 5 * 60 * 1_000;
const DIGEST_NONCE_CLOCK_SKEW_MS: u64 = 30 * 1_000;
const DIGEST_REPLAY_EVICT_AT: usize = 100_000;
const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";
const TRUSTED_CLIENT_IP_CIDRS_ENV: &str = "PXXL_TRUSTED_CLIENT_IP_CIDRS";
const LEGACY_TRUSTED_CLIENT_IP_CIDRS_ENV: &str = "PXXL_TRUSTED_PROXY_CIDRS";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProxyErrorReason {
    RouteNotRegistered,
    RouteHasNoUpstreams,
    AllUpstreamsUnhealthy,
    CircuitBreakerOpen,
    UpstreamTcpUnreachable,
    ProxyInternal,
}

impl ProxyErrorReason {
    fn code(self) -> &'static str {
        match self {
            Self::RouteNotRegistered => "route_not_registered",
            Self::RouteHasNoUpstreams => "route_has_no_upstreams",
            Self::AllUpstreamsUnhealthy => "all_upstreams_unhealthy",
            Self::CircuitBreakerOpen => "circuit_breaker_open",
            Self::UpstreamTcpUnreachable => "upstream_tcp_unreachable",
            Self::ProxyInternal => "proxy_internal_error",
        }
    }

    fn public_message(self) -> &'static str {
        match self {
            Self::RouteNotRegistered => {
                "No route is registered for this domain yet. The deployment may still be connecting to the proxy."
            }
            Self::RouteHasNoUpstreams => {
                "This domain is registered, but it does not have a runtime container target yet."
            }
            Self::AllUpstreamsUnhealthy => {
                "The app route exists, but Pxxl cannot reach the port registered for this deployment. Make sure your app listens on the same port configured in your Pxxl project settings, or reads the PORT environment variable provided by Pxxl."
            }
            Self::CircuitBreakerOpen => {
                "The app route exists, but recent upstream failures temporarily opened the protection circuit."
            }
            Self::UpstreamTcpUnreachable => {
                "The app route exists, but Pxxl could not connect to the registered runtime port. Check that your app is binding to 0.0.0.0 and listening on the same port configured in your Pxxl project settings, preferably through the PORT environment variable."
            }
            Self::ProxyInternal => "The proxy hit an internal routing error while serving this request.",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ErrorPageRenderer {
    enabled: bool,
    pages: Arc<HashMap<u16, ErrorPageTemplate>>,
    default_page: Option<ErrorPageTemplate>,
}

#[derive(Clone, Debug)]
struct ErrorPageTemplate {
    body: Arc<str>,
}

#[derive(Clone, Copy, Debug)]
struct ErrorRenderContext<'a> {
    status: StatusCode,
    message: &'a str,
    reason_code: &'a str,
    domain: &'a str,
    path: &'a str,
    request_id: &'a str,
    processing_time_ms: u128,
}

#[derive(Clone, Debug)]
pub struct BandwidthExceededContext<'a> {
    status: StatusCode,
    domain: &'a str,
    path: &'a str,
    request_id: &'a str,
    processing_time_ms: u128,
    bytes_used: u64,
    bytes_limit: u64,
    reset_day: u8,
}

impl Default for ErrorPageRenderer {
    fn default() -> Self {
        Self {
            enabled: true,
            pages: Arc::new(HashMap::new()),
            default_page: None,
        }
    }
}

impl ErrorPageRenderer {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            pages: Arc::new(HashMap::new()),
            default_page: None,
        }
    }

    pub fn load_from_dir(enabled: bool, dir: impl Into<PathBuf>) -> anyhow::Result<Self> {
        if !enabled {
            return Ok(Self::disabled());
        }

        let dir = dir.into();
        if !dir.exists() {
            warn!(
                dir = %dir.display(),
                "error page directory not found; using built-in defaults"
            );
            return Ok(Self::default());
        }

        if !dir.is_dir() {
            anyhow::bail!("error page path is not a directory: {}", dir.display());
        }

        let mut pages = HashMap::new();
        let mut default_page = None;
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("reading error page directory {}", dir.display()))?
        {
            let entry = entry
                .with_context(|| format!("reading error page entry under {}", dir.display()))?;
            let path = entry.path();
            if !path.is_file() || !is_html_template(&path) {
                continue;
            }

            let body = std::fs::read_to_string(&path)
                .with_context(|| format!("reading error page template {}", path.display()))?;
            let template = ErrorPageTemplate {
                body: Arc::<str>::from(body),
            };

            let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
                continue;
            };

            if stem.eq_ignore_ascii_case("default") {
                default_page = Some(template);
                continue;
            }

            match stem.parse::<u16>() {
                Ok(code) if StatusCode::from_u16(code).is_ok() => {
                    pages.insert(code, template);
                }
                _ => debug!(path = %path.display(), "ignoring unrecognized error page template"),
            }
        }

        info!(
            dir = %dir.display(),
            pages = pages.len(),
            has_default = default_page.is_some(),
            "loaded custom error pages"
        );

        Ok(Self {
            enabled: true,
            pages: Arc::new(pages),
            default_page,
        })
    }

    fn response(
        &self,
        status: StatusCode,
        message: &str,
        domain: &str,
        path: &str,
        request_id: &str,
        processing_time_ms: u128,
    ) -> Response<BoxBody> {
        if !self.enabled {
            return text_response(status, message);
        }

        let body = self
            .pages
            .get(&status.as_u16())
            .or(self.default_page.as_ref())
            .map(|template| {
                render_error_template(
                    template.body.as_ref(),
                    ErrorRenderContext {
                        status,
                        message,
                        reason_code: "proxy_error",
                        domain,
                        path,
                        request_id,
                        processing_time_ms,
                    },
                )
            })
            .unwrap_or_else(|| {
                default_error_html(
                    status,
                    message,
                    "proxy_error",
                    domain,
                    path,
                    request_id,
                    processing_time_ms,
                )
            });

        html_response(status, body)
    }

    fn response_with_reason(
        &self,
        status: StatusCode,
        reason: ProxyErrorReason,
        domain: &str,
        path: &str,
        request_id: &str,
        processing_time_ms: u128,
    ) -> Response<BoxBody> {
        self.response_with_reason_code(ErrorRenderContext {
            status,
            message: reason.public_message(),
            reason_code: reason.code(),
            domain,
            path,
            request_id,
            processing_time_ms,
        })
    }

    fn response_with_reason_code(&self, context: ErrorRenderContext<'_>) -> Response<BoxBody> {
        if !self.enabled {
            return text_response(context.status, context.message);
        }

        let body = self
            .pages
            .get(&context.status.as_u16())
            .or(self.default_page.as_ref())
            .map(|template| render_error_template(template.body.as_ref(), context))
            .unwrap_or_else(|| {
                default_error_html(
                    context.status,
                    context.message,
                    context.reason_code,
                    context.domain,
                    context.path,
                    context.request_id,
                    context.processing_time_ms,
                )
            });

        html_response(context.status, body)
    }

    pub fn bandwidth_exceeded_response(
        &self,
        context: BandwidthExceededContext<'_>,
    ) -> Response<BoxBody> {
        let status = context.status;
        let domain = context.domain;
        let path = context.path;
        let request_id = context.request_id;
        let processing_time_ms = context.processing_time_ms;
        let bytes_used = context.bytes_used;
        let bytes_limit = context.bytes_limit;
        let reset_day = context.reset_day;

        let percentage = if bytes_limit > 0 {
            ((bytes_used as f64 / bytes_limit as f64) * 100.0).min(100.0)
        } else {
            100.0
        };

        let reset_date = bandwidth_reset_date(reset_day);

        let body = if let Some(template) = self
            .pages
            .get(&status.as_u16())
            .or(self.default_page.as_ref())
        {
            template
                .body
                .replace("{{domain}}", domain)
                .replace("{{bytes_used}}", &format_bytes(bytes_used))
                .replace("{{bytes_limit}}", &format_bytes(bytes_limit))
                .replace("{{percentage_used}}", &format!("{:.1}", percentage))
                .replace("{{reset_date}}", &reset_date)
                .replace("{{request_id}}", request_id)
                .replace("{{processing_time_ms}}", &processing_time_ms.to_string())
                .replace("{{status_code}}", &status.as_u16().to_string())
                .replace(
                    "{{status_text}}",
                    status
                        .canonical_reason()
                        .unwrap_or("Bandwidth Limit Exceeded"),
                )
                .replace("{{message}}", "Bandwidth limit exceeded")
                .replace("{{reason_code}}", "bandwidth_limit_exceeded")
                .replace("{{path}}", path)
        } else {
            format!(
                r#"<!DOCTYPE html><html><head><title>509 Bandwidth Limit Exceeded</title></head>
<body><h1>509 Bandwidth Limit Exceeded</h1>
<p>Domain <strong>{domain}</strong> has exceeded its bandwidth limit.</p>
<p>Used: {used} / Limit: {limit} ({pct:.1}%)</p>
<p>Resets: {reset}</p>
<p>Request ID: {rid}</p>
<p>Processing time: {processing_time_ms} ms</p>
</body></html>"#,
                domain = domain,
                used = format_bytes(bytes_used),
                limit = format_bytes(bytes_limit),
                pct = percentage,
                reset = reset_date,
                rid = request_id,
                processing_time_ms = processing_time_ms,
            )
        };

        html_response(status, body)
    }
}

#[derive(Clone, Debug)]
pub struct PolicyEnforcer {
    rate_limiter: Arc<PolicyRateLimiter>,
    circuit_breakers: Arc<DashMap<String, Mutex<CircuitBreakerState>>>,
    in_flight_limits: Arc<DashMap<String, AtomicUsize>>,
    passive_health: Arc<DashMap<String, Mutex<PassiveHealthState>>>,
    bot_score_buckets: Arc<DashMap<BotScoreKey, Mutex<BotScoreBucket>>>,
    digest_secret: Arc<str>,
    digest_replays: Arc<DashMap<String, Instant>>,
}

impl Default for PolicyEnforcer {
    fn default() -> Self {
        Self {
            rate_limiter: Arc::new(PolicyRateLimiter::default()),
            circuit_breakers: Arc::new(DashMap::new()),
            in_flight_limits: Arc::new(DashMap::new()),
            passive_health: Arc::new(DashMap::new()),
            bot_score_buckets: Arc::new(DashMap::new()),
            digest_secret: Arc::<str>::from(format!("{}:{}", Uuid::new_v4(), Uuid::new_v4())),
            digest_replays: Arc::new(DashMap::new()),
        }
    }
}

#[derive(Debug, Default)]
struct PolicyRateLimiter {
    buckets: DashMap<PolicyRateKey, Mutex<PolicyRateBucket>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PolicyRateKey {
    domain: String,
    scope: RateLimitScope,
    ip: Option<IpAddr>,
    path: Option<String>,
}

#[derive(Debug)]
struct PolicyRateBucket {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BotScoreKey {
    domain: String,
    ip: IpAddr,
}

#[derive(Debug)]
struct BotScoreBucket {
    window_started: Instant,
    requests: u32,
}

#[derive(Debug)]
struct BotAssessment {
    score: u16,
    reasons: Vec<&'static str>,
}

#[derive(Debug, Default)]
struct CircuitBreakerState {
    failures: u32,
    open_until: Option<Instant>,
}

#[derive(Debug, Default)]
struct PassiveHealthState {
    failures: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestScheme {
    Http,
    Https,
}

#[derive(Clone)]
pub struct ReloadableTlsConfig {
    config: Arc<ArcSwap<ServerConfig>>,
}

impl ReloadableTlsConfig {
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            config: Arc::new(ArcSwap::new(config)),
        }
    }

    pub fn load(&self) -> Arc<ServerConfig> {
        self.config.load_full()
    }

    pub fn store(&self, config: Arc<ServerConfig>) {
        self.config.store(config);
    }
}

impl RequestScheme {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

#[derive(Debug)]
struct PolicyRejection {
    status: StatusCode,
    message: &'static str,
    metric_reason: &'static str,
    retry_after: Option<Duration>,
    location: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct ProxyRequestContext<'a> {
    request_id: &'a str,
    domain: &'a str,
    method: &'a str,
    path: &'a str,
    remote_ip: Option<IpAddr>,
    scheme: RequestScheme,
    location: &'a GeoLocation,
    timestamp_unix_ms: u64,
}

#[derive(Debug, Clone)]
struct EffectiveMiddleware {
    request_buffering: BufferingConfig,
    response_buffering: BufferingConfig,
    compression: CompressionConfig,
    content_type_autodetect: ContentTypeAutoDetectConfig,
    retry: RetryConfig,
    circuit_breaker: CircuitBreakerConfig,
    in_flight_limit: InFlightLimitConfig,
    sticky_sessions: StickySessionConfig,
    passive_health: PassiveHealthConfig,
    traffic_mirroring: TrafficMirrorConfig,
    client_cert_forwarding: ClientCertForwardingConfig,
    basic_auth: Option<BasicAuthConfig>,
    digest_auth: Option<DigestAuthConfig>,
    forward_auth: Option<ForwardAuthConfig>,
}

struct ForwardContext<'a> {
    matched: &'a RouteMatch,
    upstream: &'a Upstream,
    remote_ip: Option<IpAddr>,
    scheme: RequestScheme,
    middleware: &'a EffectiveMiddleware,
    domain: &'a str,
    client_cert_pem: Option<&'a str>,
}

struct CircuitRecord<'a> {
    config: &'a CircuitBreakerConfig,
    domain: &'a str,
    route_id: &'a str,
    path_prefix: &'a str,
    upstream: &'a str,
    status: StatusCode,
    error: bool,
    state: &'a EdgeState,
}

impl EffectiveMiddleware {
    fn from_rules(rules: &DomainRules, names: &[String]) -> Self {
        let mut effective = Self {
            request_buffering: rules.request_buffering.clone(),
            response_buffering: rules.response_buffering.clone(),
            compression: rules.compression.clone(),
            content_type_autodetect: rules.content_type_autodetect.clone(),
            retry: rules.retry.clone(),
            circuit_breaker: rules.circuit_breaker.clone(),
            in_flight_limit: rules.in_flight_limit.clone(),
            sticky_sessions: rules.sticky_sessions.clone(),
            passive_health: rules.passive_health.clone(),
            traffic_mirroring: rules.traffic_mirroring.clone(),
            client_cert_forwarding: rules.client_cert_forwarding.clone(),
            basic_auth: None,
            digest_auth: None,
            forward_auth: None,
        };
        let mut expanded = Vec::new();
        expand_middleware_names(names, rules, &mut expanded, 0);
        for name in expanded {
            if let Some(middleware) = rules.middlewares.get(&name) {
                effective.apply(middleware);
            }
        }
        effective
    }

    fn apply(&mut self, middleware: &MiddlewareDefinition) {
        if let Some(value) = &middleware.basic_auth {
            self.basic_auth = Some(value.clone());
        }
        if let Some(value) = &middleware.forward_auth {
            self.forward_auth = Some(value.clone());
        }
        if let Some(value) = &middleware.digest_auth {
            self.digest_auth = Some(value.clone());
        }
        if let Some(value) = &middleware.request_buffering {
            self.request_buffering = value.clone();
        }
        if let Some(value) = &middleware.response_buffering {
            self.response_buffering = value.clone();
        }
        if let Some(value) = &middleware.compression {
            self.compression = value.clone();
        }
        if let Some(value) = &middleware.content_type_autodetect {
            self.content_type_autodetect = value.clone();
        }
        if let Some(value) = &middleware.retry {
            self.retry = value.clone();
        }
        if let Some(value) = &middleware.circuit_breaker {
            self.circuit_breaker = value.clone();
        }
        if let Some(value) = &middleware.in_flight_limit {
            self.in_flight_limit = value.clone();
        }
        if let Some(value) = &middleware.pass_tls_client_cert {
            self.client_cert_forwarding = value.clone();
        }
    }
}

impl PolicyEnforcer {
    fn evaluate(
        &self,
        req: &Request<Incoming>,
        rules: &DomainRules,
        context: &ProxyRequestContext<'_>,
    ) -> Option<PolicyRejection> {
        if rules.maintenance_mode {
            let status = rules
                .maintenance_status_code
                .and_then(|value| StatusCode::from_u16(value).ok())
                .filter(|value| value.is_server_error() || value.is_client_error())
                .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
            return Some(policy_rejection(
                status,
                "domain is in maintenance mode",
                "maintenance_mode",
            ));
        }

        if context.scheme == RequestScheme::Http && rules.redirect_http_to_https {
            return Some(PolicyRejection {
                status: StatusCode::PERMANENT_REDIRECT,
                message: "https required",
                metric_reason: "https_redirect",
                retry_after: None,
                location: Some(format!("https://{}{}", context.domain, context.path)),
            });
        }

        if context.scheme == RequestScheme::Http && rules.require_https {
            return Some(policy_rejection(
                StatusCode::UPGRADE_REQUIRED,
                "https is required for this domain",
                "https_required",
            ));
        }

        if let Some(ip) = context.remote_ip {
            if !rules.ip_allowlist.is_empty()
                && !rules
                    .ip_allowlist
                    .iter()
                    .any(|network| network.contains(&ip))
            {
                return Some(policy_rejection(
                    StatusCode::FORBIDDEN,
                    "ip is not allowed for this domain",
                    "ip_not_allowlisted",
                ));
            }

            if rules
                .ip_blocklist
                .iter()
                .any(|network| network.contains(&ip))
            {
                return Some(policy_rejection(
                    StatusCode::FORBIDDEN,
                    "ip is blocked for this domain",
                    "ip_blocklisted",
                ));
            }
        }

        if !rules.country_allowlist.is_empty()
            && !location_code_matches(
                context.location.country_code.as_deref(),
                &rules.country_allowlist,
            )
        {
            return Some(policy_rejection(
                StatusCode::FORBIDDEN,
                "country is not allowed for this domain",
                "country_not_allowlisted",
            ));
        }

        if location_code_matches(
            context.location.country_code.as_deref(),
            &rules.country_blocklist,
        ) {
            return Some(policy_rejection(
                StatusCode::FORBIDDEN,
                "country is blocked for this domain",
                "country_blocklisted",
            ));
        }

        if !rules.continent_allowlist.is_empty()
            && !location_code_matches(
                context.location.continent_code.as_deref(),
                &rules.continent_allowlist,
            )
        {
            return Some(policy_rejection(
                StatusCode::FORBIDDEN,
                "continent is not allowed for this domain",
                "continent_not_allowlisted",
            ));
        }

        if location_code_matches(
            context.location.continent_code.as_deref(),
            &rules.continent_blocklist,
        ) {
            return Some(policy_rejection(
                StatusCode::FORBIDDEN,
                "continent is blocked for this domain",
                "continent_blocklisted",
            ));
        }

        if rules
            .blocked_methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case(req.method().as_str()))
        {
            return Some(policy_rejection(
                StatusCode::METHOD_NOT_ALLOWED,
                "method is blocked for this domain",
                "method_blocked",
            ));
        }

        if !rules.allowed_methods.is_empty()
            && !rules
                .allowed_methods
                .iter()
                .any(|method| method.eq_ignore_ascii_case(req.method().as_str()))
        {
            return Some(policy_rejection(
                StatusCode::METHOD_NOT_ALLOWED,
                "method is not allowed for this domain",
                "method_not_allowed",
            ));
        }

        if !rules.allow_websocket && is_websocket_upgrade(req.headers()) {
            return Some(policy_rejection(
                StatusCode::FORBIDDEN,
                "websocket upgrades are disabled for this domain",
                "websocket_disabled",
            ));
        }

        if let Some(limit) = rules.max_uri_length {
            if req.uri().to_string().len() > limit {
                return Some(policy_rejection(
                    StatusCode::URI_TOO_LONG,
                    "request uri is too long",
                    "uri_too_long",
                ));
            }
        }

        if let Some(limit) = rules.max_body_bytes {
            if content_length(req.headers()).is_some_and(|length| length > limit) {
                return Some(policy_rejection(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body is too large",
                    "body_too_large",
                ));
            }
        }

        if let Some(reason) = self.waf_rejection_reason(req, rules, context) {
            return Some(policy_rejection(
                StatusCode::FORBIDDEN,
                "request blocked by waf rules",
                reason,
            ));
        }

        if !rules.allowed_content_types.is_empty() && request_can_have_body(req.method()) {
            match req
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
            {
                Some(content_type)
                    if rules
                        .allowed_content_types
                        .iter()
                        .any(|allowed| content_type_matches(content_type, allowed)) => {}
                _ => {
                    return Some(policy_rejection(
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        "content-type is not allowed for this domain",
                        "content_type_not_allowed",
                    ));
                }
            }
        }

        for blocked in &rules.blocked_headers {
            if header_present(req.headers(), blocked) {
                return Some(policy_rejection(
                    StatusCode::FORBIDDEN,
                    "request contains a blocked header",
                    "header_blocked",
                ));
            }
        }

        if !rules.allowed_headers.is_empty() {
            for name in req.headers().keys() {
                if !rules
                    .allowed_headers
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(name.as_str()))
                {
                    return Some(policy_rejection(
                        StatusCode::FORBIDDEN,
                        "request contains a header that is not allowed",
                        "header_not_allowed",
                    ));
                }
            }
        }

        for required in &rules.required_headers {
            let Some(value) = header_value(req.headers(), &required.name) else {
                return Some(policy_rejection(
                    StatusCode::BAD_REQUEST,
                    "request is missing a required header",
                    "header_required",
                ));
            };

            if required
                .value
                .as_ref()
                .is_some_and(|expected| expected != value)
            {
                return Some(policy_rejection(
                    StatusCode::BAD_REQUEST,
                    "request header has an invalid value",
                    "header_required_value",
                ));
            }
        }

        if let Some(limit) = rules.rate_limit.as_ref() {
            if let Some(retry_after) = self.rate_limiter.retry_after(
                limit,
                context.domain,
                context.path,
                context.remote_ip,
            ) {
                return Some(PolicyRejection {
                    status: StatusCode::from_u16(limit.status_code)
                        .unwrap_or(StatusCode::TOO_MANY_REQUESTS),
                    message: "rate limited by domain rules",
                    metric_reason: "domain_rate_limited",
                    retry_after: Some(retry_after),
                    location: None,
                });
            }
        }

        if is_cors_preflight(req, rules) {
            return Some(PolicyRejection {
                status: StatusCode::NO_CONTENT,
                message: "cors preflight accepted",
                metric_reason: "cors_preflight",
                retry_after: None,
                location: None,
            });
        }

        None
    }

    fn waf_rejection_reason(
        &self,
        req: &Request<Incoming>,
        rules: &DomainRules,
        context: &ProxyRequestContext<'_>,
    ) -> Option<&'static str> {
        let waf = &rules.waf;
        if !waf.enabled {
            return None;
        }

        if let Some(reason) = static_waf_rejection_reason(req, rules, context.path) {
            return Some(reason);
        }

        if waf.block_bad_bots {
            let assessment = self.assess_bot_request(req, context);
            if assessment.score >= 60 {
                debug!(
                    request_id = %context.request_id,
                    domain = %context.domain,
                    score = assessment.score,
                    reasons = ?assessment.reasons,
                    "request blocked by bot score"
                );
                return Some("waf_bot_score");
            }
        }

        None
    }

    fn assess_bot_request(
        &self,
        req: &Request<Incoming>,
        context: &ProxyRequestContext<'_>,
    ) -> BotAssessment {
        let mut score = 0u16;
        let mut reasons = Vec::new();
        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let user_agent_lower = user_agent.to_ascii_lowercase();

        if user_agent.trim().is_empty() {
            score += 20;
            reasons.push("missing_user_agent");
        } else if user_agent.len() < 8 {
            score += 10;
            reasons.push("short_user_agent");
        }

        if contains_any(
            &user_agent_lower,
            &[
                "sqlmap",
                "nikto",
                "masscan",
                "zgrab",
                "nmap",
                "dirbuster",
                "gobuster",
                "ffuf",
                "acunetix",
                "nessus",
                "wpscan",
            ],
        ) {
            score += 70;
            reasons.push("scanner_user_agent");
        } else if contains_any(
            &user_agent_lower,
            &[
                "python-requests",
                "aiohttp",
                "httpx",
                "libwww-perl",
                "scrapy",
                "go-http-client",
                "java/",
                "okhttp",
                "curl",
                "wget",
            ],
        ) {
            score += 20;
            reasons.push("automation_user_agent");
        }

        if let Some(ip) = context.remote_ip {
            let rate_points = self.bot_rate_points(context.domain, ip);
            if rate_points > 0 {
                score += rate_points;
                reasons.push("request_rate");
            }
        }

        let entropy = shannon_entropy(context.path);
        if context.path.len() >= 48 && entropy >= 4.25 {
            score += 20;
            reasons.push("path_entropy");
        }
        if path_has_long_random_segment(context.path) {
            score += 20;
            reasons.push("random_path_segment");
        }

        let source_lower = context.location.source.to_ascii_lowercase();
        if source_lower == "unknown" {
            score += 5;
            reasons.push("unknown_geo");
        }
        if source_lower.contains("asn") {
            score += 5;
            reasons.push("asn_seen");
            if contains_any(
                &source_lower,
                &[
                    "hosting",
                    "cloud",
                    "digitalocean",
                    "linode",
                    "vultr",
                    "hetzner",
                    "ovh",
                    "contabo",
                    "amazon",
                    "aws",
                    "google",
                    "microsoft",
                    "azure",
                    "leaseweb",
                    "colo",
                    "datacenter",
                ],
            ) {
                score += 15;
                reasons.push("hosting_asn");
            }
        }

        BotAssessment { score, reasons }
    }

    fn bot_rate_points(&self, domain: &str, ip: IpAddr) -> u16 {
        const BOT_WINDOW: Duration = Duration::from_secs(10);
        const BOT_BUCKET_EVICT_AT: usize = 100_000;

        if self.bot_score_buckets.len() >= BOT_BUCKET_EVICT_AT {
            let now = Instant::now();
            self.bot_score_buckets.retain(|_, bucket| {
                now.duration_since(bucket.lock().window_started) <= BOT_WINDOW * 6
            });
        }

        let key = BotScoreKey {
            domain: domain.to_string(),
            ip,
        };
        let entry = self.bot_score_buckets.entry(key).or_insert_with(|| {
            Mutex::new(BotScoreBucket {
                window_started: Instant::now(),
                requests: 0,
            })
        });
        let mut bucket = entry.lock();
        let now = Instant::now();
        if now.duration_since(bucket.window_started) > BOT_WINDOW {
            bucket.window_started = now;
            bucket.requests = 0;
        }
        bucket.requests = bucket.requests.saturating_add(1);

        match bucket.requests {
            0..=40 => 0,
            41..=120 => 15,
            121..=300 => 30,
            _ => 45,
        }
    }

    fn location_upstreams<'a>(
        &self,
        rules: &'a DomainRules,
        location: &GeoLocation,
    ) -> Option<(String, &'a [Upstream])> {
        rules.location_routes.iter().find_map(|rule| {
            if rule.upstreams.is_empty() {
                return None;
            }

            let country_matches = rule.countries.is_empty()
                || location_code_matches(location.country_code.as_deref(), &rule.countries);
            let continent_matches = rule.continents.is_empty()
                || location_code_matches(location.continent_code.as_deref(), &rule.continents);

            if country_matches && continent_matches {
                Some((
                    rule.name.clone().unwrap_or_else(|| {
                        format!(
                            "geo:{}:{}",
                            rule.countries.join("_"),
                            rule.continents.join("_")
                        )
                    }),
                    rule.upstreams.as_slice(),
                ))
            } else {
                None
            }
        })
    }

    fn matching_traffic_splits<'a>(
        &self,
        rules: &'a DomainRules,
        location: &GeoLocation,
    ) -> Vec<&'a TrafficSplitRule> {
        rules
            .traffic_splits
            .iter()
            .filter(|rule| !rule.upstreams.is_empty() && location_rule_matches(rule, location))
            .collect()
    }

    fn apply_request_rules(&self, headers: &mut HeaderMap, rules: &DomainRules) {
        for header in &rules.strip_request_headers {
            if let Ok(name) = HeaderName::from_bytes(header.as_bytes()) {
                headers.remove(name);
            }
        }

        for (name, value) in &rules.add_request_headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(name, value);
            }
        }
    }

    fn apply_response_rules(
        &self,
        headers: &mut HeaderMap,
        rules: &DomainRules,
        request_origin: Option<&HeaderValue>,
    ) {
        if rules.add_security_headers {
            insert_static_header(
                headers,
                "strict-transport-security",
                "max-age=31536000; includeSubDomains; preload",
            );
            insert_static_header(
                headers,
                "cross-origin-opener-policy",
                "same-origin-allow-popups",
            );
            insert_static_header(headers, "x-frame-options", "DENY");
            insert_static_header(headers, "x-content-type-options", "nosniff");
            insert_static_header(headers, "referrer-policy", "origin-when-cross-origin");
            insert_static_header(
                headers,
                "permissions-policy",
                "camera=(), microphone=(), geolocation=()",
            );
            insert_static_header(
                headers,
                "content-security-policy",
                "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https:; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; font-src 'self' data:; connect-src 'self' data: https: wss:; frame-src 'self' https:; upgrade-insecure-requests",
            );
        }

        for (name, value) in &rules.response_headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(name, value);
            }
        }

        if let Some(origin) = request_origin {
            if cors_origin_allowed(origin, &rules.cors_allowed_origins) {
                headers.insert("access-control-allow-origin", origin.clone());
                headers.insert(VARY, HeaderValue::from_static("origin"));

                if rules.cors_allow_credentials {
                    headers.insert(
                        "access-control-allow-credentials",
                        HeaderValue::from_static("true"),
                    );
                }

                if !rules.cors_allowed_methods.is_empty() {
                    if let Ok(value) = HeaderValue::from_str(&rules.cors_allowed_methods.join(", "))
                    {
                        headers.insert("access-control-allow-methods", value);
                    }
                }

                if !rules.cors_allowed_headers.is_empty() {
                    if let Ok(value) = HeaderValue::from_str(&rules.cors_allowed_headers.join(", "))
                    {
                        headers.insert("access-control-allow-headers", value);
                    }
                }
            }
        } else if rules
            .cors_allowed_origins
            .iter()
            .any(|origin| origin == "*")
        {
            headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
        }
    }

    fn circuit_is_open(&self, route_id: &str, path_prefix: &str, upstream: &str) -> bool {
        let key = circuit_key(route_id, path_prefix, upstream);
        let Some(state) = self.circuit_breakers.get(&key) else {
            return false;
        };
        let mut state = state.lock();
        if state
            .open_until
            .is_some_and(|open_until| Instant::now() < open_until)
        {
            return true;
        }
        state.open_until = None;
        false
    }

    fn try_acquire_in_flight(
        &self,
        limit: &InFlightLimitConfig,
        matched: &RouteMatch,
        upstream: &Upstream,
    ) -> Result<Option<String>, &'static str> {
        if !limit.enabled {
            return Ok(None);
        }
        let Some(max) = limit.max else {
            return Ok(None);
        };
        let (key, scope) = in_flight_key(limit, matched, upstream);
        let counter = self
            .in_flight_limits
            .entry(key.clone())
            .or_insert_with(|| AtomicUsize::new(0));

        loop {
            let current = counter.load(Ordering::Relaxed);
            if current >= max as usize {
                return Err(scope);
            }
            if counter
                .compare_exchange_weak(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(Some(key));
            }
        }
    }

    fn release_in_flight(&self, key: Option<String>) {
        if let Some(key) = key {
            if let Some(counter) = self.in_flight_limits.get(&key) {
                counter
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                        Some(value.saturating_sub(1))
                    })
                    .ok();
            }
        }
    }

    fn record_passive_health(
        &self,
        state: &EdgeState,
        config: &PassiveHealthConfig,
        domain: &str,
        upstream: &str,
        status: StatusCode,
        error: Option<&PxxlError>,
    ) {
        if !config.enabled {
            return;
        }

        let failed = error.is_some()
            || config
                .failure_statuses
                .iter()
                .any(|code| *code == status.as_u16())
            || status.is_server_error();
        let entry = self
            .passive_health
            .entry(upstream.to_string())
            .or_insert_with(|| Mutex::new(PassiveHealthState::default()));
        let mut passive = entry.lock();

        if failed {
            passive.failures = passive.failures.saturating_add(1);
            state
                .metrics
                .passive_health_events_total
                .with_label_values(&[upstream, "failure"])
                .inc();
            if passive.failures >= config.failure_threshold.max(1) {
                state.set_single_upstream_health(upstream, false);
                state
                    .metrics
                    .passive_health_events_total
                    .with_label_values(&[upstream, "marked_unhealthy"])
                    .inc();
                state
                    .metrics
                    .circuit_breaker_open_total
                    .with_label_values(&[domain, upstream])
                    .inc();
                let state = state.clone();
                let upstream = upstream.to_string();
                let recovery = Duration::from_secs(config.recovery_seconds.max(1));
                tokio::spawn(async move {
                    tokio::time::sleep(recovery).await;
                    state.set_single_upstream_health(&upstream, true);
                });
            }
        } else {
            passive.failures = 0;
        }
    }

    fn record_circuit_result(&self, record: CircuitRecord<'_>) {
        if !record.config.enabled {
            return;
        }
        let key = circuit_key(record.route_id, record.path_prefix, record.upstream);
        let entry = self
            .circuit_breakers
            .entry(key)
            .or_insert_with(|| Mutex::new(CircuitBreakerState::default()));
        let mut breaker = entry.lock();

        if record.error || record.status.is_server_error() {
            breaker.failures = breaker.failures.saturating_add(1);
            if breaker.failures >= record.config.failure_threshold.max(1) {
                breaker.open_until =
                    Some(Instant::now() + Duration::from_secs(record.config.open_seconds.max(1)));
                record
                    .state
                    .metrics
                    .circuit_breaker_open_total
                    .with_label_values(&[record.domain, record.upstream])
                    .inc();
            }
        } else {
            breaker.failures = 0;
            breaker.open_until = None;
        }
    }
}

impl PolicyRateLimiter {
    fn retry_after(
        &self,
        limit: &DomainRateLimit,
        domain: &str,
        path: &str,
        remote_ip: Option<IpAddr>,
    ) -> Option<Duration> {
        if !limit.enabled {
            return None;
        }

        let rate = effective_rate_per_second(limit)?;
        let burst = limit.burst.max(1) as f64;
        let key = PolicyRateKey::new(domain, path, remote_ip, &limit.scope);
        self.evict_stale();
        let entry = self.buckets.entry(key).or_insert_with(|| {
            Mutex::new(PolicyRateBucket {
                tokens: burst,
                last_refill: Instant::now(),
            })
        });

        let mut bucket = entry.lock();
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        let refill = elapsed * rate;

        if refill > 0.0 {
            bucket.tokens = (bucket.tokens + refill).min(burst);
            bucket.last_refill = now;
        }

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            None
        } else {
            Some(
                limit
                    .retry_after_seconds
                    .map(Duration::from_secs)
                    .unwrap_or_else(|| Duration::from_secs_f64(1.0 / rate.max(0.001))),
            )
        }
    }

    fn evict_stale(&self) {
        if self.buckets.len() < POLICY_RATE_BUCKET_EVICT_AT {
            return;
        }
        let now = Instant::now();
        let ttl = Duration::from_secs(POLICY_RATE_BUCKET_TTL_SECONDS);
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.lock().last_refill) <= ttl);
    }
}

impl PolicyRateKey {
    fn new(domain: &str, path: &str, remote_ip: Option<IpAddr>, scope: &RateLimitScope) -> Self {
        match scope {
            RateLimitScope::PerIp => Self {
                domain: domain.to_string(),
                scope: scope.clone(),
                ip: remote_ip,
                path: None,
            },
            RateLimitScope::PerDomain => Self {
                domain: domain.to_string(),
                scope: scope.clone(),
                ip: None,
                path: None,
            },
            RateLimitScope::PerIpPath => Self {
                domain: domain.to_string(),
                scope: scope.clone(),
                ip: remote_ip,
                path: Some(path_without_query(path).to_string()),
            },
        }
    }
}

#[derive(Clone)]
pub struct ProxyServer {
    state: EdgeState,
    client: Client<HttpsConnector<HttpConnector>, BoxBody>,
    error_pages: ErrorPageRenderer,
    policy: PolicyEnforcer,
    geoip: GeoIpResolver,
    trusted_client_ip: TrustedClientIpConfig,
    bandwidth_tracker: Option<Arc<RedisBandwidthTracker>>,
}

#[derive(Debug, Clone, Default)]
struct TrustedClientIpConfig {
    cidrs: Arc<Vec<IpNet>>,
}

impl TrustedClientIpConfig {
    fn from_env() -> Self {
        let value = std::env::var(TRUSTED_CLIENT_IP_CIDRS_ENV)
            .or_else(|_| std::env::var(LEGACY_TRUSTED_CLIENT_IP_CIDRS_ENV))
            .unwrap_or_default();
        Self::parse(&value)
    }

    fn parse(value: &str) -> Self {
        let mut cidrs = Vec::new();
        for entry in value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            match parse_ip_net(entry) {
                Ok(network) => cidrs.push(network),
                Err(error) => warn!(
                    cidr = %entry,
                    %error,
                    "ignoring invalid trusted client IP CIDR"
                ),
            }
        }
        Self {
            cidrs: Arc::new(cidrs),
        }
    }

    fn trusted_peer(&self, peer_ip: IpAddr) -> bool {
        self.cidrs.iter().any(|network| network.contains(&peer_ip))
    }
}

fn https_connector() -> HttpsConnector<HttpConnector> {
    let mut http = HttpConnector::new();
    http.enforce_http(false);

    hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("native TLS roots should be available")
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http)
}

impl ProxyServer {
    pub fn new(state: EdgeState) -> Self {
        Self::with_error_pages_and_policy(
            state,
            ErrorPageRenderer::default(),
            PolicyEnforcer::default(),
        )
    }

    pub fn with_error_pages(state: EdgeState, error_pages: ErrorPageRenderer) -> Self {
        Self::with_error_pages_and_policy(state, error_pages, PolicyEnforcer::default())
    }

    pub fn with_error_pages_and_policy(
        state: EdgeState,
        error_pages: ErrorPageRenderer,
        policy: PolicyEnforcer,
    ) -> Self {
        Self::with_error_pages_policy_and_geoip(
            state,
            error_pages,
            policy,
            GeoIpResolver::default(),
        )
    }

    pub fn with_error_pages_policy_and_geoip(
        state: EdgeState,
        error_pages: ErrorPageRenderer,
        policy: PolicyEnforcer,
        geoip: GeoIpResolver,
    ) -> Self {
        let client = Client::builder(TokioExecutor::new()).build(https_connector());
        Self {
            state,
            client,
            error_pages,
            policy,
            geoip,
            trusted_client_ip: TrustedClientIpConfig::from_env(),
            bandwidth_tracker: None,
        }
    }

    pub fn with_bandwidth_tracker(mut self, tracker: Arc<RedisBandwidthTracker>) -> Self {
        self.bandwidth_tracker = Some(tracker);
        self
    }

    pub async fn handle(
        &self,
        req: Request<Incoming>,
        peer_ip: Option<IpAddr>,
        scheme: RequestScheme,
        client_cert_pem: Option<String>,
    ) -> Response<BoxBody> {
        let started = Instant::now();
        let request_id = generate_request_id();
        macro_rules! finish_response {
            ($response:expr) => {{
                let mut response = $response;
                attach_request_id_header(response.headers_mut(), &request_id);
                return response;
            }};
        }

        let method = req.method().clone();
        let original_query = req.uri().query().map(str::to_string);
        let remote_ip =
            resolve_effective_client_ip(req.headers(), peer_ip, &self.trusted_client_ip);
        let path = match canonicalize_request_path(req.uri().path()) {
            Ok(path) => path,
            Err(error) => {
                warn!(%error, request_id = %request_id, "rejected invalid request path");
                let raw_path = req
                    .uri()
                    .path_and_query()
                    .map(|value| value.as_str().to_string())
                    .unwrap_or_else(|| "/".to_string());
                let unknown_location = GeoLocation::unknown();
                let context = ProxyRequestContext {
                    request_id: &request_id,
                    domain: "unknown",
                    method: method.as_str(),
                    path: &raw_path,
                    remote_ip,
                    scheme,
                    location: &unknown_location,
                    timestamp_unix_ms: now_unix_ms(),
                };
                self.observe_request(&context, StatusCode::BAD_REQUEST, started, None, 0, 0);
                finish_response!(self.error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid request path",
                    "unknown",
                    &raw_path,
                    &request_id,
                    started,
                ));
            }
        };
        let location = remote_ip
            .map(|ip| self.geoip.lookup(ip))
            .unwrap_or_else(GeoLocation::unknown);
        let timestamp_unix_ms = now_unix_ms();
        let host = match req
            .headers()
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .or_else(|| {
                req.uri()
                    .authority()
                    .map(|authority| authority.as_str().to_owned())
            }) {
            Some(host) => host,
            None => {
                let context = ProxyRequestContext {
                    request_id: &request_id,
                    domain: "unknown",
                    method: method.as_str(),
                    path: &path,
                    remote_ip,
                    scheme,
                    location: &location,
                    timestamp_unix_ms,
                };
                self.observe_request(&context, StatusCode::BAD_REQUEST, started, None, 0, 0);
                finish_response!(self.error_response(
                    StatusCode::BAD_REQUEST,
                    "missing host header",
                    "unknown",
                    &path,
                    &request_id,
                    started,
                ));
            }
        };
        let domain = normalize_domain(&host);
        let context = ProxyRequestContext {
            request_id: &request_id,
            domain: &domain,
            method: method.as_str(),
            path: &path,
            remote_ip,
            scheme,
            location: &location,
            timestamp_unix_ms,
        };

        if let Some(response) = serve_acme_http01_challenge(&path).await {
            self.observe_request(&context, response.status(), started, None, 0, 0);
            finish_response!(response);
        }

        if let Some(ip) = remote_ip {
            match self.state.security.check(&domain, ip) {
                SecurityDecision::Allowed => {}
                SecurityDecision::Blocked { reason } => {
                    self.state
                        .metrics
                        .blocked_total
                        .with_label_values(&[&domain, &reason])
                        .inc();
                    self.observe_request(&context, StatusCode::FORBIDDEN, started, None, 0, 0);
                    finish_response!(self.error_response(
                        StatusCode::FORBIDDEN,
                        "request blocked",
                        &domain,
                        &path,
                        &request_id,
                        started,
                    ));
                }
                SecurityDecision::RateLimited { retry_after } => {
                    self.state
                        .metrics
                        .rate_limited_total
                        .with_label_values(&[&domain])
                        .inc();
                    self.observe_request(
                        &context,
                        StatusCode::TOO_MANY_REQUESTS,
                        started,
                        None,
                        0,
                        0,
                    );
                    let mut response = self.error_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        "rate limited",
                        &domain,
                        &path,
                        &request_id,
                        started,
                    );
                    if let Ok(value) =
                        HeaderValue::from_str(&retry_after.as_secs().max(1).to_string())
                    {
                        response.headers_mut().insert("retry-after", value);
                    }
                    finish_response!(response);
                }
            }
        }

        let matched = match self.state.routes.find(&host, &path) {
            Some(matched) => matched,
            None => {
                self.observe_request(&context, StatusCode::NOT_FOUND, started, None, 0, 0);
                finish_response!(self.diagnostic_error_response(
                    StatusCode::NOT_FOUND,
                    ProxyErrorReason::RouteNotRegistered,
                    &domain,
                    &path,
                    &request_id,
                    started,
                ));
            }
        };

        if matched.route.rules.redirect_www_to_apex
            && matched.route.rules.www_alias
            && domain != matched.route.domain
            && domain
                .strip_prefix("www.")
                .is_some_and(|base| base == matched.route.domain)
        {
            let scheme = if matched.route.rules.redirect_http_to_https
                || matched.route.rules.require_https
            {
                "https"
            } else {
                scheme.as_str()
            };
            let mut location = format!("{scheme}://{}{}", matched.route.domain, path);
            if let Some(query) = &original_query {
                location.push('?');
                location.push_str(query);
            }
            self.observe_request(
                &context,
                StatusCode::PERMANENT_REDIRECT,
                started,
                None,
                0,
                0,
            );
            let mut response = response_with_body(
                StatusCode::PERMANENT_REDIRECT,
                "text/plain; charset=utf-8",
                String::new(),
            );
            if let Ok(value) = HeaderValue::from_str(&location) {
                response.headers_mut().insert(LOCATION, value);
            }
            finish_response!(response);
        }

        let request_origin = req.headers().get(ORIGIN).cloned();
        let request_accept_encoding = req.headers().get(ACCEPT_ENCODING).cloned();
        if let Some(rejection) = self.policy.evaluate(&req, &matched.route.rules, &context) {
            if rejection.status == StatusCode::TOO_MANY_REQUESTS {
                self.state
                    .metrics
                    .rate_limited_total
                    .with_label_values(&[&domain])
                    .inc();
            } else if rejection.status.is_client_error() || rejection.status.is_server_error() {
                self.state
                    .metrics
                    .blocked_total
                    .with_label_values(&[&domain, rejection.metric_reason])
                    .inc();
            }

            self.observe_request(&context, rejection.status, started, None, 0, 0);
            let mut response = if rejection.status == StatusCode::NO_CONTENT {
                response_with_body(rejection.status, "text/plain; charset=utf-8", String::new())
            } else {
                self.error_response(
                    rejection.status,
                    rejection.message,
                    &domain,
                    &path,
                    &request_id,
                    started,
                )
            };
            if let Some(location) = rejection.location {
                if let Ok(value) = HeaderValue::from_str(&location) {
                    response.headers_mut().insert(LOCATION, value);
                }
            }
            if let Some(retry_after) = rejection.retry_after {
                if let Ok(value) = HeaderValue::from_str(&retry_after.as_secs().max(1).to_string())
                {
                    response.headers_mut().insert("retry-after", value);
                }
            }
            self.policy.apply_response_rules(
                response.headers_mut(),
                &matched.route.rules,
                request_origin.as_ref(),
            );
            finish_response!(response);
        }

        let middleware =
            EffectiveMiddleware::from_rules(&matched.route.rules, &matched.path.middlewares);
        let mut edge_authorization_consumed = false;

        // Bandwidth limit check — async Redis lookup, non-blocking to hot path
        if let Some(limit_config) = &matched.route.rules.bandwidth_limit {
            if limit_config.enabled {
                if let Some(tracker) = &self.bandwidth_tracker {
                    let within_limit = tracker
                        .check_limit(
                            &domain,
                            limit_config.max_bytes_per_month,
                            limit_config.max_bytes_per_day,
                        )
                        .await
                        .unwrap_or(true); // fail open: if Redis is down, allow the request
                    if !within_limit {
                        let monthly_used = tracker.get_monthly_usage(&domain).await.unwrap_or(0);
                        let limit_bytes = limit_config
                            .max_bytes_per_month
                            .or(limit_config.max_bytes_per_day)
                            .unwrap_or(0);
                        let status_code = limit_config.exceeded_status_code.unwrap_or(509);
                        let status = StatusCode::from_u16(status_code)
                            .unwrap_or(StatusCode::TOO_MANY_REQUESTS);
                        self.observe_request(&context, status, started, None, 0, 0);
                        let mut response = self.error_pages.bandwidth_exceeded_response(
                            BandwidthExceededContext {
                                status,
                                domain: &domain,
                                path: &path,
                                request_id: &request_id,
                                processing_time_ms: started.elapsed().as_millis(),
                                bytes_used: monthly_used,
                                bytes_limit: limit_bytes,
                                reset_day: limit_config.reset_day_of_month,
                            },
                        );
                        attach_request_id_header(response.headers_mut(), &request_id);
                        return response;
                    }
                }
            }
        }

        if let Some(basic_auth) = &middleware.basic_auth {
            if let Some(response) =
                self.evaluate_basic_auth(&req, basic_auth, &domain, &path, &request_id, started)
            {
                self.state
                    .metrics
                    .middleware_executions_total
                    .with_label_values(&[&domain, "basic_auth", "rejected"])
                    .inc();
                self.observe_request(&context, response.status(), started, None, 0, 0);
                finish_response!(response);
            }
            self.state
                .metrics
                .middleware_executions_total
                .with_label_values(&[&domain, "basic_auth", "allowed"])
                .inc();
            edge_authorization_consumed |= basic_auth.enabled;
        }

        if let Some(digest_auth) = &middleware.digest_auth {
            if let Some(response) =
                self.evaluate_digest_auth(&req, digest_auth, &domain, &path, &request_id, started)
            {
                self.state
                    .metrics
                    .middleware_executions_total
                    .with_label_values(&[&domain, "digest_auth", "rejected"])
                    .inc();
                self.observe_request(&context, response.status(), started, None, 0, 0);
                finish_response!(response);
            }
            self.state
                .metrics
                .middleware_executions_total
                .with_label_values(&[&domain, "digest_auth", "allowed"])
                .inc();
            edge_authorization_consumed |= digest_auth.enabled;
        }

        if let Some(forward_auth) = &middleware.forward_auth {
            match self
                .run_forward_auth(&req, forward_auth, &matched.route.source)
                .await
            {
                Ok(true) => self
                    .state
                    .metrics
                    .middleware_executions_total
                    .with_label_values(&[&domain, "forward_auth", "allowed"])
                    .inc(),
                Ok(false) => {
                    self.state
                        .metrics
                        .middleware_executions_total
                        .with_label_values(&[&domain, "forward_auth", "rejected"])
                        .inc();
                    self.observe_request(&context, StatusCode::UNAUTHORIZED, started, None, 0, 0);
                    finish_response!(self.error_response(
                        StatusCode::UNAUTHORIZED,
                        "forward auth denied the request",
                        &domain,
                        &path,
                        &request_id,
                        started,
                    ));
                }
                Err(error) => {
                    warn!(%error, request_id = %request_id, domain = %domain, "forward auth request failed");
                    self.state
                        .metrics
                        .middleware_executions_total
                        .with_label_values(&[&domain, "forward_auth", "error"])
                        .inc();
                    self.observe_request(&context, StatusCode::BAD_GATEWAY, started, None, 0, 0);
                    finish_response!(self.error_response(
                        StatusCode::BAD_GATEWAY,
                        "forward auth request failed",
                        &domain,
                        &path,
                        &request_id,
                        started,
                    ));
                }
            }
        }

        let mut req = req;
        if edge_authorization_consumed {
            req.headers_mut().remove(AUTHORIZATION);
        }
        if let Ok(uri) = canonical_forward_uri(req.uri(), &path, original_query.as_deref()) {
            *req.uri_mut() = uri;
        }
        self.policy
            .apply_request_rules(req.headers_mut(), &matched.route.rules);
        if middleware.content_type_autodetect.enabled {
            let uri = req.uri().clone();
            apply_request_content_type_detection(req.headers_mut(), &uri, None);
        }

        if !requires_buffered_forwarding(&middleware, matched.route.rules.max_body_bytes.is_some())
        {
            ensure_trace_headers(req.headers_mut(), &request_id);
            let base_route_key = format!("{}:{}", matched.route.id, matched.path.prefix);
            let (route_key_suffix, upstreams) =
                self.select_upstream_pool(&base_route_key, &matched, &location);
            let route_key = format!("{base_route_key}{route_key_suffix}");

            let upstream = match self.select_available_upstream(
                &route_key,
                &matched,
                upstreams,
                remote_ip,
                req.headers(),
                &middleware,
            ) {
                Some(upstream) => upstream,
                None => {
                    self.observe_request(
                        &context,
                        StatusCode::SERVICE_UNAVAILABLE,
                        started,
                        None,
                        0,
                        0,
                    );
                    finish_response!(self.diagnostic_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        self.route_unavailable_reason(&matched, upstreams),
                        &domain,
                        &path,
                        &request_id,
                        started,
                    ));
                }
            };

            let in_flight_key = match self.policy.try_acquire_in_flight(
                &middleware.in_flight_limit,
                &matched,
                &upstream,
            ) {
                Ok(key) => key,
                Err(scope) => {
                    self.state
                        .metrics
                        .in_flight_limited_total
                        .with_label_values(&[&domain, scope])
                        .inc();
                    self.observe_request(
                        &context,
                        StatusCode::TOO_MANY_REQUESTS,
                        started,
                        None,
                        0,
                        0,
                    );
                    finish_response!(self.error_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        "too many in-flight requests",
                        &domain,
                        &path,
                        &request_id,
                        started,
                    ));
                }
            };

            self.state
                .load_balancer
                .begin_request(&route_key, &upstream.url);
            self.state
                .metrics
                .upstream_in_flight
                .with_label_values(&[
                    &domain,
                    &matched.route.id,
                    &matched.path.prefix,
                    &upstream.url,
                ])
                .inc();

            // Capture metadata before req is moved into forward_streaming.
            let req_content_length = content_length(req.headers()).unwrap_or(0);
            let is_upgrade_request = is_websocket_upgrade(req.headers());

            match self
                .forward_streaming(
                    req,
                    &ForwardContext {
                        matched: &matched,
                        upstream: &upstream,
                        remote_ip,
                        scheme,
                        middleware: &middleware,
                        domain: &domain,
                        client_cert_pem: client_cert_pem.as_deref(),
                    },
                    request_body_limit(&matched.route.rules, &middleware),
                )
                .await
            {
                Ok(mut response) => {
                    let status = response.status();
                    self.policy.release_in_flight(in_flight_key);
                    self.state.load_balancer.end_request(
                        &route_key,
                        &upstream.url,
                        started.elapsed().as_micros() as u64,
                    );
                    self.state
                        .metrics
                        .upstream_in_flight
                        .with_label_values(&[
                            &domain,
                            &matched.route.id,
                            &matched.path.prefix,
                            &upstream.url,
                        ])
                        .dec();
                    self.policy.record_passive_health(
                        &self.state,
                        &middleware.passive_health,
                        &domain,
                        &upstream.url,
                        status,
                        None,
                    );
                    self.policy.record_circuit_result(CircuitRecord {
                        config: &middleware.circuit_breaker,
                        domain: &domain,
                        route_id: &matched.route.id,
                        path_prefix: &matched.path.prefix,
                        upstream: &upstream.url,
                        status,
                        error: false,
                        state: &self.state,
                    });
                    self.policy.apply_response_rules(
                        response.headers_mut(),
                        &matched.route.rules,
                        request_origin.as_ref(),
                    );
                    apply_default_cache_headers(response.headers_mut(), context.path);
                    apply_sticky_cookie(
                        response.headers_mut(),
                        &middleware.sticky_sessions,
                        &upstream,
                    );
                    if !is_upgrade_request || status != StatusCode::SWITCHING_PROTOCOLS {
                        strip_hop_by_hop_response_headers(response.headers_mut());
                    }
                    let stream_bytes_sent = req_content_length;
                    let stream_bytes_received = content_length(response.headers()).unwrap_or(0);
                    self.observe_request(
                        &context,
                        status,
                        started,
                        Some(&upstream.url),
                        stream_bytes_sent,
                        stream_bytes_received,
                    );
                    self.state
                        .metrics
                        .upstream_latency_seconds
                        .with_label_values(&[&domain, &upstream.url])
                        .observe(started.elapsed().as_secs_f64());
                    self.state
                        .metrics
                        .router_request_duration_seconds
                        .with_label_values(&[
                            &domain,
                            &matched.route.id,
                            &matched.path.prefix,
                            &upstream.url,
                            &status.as_u16().to_string(),
                        ])
                        .observe(started.elapsed().as_secs_f64());
                    info!(
                        request_id = %request_id,
                        domain = %domain,
                        method = %method,
                        path = %path,
                        upstream = %upstream.url,
                        status = status.as_u16(),
                        latency_ms = started.elapsed().as_millis(),
                        "streamed proxied request"
                    );
                    finish_response!(response);
                }
                Err(error) => {
                    warn!(%error, request_id = %request_id, domain = %domain, upstream = %upstream.url, "streaming upstream request failed");
                    self.policy.release_in_flight(in_flight_key);
                    self.state.load_balancer.end_request(
                        &route_key,
                        &upstream.url,
                        started.elapsed().as_micros() as u64,
                    );
                    self.state
                        .metrics
                        .upstream_in_flight
                        .with_label_values(&[
                            &domain,
                            &matched.route.id,
                            &matched.path.prefix,
                            &upstream.url,
                        ])
                        .dec();
                    self.policy.record_passive_health(
                        &self.state,
                        &middleware.passive_health,
                        &domain,
                        &upstream.url,
                        StatusCode::BAD_GATEWAY,
                        Some(&error),
                    );
                    self.policy.record_circuit_result(CircuitRecord {
                        config: &middleware.circuit_breaker,
                        domain: &domain,
                        route_id: &matched.route.id,
                        path_prefix: &matched.path.prefix,
                        upstream: &upstream.url,
                        status: StatusCode::BAD_GATEWAY,
                        error: true,
                        state: &self.state,
                    });
                    self.observe_request(
                        &context,
                        StatusCode::BAD_GATEWAY,
                        started,
                        Some(&upstream.url),
                        0,
                        0,
                    );
                    finish_response!(self.diagnostic_error_response(
                        StatusCode::BAD_GATEWAY,
                        self.upstream_failure_reason(&error),
                        &domain,
                        &path,
                        &request_id,
                        started,
                    ));
                }
            }
        }

        let max_request_bytes = request_body_limit(&matched.route.rules, &middleware);
        let buffered_request = match BufferedRequest::from_request(req, max_request_bytes).await {
            Ok(mut request) => {
                ensure_trace_headers(&mut request.headers, &request_id);
                if middleware.content_type_autodetect.enabled {
                    apply_request_content_type_detection(
                        &mut request.headers,
                        &request.uri,
                        Some(&request.body),
                    );
                }
                request
            }
            Err(BufferError::TooLarge) => {
                self.observe_request(&context, StatusCode::PAYLOAD_TOO_LARGE, started, None, 0, 0);
                finish_response!(self.error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body is too large",
                    &domain,
                    &path,
                    &request_id,
                    started,
                ));
            }
            Err(BufferError::Body(error)) => {
                warn!(%error, request_id = %request_id, domain = %domain, "failed to buffer request body");
                self.observe_request(&context, StatusCode::BAD_REQUEST, started, None, 0, 0);
                finish_response!(self.error_response(
                    StatusCode::BAD_REQUEST,
                    "failed to read request body",
                    &domain,
                    &path,
                    &request_id,
                    started,
                ));
            }
        };

        let base_route_key = format!("{}:{}", matched.route.id, matched.path.prefix);
        let (route_key_suffix, upstreams) =
            self.select_upstream_pool(&base_route_key, &matched, &location);
        let route_key = format!("{base_route_key}{route_key_suffix}");

        self.mirror_request(
            buffered_request.clone(),
            &matched,
            &middleware.traffic_mirroring,
            &domain,
        );

        let upstream = match self.select_available_upstream(
            &route_key,
            &matched,
            upstreams,
            remote_ip,
            &buffered_request.headers,
            &middleware,
        ) {
            Some(upstream) => upstream,
            None => {
                self.observe_request(
                    &context,
                    StatusCode::SERVICE_UNAVAILABLE,
                    started,
                    None,
                    0,
                    0,
                );
                finish_response!(self.diagnostic_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    self.route_unavailable_reason(&matched, upstreams),
                    &domain,
                    &path,
                    &request_id,
                    started,
                ));
            }
        };

        let in_flight_key = match self.policy.try_acquire_in_flight(
            &middleware.in_flight_limit,
            &matched,
            &upstream,
        ) {
            Ok(key) => key,
            Err(scope) => {
                self.state
                    .metrics
                    .in_flight_limited_total
                    .with_label_values(&[&domain, scope])
                    .inc();
                self.observe_request(&context, StatusCode::TOO_MANY_REQUESTS, started, None, 0, 0);
                finish_response!(self.error_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many in-flight requests",
                    &domain,
                    &path,
                    &request_id,
                    started,
                ));
            }
        };

        self.state
            .load_balancer
            .begin_request(&route_key, &upstream.url);
        self.state
            .metrics
            .upstream_in_flight
            .with_label_values(&[
                &domain,
                &matched.route.id,
                &matched.path.prefix,
                &upstream.url,
            ])
            .inc();

        let request_body_len = buffered_request.body.len() as u64;
        match self
            .forward_with_retry(
                buffered_request,
                ForwardContext {
                    matched: &matched,
                    upstream: &upstream,
                    remote_ip,
                    scheme,
                    middleware: &middleware,
                    domain: &domain,
                    client_cert_pem: client_cert_pem.as_deref(),
                },
            )
            .await
        {
            Ok(mut response) => {
                let status = response.status;
                self.policy.release_in_flight(in_flight_key);
                self.state.load_balancer.end_request(
                    &route_key,
                    &upstream.url,
                    started.elapsed().as_micros() as u64,
                );
                self.state
                    .metrics
                    .upstream_in_flight
                    .with_label_values(&[
                        &domain,
                        &matched.route.id,
                        &matched.path.prefix,
                        &upstream.url,
                    ])
                    .dec();
                self.policy.record_passive_health(
                    &self.state,
                    &middleware.passive_health,
                    &domain,
                    &upstream.url,
                    status,
                    None,
                );
                self.policy.record_circuit_result(CircuitRecord {
                    config: &middleware.circuit_breaker,
                    domain: &domain,
                    route_id: &matched.route.id,
                    path_prefix: &matched.path.prefix,
                    upstream: &upstream.url,
                    status,
                    error: false,
                    state: &self.state,
                });
                self.policy.apply_response_rules(
                    &mut response.headers,
                    &matched.route.rules,
                    request_origin.as_ref(),
                );
                apply_default_cache_headers(&mut response.headers, context.path);
                apply_response_middleware(
                    &mut response,
                    &middleware,
                    accepts_gzip(request_accept_encoding.as_ref()),
                );
                apply_sticky_cookie(
                    &mut response.headers,
                    &middleware.sticky_sessions,
                    &upstream,
                );
                self.observe_request(
                    &context,
                    status,
                    started,
                    Some(&upstream.url),
                    request_body_len,
                    response.body.len() as u64,
                );
                self.state
                    .metrics
                    .upstream_latency_seconds
                    .with_label_values(&[&domain, &upstream.url])
                    .observe(started.elapsed().as_secs_f64());
                self.state
                    .metrics
                    .router_request_duration_seconds
                    .with_label_values(&[
                        &domain,
                        &matched.route.id,
                        &matched.path.prefix,
                        &upstream.url,
                        &status.as_u16().to_string(),
                    ])
                    .observe(started.elapsed().as_secs_f64());
                info!(
                    request_id = %request_id,
                    domain = %domain,
                    method = %method,
                    path = %path,
                    upstream = %upstream.url,
                    status = status.as_u16(),
                    latency_ms = started.elapsed().as_millis(),
                    "proxied request"
                );
                finish_response!(response.into_response());
            }
            Err(error) => {
                warn!(%error, request_id = %request_id, domain = %domain, upstream = %upstream.url, "upstream request failed");
                self.policy.release_in_flight(in_flight_key);
                self.state.load_balancer.end_request(
                    &route_key,
                    &upstream.url,
                    started.elapsed().as_micros() as u64,
                );
                self.state
                    .metrics
                    .upstream_in_flight
                    .with_label_values(&[
                        &domain,
                        &matched.route.id,
                        &matched.path.prefix,
                        &upstream.url,
                    ])
                    .dec();
                self.policy.record_passive_health(
                    &self.state,
                    &middleware.passive_health,
                    &domain,
                    &upstream.url,
                    StatusCode::BAD_GATEWAY,
                    Some(&error),
                );
                self.policy.record_circuit_result(CircuitRecord {
                    config: &middleware.circuit_breaker,
                    domain: &domain,
                    route_id: &matched.route.id,
                    path_prefix: &matched.path.prefix,
                    upstream: &upstream.url,
                    status: StatusCode::BAD_GATEWAY,
                    error: true,
                    state: &self.state,
                });
                self.observe_request(
                    &context,
                    StatusCode::BAD_GATEWAY,
                    started,
                    Some(&upstream.url),
                    0,
                    0,
                );
                finish_response!(self.diagnostic_error_response(
                    StatusCode::BAD_GATEWAY,
                    self.upstream_failure_reason(&error),
                    &domain,
                    &path,
                    &request_id,
                    started,
                ));
            }
        }
    }

    async fn forward_with_retry(
        &self,
        request: BufferedRequest,
        context: ForwardContext<'_>,
    ) -> Result<BufferedResponse, PxxlError> {
        let attempts = if context.middleware.retry.enabled {
            context.middleware.retry.attempts.max(1)
        } else {
            1
        };
        let mut last_error = None;

        for attempt in 1..=attempts {
            match self.forward_buffered(&request, &context).await {
                Ok(response)
                    if attempt < attempts
                        && retryable_status(response.status, &context.middleware.retry) =>
                {
                    self.state
                        .metrics
                        .retries_total
                        .with_label_values(&[context.domain, &context.upstream.url, "status"])
                        .inc();
                    tokio::time::sleep(Duration::from_millis(context.middleware.retry.backoff_ms))
                        .await;
                    continue;
                }
                Ok(response) => return Ok(response),
                Err(error) if attempt < attempts => {
                    self.state
                        .metrics
                        .retries_total
                        .with_label_values(&[context.domain, &context.upstream.url, "error"])
                        .inc();
                    last_error = Some(error);
                    tokio::time::sleep(Duration::from_millis(context.middleware.retry.backoff_ms))
                        .await;
                }
                Err(error) => return Err(error),
            }
        }

        Err(last_error.unwrap_or_else(|| PxxlError::InvalidUpstream(context.upstream.url.clone())))
    }

    async fn forward_buffered(
        &self,
        request: &BufferedRequest,
        context: &ForwardContext<'_>,
    ) -> Result<BufferedResponse, PxxlError> {
        ensure_runtime_upstream_allowed(&context.matched.route.source, &context.upstream.url)
            .await?;
        let mut req = request.to_request(context.upstream)?;

        if !context.matched.route.rules.preserve_host_header {
            let authority = context.upstream.authority()?;
            req.headers_mut().insert(
                HOST,
                HeaderValue::from_str(&authority)
                    .map_err(|_| PxxlError::InvalidUpstream(context.upstream.url.clone()))?,
            );
        }
        req.headers_mut().insert(
            HeaderName::from_static("x-forwarded-host"),
            HeaderValue::from_str(&context.matched.route.domain)
                .map_err(|_| PxxlError::InvalidHost)?,
        );
        req.headers_mut().insert(
            HeaderName::from_static("x-forwarded-proto"),
            HeaderValue::from_static(context.scheme.as_str()),
        );
        if let Some(ip) = context.remote_ip {
            if let Ok(value) = HeaderValue::from_str(&ip.to_string()) {
                req.headers_mut()
                    .insert(HeaderName::from_static("x-forwarded-for"), value);
            }
        }
        if context.middleware.client_cert_forwarding.enabled {
            if let (Some(cert), Ok(name)) = (
                context.client_cert_pem,
                HeaderName::from_bytes(
                    context
                        .middleware
                        .client_cert_forwarding
                        .header_name
                        .as_bytes(),
                ),
            ) {
                if let Ok(value) = HeaderValue::from_str(cert) {
                    req.headers_mut().insert(name, value);
                }
            }
        }

        let response = self
            .client
            .request(req)
            .await
            .map_err(|_| PxxlError::InvalidUpstream(context.upstream.url.clone()))?;
        BufferedResponse::from_response(
            response,
            context.middleware.response_buffering.max_response_bytes,
        )
        .await
        .map_err(|_| PxxlError::InvalidUpstream(context.upstream.url.clone()))
    }

    async fn forward_streaming(
        &self,
        mut req: Request<Incoming>,
        context: &ForwardContext<'_>,
        max_request_bytes: u64,
    ) -> Result<Response<BoxBody>, PxxlError> {
        ensure_runtime_upstream_allowed(&context.matched.route.source, &context.upstream.url)
            .await?;
        let websocket_upgrade = is_websocket_upgrade(req.headers());
        let downstream_upgrade = websocket_upgrade.then(|| hyper::upgrade::on(&mut req));
        let (parts, body) = req.into_parts();
        let limited_body = Limited::new(body, limit_to_usize(max_request_bytes)).boxed();
        let mut req = Request::from_parts(parts, limited_body);
        *req.version_mut() = Version::HTTP_11;
        let upstream_uri = build_upstream_uri(context.upstream, req.uri())?;
        *req.uri_mut() = upstream_uri;
        strip_forwarded_request_headers(req.headers_mut());
        if websocket_upgrade {
            preserve_websocket_upgrade_headers(req.headers_mut());
        }

        if !context.matched.route.rules.preserve_host_header {
            let authority = context.upstream.authority()?;
            req.headers_mut().insert(
                HOST,
                HeaderValue::from_str(&authority)
                    .map_err(|_| PxxlError::InvalidUpstream(context.upstream.url.clone()))?,
            );
        }
        req.headers_mut().insert(
            HeaderName::from_static("x-forwarded-host"),
            HeaderValue::from_str(&context.matched.route.domain)
                .map_err(|_| PxxlError::InvalidHost)?,
        );
        req.headers_mut().insert(
            HeaderName::from_static("x-forwarded-proto"),
            HeaderValue::from_static(context.scheme.as_str()),
        );
        if let Some(ip) = context.remote_ip {
            if let Ok(value) = HeaderValue::from_str(&ip.to_string()) {
                req.headers_mut()
                    .insert(HeaderName::from_static("x-forwarded-for"), value);
            }
        }
        if context.middleware.client_cert_forwarding.enabled {
            if let (Some(cert), Ok(name)) = (
                context.client_cert_pem,
                HeaderName::from_bytes(
                    context
                        .middleware
                        .client_cert_forwarding
                        .header_name
                        .as_bytes(),
                ),
            ) {
                if let Ok(value) = HeaderValue::from_str(cert) {
                    req.headers_mut().insert(name, value);
                }
            }
        }

        let response = self
            .client
            .request(req)
            .await
            .map_err(|_| PxxlError::InvalidUpstream(context.upstream.url.clone()))?;

        if websocket_upgrade && response.status() == StatusCode::SWITCHING_PROTOCOLS {
            let mut response = response.map(|body| {
                body.map_err(|error| -> BoxError { Box::new(error) })
                    .boxed()
            });
            let upstream_upgrade = hyper::upgrade::on(&mut response);
            if let Some(downstream_upgrade) = downstream_upgrade {
                let upstream_url = context.upstream.url.clone();
                tokio::spawn(async move {
                    match tokio::try_join!(downstream_upgrade, upstream_upgrade) {
                        Ok((downstream, upstream)) => {
                            let mut downstream = TokioIo::new(downstream);
                            let mut upstream = TokioIo::new(upstream);
                            if let Err(error) =
                                tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await
                            {
                                debug!(%error, upstream = %upstream_url, "websocket tunnel closed");
                            }
                        }
                        Err(error) => {
                            debug!(%error, upstream = %upstream_url, "websocket upgrade failed");
                        }
                    }
                });
            }
            return Ok(response);
        }

        let (parts, body) = response.into_parts();
        let body = Limited::new(
            body,
            limit_to_usize(context.middleware.response_buffering.max_response_bytes),
        )
        .boxed();
        let mut response = Response::from_parts(parts, body);
        strip_hop_by_hop_response_headers(response.headers_mut());
        Ok(response)
    }

    fn error_response(
        &self,
        status: StatusCode,
        message: &str,
        domain: &str,
        path: &str,
        request_id: &str,
        started: Instant,
    ) -> Response<BoxBody> {
        self.error_pages.response(
            status,
            message,
            domain,
            path,
            request_id,
            started.elapsed().as_millis(),
        )
    }

    fn diagnostic_error_response(
        &self,
        status: StatusCode,
        reason: ProxyErrorReason,
        domain: &str,
        path: &str,
        request_id: &str,
        started: Instant,
    ) -> Response<BoxBody> {
        self.error_pages.response_with_reason(
            status,
            reason,
            domain,
            path,
            request_id,
            started.elapsed().as_millis(),
        )
    }

    fn route_unavailable_reason(
        &self,
        matched: &RouteMatch,
        upstreams: &[Upstream],
    ) -> ProxyErrorReason {
        if upstreams.is_empty() {
            return ProxyErrorReason::RouteHasNoUpstreams;
        }

        let healthy_count = upstreams.iter().filter(|upstream| upstream.healthy).count();
        if healthy_count == 0 {
            return ProxyErrorReason::AllUpstreamsUnhealthy;
        }

        let all_healthy_upstreams_blocked_by_circuit = upstreams
            .iter()
            .filter(|upstream| upstream.healthy)
            .all(|upstream| {
                self.policy
                    .circuit_is_open(&matched.route.id, &matched.path.prefix, &upstream.url)
            });
        if all_healthy_upstreams_blocked_by_circuit {
            ProxyErrorReason::CircuitBreakerOpen
        } else {
            ProxyErrorReason::AllUpstreamsUnhealthy
        }
    }

    fn upstream_failure_reason(&self, error: &PxxlError) -> ProxyErrorReason {
        match error {
            PxxlError::InvalidUpstream(_) => ProxyErrorReason::UpstreamTcpUnreachable,
            _ => ProxyErrorReason::ProxyInternal,
        }
    }

    fn observe_request(
        &self,
        context: &ProxyRequestContext<'_>,
        status: StatusCode,
        started: Instant,
        upstream: Option<&str>,
        bytes_sent: u64,
        bytes_received: u64,
    ) {
        self.state
            .metrics
            .requests_total
            .with_label_values(&[context.domain, context.method, &status.as_u16().to_string()])
            .inc();
        self.state.stats.record(RequestObservation {
            request_id: context.request_id.to_string(),
            domain: context.domain.to_string(),
            method: context.method.to_string(),
            path: context.path.to_string(),
            status: status.as_u16(),
            latency_ms: started.elapsed().as_millis() as u64,
            upstream: upstream.map(str::to_string),
            remote_ip: context.remote_ip,
            location: context.location.clone(),
            timestamp_unix_ms: context.timestamp_unix_ms,
            bytes_sent,
            bytes_received,
        });
        if let Some(ip) = context.remote_ip {
            let adaptive_blocker = self.state.security.adaptive_blocker();
            if let Some(block) = self.state.security.record_request(RequestObservationInput {
                ip,
                domain: context.domain,
                path: context.path,
                status: status.as_u16(),
                timestamp_unix_ms: context.timestamp_unix_ms,
            }) {
                self.state
                    .metrics
                    .adaptive_blocks_total
                    .with_label_values(&[&block.reason])
                    .inc();
            }
            self.state
                .metrics
                .adaptive_active_blocks
                .set(adaptive_blocker.active_block_count() as i64);
            self.state
                .metrics
                .adaptive_observed_ips
                .set(adaptive_blocker.observed_ip_count() as i64);
        }
    }

    fn select_upstream_pool<'a>(
        &self,
        base_route_key: &str,
        matched: &'a RouteMatch,
        location: &GeoLocation,
    ) -> (String, &'a [Upstream]) {
        let traffic_splits = self
            .policy
            .matching_traffic_splits(&matched.route.rules, location);
        if !traffic_splits.is_empty() {
            let weights = traffic_splits
                .iter()
                .map(|split| split.weight)
                .collect::<Vec<_>>();
            if let Some(index) = self
                .state
                .load_balancer
                .select_weighted_index(&format!("{base_route_key}:traffic_split"), &weights)
            {
                if let Some(split) = traffic_splits.get(index) {
                    let name = split
                        .name
                        .clone()
                        .unwrap_or_else(|| format!("weighted-{index}"));
                    return (format!(":split:{name}"), split.upstreams.as_slice());
                }
            }
        }

        self.policy
            .location_upstreams(&matched.route.rules, location)
            .map(|(name, upstreams)| (format!(":location:{name}"), upstreams))
            .unwrap_or_else(|| (String::new(), matched.path.upstreams.as_slice()))
    }

    fn select_available_upstream(
        &self,
        route_key: &str,
        matched: &RouteMatch,
        upstreams: &[Upstream],
        remote_ip: Option<IpAddr>,
        headers: &HeaderMap,
        middleware: &EffectiveMiddleware,
    ) -> Option<Upstream> {
        if let Some(upstream) = sticky_upstream(headers, upstreams, &middleware.sticky_sessions) {
            if upstream.healthy
                && !self.policy.circuit_is_open(
                    &matched.route.id,
                    &matched.path.prefix,
                    &upstream.url,
                )
            {
                return Some(upstream);
            }
        }

        let primary = upstreams
            .iter()
            .filter(|upstream| {
                !upstream.backup
                    && upstream.healthy
                    && !self.policy.circuit_is_open(
                        &matched.route.id,
                        &matched.path.prefix,
                        &upstream.url,
                    )
            })
            .cloned()
            .collect::<Vec<_>>();
        if let Some(upstream) = self.state.load_balancer.select(
            route_key,
            &matched.route.algorithm,
            &primary,
            remote_ip,
        ) {
            return Some(upstream);
        }

        let backup = upstreams
            .iter()
            .filter(|upstream| {
                upstream.backup
                    && upstream.healthy
                    && !self.policy.circuit_is_open(
                        &matched.route.id,
                        &matched.path.prefix,
                        &upstream.url,
                    )
            })
            .cloned()
            .collect::<Vec<_>>();
        self.state
            .load_balancer
            .select(route_key, &matched.route.algorithm, &backup, remote_ip)
    }

    fn evaluate_basic_auth(
        &self,
        req: &Request<Incoming>,
        config: &BasicAuthConfig,
        domain: &str,
        path: &str,
        request_id: &str,
        started: Instant,
    ) -> Option<Response<BoxBody>> {
        if !config.enabled {
            return None;
        }
        let authorized = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Basic "))
            .and_then(|encoded| {
                base64::engine::general_purpose::STANDARD
                    .decode(encoded.trim())
                    .ok()
            })
            .and_then(|decoded| String::from_utf8(decoded).ok())
            .and_then(|decoded| {
                decoded
                    .split_once(':')
                    .map(|(user, pass)| (user.to_string(), pass.to_string()))
            })
            .is_some_and(|(user, pass)| {
                config
                    .users
                    .get(&user)
                    .is_some_and(|expected| expected == &pass)
            });

        if authorized {
            return None;
        }

        let mut response = self.error_response(
            StatusCode::UNAUTHORIZED,
            "authentication required",
            domain,
            path,
            request_id,
            started,
        );
        if let Ok(value) = HeaderValue::from_str(&format!("Basic realm=\"{}\"", config.realm)) {
            response.headers_mut().insert(WWW_AUTHENTICATE, value);
        }
        Some(response)
    }

    fn evaluate_digest_auth(
        &self,
        req: &Request<Incoming>,
        config: &DigestAuthConfig,
        domain: &str,
        path: &str,
        request_id: &str,
        started: Instant,
    ) -> Option<Response<BoxBody>> {
        if !config.enabled {
            return None;
        }
        let authorized = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Digest "))
            .map(parse_digest_authorization)
            .is_some_and(|params| {
                let actual_uri = digest_request_uri(req, path);
                digest_authorized(DigestAuthCheck {
                    method: req.method(),
                    realm: &config.realm,
                    users: &config.users,
                    params: &params,
                    actual_uri: &actual_uri,
                    secret: &self.policy.digest_secret,
                    replays: &self.policy.digest_replays,
                })
            });

        if authorized {
            return None;
        }

        let nonce = digest_nonce(&self.policy.digest_secret, &config.realm, now_unix_ms());
        let mut response = self.error_response(
            StatusCode::UNAUTHORIZED,
            "digest authentication required",
            domain,
            path,
            request_id,
            started,
        );
        if let Ok(value) = HeaderValue::from_str(&format!(
            "Digest realm=\"{}\", qop=\"auth\", algorithm=SHA-256, nonce=\"{}\"",
            config.realm, nonce
        )) {
            response.headers_mut().insert(WWW_AUTHENTICATE, value);
        }
        Some(response)
    }

    async fn run_forward_auth(
        &self,
        req: &Request<Incoming>,
        config: &ForwardAuthConfig,
        source: &RouteSource,
    ) -> Result<bool, PxxlError> {
        if !config.enabled {
            return Ok(true);
        }
        ensure_runtime_upstream_allowed(source, &config.url).await?;
        let mut builder = Request::builder().method(Method::GET).uri(&config.url);
        for header in &config.request_headers {
            if let Ok(name) = HeaderName::from_bytes(header.as_bytes()) {
                if let Some(value) = req.headers().get(&name) {
                    builder = builder.header(name, value.clone());
                } else if name.as_str().eq_ignore_ascii_case("x-forwarded-host") {
                    if let Some(value) = req.headers().get(HOST) {
                        builder = builder.header(name, value.clone());
                    }
                }
            }
        }
        let request = builder
            .body(boxed_full(Bytes::new()))
            .map_err(|_| PxxlError::InvalidUpstream(config.url.clone()))?;
        let response = self
            .client
            .request(request)
            .await
            .map_err(|_| PxxlError::InvalidUpstream(config.url.clone()))?;
        Ok(response.status().is_success())
    }

    fn mirror_request(
        &self,
        request: BufferedRequest,
        matched: &RouteMatch,
        mirror: &TrafficMirrorConfig,
        domain: &str,
    ) {
        if !mirror.enabled || mirror.upstreams.is_empty() || mirror.percent == 0 {
            return;
        }
        for upstream in mirror.upstreams.iter().filter(|upstream| upstream.healthy) {
            if !mirror_should_run(domain, &request.uri, &upstream.url, mirror.percent) {
                continue;
            }
            let server = self.clone();
            let request = request.clone();
            let matched = matched.clone();
            let upstream = upstream.clone();
            let domain = domain.to_string();
            tokio::spawn(async move {
                let middleware = EffectiveMiddleware::from_rules(&matched.route.rules, &[]);
                let context = ForwardContext {
                    matched: &matched,
                    upstream: &upstream,
                    remote_ip: None,
                    scheme: RequestScheme::Http,
                    middleware: &middleware,
                    domain: &domain,
                    client_cert_pem: None,
                };
                let result = server.forward_buffered(&request, &context).await;
                let label = if result.is_ok() { "ok" } else { "error" };
                server
                    .state
                    .metrics
                    .mirror_requests_total
                    .with_label_values(&[&domain, &upstream.url, label])
                    .inc();
            });
        }
    }
}

#[derive(Debug, Clone)]
struct BufferedRequest {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
}

impl BufferedRequest {
    async fn from_request(req: Request<Incoming>, max_bytes: u64) -> Result<Self, BufferError> {
        let (parts, body) = req.into_parts();
        let body = collect_body_with_limit(body, max_bytes).await?;
        Ok(Self {
            method: parts.method,
            uri: parts.uri,
            headers: parts.headers,
            body,
        })
    }

    fn to_request(&self, upstream: &Upstream) -> Result<Request<BoxBody>, PxxlError> {
        let mut request = Request::builder()
            .method(self.method.clone())
            .uri(build_upstream_uri(upstream, &self.uri)?)
            .body(boxed_full(self.body.clone()))
            .map_err(|_| PxxlError::InvalidUpstream(upstream.url.clone()))?;
        *request.headers_mut() = self.headers.clone();
        strip_forwarded_request_headers(request.headers_mut());
        if let Ok(length) = HeaderValue::from_str(&self.body.len().to_string()) {
            request.headers_mut().insert(CONTENT_LENGTH, length);
        }
        Ok(request)
    }
}

#[derive(Debug)]
struct BufferedResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl BufferedResponse {
    async fn from_response(
        response: Response<Incoming>,
        max_bytes: u64,
    ) -> Result<Self, BufferError> {
        let (parts, body) = response.into_parts();
        let body = collect_body_with_limit(body, max_bytes).await?;
        Ok(Self {
            status: parts.status,
            headers: parts.headers,
            body,
        })
    }

    fn into_response(self) -> Response<BoxBody> {
        let body = Full::new(self.body).map_err(|never| match never {}).boxed();
        let mut response = Response::new(body);
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;
        strip_hop_by_hop_response_headers(response.headers_mut());
        response
    }
}

#[derive(Debug)]
enum BufferError {
    TooLarge,
    Body(String),
}

pub fn build_upstream_uri(upstream: &Upstream, original: &Uri) -> Result<Uri, PxxlError> {
    let path_and_query = original
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let target = format!("{}{}", upstream.url.trim_end_matches('/'), path_and_query);
    target
        .parse::<Uri>()
        .map_err(|_| PxxlError::InvalidUpstream(upstream.url.clone()))
}

async fn ensure_runtime_upstream_allowed(source: &RouteSource, raw: &str) -> Result<(), PxxlError> {
    if *source != RouteSource::Api {
        return Ok(());
    }
    if runtime_upstream_network_allowed(raw).await {
        Ok(())
    } else {
        Err(PxxlError::InvalidUpstream(raw.to_string()))
    }
}

async fn runtime_upstream_network_allowed(raw: &str) -> bool {
    let Ok(parsed) = url::Url::parse(raw) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if reserved_host_gateway(&host) {
        return host_gateway_upstreams_allowed();
    }
    if private_upstreams_allowed() {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip_allowed_for_upstream(ip);
    }
    let Some(port) = parsed.port_or_known_default() else {
        return false;
    };
    let lookup = time::timeout(
        Duration::from_secs(2),
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await;
    match lookup {
        Ok(Ok(addresses)) => addresses
            .into_iter()
            .all(|address| ip_allowed_for_upstream(address.ip())),
        Ok(Err(_)) | Err(_) => true,
    }
}

fn reserved_host_gateway(host: &str) -> bool {
    matches!(host, "host.docker.internal" | "gateway.docker.internal")
}

fn host_gateway_upstreams_allowed() -> bool {
    std::env::var("PXXL_ALLOW_HOST_GATEWAY_UPSTREAMS")
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn private_upstreams_allowed() -> bool {
    std::env::var("PXXL_ALLOW_PRIVATE_UPSTREAMS")
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn canonical_forward_uri(
    original: &Uri,
    canonical_path: &str,
    query: Option<&str>,
) -> Result<Uri, PxxlError> {
    let path_and_query = match query {
        Some(query) if !query.is_empty() => format!("{canonical_path}?{query}"),
        _ => canonical_path.to_string(),
    };
    let _ = original;
    path_and_query
        .parse::<Uri>()
        .map_err(|_| PxxlError::InvalidPath(canonical_path.to_string()))
}

fn strip_forwarded_request_headers(headers: &mut HeaderMap) {
    let connection_tokens = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(',').map(str::trim).map(str::to_string))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();

    for token in connection_tokens {
        if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
            headers.remove(name);
        }
    }

    for name in [
        "connection",
        "host",
        "upgrade",
        "te",
        "trailer",
        "proxy-authorization",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-prefix",
        "x-real-ip",
        "x-original-url",
        "x-rewrite-url",
        "x-client-ip",
    ] {
        headers.remove(HeaderName::from_static(name));
    }
}

fn resolve_effective_client_ip(
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    trusted: &TrustedClientIpConfig,
) -> Option<IpAddr> {
    let peer_ip = peer_ip?;
    if !trusted.trusted_peer(peer_ip) {
        return Some(peer_ip);
    }
    forwarded_client_ip(headers).or(Some(peer_ip))
}

fn forwarded_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    for name in ["cf-connecting-ip", "x-real-ip", "true-client-ip"] {
        if let Some(ip) = headers
            .get(HeaderName::from_static(name))
            .and_then(|value| value.to_str().ok())
            .and_then(parse_forwarded_ip_value)
        {
            return Some(ip);
        }
    }

    if let Some(ip) = headers
        .get(HeaderName::from_static("x-forwarded-for"))
        .and_then(|value| value.to_str().ok())
        .and_then(parse_x_forwarded_for)
    {
        return Some(ip);
    }

    headers
        .get(HeaderName::from_static("forwarded"))
        .and_then(|value| value.to_str().ok())
        .and_then(parse_forwarded_header)
}

fn parse_x_forwarded_for(value: &str) -> Option<IpAddr> {
    value.split(',').find_map(parse_forwarded_ip_value)
}

fn parse_forwarded_header(value: &str) -> Option<IpAddr> {
    for segment in value.split(',') {
        for pair in segment.split(';') {
            let pair = pair.trim();
            let Some((name, raw_value)) = pair.split_once('=') else {
                continue;
            };
            if !name.trim().eq_ignore_ascii_case("for") {
                continue;
            }
            if let Some(ip) = parse_forwarded_ip_value(raw_value) {
                return Some(ip);
            }
        }
    }
    None
}

fn parse_forwarded_ip_value(value: &str) -> Option<IpAddr> {
    let mut value = value
        .trim()
        .trim_matches('"')
        .trim_matches('[')
        .trim_matches(']');
    if value.is_empty() || value.eq_ignore_ascii_case("unknown") || value.starts_with('_') {
        return None;
    }

    if let Ok(ip) = value.parse::<IpAddr>() {
        return is_public_client_ip(ip).then_some(ip);
    }

    if let Some((host, _port)) = value.rsplit_once(':') {
        value = host.trim().trim_matches('[').trim_matches(']');
        if let Ok(ip) = value.parse::<IpAddr>() {
            return is_public_client_ip(ip).then_some(ip);
        }
    }

    None
}

fn is_public_client_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && !ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            let first = segments[0];
            let unique_local = (first & 0xfe00) == 0xfc00;
            let link_local = (first & 0xffc0) == 0xfe80;
            !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_unspecified()
                && !unique_local
                && !link_local
        }
    }
}

fn preserve_websocket_upgrade_headers(headers: &mut HeaderMap) {
    headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
}

fn strip_hop_by_hop_response_headers(headers: &mut HeaderMap) {
    let connection_tokens = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(',').map(str::trim).map(str::to_string))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();

    for token in connection_tokens {
        if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
            headers.remove(name);
        }
    }

    for name in [
        "connection",
        "host",
        "upgrade",
        "te",
        "trailer",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
    ] {
        headers.remove(HeaderName::from_static(name));
    }
}

pub async fn run_http_proxy(
    addr: SocketAddr,
    state: EdgeState,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    run_http_proxy_with_error_pages(addr, state, ErrorPageRenderer::default(), shutdown).await
}

pub async fn run_http_proxy_with_error_pages(
    addr: SocketAddr,
    state: EdgeState,
    error_pages: ErrorPageRenderer,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    run_http_proxy_with_error_pages_and_policy(
        addr,
        state,
        error_pages,
        PolicyEnforcer::default(),
        shutdown,
    )
    .await
}

pub async fn run_http_proxy_with_error_pages_and_policy(
    addr: SocketAddr,
    state: EdgeState,
    error_pages: ErrorPageRenderer,
    policy: PolicyEnforcer,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    run_http_proxy_with_error_pages_policy_and_geoip(
        addr,
        state,
        error_pages,
        policy,
        GeoIpResolver::default(),
        shutdown,
    )
    .await
}

pub async fn run_http_proxy_with_error_pages_policy_and_geoip(
    addr: SocketAddr,
    state: EdgeState,
    error_pages: ErrorPageRenderer,
    policy: PolicyEnforcer,
    geoip: GeoIpResolver,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "HTTP proxy listening");
    run_plain_listener(listener, state, error_pages, policy, geoip, shutdown).await
}

pub async fn run_http_proxy_on_listener(
    listener: TcpListener,
    state: EdgeState,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    run_http_proxy_on_listener_with_error_pages(
        listener,
        state,
        ErrorPageRenderer::default(),
        shutdown,
    )
    .await
}

pub async fn run_http_proxy_on_listener_with_error_pages(
    listener: TcpListener,
    state: EdgeState,
    error_pages: ErrorPageRenderer,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    run_http_proxy_on_listener_with_error_pages_and_policy(
        listener,
        state,
        error_pages,
        PolicyEnforcer::default(),
        shutdown,
    )
    .await
}

pub async fn run_http_proxy_on_listener_with_error_pages_and_policy(
    listener: TcpListener,
    state: EdgeState,
    error_pages: ErrorPageRenderer,
    policy: PolicyEnforcer,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    run_http_proxy_on_listener_with_error_pages_policy_and_geoip(
        listener,
        state,
        error_pages,
        policy,
        GeoIpResolver::default(),
        shutdown,
    )
    .await
}

pub async fn run_http_proxy_on_listener_with_error_pages_policy_and_geoip(
    listener: TcpListener,
    state: EdgeState,
    error_pages: ErrorPageRenderer,
    policy: PolicyEnforcer,
    geoip: GeoIpResolver,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    info!(addr = %listener.local_addr()?, "HTTP proxy listening");
    run_plain_listener(listener, state, error_pages, policy, geoip, shutdown).await
}

pub async fn run_https_proxy(
    addr: SocketAddr,
    state: EdgeState,
    tls_config: Arc<ServerConfig>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    run_https_proxy_with_error_pages(
        addr,
        state,
        tls_config,
        ErrorPageRenderer::default(),
        shutdown,
    )
    .await
}

pub async fn run_https_proxy_with_error_pages(
    addr: SocketAddr,
    state: EdgeState,
    tls_config: Arc<ServerConfig>,
    error_pages: ErrorPageRenderer,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    run_https_proxy_with_error_pages_and_policy(
        addr,
        state,
        tls_config,
        error_pages,
        PolicyEnforcer::default(),
        shutdown,
    )
    .await
}

pub async fn run_https_proxy_with_error_pages_and_policy(
    addr: SocketAddr,
    state: EdgeState,
    tls_config: Arc<ServerConfig>,
    error_pages: ErrorPageRenderer,
    policy: PolicyEnforcer,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    run_https_proxy_with_error_pages_policy_and_geoip(
        addr,
        state,
        tls_config,
        error_pages,
        policy,
        GeoIpResolver::default(),
        shutdown,
    )
    .await
}

pub async fn run_https_proxy_with_error_pages_policy_and_geoip(
    addr: SocketAddr,
    state: EdgeState,
    tls_config: Arc<ServerConfig>,
    error_pages: ErrorPageRenderer,
    policy: PolicyEnforcer,
    geoip: GeoIpResolver,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    run_https_proxy_with_reloadable_error_pages_policy_and_geoip(
        addr,
        state,
        ReloadableTlsConfig::new(tls_config),
        error_pages,
        policy,
        geoip,
        shutdown,
    )
    .await
}

pub async fn run_https_proxy_with_reloadable_error_pages_policy_and_geoip(
    addr: SocketAddr,
    state: EdgeState,
    tls_config: ReloadableTlsConfig,
    error_pages: ErrorPageRenderer,
    policy: PolicyEnforcer,
    geoip: GeoIpResolver,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "HTTPS proxy listening");
    run_tls_listener(
        listener,
        tls_config,
        state,
        error_pages,
        policy,
        geoip,
        shutdown,
    )
    .await
}

async fn run_plain_listener(
    listener: TcpListener,
    state: EdgeState,
    error_pages: ErrorPageRenderer,
    policy: PolicyEnforcer,
    geoip: GeoIpResolver,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let server = ProxyServer::with_error_pages_policy_and_geoip(state, error_pages, policy, geoip);
    let limiter = Arc::new(Semaphore::new(EDGE_MAX_CONNECTIONS));

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let Ok(permit) = limiter.clone().try_acquire_owned() else {
                    debug!(peer = %peer, "edge HTTP connection limit reached");
                    continue;
                };
                spawn_connection(stream, peer, server.clone(), RequestScheme::Http, permit);
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    info!("stopping HTTP listener");
                    break;
                }
            }
        }
    }

    Ok(())
}

async fn run_tls_listener(
    listener: TcpListener,
    tls_config: ReloadableTlsConfig,
    state: EdgeState,
    error_pages: ErrorPageRenderer,
    policy: PolicyEnforcer,
    geoip: GeoIpResolver,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let server = ProxyServer::with_error_pages_policy_and_geoip(state, error_pages, policy, geoip);
    let limiter = Arc::new(Semaphore::new(EDGE_MAX_CONNECTIONS));

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let Ok(permit) = limiter.clone().try_acquire_owned() else {
                    debug!(peer = %peer, "edge HTTPS connection limit reached");
                    continue;
                };
                let acceptor = TlsAcceptor::from(tls_config.load());
                let server = server.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let client_cert = peer_certificate_pem(&tls_stream);
                            serve_stream(tls_stream, peer, server, RequestScheme::Https, client_cert).await
                        },
                        Err(error) => warn!(%error, "TLS handshake failed"),
                    }
                });
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    info!("stopping HTTPS listener");
                    break;
                }
            }
        }
    }

    Ok(())
}

fn spawn_connection(
    stream: TcpStream,
    peer: SocketAddr,
    server: ProxyServer,
    scheme: RequestScheme,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    tokio::spawn(async move {
        let _permit = permit;
        serve_stream(stream, peer, server, scheme, None).await;
    });
}

fn peer_certificate_pem<S>(stream: &TlsStream<S>) -> Option<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let cert = stream.get_ref().1.peer_certificates()?.first()?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(cert.as_ref());
    Some(format!(
        "-----BEGIN CERTIFICATE-----\\n{encoded}\\n-----END CERTIFICATE-----"
    ))
}

async fn serve_stream<S>(
    stream: S,
    peer: SocketAddr,
    server: ProxyServer,
    scheme: RequestScheme,
    client_cert_pem: Option<String>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let state = server.state.clone();
    state.metrics.active_connections.inc();
    let remote_ip = peer.ip();
    let service_server = server.clone();
    let service = service_fn(move |req| {
        let server = service_server.clone();
        let client_cert_pem = client_cert_pem.clone();
        async move {
            Ok::<_, Infallible>(
                server
                    .handle(req, Some(remote_ip), scheme, client_cert_pem)
                    .await,
            )
        }
    });
    let io = TokioIo::new(stream);
    let builder = hardened_auto_builder();

    match time::timeout(
        Duration::from_secs(EDGE_CONNECTION_TIMEOUT_SECONDS),
        builder.serve_connection_with_upgrades(io, service),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => debug!(%error, "connection ended with error"),
        Err(_) => debug!("connection timed out"),
    }

    state.metrics.active_connections.dec();
}

fn hardened_auto_builder() -> AutoBuilder<TokioExecutor> {
    let mut builder = AutoBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Some(Duration::from_secs(10)))
        .max_headers(100)
        .max_buf_size(64 * 1024);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(Some(64))
        .max_pending_accept_reset_streams(Some(32))
        .max_local_error_reset_streams(Some(64))
        .max_header_list_size(64 * 1024)
        .max_frame_size(Some(16 * 1024))
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(10))
        .max_send_buf_size(128 * 1024);
    builder
}

fn policy_rejection(
    status: StatusCode,
    message: &'static str,
    metric_reason: &'static str,
) -> PolicyRejection {
    PolicyRejection {
        status,
        message,
        metric_reason,
        retry_after: None,
        location: None,
    }
}

fn effective_rate_per_second(limit: &DomainRateLimit) -> Option<f64> {
    if let Some(rate) = limit.requests_per_second {
        if rate > 0 {
            return Some(rate as f64);
        }
    }

    limit
        .requests_per_minute
        .filter(|rate| *rate > 0)
        .map(|rate| rate as f64 / 60.0)
        .or(Some(120.0))
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let has_upgrade_connection = headers
        .get(CONNECTION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
        });
    let websocket_upgrade = headers
        .get(UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));

    has_upgrade_connection && websocket_upgrade
}

fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}

fn request_can_have_body(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn content_type_matches(actual: &str, expected: &str) -> bool {
    actual
        .split(';')
        .next()
        .unwrap_or(actual)
        .trim()
        .eq_ignore_ascii_case(expected.trim())
}

fn header_present(headers: &HeaderMap, name: &str) -> bool {
    HeaderName::from_bytes(name.as_bytes())
        .ok()
        .is_some_and(|name| headers.contains_key(name))
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    HeaderName::from_bytes(name.as_bytes())
        .ok()
        .and_then(|name| headers.get(name))
        .and_then(|value| value.to_str().ok())
}

fn is_cors_preflight(req: &Request<Incoming>, rules: &DomainRules) -> bool {
    rules.cors_preflight_enabled
        && !rules.cors_allowed_origins.is_empty()
        && req.method() == Method::OPTIONS
        && req.headers().contains_key(ORIGIN)
        && req.headers().contains_key(ACCESS_CONTROL_REQUEST_METHOD)
}

fn cors_origin_allowed(origin: &HeaderValue, allowed_origins: &[String]) -> bool {
    let Some(origin) = origin.to_str().ok() else {
        return false;
    };

    allowed_origins
        .iter()
        .any(|allowed| allowed == "*" || allowed.eq_ignore_ascii_case(origin))
}

fn static_waf_rejection_reason(
    req: &Request<Incoming>,
    rules: &DomainRules,
    canonical_path: &str,
) -> Option<&'static str> {
    let waf = &rules.waf;
    if !waf.enabled {
        return None;
    }

    let path = req.uri().path();
    let query = req.uri().query().unwrap_or_default();
    let path_lower = path.to_ascii_lowercase();
    let canonical_path_lower = canonical_path.to_ascii_lowercase();
    let query_lower = query.to_ascii_lowercase();
    let user_agent_lower = req
        .headers()
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if waf.block_path_traversal
        && (contains_any(&path_lower, &["../", "..\\", "%2e%2e", "%252e%252e"])
            || path_had_structural_normalization(path, canonical_path))
    {
        return Some("waf_path_traversal");
    }

    if waf.block_sql_injection
        && contains_any(
            &query_lower,
            &[
                " union select ",
                "union%20select",
                "' or 1=1",
                "%27%20or%201=1",
                "\" or 1=1",
                "%22%20or%201=1",
                "information_schema",
                "sleep(",
                "benchmark(",
            ],
        )
    {
        return Some("waf_sql_injection");
    }

    if waf.block_xss
        && (contains_any(&query_lower, &["<script", "%3cscript", "javascript:"])
            || contains_any(&path_lower, &["<script", "%3cscript", "javascript:"])
            || contains_any(
                &canonical_path_lower,
                &["<script", "%3cscript", "javascript:"],
            ))
    {
        return Some("waf_xss");
    }

    if waf.block_bad_bots
        && contains_any(
            &user_agent_lower,
            &["sqlmap", "nikto", "masscan", "zgrab", "nmap", "dirbuster"],
        )
    {
        return Some("waf_bad_bot");
    }

    if string_patterns_match(&user_agent_lower, &waf.blocked_user_agents) {
        return Some("waf_user_agent");
    }

    if string_patterns_match(&path_lower, &waf.blocked_path_patterns)
        || string_patterns_match(&canonical_path_lower, &waf.blocked_path_patterns)
    {
        return Some("waf_path_pattern");
    }

    if string_patterns_match(&query_lower, &waf.blocked_query_patterns) {
        return Some("waf_query_pattern");
    }

    None
}

fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }

    let mut counts = [0u16; 256];
    for byte in value.bytes() {
        counts[byte as usize] = counts[byte as usize].saturating_add(1);
    }

    let len = value.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let probability = count as f64 / len;
            -probability * probability.log2()
        })
        .sum()
}

fn path_has_long_random_segment(path: &str) -> bool {
    path.split('/')
        .filter(|segment| segment.len() >= 20)
        .any(|segment| {
            let alphanumeric = segment
                .bytes()
                .filter(|byte| byte.is_ascii_alphanumeric())
                .count();
            let digit_count = segment.bytes().filter(|byte| byte.is_ascii_digit()).count();
            let letter_count = segment
                .bytes()
                .filter(|byte| byte.is_ascii_alphabetic())
                .count();

            alphanumeric >= segment.len() * 9 / 10
                && digit_count >= 3
                && letter_count >= 8
                && shannon_entropy(segment) >= 4.0
        })
}

fn contains_any(value: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| value.contains(pattern))
}

fn string_patterns_match(value_lower: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .map(|pattern| pattern.to_ascii_lowercase())
        .any(|pattern| !pattern.is_empty() && value_lower.contains(&pattern))
}

fn path_had_structural_normalization(raw_path: &str, canonical_path: &str) -> bool {
    if raw_path == canonical_path {
        return false;
    }
    let raw_lower = raw_path.to_ascii_lowercase();
    contains_any(
        &raw_lower,
        &[
            "..", "%2e", "%252e", "%2f", "%252f", "%5c", "%255c", "\\", "//",
        ],
    )
}

fn location_rule_matches(rule: &TrafficSplitRule, location: &GeoLocation) -> bool {
    let country_matches = rule.countries.is_empty()
        || location_code_matches(location.country_code.as_deref(), &rule.countries);
    let continent_matches = rule.continents.is_empty()
        || location_code_matches(location.continent_code.as_deref(), &rule.continents);

    country_matches && continent_matches
}

fn location_code_matches(actual: Option<&str>, configured: &[String]) -> bool {
    let Some(actual) = actual else {
        return false;
    };

    configured
        .iter()
        .any(|code| code == "*" || code.eq_ignore_ascii_case(actual))
}

fn insert_static_header(headers: &mut HeaderMap, name: &'static str, value: &'static str) {
    headers.insert(
        HeaderName::from_static(name),
        HeaderValue::from_static(value),
    );
}

async fn collect_body_with_limit(body: Incoming, max_bytes: u64) -> Result<Bytes, BufferError> {
    let mut body = body;
    let mut collected = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| BufferError::Body(error.to_string()))?;
        if let Some(data) = frame.data_ref() {
            if collected.len() as u64 + data.len() as u64 > max_bytes {
                return Err(BufferError::TooLarge);
            }
            collected.extend_from_slice(data);
        }
    }
    Ok(collected.freeze())
}

fn expand_middleware_names(
    names: &[String],
    rules: &DomainRules,
    output: &mut Vec<String>,
    depth: usize,
) {
    if depth > 8 {
        return;
    }
    for name in names {
        if let Some(chain) = rules.middleware_chains.get(name) {
            expand_middleware_names(chain, rules, output, depth + 1);
            continue;
        }
        output.push(name.clone());
        if let Some(middleware) = rules.middlewares.get(name) {
            expand_middleware_names(&middleware.chain, rules, output, depth + 1);
        }
    }
}

fn request_body_limit(rules: &DomainRules, middleware: &EffectiveMiddleware) -> u64 {
    rules
        .max_body_bytes
        .unwrap_or(middleware.request_buffering.max_request_bytes)
        .min(middleware.request_buffering.max_request_bytes)
}

fn requires_buffered_forwarding(middleware: &EffectiveMiddleware, strict_body_limit: bool) -> bool {
    strict_body_limit
        || middleware.request_buffering.enabled
        || middleware.response_buffering.enabled
        || middleware.retry.enabled
        || middleware.compression.enabled
        || middleware.content_type_autodetect.enabled
        || (middleware.traffic_mirroring.enabled
            && !middleware.traffic_mirroring.upstreams.is_empty()
            && middleware.traffic_mirroring.percent > 0)
}

fn limit_to_usize(limit: u64) -> usize {
    usize::try_from(limit).unwrap_or(usize::MAX)
}

fn retryable_status(status: StatusCode, retry: &RetryConfig) -> bool {
    retry.enabled
        && (retry.retry_statuses.is_empty()
            || retry
                .retry_statuses
                .iter()
                .any(|code| *code == status.as_u16()))
}

fn apply_request_content_type_detection(headers: &mut HeaderMap, uri: &Uri, body: Option<&Bytes>) {
    if headers.contains_key(CONTENT_TYPE) {
        return;
    }
    let detected = detect_content_type(uri.path(), body);
    if let Some(content_type) = detected {
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    }
}

fn ensure_trace_headers(headers: &mut HeaderMap, request_id: &str) {
    if !headers.contains_key("traceparent") {
        let trace_id = Uuid::new_v4().simple().to_string();
        let span_id = format!("{:016x}", monotonic_nanos() as u64);
        if let Ok(value) = HeaderValue::from_str(&format!("00-{trace_id}-{span_id}-01")) {
            headers.insert(HeaderName::from_static("traceparent"), value);
        }
    }
    if let Ok(value) = HeaderValue::from_str(request_id) {
        headers.insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
    }
}

fn generate_request_id() -> String {
    Uuid::new_v4().to_string()
}

fn attach_request_id_header(headers: &mut HeaderMap, request_id: &str) {
    if let Ok(value) = HeaderValue::from_str(request_id) {
        headers.insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
    }
}

fn apply_default_cache_headers(headers: &mut HeaderMap, path: &str) {
    const LONG_LIVED_EXPIRES: &str = "Thu, 31 Dec 2037 23:55:55 GMT";

    if is_static_asset_path(path) {
        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=31536000, immutable"),
        );
        headers.insert(
            HeaderName::from_static("expires"),
            HeaderValue::from_static(LONG_LIVED_EXPIRES),
        );
        return;
    }

    if is_html_document_path(path) {
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    }
}

fn is_static_asset_path(path: &str) -> bool {
    let lower = path_without_query(path).to_ascii_lowercase();
    lower.starts_with("/assets/")
        || lower.starts_with("/fonts/")
        || lower.starts_with("/generated/website-assets/")
        || lower.starts_with("/_build/")
        || lower.ends_with(".avif")
        || lower.ends_with(".webp")
        || lower.ends_with(".png")
        || lower.ends_with(".jpg")
        || lower.ends_with(".jpeg")
        || lower.ends_with(".svg")
        || lower.ends_with(".gif")
        || lower.ends_with(".ico")
        || lower.ends_with(".css")
        || lower.ends_with(".js")
        || lower.ends_with(".mjs")
        || lower.ends_with(".woff")
        || lower.ends_with(".woff2")
        || lower.ends_with(".ttf")
        || lower.ends_with(".otf")
        || lower.ends_with(".wasm")
        || lower.ends_with(".map")
}

fn is_html_document_path(path: &str) -> bool {
    let clean = path_without_query(path);
    clean == "/"
        || clean.ends_with(".html")
        || (!clean.starts_with("/api/") && !clean.contains('.'))
}

fn monotonic_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

fn detect_content_type(path: &str, body: Option<&Bytes>) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".json") {
        return Some("application/json");
    }
    if lower.ends_with(".html") || lower.ends_with(".htm") {
        return Some("text/html; charset=utf-8");
    }
    if lower.ends_with(".css") {
        return Some("text/css; charset=utf-8");
    }
    if lower.ends_with(".js") || lower.ends_with(".mjs") {
        return Some("application/javascript");
    }
    if lower.ends_with(".svg") {
        return Some("image/svg+xml");
    }
    if lower.ends_with(".txt") {
        return Some("text/plain; charset=utf-8");
    }
    let body = body?;
    let trimmed = body
        .iter()
        .copied()
        .skip_while(|byte| byte.is_ascii_whitespace())
        .take(16)
        .collect::<Vec<_>>();
    if matches!(trimmed.first(), Some(b'{') | Some(b'[')) {
        return Some("application/json");
    }
    if trimmed.starts_with(b"<!doctype") || trimmed.starts_with(b"<html") {
        return Some("text/html; charset=utf-8");
    }
    None
}

fn apply_response_middleware(
    response: &mut BufferedResponse,
    middleware: &EffectiveMiddleware,
    accepts_gzip: bool,
) {
    if middleware.content_type_autodetect.enabled && !response.headers.contains_key(CONTENT_TYPE) {
        if let Some(content_type) = detect_content_type("", Some(&response.body)) {
            response
                .headers
                .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
        }
    }

    if !middleware.compression.enabled
        || !accepts_gzip
        || response.body.len() < middleware.compression.min_bytes
        || response.headers.contains_key(CONTENT_ENCODING)
        || !response_is_compressible(&response.headers, &middleware.compression)
    {
        return;
    }

    if let Ok(body) = gzip_bytes(&response.body) {
        response.body = Bytes::from(body);
        response
            .headers
            .insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        response.headers.remove(CONTENT_LENGTH);
        response
            .headers
            .insert(VARY, HeaderValue::from_static("accept-encoding"));
    }
}

fn response_is_compressible(headers: &HeaderMap, compression: &CompressionConfig) -> bool {
    let Some(content_type) = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    if !compression.content_types.is_empty() {
        return compression
            .content_types
            .iter()
            .any(|expected| content_type_matches(content_type, expected));
    }
    content_type.starts_with("text/")
        || content_type_matches(content_type, "application/json")
        || content_type_matches(content_type, "application/javascript")
        || content_type_matches(content_type, "image/svg+xml")
}

fn gzip_bytes(body: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body)?;
    encoder.finish()
}

fn accepts_gzip(value: Option<&HeaderValue>) -> bool {
    value
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|part| part.trim().starts_with("gzip")))
}

fn parse_digest_authorization(value: &str) -> HashMap<String, String> {
    value
        .split(',')
        .filter_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            Some((
                key.trim().to_ascii_lowercase(),
                value.trim().trim_matches('"').to_string(),
            ))
        })
        .collect()
}

struct DigestAuthCheck<'a> {
    method: &'a Method,
    realm: &'a str,
    users: &'a HashMap<String, String>,
    params: &'a HashMap<String, String>,
    actual_uri: &'a str,
    secret: &'a str,
    replays: &'a DashMap<String, Instant>,
}

fn digest_authorized(check: DigestAuthCheck<'_>) -> bool {
    let now_unix_ms = now_unix_ms();
    let Some(username) = check.params.get("username") else {
        return false;
    };
    let Some(password) = check.users.get(username) else {
        return false;
    };
    if check
        .params
        .get("realm")
        .is_some_and(|value| value != check.realm)
    {
        return false;
    }
    let Some(nonce) = check.params.get("nonce") else {
        return false;
    };
    if !digest_nonce_is_valid(check.secret, check.realm, nonce, now_unix_ms) {
        return false;
    }
    let Some(uri) = check.params.get("uri") else {
        return false;
    };
    if uri != check.actual_uri {
        return false;
    }
    if check
        .params
        .get("algorithm")
        .is_some_and(|algorithm| !algorithm.eq_ignore_ascii_case("SHA-256"))
    {
        return false;
    }
    let Some(qop) = check
        .params
        .get("qop")
        .filter(|qop| qop.eq_ignore_ascii_case("auth"))
    else {
        return false;
    };
    let Some(nc) = check
        .params
        .get("nc")
        .filter(|value| valid_digest_nc(value))
    else {
        return false;
    };
    let Some(cnonce) = check.params.get("cnonce").filter(|value| !value.is_empty()) else {
        return false;
    };
    let Some(response) = check.params.get("response") else {
        return false;
    };

    let ha1 = sha256_hex(&format!("{username}:{}:{password}", check.realm));
    let ha2 = sha256_hex(&format!("{}:{uri}", check.method.as_str()));
    let expected = sha256_hex(&format!("{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}"));
    if !constant_time_str_eq(&expected, response) {
        return false;
    }

    prune_digest_replays(check.replays);
    let replay_key = format!("{username}:{nonce}:{nc}:{cnonce}:{uri}");
    check
        .replays
        .insert(
            replay_key,
            Instant::now() + Duration::from_millis(DIGEST_NONCE_TTL_MS),
        )
        .is_none()
}

fn digest_request_uri(req: &Request<Incoming>, canonical_path: &str) -> String {
    match req.uri().query() {
        Some(query) if !query.is_empty() => format!("{canonical_path}?{query}"),
        _ => canonical_path.to_string(),
    }
}

fn digest_nonce(secret: &str, realm: &str, timestamp_unix_ms: u64) -> String {
    let timestamp_hex = format!("{timestamp_unix_ms:x}");
    let signature = digest_nonce_signature(secret, realm, &timestamp_hex);
    format!("{timestamp_hex}.{signature}")
}

fn digest_nonce_is_valid(secret: &str, realm: &str, nonce: &str, now_unix_ms: u64) -> bool {
    let Some((timestamp_hex, signature)) = nonce.split_once('.') else {
        return false;
    };
    if timestamp_hex.is_empty() || signature.is_empty() {
        return false;
    }
    let Ok(timestamp_unix_ms) = u64::from_str_radix(timestamp_hex, 16) else {
        return false;
    };
    if timestamp_unix_ms > now_unix_ms.saturating_add(DIGEST_NONCE_CLOCK_SKEW_MS) {
        return false;
    }
    if now_unix_ms.saturating_sub(timestamp_unix_ms) > DIGEST_NONCE_TTL_MS {
        return false;
    }
    constant_time_str_eq(
        &digest_nonce_signature(secret, realm, timestamp_hex),
        signature,
    )
}

fn digest_nonce_signature(secret: &str, realm: &str, timestamp_hex: &str) -> String {
    sha256_hex(&format!("{secret}:{realm}:{timestamp_hex}"))
}

fn valid_digest_nc(value: &str) -> bool {
    value.len() == 8 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn prune_digest_replays(replays: &DashMap<String, Instant>) {
    if replays.len() < DIGEST_REPLAY_EVICT_AT {
        return;
    }
    let now = Instant::now();
    replays.retain(|_, expires_at| *expires_at > now);
}

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn constant_time_str_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0_u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}

fn sticky_upstream(
    headers: &HeaderMap,
    upstreams: &[Upstream],
    sticky: &StickySessionConfig,
) -> Option<Upstream> {
    if !sticky.enabled {
        return None;
    }
    let cookie = headers.get(COOKIE)?.to_str().ok()?;
    let wanted = cookie_value(cookie, &sticky.cookie_name)?;
    upstreams
        .iter()
        .find(|upstream| sticky_upstream_id(&upstream.url) == wanted)
        .cloned()
}

fn apply_sticky_cookie(headers: &mut HeaderMap, sticky: &StickySessionConfig, upstream: &Upstream) {
    if !sticky.enabled {
        return;
    }
    let mut cookie = format!(
        "{}={}; Path=/",
        sticky.cookie_name,
        sticky_upstream_id(&upstream.url)
    );
    if sticky.http_only {
        cookie.push_str("; HttpOnly");
    }
    if sticky.secure {
        cookie.push_str("; Secure");
    }
    if let Some(same_site) = &sticky.same_site {
        cookie.push_str("; SameSite=");
        cookie.push_str(same_site);
    }
    if let Some(max_age) = sticky.max_age_seconds {
        cookie.push_str("; Max-Age=");
        cookie.push_str(&max_age.to_string());
    }
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.insert(SET_COOKIE, value);
    }
}

fn cookie_value(cookie: &str, name: &str) -> Option<String> {
    cookie.split(';').find_map(|part| {
        let (cookie_name, value) = part.trim().split_once('=')?;
        if cookie_name == name {
            Some(value.to_string())
        } else {
            None
        }
    })
}

fn sticky_upstream_id(upstream: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in upstream.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:x}")
}

fn mirror_should_run(domain: &str, uri: &Uri, upstream: &str, percent: u8) -> bool {
    if percent >= 100 {
        return true;
    }
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in format!("{domain}:{uri}:{upstream}").as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    (hash % 100) < u64::from(percent)
}

fn circuit_key(route_id: &str, path_prefix: &str, upstream: &str) -> String {
    format!("{route_id}:{path_prefix}:{upstream}")
}

fn in_flight_key(
    limit: &InFlightLimitConfig,
    matched: &RouteMatch,
    upstream: &Upstream,
) -> (String, &'static str) {
    match limit.scope {
        InFlightLimitScope::Domain => (matched.route.domain.clone(), "domain"),
        InFlightLimitScope::Upstream => (
            format!(
                "{}:{}:{}",
                matched.route.id, matched.path.prefix, upstream.url
            ),
            "upstream",
        ),
        InFlightLimitScope::Route => (
            format!("{}:{}", matched.route.id, matched.path.prefix),
            "route",
        ),
    }
}

fn path_without_query(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn is_html_template(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("html") || extension.eq_ignore_ascii_case("htm")
        })
}

fn html_response(status: StatusCode, body: String) -> Response<BoxBody> {
    response_with_body(status, "text/html; charset=utf-8", body)
}

fn text_response(status: StatusCode, message: &str) -> Response<BoxBody> {
    response_with_body(status, "text/plain; charset=utf-8", message.to_string())
}

async fn serve_acme_http01_challenge(path: &str) -> Option<Response<BoxBody>> {
    let token = path.strip_prefix(ACME_CHALLENGE_PREFIX)?;
    if token.is_empty()
        || token.contains('/')
        || token.contains('\\')
        || token == "."
        || token == ".."
        || token.starts_with('.')
    {
        return Some(text_response(
            StatusCode::BAD_REQUEST,
            "invalid acme challenge token",
        ));
    }

    let root = PathBuf::from(
        std::env::var("PXXL_ACME_CHALLENGE_DIR")
            .unwrap_or_else(|_| "/data/acme-challenges".to_string()),
    );
    let certbot_path = root.join(".well-known").join("acme-challenge").join(token);
    let flat_path = root.join(token);
    match tokio::fs::read_to_string(&certbot_path)
        .await
        .or_else(|_| std::fs::read_to_string(flat_path))
    {
        Ok(value) => Some(response_with_body(
            StatusCode::OK,
            "text/plain; charset=utf-8",
            value,
        )),
        Err(_) => Some(text_response(
            StatusCode::NOT_FOUND,
            "acme challenge not found",
        )),
    }
}

fn response_with_body(
    status: StatusCode,
    content_type: &'static str,
    body: String,
) -> Response<BoxBody> {
    let body = boxed_full(Bytes::from(body));
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, content_type)
        .header(CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .body(body)
        .unwrap_or_else(|error| {
            error!(%error, "failed to build text response");
            Response::new(boxed_full(Bytes::from_static(
                b"internal response build error",
            )))
        })
}

fn boxed_full(body: Bytes) -> BoxBody {
    Full::new(body).map_err(|never| match never {}).boxed()
}

fn default_error_html(
    status: StatusCode,
    message: &str,
    reason_code: &str,
    domain: &str,
    path: &str,
    request_id: &str,
    processing_time_ms: u128,
) -> String {
    render_error_template(
        DEFAULT_ERROR_TEMPLATE,
        ErrorRenderContext {
            status,
            message,
            reason_code,
            domain,
            path,
            request_id,
            processing_time_ms,
        },
    )
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;
    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn bandwidth_reset_date(reset_day: u8) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Simple calculation: next occurrence of reset_day
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Approximate: 30 days from now if we can't compute exactly
    let approx_reset = now_secs + (30 * 24 * 3600);
    let days = approx_reset / 86400;
    // Convert days since epoch to a rough date string
    let year = 1970 + days / 365;
    let month = ((days % 365) / 30) + 1;
    let day = reset_day.min(28);
    format!("{year}-{month:02}-{day:02}")
}

fn render_error_template(template: &str, context: ErrorRenderContext<'_>) -> String {
    let status_code = context.status.as_u16().to_string();
    let status_text = context.status.canonical_reason().unwrap_or("Proxy Error");
    let domain = if context.domain.is_empty() {
        "unknown"
    } else {
        context.domain
    };
    let path = if context.path.is_empty() {
        "/"
    } else {
        context.path
    };
    let processing_time_ms = context.processing_time_ms.to_string();

    template
        .replace("{{status_code}}", &escape_html(&status_code))
        .replace("{{status_text}}", &escape_html(status_text))
        .replace("{{message}}", &escape_html(context.message))
        .replace("{{reason_code}}", &escape_html(context.reason_code))
        .replace("{{domain}}", &escape_html(domain))
        .replace("{{path}}", &escape_html(path))
        .replace("{{request_id}}", &escape_html(context.request_id))
        .replace("{{processing_time_ms}}", &escape_html(&processing_time_ms))
}

fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

const DEFAULT_ERROR_TEMPLATE: &str = include_str!("../../../../config/error-pages/default.html");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_upstream_uri_with_path_and_query() {
        let upstream = Upstream::new("http://api:3000");
        let uri: Uri = "/v1/users?page=1".parse().unwrap();

        let built = build_upstream_uri(&upstream, &uri).unwrap();

        assert_eq!(built.to_string(), "http://api:3000/v1/users?page=1");
    }

    #[test]
    fn renders_custom_error_page_template() {
        let rendered = render_error_template(
            "<h1>{{status_code}} {{status_text}}</h1><p>{{message}}</p><b>{{reason_code}}</b><span>{{domain}}{{path}}</span><em>{{processing_time_ms}} ms</em>",
            ErrorRenderContext {
                status: StatusCode::BAD_GATEWAY,
                message: "upstream <failed>",
                reason_code: "upstream_tcp_unreachable",
                domain: "app.pxxlhost",
                path: "/users?name=<x>",
                request_id: "request-123",
                processing_time_ms: 17,
            },
        );

        assert!(rendered.contains("502 Bad Gateway"));
        assert!(rendered.contains("upstream &lt;failed&gt;"));
        assert!(rendered.contains("upstream_tcp_unreachable"));
        assert!(rendered.contains("app.pxxlhost/users?name=&lt;x&gt;"));
        assert!(rendered.contains("17"));
    }

    #[test]
    fn bot_path_entropy_flags_random_segments() {
        assert!(path_has_long_random_segment(
            "/assets/a8F91bcD77E2ghIJ992kLmNopQrStUv"
        ));
        assert!(!path_has_long_random_segment(
            "/blog/how-to-deploy-a-normal-project"
        ));
    }

    #[test]
    fn trusted_peer_uses_first_public_forwarded_client_ip() {
        let trusted = TrustedClientIpConfig::parse("10.88.0.0/24");
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("10.0.0.7, 8.8.8.8, 1.1.1.1"),
        );

        let ip =
            resolve_effective_client_ip(&headers, Some("10.88.0.31".parse().unwrap()), &trusted);

        assert_eq!(ip, Some("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn untrusted_peer_cannot_spoof_forwarded_client_ip() {
        let trusted = TrustedClientIpConfig::parse("10.88.0.0/24");
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("cf-connecting-ip"),
            HeaderValue::from_static("8.8.8.8"),
        );

        let ip =
            resolve_effective_client_ip(&headers, Some("203.0.113.10".parse().unwrap()), &trusted);

        assert_eq!(ip, Some("203.0.113.10".parse().unwrap()));
    }

    #[test]
    fn forwarded_header_supports_quoted_ipv6_and_ports() {
        let trusted = TrustedClientIpConfig::parse("10.89.0.0/16");
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("forwarded"),
            HeaderValue::from_static("for=\"[2606:4700:4700::1111]:443\";proto=https"),
        );

        let ip =
            resolve_effective_client_ip(&headers, Some("10.89.2.27".parse().unwrap()), &trusted);

        assert_eq!(ip, Some("2606:4700:4700::1111".parse().unwrap()));
    }
}
