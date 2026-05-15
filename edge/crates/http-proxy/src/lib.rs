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
    Method, Request, Response, StatusCode, Uri,
};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as AutoBuilder,
};
use parking_lot::Mutex;
use pxxl_common::{
    canonicalize_request_path, normalize_domain, BasicAuthConfig, BufferingConfig,
    CircuitBreakerConfig, ClientCertForwardingConfig, CompressionConfig,
    ContentTypeAutoDetectConfig, DigestAuthConfig, DomainRateLimit, DomainRules, ForwardAuthConfig,
    GeoLocation, InFlightLimitConfig, InFlightLimitScope, MiddlewareDefinition,
    PassiveHealthConfig, PxxlError, RateLimitScope, RetryConfig, RouteMatch, StickySessionConfig,
    TrafficMirrorConfig, TrafficSplitRule, Upstream,
};
use pxxl_core::{EdgeState, RequestObservation};
use pxxl_ddos::SecurityDecision;
use pxxl_geo::GeoIpResolver;
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
    ) -> Response<BoxBody> {
        if !self.enabled {
            return text_response(status, message);
        }

        let body = self
            .pages
            .get(&status.as_u16())
            .or(self.default_page.as_ref())
            .map(|template| {
                render_error_template(template.body.as_ref(), status, message, domain, path)
            })
            .unwrap_or_else(|| default_error_html(status, message, domain, path));

        html_response(status, body)
    }
}

#[derive(Clone, Debug, Default)]
pub struct PolicyEnforcer {
    rate_limiter: Arc<PolicyRateLimiter>,
    circuit_breakers: Arc<DashMap<String, Mutex<CircuitBreakerState>>>,
    in_flight_limits: Arc<DashMap<String, AtomicUsize>>,
    passive_health: Arc<DashMap<String, Mutex<PassiveHealthState>>>,
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
            return Some(policy_rejection(
                StatusCode::SERVICE_UNAVAILABLE,
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

        if let Some(reason) = waf_rejection_reason(req, rules, context.path) {
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

        if is_cors_preflight(req, rules) {
            return Some(PolicyRejection {
                status: StatusCode::NO_CONTENT,
                message: "cors preflight accepted",
                metric_reason: "cors_preflight",
                retry_after: None,
                location: None,
            });
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

        None
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
            insert_static_header(headers, "x-frame-options", "DENY");
            insert_static_header(headers, "x-content-type-options", "nosniff");
            insert_static_header(headers, "referrer-policy", "no-referrer");
            insert_static_header(
                headers,
                "permissions-policy",
                "camera=(), microphone=(), geolocation=()",
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
    client: Client<HttpConnector, Full<Bytes>>,
    error_pages: ErrorPageRenderer,
    policy: PolicyEnforcer,
    geoip: GeoIpResolver,
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
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Self {
            state,
            client,
            error_pages,
            policy,
            geoip,
        }
    }

    pub async fn handle(
        &self,
        req: Request<Incoming>,
        remote_ip: Option<IpAddr>,
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
                self.observe_request(&context, StatusCode::BAD_REQUEST, started, None);
                finish_response!(self.error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid request path",
                    "unknown",
                    &raw_path,
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
        {
            Some(host) => host.to_string(),
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
                self.observe_request(&context, StatusCode::BAD_REQUEST, started, None);
                finish_response!(self.error_response(
                    StatusCode::BAD_REQUEST,
                    "missing host header",
                    "unknown",
                    &path,
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

        if let Some(ip) = remote_ip {
            match self.state.security.check(&domain, ip) {
                SecurityDecision::Allowed => {}
                SecurityDecision::Blocked { reason } => {
                    self.state
                        .metrics
                        .blocked_total
                        .with_label_values(&[&domain, &reason])
                        .inc();
                    self.observe_request(&context, StatusCode::FORBIDDEN, started, None);
                    finish_response!(self.error_response(
                        StatusCode::FORBIDDEN,
                        "request blocked",
                        &domain,
                        &path,
                    ));
                }
                SecurityDecision::RateLimited { retry_after } => {
                    self.state
                        .metrics
                        .rate_limited_total
                        .with_label_values(&[&domain])
                        .inc();
                    self.observe_request(&context, StatusCode::TOO_MANY_REQUESTS, started, None);
                    let mut response = self.error_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        "rate limited",
                        &domain,
                        &path,
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
                self.observe_request(&context, StatusCode::NOT_FOUND, started, None);
                finish_response!(self.error_response(
                    StatusCode::NOT_FOUND,
                    "no route matched this host/path",
                    &domain,
                    &path,
                ));
            }
        };

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

            self.observe_request(&context, rejection.status, started, None);
            let mut response = if rejection.status == StatusCode::NO_CONTENT {
                response_with_body(rejection.status, "text/plain; charset=utf-8", String::new())
            } else {
                self.error_response(rejection.status, rejection.message, &domain, &path)
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

        if let Some(basic_auth) = &middleware.basic_auth {
            if let Some(response) = self.evaluate_basic_auth(&req, basic_auth, &domain, &path) {
                self.state
                    .metrics
                    .middleware_executions_total
                    .with_label_values(&[&domain, "basic_auth", "rejected"])
                    .inc();
                self.observe_request(&context, response.status(), started, None);
                finish_response!(response);
            }
            self.state
                .metrics
                .middleware_executions_total
                .with_label_values(&[&domain, "basic_auth", "allowed"])
                .inc();
        }

        if let Some(digest_auth) = &middleware.digest_auth {
            if let Some(response) = self.evaluate_digest_auth(&req, digest_auth, &domain, &path) {
                self.state
                    .metrics
                    .middleware_executions_total
                    .with_label_values(&[&domain, "digest_auth", "rejected"])
                    .inc();
                self.observe_request(&context, response.status(), started, None);
                finish_response!(response);
            }
            self.state
                .metrics
                .middleware_executions_total
                .with_label_values(&[&domain, "digest_auth", "allowed"])
                .inc();
        }

        if let Some(forward_auth) = &middleware.forward_auth {
            match self.run_forward_auth(&req, forward_auth).await {
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
                    self.observe_request(&context, StatusCode::UNAUTHORIZED, started, None);
                    finish_response!(self.error_response(
                        StatusCode::UNAUTHORIZED,
                        "forward auth denied the request",
                        &domain,
                        &path,
                    ));
                }
                Err(error) => {
                    warn!(%error, request_id = %request_id, domain = %domain, "forward auth request failed");
                    self.state
                        .metrics
                        .middleware_executions_total
                        .with_label_values(&[&domain, "forward_auth", "error"])
                        .inc();
                    self.observe_request(&context, StatusCode::BAD_GATEWAY, started, None);
                    finish_response!(self.error_response(
                        StatusCode::BAD_GATEWAY,
                        "forward auth request failed",
                        &domain,
                        &path,
                    ));
                }
            }
        }

        let mut req = req;
        if let Ok(uri) = canonical_forward_uri(req.uri(), &path, original_query.as_deref()) {
            *req.uri_mut() = uri;
        }
        self.policy
            .apply_request_rules(req.headers_mut(), &matched.route.rules);
        if middleware.content_type_autodetect.enabled {
            let uri = req.uri().clone();
            apply_request_content_type_detection(req.headers_mut(), &uri, None);
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
                self.observe_request(&context, StatusCode::PAYLOAD_TOO_LARGE, started, None);
                finish_response!(self.error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body is too large",
                    &domain,
                    &path,
                ));
            }
            Err(BufferError::Body(error)) => {
                warn!(%error, request_id = %request_id, domain = %domain, "failed to buffer request body");
                self.observe_request(&context, StatusCode::BAD_REQUEST, started, None);
                finish_response!(self.error_response(
                    StatusCode::BAD_REQUEST,
                    "failed to read request body",
                    &domain,
                    &path,
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
                self.observe_request(&context, StatusCode::SERVICE_UNAVAILABLE, started, None);
                finish_response!(self.error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "no healthy upstreams",
                    &domain,
                    &path,
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
                self.observe_request(&context, StatusCode::TOO_MANY_REQUESTS, started, None);
                finish_response!(self.error_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many in-flight requests",
                    &domain,
                    &path,
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
                self.observe_request(&context, status, started, Some(&upstream.url));
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
                );
                finish_response!(self.error_response(
                    StatusCode::BAD_GATEWAY,
                    "upstream request failed",
                    &domain,
                    &path,
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

    fn error_response(
        &self,
        status: StatusCode,
        message: &str,
        domain: &str,
        path: &str,
    ) -> Response<BoxBody> {
        self.error_pages.response(status, message, domain, path)
    }

    fn observe_request(
        &self,
        context: &ProxyRequestContext<'_>,
        status: StatusCode,
        started: Instant,
        upstream: Option<&str>,
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
        });
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
                digest_authorized(req.method(), &config.realm, &config.users, &params)
            });

        if authorized {
            return None;
        }

        let nonce = format!("{:x}", now_unix_ms());
        let mut response = self.error_response(
            StatusCode::UNAUTHORIZED,
            "digest authentication required",
            domain,
            path,
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
    ) -> Result<bool, PxxlError> {
        if !config.enabled {
            return Ok(true);
        }
        let mut builder = Request::builder().method(Method::GET).uri(&config.url);
        for header in &config.request_headers {
            if let Ok(name) = HeaderName::from_bytes(header.as_bytes()) {
                if let Some(value) = req.headers().get(&name) {
                    builder = builder.header(name, value.clone());
                }
            }
        }
        let request = builder
            .body(Full::new(Bytes::new()))
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

    fn to_request(&self, upstream: &Upstream) -> Result<Request<Full<Bytes>>, PxxlError> {
        let mut request = Request::builder()
            .method(self.method.clone())
            .uri(build_upstream_uri(upstream, &self.uri)?)
            .body(Full::new(self.body.clone()))
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
    let builder = AutoBuilder::new(TokioExecutor::new());

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

fn waf_rejection_reason(
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

fn digest_authorized(
    method: &Method,
    realm: &str,
    users: &HashMap<String, String>,
    params: &HashMap<String, String>,
) -> bool {
    let Some(username) = params.get("username") else {
        return false;
    };
    let Some(password) = users.get(username) else {
        return false;
    };
    if params.get("realm").is_some_and(|value| value != realm) {
        return false;
    }
    let Some(nonce) = params.get("nonce") else {
        return false;
    };
    let Some(uri) = params.get("uri") else {
        return false;
    };
    let Some(response) = params.get("response") else {
        return false;
    };

    let ha1 = sha256_hex(&format!("{username}:{realm}:{password}"));
    let ha2 = sha256_hex(&format!("{}:{uri}", method.as_str()));
    let expected = match (params.get("qop"), params.get("nc"), params.get("cnonce")) {
        (Some(qop), Some(nc), Some(cnonce)) => {
            sha256_hex(&format!("{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}"))
        }
        _ => sha256_hex(&format!("{ha1}:{nonce}:{ha2}")),
    };
    constant_time_str_eq(&expected, response)
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

fn response_with_body(
    status: StatusCode,
    content_type: &'static str,
    body: String,
) -> Response<BoxBody> {
    let body = Full::new(Bytes::from(body))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, content_type)
        .header(CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .body(body)
        .unwrap_or_else(|error| {
            error!(%error, "failed to build text response");
            Response::new(
                Full::new(Bytes::from_static(b"internal response build error"))
                    .map_err(|never| match never {})
                    .boxed(),
            )
        })
}

fn default_error_html(status: StatusCode, message: &str, domain: &str, path: &str) -> String {
    render_error_template(DEFAULT_ERROR_TEMPLATE, status, message, domain, path)
}

fn render_error_template(
    template: &str,
    status: StatusCode,
    message: &str,
    domain: &str,
    path: &str,
) -> String {
    let status_code = status.as_u16().to_string();
    let status_text = status.canonical_reason().unwrap_or("Proxy Error");
    let domain = if domain.is_empty() { "unknown" } else { domain };
    let path = if path.is_empty() { "/" } else { path };

    template
        .replace("{{status_code}}", &escape_html(&status_code))
        .replace("{{status_text}}", &escape_html(status_text))
        .replace("{{message}}", &escape_html(message))
        .replace("{{domain}}", &escape_html(domain))
        .replace("{{path}}", &escape_html(path))
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

const DEFAULT_ERROR_TEMPLATE: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{status_code}} {{status_text}}</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #101318;
      --panel: #171c24;
      --text: #f5f7fb;
      --muted: #a9b2c3;
      --accent: #66d9c7;
      --border: #2a3342;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 32px;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    main {
      width: min(720px, 100%);
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--panel);
      padding: 32px;
      box-shadow: 0 24px 70px rgba(0, 0, 0, 0.25);
    }
    .code {
      color: var(--accent);
      font-size: 14px;
      font-weight: 700;
      letter-spacing: 0;
      text-transform: uppercase;
    }
    h1 {
      margin: 12px 0;
      font-size: clamp(30px, 5vw, 48px);
      line-height: 1.05;
      letter-spacing: 0;
    }
    p {
      margin: 0;
      color: var(--muted);
      font-size: 16px;
      line-height: 1.6;
    }
    dl {
      display: grid;
      grid-template-columns: max-content 1fr;
      gap: 10px 16px;
      margin: 28px 0 0;
      color: var(--muted);
      font-size: 14px;
    }
    dt { color: var(--text); font-weight: 700; }
    dd { margin: 0; overflow-wrap: anywhere; }
  </style>
</head>
<body>
  <main>
    <div class="code">Pxxl Proxy / {{status_code}}</div>
    <h1>{{status_text}}</h1>
    <p>{{message}}</p>
    <dl>
      <dt>Domain</dt>
      <dd>{{domain}}</dd>
      <dt>Path</dt>
      <dd>{{path}}</dd>
    </dl>
  </main>
</body>
</html>
"#;

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
            "<h1>{{status_code}} {{status_text}}</h1><p>{{message}}</p><span>{{domain}}{{path}}</span>",
            StatusCode::BAD_GATEWAY,
            "upstream <failed>",
            "app.pxxlhost",
            "/users?name=<x>",
        );

        assert!(rendered.contains("502 Bad Gateway"));
        assert!(rendered.contains("upstream &lt;failed&gt;"));
        assert!(rendered.contains("app.pxxlhost/users?name=&lt;x&gt;"));
    }
}
