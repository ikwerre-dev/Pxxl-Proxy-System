use anyhow::Context;
use bytes::Bytes;
use dashmap::DashMap;
use http::{
    header::{
        HeaderMap, HeaderName, HeaderValue, ACCESS_CONTROL_REQUEST_METHOD, CACHE_CONTROL,
        CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, LOCATION, ORIGIN, UPGRADE, VARY,
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
    normalize_domain, DomainRateLimit, DomainRules, PxxlError, RateLimitScope, RouteMatch, Upstream,
};
use pxxl_core::EdgeState;
use pxxl_ddos::SecurityDecision;
use rustls::ServerConfig;
use std::{
    collections::HashMap,
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type BoxBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestScheme {
    Http,
    Https,
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

impl PolicyEnforcer {
    fn evaluate(
        &self,
        req: &Request<Incoming>,
        rules: &DomainRules,
        domain: &str,
        path: &str,
        remote_ip: Option<IpAddr>,
        scheme: RequestScheme,
    ) -> Option<PolicyRejection> {
        if rules.maintenance_mode {
            return Some(policy_rejection(
                StatusCode::SERVICE_UNAVAILABLE,
                "domain is in maintenance mode",
                "maintenance_mode",
            ));
        }

        if scheme == RequestScheme::Http && rules.redirect_http_to_https {
            return Some(PolicyRejection {
                status: StatusCode::PERMANENT_REDIRECT,
                message: "https required",
                metric_reason: "https_redirect",
                retry_after: None,
                location: Some(format!("https://{domain}{path}")),
            });
        }

        if scheme == RequestScheme::Http && rules.require_https {
            return Some(policy_rejection(
                StatusCode::UPGRADE_REQUIRED,
                "https is required for this domain",
                "https_required",
            ));
        }

        if let Some(ip) = remote_ip {
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
            if let Some(retry_after) = self
                .rate_limiter
                .retry_after(limit, domain, path, remote_ip)
            {
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
    client: Client<HttpConnector, Incoming>,
    error_pages: ErrorPageRenderer,
    policy: PolicyEnforcer,
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
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Self {
            state,
            client,
            error_pages,
            policy,
        }
    }

    pub async fn handle(
        &self,
        req: Request<Incoming>,
        remote_ip: Option<IpAddr>,
        scheme: RequestScheme,
    ) -> Response<BoxBody> {
        let started = Instant::now();
        let method = req.method().clone();
        let path = req
            .uri()
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let host = match req
            .headers()
            .get(HOST)
            .and_then(|value| value.to_str().ok())
        {
            Some(host) => host.to_string(),
            None => {
                return self.error_response(
                    StatusCode::BAD_REQUEST,
                    "missing host header",
                    "",
                    &path,
                )
            }
        };
        let domain = normalize_domain(&host);

        if let Some(ip) = remote_ip {
            match self.state.security.check(&domain, ip) {
                SecurityDecision::Allowed => {}
                SecurityDecision::Blocked { reason } => {
                    self.state
                        .metrics
                        .blocked_total
                        .with_label_values(&[&domain, &reason])
                        .inc();
                    self.observe_request(
                        &domain,
                        method.as_str(),
                        StatusCode::FORBIDDEN,
                        started,
                        None,
                    );
                    return self.error_response(
                        StatusCode::FORBIDDEN,
                        "request blocked",
                        &domain,
                        &path,
                    );
                }
                SecurityDecision::RateLimited { retry_after } => {
                    self.state
                        .metrics
                        .rate_limited_total
                        .with_label_values(&[&domain])
                        .inc();
                    self.observe_request(
                        &domain,
                        method.as_str(),
                        StatusCode::TOO_MANY_REQUESTS,
                        started,
                        None,
                    );
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
                    return response;
                }
            }
        }

        let matched = match self.state.routes.find(&host, &path) {
            Some(matched) => matched,
            None => {
                self.observe_request(
                    &domain,
                    method.as_str(),
                    StatusCode::NOT_FOUND,
                    started,
                    None,
                );
                return self.error_response(
                    StatusCode::NOT_FOUND,
                    "no route matched this host/path",
                    &domain,
                    &path,
                );
            }
        };

        let request_origin = req.headers().get(ORIGIN).cloned();
        if let Some(rejection) = self.policy.evaluate(
            &req,
            &matched.route.rules,
            &domain,
            &path,
            remote_ip,
            scheme,
        ) {
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

            self.observe_request(&domain, method.as_str(), rejection.status, started, None);
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
            return response;
        }

        let mut req = req;
        self.policy
            .apply_request_rules(req.headers_mut(), &matched.route.rules);

        let route_key = format!("{}:{}", matched.route.id, matched.path.prefix);
        let upstream = match self.state.load_balancer.select(
            &route_key,
            &matched.route.algorithm,
            &matched.path.upstreams,
            remote_ip,
        ) {
            Some(upstream) => upstream,
            None => {
                self.observe_request(
                    &domain,
                    method.as_str(),
                    StatusCode::SERVICE_UNAVAILABLE,
                    started,
                    None,
                );
                return self.error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "no healthy upstreams",
                    &domain,
                    &path,
                );
            }
        };

        match self
            .forward(req, &matched, &upstream, remote_ip, scheme)
            .await
        {
            Ok(mut response) => {
                let status = response.status();
                self.policy.apply_response_rules(
                    response.headers_mut(),
                    &matched.route.rules,
                    request_origin.as_ref(),
                );
                self.observe_request(
                    &domain,
                    method.as_str(),
                    status,
                    started,
                    Some(&upstream.url),
                );
                self.state
                    .metrics
                    .upstream_latency_seconds
                    .with_label_values(&[&domain, &upstream.url])
                    .observe(started.elapsed().as_secs_f64());
                info!(
                    domain = %domain,
                    method = %method,
                    path = %path,
                    upstream = %upstream.url,
                    status = status.as_u16(),
                    latency_ms = started.elapsed().as_millis(),
                    "proxied request"
                );
                response
            }
            Err(error) => {
                warn!(%error, domain = %domain, upstream = %upstream.url, "upstream request failed");
                self.observe_request(
                    &domain,
                    method.as_str(),
                    StatusCode::BAD_GATEWAY,
                    started,
                    Some(&upstream.url),
                );
                self.error_response(
                    StatusCode::BAD_GATEWAY,
                    "upstream request failed",
                    &domain,
                    &path,
                )
            }
        }
    }

    async fn forward(
        &self,
        mut req: Request<Incoming>,
        matched: &RouteMatch,
        upstream: &Upstream,
        remote_ip: Option<IpAddr>,
        scheme: RequestScheme,
    ) -> Result<Response<BoxBody>, PxxlError> {
        let uri = build_upstream_uri(upstream, req.uri())?;
        *req.uri_mut() = uri;

        if !matched.route.rules.preserve_host_header {
            let authority = upstream.authority()?;
            req.headers_mut().insert(
                HOST,
                HeaderValue::from_str(&authority)
                    .map_err(|_| PxxlError::InvalidUpstream(upstream.url.clone()))?,
            );
        }
        req.headers_mut().insert(
            HeaderName::from_static("x-forwarded-host"),
            HeaderValue::from_str(&matched.route.domain).map_err(|_| PxxlError::InvalidHost)?,
        );
        req.headers_mut().insert(
            HeaderName::from_static("x-forwarded-proto"),
            HeaderValue::from_static(scheme.as_str()),
        );
        if let Some(ip) = remote_ip {
            if let Ok(value) = HeaderValue::from_str(&ip.to_string()) {
                req.headers_mut()
                    .insert(HeaderName::from_static("x-forwarded-for"), value);
            }
        }

        let response = self
            .client
            .request(req)
            .await
            .map_err(|_| PxxlError::InvalidUpstream(upstream.url.clone()))?;
        let (parts, body) = response.into_parts();
        Ok(Response::from_parts(
            parts,
            body.map_err(|error| -> BoxError { Box::new(error) })
                .boxed(),
        ))
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
        domain: &str,
        method: &str,
        status: StatusCode,
        started: Instant,
        upstream: Option<&str>,
    ) {
        self.state
            .metrics
            .requests_total
            .with_label_values(&[domain, method, &status.as_u16().to_string()])
            .inc();
        self.state.stats.record(
            domain,
            status.as_u16(),
            started.elapsed().as_millis() as u64,
            upstream,
        );
    }
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
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "HTTP proxy listening");
    run_plain_listener(listener, state, error_pages, policy, shutdown).await
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
    info!(addr = %listener.local_addr()?, "HTTP proxy listening");
    run_plain_listener(listener, state, error_pages, policy, shutdown).await
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
    let listener = TcpListener::bind(addr).await?;
    let acceptor = TlsAcceptor::from(tls_config);
    info!(%addr, "HTTPS proxy listening");
    run_tls_listener(listener, acceptor, state, error_pages, policy, shutdown).await
}

async fn run_plain_listener(
    listener: TcpListener,
    state: EdgeState,
    error_pages: ErrorPageRenderer,
    policy: PolicyEnforcer,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let server = ProxyServer::with_error_pages_and_policy(state, error_pages, policy);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                spawn_connection(stream, peer, server.clone(), RequestScheme::Http);
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
    acceptor: TlsAcceptor,
    state: EdgeState,
    error_pages: ErrorPageRenderer,
    policy: PolicyEnforcer,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let server = ProxyServer::with_error_pages_and_policy(state, error_pages, policy);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let acceptor = acceptor.clone();
                let server = server.clone();
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => serve_stream(tls_stream, peer, server, RequestScheme::Https).await,
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
) {
    tokio::spawn(async move {
        serve_stream(stream, peer, server, scheme).await;
    });
}

async fn serve_stream<S>(stream: S, peer: SocketAddr, server: ProxyServer, scheme: RequestScheme)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let state = server.state.clone();
    state.metrics.active_connections.inc();
    let remote_ip = peer.ip();
    let service_server = server.clone();
    let service = service_fn(move |req| {
        let server = service_server.clone();
        async move { Ok::<_, Infallible>(server.handle(req, Some(remote_ip), scheme).await) }
    });
    let io = TokioIo::new(stream);
    let builder = AutoBuilder::new(TokioExecutor::new());

    if let Err(error) = builder.serve_connection_with_upgrades(io, service).await {
        debug!(%error, "connection ended with error");
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

fn insert_static_header(headers: &mut HeaderMap, name: &'static str, value: &'static str) {
    headers.insert(
        HeaderName::from_static(name),
        HeaderValue::from_static(value),
    );
}

fn path_without_query(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
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
