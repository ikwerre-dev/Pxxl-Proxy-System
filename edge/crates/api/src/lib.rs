use bytes::{Bytes, BytesMut};
use http::{header::AUTHORIZATION, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder as AutoBuilder,
};
use ipnet::IpNet;
use pxxl_common::{
    ip_allowed_for_upstream, normalize_domain, normalize_path_prefix, DomainRules,
    LoadBalancingAlgorithm, MiddlewareDefinition, PathRoute, Route, RouteSource, Upstream,
    UpstreamTransport, MAX_ROUTES_PER_SOURCE,
};
use pxxl_core::EdgeState;
use pxxl_database_proxy::{DatabaseProxyRoute, DatabaseRouteRegistry};
use pxxl_metrics::PxxlMetrics;
use pxxl_redis_sync::{RedisRouteStore, RedisTokenStore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, UNIX_EPOCH},
};
use tokio::{
    net::TcpListener,
    process::Command,
    sync::{watch, Semaphore},
    time,
};
use tracing::{debug, info};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type BoxBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;
const ADMIN_BODY_LIMIT_BYTES: u64 = 1024 * 1024;
const ADMIN_TOKEN_NAME_MAX_BYTES: usize = 128;
const API_CONNECTION_TIMEOUT_SECONDS: u64 = 120;
const API_MAX_CONNECTIONS: usize = 2048;
const SCOPE_ADMIN: &str = "admin";
const SCOPE_ROUTES_READ: &str = "routes:read";
const SCOPE_ROUTES_WRITE: &str = "routes:write";
const SCOPE_TOKENS_READ: &str = "tokens:read";
const SCOPE_TOKENS_WRITE: &str = "tokens:write";
const SCOPE_ANALYTICS_READ: &str = "analytics:read";
const ADMIN_LOGIN_MAX_ATTEMPTS: u32 = 5;
const ADMIN_LOGIN_WINDOW: Duration = Duration::from_secs(10 * 60);
const ANALYTICS_RECENT_LIMIT_MAX: usize = 5000;

#[derive(Clone)]
struct ApiServer {
    state: EdgeState,
    cert_dir: String,
    tls_status: TlsCertificateRuntimeStatus,
    route_store: Option<RedisRouteStore>,
    database_routes: Option<DatabaseRouteRegistry>,
    auth: AdminApiAuth,
}

#[derive(Clone)]
pub struct AdminApiRuntime {
    pub state: EdgeState,
    pub cert_dir: String,
    pub tls_status: TlsCertificateRuntimeStatus,
    pub route_store: Option<RedisRouteStore>,
    pub database_routes: Option<DatabaseRouteRegistry>,
    pub auth: AdminApiAuth,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TlsCertificateRuntimeSnapshot {
    pub last_attempt_unix_ms: Option<u128>,
    pub last_success_unix_ms: Option<u128>,
    pub last_error_unix_ms: Option<u128>,
    pub last_error: Option<String>,
    pub last_error_stage: Option<String>,
    pub last_domains: Vec<String>,
    pub exhausted_domains: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct TlsCertificateRuntimeStatus {
    inner: Arc<Mutex<TlsCertificateRuntimeSnapshot>>,
}

impl TlsCertificateRuntimeStatus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_success(&self, domains: Vec<String>) {
        if let Ok(mut status) = self.inner.lock() {
            let now = unix_now_ms();
            status.last_attempt_unix_ms = Some(now);
            status.last_success_unix_ms = Some(now);
            status.last_error = None;
            status.last_error_stage = None;
            status.last_domains = domains;
            status.exhausted_domains.clear();
        }
    }

    pub fn mark_error(&self, stage: impl Into<String>, error: impl ToString, domains: Vec<String>) {
        if let Ok(mut status) = self.inner.lock() {
            let now = unix_now_ms();
            status.last_attempt_unix_ms = Some(now);
            status.last_error_unix_ms = Some(now);
            status.last_error = Some(error.to_string());
            status.last_error_stage = Some(stage.into());
            status.last_domains = domains;
        }
    }

    pub fn mark_exhausted(&self, domains: Vec<String>) {
        if let Ok(mut status) = self.inner.lock() {
            status.exhausted_domains = domains;
        }
    }

    pub fn snapshot(&self) -> TlsCertificateRuntimeSnapshot {
        self.inner
            .lock()
            .map(|status| status.clone())
            .unwrap_or_default()
    }
}

fn unix_now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

#[derive(Debug, Deserialize)]
struct BlacklistBody {
    ip: IpAddr,
}

#[derive(Clone)]
pub struct AdminApiAuth {
    enabled: bool,
    bootstrap_token: Option<String>,
    bootstrap_token_permanent: bool,
    ip_allowlist: Vec<IpNet>,
    token_store: Option<RedisTokenStore>,
    login_account: Option<AdminLoginAccount>,
}

#[derive(Clone)]
pub struct AdminLoginAccount {
    email: String,
    password_hash: PasswordHashSpec,
}

#[derive(Clone)]
struct PasswordHashSpec {
    iterations: u32,
    salt: String,
    hash: Vec<u8>,
}

#[derive(Clone, Debug)]
struct AdminPrincipal {
    scopes: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct MetricsAuth {
    bearer_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenCreateBody {
    name: String,
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LoginBody {
    email: String,
    password: String,
}

#[derive(Clone, Debug)]
struct LoginAttemptWindow {
    failures: u32,
    expires_at: std::time::Instant,
}

static ADMIN_LOGIN_ATTEMPTS: OnceLock<Mutex<HashMap<String, LoginAttemptWindow>>> = OnceLock::new();

#[derive(Debug, Deserialize)]
struct DomainRouteBody {
    domain: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    tls: Option<bool>,
    #[serde(default)]
    algorithm: LoadBalancingAlgorithm,
    #[serde(default)]
    upstreams: Vec<UpstreamBody>,
    #[serde(default)]
    paths: Vec<PathBody>,
    #[serde(default)]
    rules: DomainRules,
}

#[derive(Debug, Deserialize)]
struct PathBody {
    #[serde(default = "root_path")]
    prefix: String,
    #[serde(default)]
    upstreams: Vec<UpstreamBody>,
    #[serde(default)]
    middlewares: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct UpstreamBody {
    url: String,
    #[serde(default = "default_weight")]
    weight: u32,
    #[serde(default)]
    backup: bool,
    #[serde(default)]
    transport: UpstreamTransport,
}

#[derive(Debug, Serialize)]
struct UpstreamView {
    route_id: String,
    domain: String,
    path: String,
    url: String,
    healthy: bool,
    weight: u32,
}

#[derive(Debug, Serialize)]
struct CertificateDomainStatus {
    domain: String,
    tls_enabled: bool,
    covered: bool,
    status: &'static str,
    reason: &'static str,
    dedicated: bool,
}

#[derive(Debug, Serialize)]
struct CertificateStatusResponse {
    mode: &'static str,
    cert_dir: String,
    cert_path: String,
    key_path: String,
    generated: bool,
    cert_modified_unix_ms: Option<u128>,
    domains: Vec<CertificateDomainStatus>,
    runtime: TlsCertificateRuntimeSnapshot,
}

#[derive(Debug, Deserialize)]
struct DatabaseRouteBody {
    #[serde(rename = "type", alias = "database_type")]
    database_type: String,
    key: String,
    upstream: String,
}

pub async fn run_admin_api(
    addr: SocketAddr,
    runtime: AdminApiRuntime,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let server = ApiServer {
        state: runtime.state,
        cert_dir: runtime.cert_dir,
        tls_status: runtime.tls_status,
        route_store: runtime.route_store,
        database_routes: runtime.database_routes,
        auth: runtime.auth,
    };
    info!(%addr, "admin API listening");
    run_api_listener(listener, server, shutdown).await
}

pub async fn run_metrics_server(
    addr: SocketAddr,
    metrics: Arc<PxxlMetrics>,
    auth: MetricsAuth,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "metrics endpoint listening");
    run_metrics_listener(listener, metrics, auth, shutdown).await
}

impl AdminApiAuth {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            bootstrap_token: None,
            bootstrap_token_permanent: false,
            ip_allowlist: Vec::new(),
            token_store: None,
            login_account: None,
        }
    }

    pub fn new(
        enabled: bool,
        bootstrap_token: Option<String>,
        bootstrap_token_permanent: bool,
        ip_allowlist: Vec<IpNet>,
        token_store: Option<RedisTokenStore>,
        login_account: Option<AdminLoginAccount>,
    ) -> Self {
        Self {
            enabled,
            bootstrap_token,
            bootstrap_token_permanent,
            ip_allowlist,
            token_store,
            login_account,
        }
    }

    async fn authorize(
        &self,
        req: &Request<Incoming>,
        remote_ip: IpAddr,
    ) -> std::result::Result<AdminPrincipal, Response<BoxBody>> {
        if !self.ip_allowlist.is_empty()
            && !self
                .ip_allowlist
                .iter()
                .any(|network| network.contains(&remote_ip))
        {
            return Err(json_response(
                StatusCode::FORBIDDEN,
                json!({"error": "admin api ip is not allowed"}),
            ));
        }

        if is_public_admin_path(req.method(), req.uri().path()) {
            return Ok(AdminPrincipal::admin());
        }
        if !self.enabled {
            return Err(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "admin auth is disabled"}),
            ));
        }

        let Some(token) = bearer_token(req) else {
            return Err(json_response(
                StatusCode::UNAUTHORIZED,
                json!({"error": "missing bearer token"}),
            ));
        };

        if self
            .bootstrap_token
            .as_deref()
            .is_some_and(|bootstrap| constant_time_eq(bootstrap.as_bytes(), token.as_bytes()))
        {
            if self.bootstrap_token_permanent {
                return Ok(AdminPrincipal::admin());
            }
            let Some(store) = &self.token_store else {
                return Err(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    json!({"error": "admin token store is not configured"}),
                ));
            };
            return match store.list_tokens().await {
                Ok(tokens) if tokens.is_empty() => Ok(AdminPrincipal::admin()),
                Ok(_) => Err(json_response(
                    StatusCode::UNAUTHORIZED,
                    json!({"error": "bootstrap token expired after first admin token"}),
                )),
                Err(error) => {
                    debug!(%error, "failed to verify bootstrap token lifecycle");
                    Err(json_response(
                        StatusCode::BAD_GATEWAY,
                        json!({"error": "authentication backend unavailable"}),
                    ))
                }
            };
        }

        match &self.token_store {
            Some(store) => match store.verify_token(token).await {
                Ok(Some(token)) => Ok(AdminPrincipal::new(token.scopes)),
                Ok(None) => Err(json_response(
                    StatusCode::UNAUTHORIZED,
                    json!({"error": "invalid bearer token"}),
                )),
                Err(error) => {
                    debug!(%error, "failed to verify bearer token");
                    Err(json_response(
                        StatusCode::BAD_GATEWAY,
                        json!({"error": "authentication backend unavailable"}),
                    ))
                }
            },
            None => Err(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "admin token store is not configured"}),
            )),
        }
    }
}

impl AdminLoginAccount {
    pub fn new(email: impl Into<String>, password_hash: impl AsRef<str>) -> Result<Self, String> {
        let email = normalize_login_email(&email.into())
            .ok_or_else(|| "admin email must be a valid email-like value".to_string())?;
        let password_hash = PasswordHashSpec::parse(password_hash.as_ref())?;
        Ok(Self {
            email,
            password_hash,
        })
    }

    fn email(&self) -> &str {
        &self.email
    }

    fn token_name(&self) -> String {
        format!("account:{}", self.email)
    }

    fn verify(&self, email: &str, password: &str) -> bool {
        let Some(email) = normalize_login_email(email) else {
            return false;
        };

        if !constant_time_eq(email.as_bytes(), self.email.as_bytes()) {
            return false;
        }

        self.password_hash.verify(password.as_bytes())
    }
}

impl PasswordHashSpec {
    fn parse(encoded: &str) -> Result<Self, String> {
        let parts = encoded.split(':').collect::<Vec<_>>();
        if parts.len() != 4 || parts[0] != "pbkdf2-sha256" {
            return Err(
                "admin password hash must use pbkdf2-sha256:<iterations>:<salt>:<hash>".to_string(),
            );
        }

        let iterations = parts[1]
            .parse::<u32>()
            .map_err(|_| "admin password hash iterations must be a positive integer".to_string())?;
        if !(10_000..=1_000_000).contains(&iterations) {
            return Err(
                "admin password hash iterations must be between 10000 and 1000000".to_string(),
            );
        }

        let salt = parts[2].to_string();
        if salt.len() < 16 || !salt.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("admin password hash salt must be at least 16 hex characters".to_string());
        }

        let hash = decode_hex(parts[3])?;
        if hash.len() != 32 {
            return Err("admin password hash must be a 32-byte SHA-256 derived key".to_string());
        }

        Ok(Self {
            iterations,
            salt,
            hash,
        })
    }

    fn verify(&self, password: &[u8]) -> bool {
        let derived = pbkdf2_sha256(
            password,
            self.salt.as_bytes(),
            self.iterations,
            self.hash.len(),
        );
        constant_time_eq(&derived, &self.hash)
    }
}

impl AdminPrincipal {
    fn admin() -> Self {
        Self {
            scopes: vec![SCOPE_ADMIN.to_string()],
        }
    }

    fn new(scopes: Vec<String>) -> Self {
        let scopes = normalize_scopes(scopes);
        Self { scopes }
    }

    fn has_scope(&self, scope: &str) -> bool {
        self.scopes
            .iter()
            .any(|value| value == SCOPE_ADMIN || value == scope)
    }
}

impl MetricsAuth {
    pub fn new(bearer_token: Option<String>) -> Self {
        Self { bearer_token }
    }

    fn authorize(&self, req: &Request<Incoming>) -> Option<Response<BoxBody>> {
        let expected = self.bearer_token.as_deref()?;
        let Some(token) = bearer_token(req) else {
            return Some(text_response(
                StatusCode::UNAUTHORIZED,
                "text/plain",
                "missing bearer token",
            ));
        };
        if constant_time_eq(expected.as_bytes(), token.as_bytes()) {
            None
        } else {
            Some(text_response(
                StatusCode::UNAUTHORIZED,
                "text/plain",
                "invalid bearer token",
            ))
        }
    }
}

async fn run_api_listener(
    listener: TcpListener,
    server: ApiServer,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let limiter = Arc::new(Semaphore::new(API_MAX_CONNECTIONS));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let Ok(permit) = limiter.clone().try_acquire_owned() else {
                    debug!(peer = %peer, "admin API connection limit reached");
                    continue;
                };
                let server = server.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let service = service_fn(move |req| {
                        let server = server.clone();
                        async move { Ok::<_, Infallible>(server.handle(req, peer.ip()).await) }
                    });
                    let io = TokioIo::new(stream);
                    let builder = hardened_auto_builder();
                    match time::timeout(
                        Duration::from_secs(API_CONNECTION_TIMEOUT_SECONDS),
                        builder.serve_connection_with_upgrades(io, service),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => debug!(%error, "admin API connection ended with error"),
                        Err(_) => debug!("admin API connection timed out"),
                    }
                });
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    info!("stopping admin API");
                    break;
                }
            }
        }
    }

    Ok(())
}

async fn run_metrics_listener(
    listener: TcpListener,
    metrics: Arc<PxxlMetrics>,
    auth: MetricsAuth,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let limiter = Arc::new(Semaphore::new(API_MAX_CONNECTIONS));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = limiter.clone().try_acquire_owned() else {
                    debug!("metrics connection limit reached");
                    continue;
                };
                let metrics = metrics.clone();
                let auth = auth.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let service = service_fn(move |req| {
                        let metrics = metrics.clone();
                        let auth = auth.clone();
                        async move {
                            if let Some(response) = auth.authorize(&req) {
                                return Ok::<_, Infallible>(response);
                            }
                            let response = match metrics.gather() {
                                Ok(body) => text_response(StatusCode::OK, "text/plain; version=0.0.4", body),
                                Err(error) => text_response(StatusCode::INTERNAL_SERVER_ERROR, "text/plain", error.to_string()),
                            };
                            Ok::<_, Infallible>(response)
                        }
                    });
                    let io = TokioIo::new(stream);
                    let builder = hardened_auto_builder();
                    match time::timeout(
                        Duration::from_secs(API_CONNECTION_TIMEOUT_SECONDS),
                        builder.serve_connection_with_upgrades(io, service),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => debug!(%error, "metrics connection ended with error"),
                        Err(_) => debug!("metrics connection timed out"),
                    }
                });
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    info!("stopping metrics endpoint");
                    break;
                }
            }
        }
    }

    Ok(())
}

impl ApiServer {
    async fn handle(&self, req: Request<Incoming>, remote_ip: IpAddr) -> Response<BoxBody> {
        if req
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > ADMIN_BODY_LIMIT_BYTES)
        {
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({"error": "request body is too large"}),
            );
        }
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("").to_string();

        let principal = match self.auth.authorize(&req, remote_ip).await {
            Ok(principal) => principal,
            Err(response) => return response,
        };

        match (method, path.as_str()) {
            (Method::GET, "/healthz") => json_response(StatusCode::OK, json!({"status": "ok"})),
            (Method::GET, "/readyz") => {
                let routes = self.state.routes.snapshot();
                json_response(
                    StatusCode::OK,
                    json!({
                        "status": "ready",
                        "routes": routes.len()
                    }),
                )
            }
            (Method::GET, "/v1/routes") => {
                if let Some(response) = require_scope(&principal, SCOPE_ROUTES_READ) {
                    return response;
                }
                json_response(
                    StatusCode::OK,
                    json!({ "routes": redact_routes(self.state.routes.snapshot()) }),
                )
            }
            (Method::GET, "/v1/domains") => {
                if let Some(response) = require_scope(&principal, SCOPE_ROUTES_READ) {
                    return response;
                }
                json_response(
                    StatusCode::OK,
                    json!({ "domains": redact_routes(self.state.routes.snapshot()) }),
                )
            }
            (Method::POST, "/v1/domains") => {
                if let Some(response) = require_scope(&principal, SCOPE_ROUTES_WRITE) {
                    return response;
                }
                self.create_domain(req).await
            }
            (Method::POST, "/v1/auth/login") => self.login(req, remote_ip).await,
            (Method::POST, "/v1/auth/tokens") => {
                if let Some(response) = require_scope(&principal, SCOPE_TOKENS_WRITE) {
                    return response;
                }
                self.create_auth_token(req).await
            }
            (Method::GET, "/v1/auth/tokens") => {
                if let Some(response) = require_scope(&principal, SCOPE_TOKENS_READ) {
                    return response;
                }
                self.list_auth_tokens().await
            }
            (Method::DELETE, path) if path.starts_with("/v1/auth/tokens/") => {
                if let Some(response) = require_scope(&principal, SCOPE_TOKENS_WRITE) {
                    return response;
                }
                self.revoke_auth_token(path).await
            }
            (Method::GET, "/v1/stats/domains") => {
                if let Some(response) = require_scope(&principal, SCOPE_ANALYTICS_READ) {
                    return response;
                }
                json_response(
                    StatusCode::OK,
                    json!({ "domains": self.state.stats.snapshots() }),
                )
            }
            (Method::GET, "/v1/analytics/routes") => {
                if let Some(response) = require_scope(&principal, SCOPE_ANALYTICS_READ) {
                    return response;
                }
                json_response(
                    StatusCode::OK,
                    json!({ "routes": self.state.stats.snapshots() }),
                )
            }
            (Method::GET, "/v1/analytics/visits") => {
                if let Some(response) = require_scope(&principal, SCOPE_ANALYTICS_READ) {
                    return response;
                }
                let limit = query_limit(&query, 50, ANALYTICS_RECENT_LIMIT_MAX);
                json_response(
                    StatusCode::OK,
                    json!({ "visits": self.state.stats.recent_visits_all(limit) }),
                )
            }
            (Method::GET, "/v1/analytics/logs") => {
                if let Some(response) = require_scope(&principal, SCOPE_ANALYTICS_READ) {
                    return response;
                }
                let limit = query_limit(&query, 50, ANALYTICS_RECENT_LIMIT_MAX);
                let request_id = query_value(&query, "request_id");
                let logs = request_id
                    .as_deref()
                    .map(|request_id| {
                        self.state
                            .stats
                            .recent_visits_by_request_id(request_id, limit)
                    })
                    .unwrap_or_else(|| self.state.stats.recent_visits_all(limit));
                json_response(
                    StatusCode::OK,
                    json!({
                        "request_id": request_id,
                        "logs": logs
                    }),
                )
            }
            (Method::GET, path) if path.starts_with("/v1/domains/") && path.ends_with("/stats") => {
                if let Some(response) = require_scope(&principal, SCOPE_ANALYTICS_READ) {
                    return response;
                }
                let domain = path
                    .trim_start_matches("/v1/domains/")
                    .trim_end_matches("/stats")
                    .trim_matches('/');
                if domain.is_empty() {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        json!({"error": "missing domain"}),
                    );
                }
                let normalized = normalize_domain(domain);
                match self.state.stats.snapshot_domain(&normalized) {
                    Some(stats) => json_response(StatusCode::OK, json!({ "stats": stats })),
                    None => json_response(
                        StatusCode::OK,
                        json!({
                            "stats": {
                                "domain": normalized,
                                "requests_total": 0,
                                "responses_2xx": 0,
                                "responses_3xx": 0,
                                "responses_4xx": 0,
                                "responses_5xx": 0,
                                "average_latency_ms": 0.0,
                                "last_status": null,
                                "last_seen_unix_ms": null,
                                "top_countries": [],
                                "top_continents": [],
                                "top_paths": [],
                                "top_upstreams": []
                            }
                        }),
                    ),
                }
            }
            (Method::GET, path)
                if path.starts_with("/v1/domains/") && path.ends_with("/visits") =>
            {
                if let Some(response) = require_scope(&principal, SCOPE_ANALYTICS_READ) {
                    return response;
                }
                let domain = path
                    .trim_start_matches("/v1/domains/")
                    .trim_end_matches("/visits")
                    .trim_matches('/');
                if domain.is_empty() {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        json!({"error": "missing domain"}),
                    );
                }
                let normalized = normalize_domain(domain);
                let limit = query_limit(&query, 50, ANALYTICS_RECENT_LIMIT_MAX);
                json_response(
                    StatusCode::OK,
                    json!({
                        "domain": normalized,
                        "visits": self.state.stats.recent_visits(&normalized, limit)
                    }),
                )
            }
            (Method::GET, path) if path.starts_with("/v1/domains/") && path.ends_with("/logs") => {
                if let Some(response) = require_scope(&principal, SCOPE_ANALYTICS_READ) {
                    return response;
                }
                let domain = path
                    .trim_start_matches("/v1/domains/")
                    .trim_end_matches("/logs")
                    .trim_matches('/');
                if domain.is_empty() {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        json!({"error": "missing domain"}),
                    );
                }
                let normalized = normalize_domain(domain);
                let limit = query_limit(&query, 50, ANALYTICS_RECENT_LIMIT_MAX);
                let request_id = query_value(&query, "request_id");
                let logs = request_id
                    .as_deref()
                    .map(|request_id| {
                        self.state.stats.recent_visits_for_domain_by_request_id(
                            &normalized,
                            request_id,
                            limit,
                        )
                    })
                    .unwrap_or_else(|| self.state.stats.recent_visits(&normalized, limit));
                json_response(
                    StatusCode::OK,
                    json!({
                        "domain": normalized,
                        "request_id": request_id,
                        "logs": logs
                    }),
                )
            }
            (Method::GET, path) if path.starts_with("/v1/domains/") && path.ends_with("/cert") => {
                if let Some(response) = require_scope(&principal, SCOPE_ROUTES_READ) {
                    return response;
                }
                let domain = path
                    .trim_start_matches("/v1/domains/")
                    .trim_end_matches("/cert")
                    .trim_matches('/');
                if domain.is_empty() {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        json!({"error": "missing domain"}),
                    );
                }
                json_response(
                    StatusCode::OK,
                    json!({ "certificate": self.certificate_status(Some(domain)).await }),
                )
            }
            (Method::POST, path)
                if path.starts_with("/v1/domains/") && path.ends_with("/cert/resync") =>
            {
                if let Some(response) = require_scope(&principal, SCOPE_ROUTES_WRITE) {
                    return response;
                }
                let domain = path
                    .trim_start_matches("/v1/domains/")
                    .trim_end_matches("/cert/resync")
                    .trim_matches('/');
                if domain.is_empty() {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        json!({"error": "missing domain"}),
                    );
                }
                self.resync_domain_certificate(domain).await
            }
            (Method::GET, path) if path.starts_with("/v1/domains/") => {
                if let Some(response) = require_scope(&principal, SCOPE_ROUTES_READ) {
                    return response;
                }
                let domain = path.trim_start_matches("/v1/domains/").trim_matches('/');
                if domain.is_empty() {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        json!({"error": "missing domain"}),
                    );
                }
                match self.state.routes.find_domain(&normalize_domain(domain)) {
                    Some(route) => {
                        json_response(StatusCode::OK, json!({ "domain": redact_route(route) }))
                    }
                    None => {
                        json_response(StatusCode::NOT_FOUND, json!({"error": "domain not found"}))
                    }
                }
            }
            (Method::DELETE, path) if path.starts_with("/v1/domains/") => {
                if let Some(response) = require_scope(&principal, SCOPE_ROUTES_WRITE) {
                    return response;
                }
                let domain =
                    normalize_domain(path.trim_start_matches("/v1/domains/").trim_matches('/'));
                if domain.is_empty() {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        json!({"error": "missing domain"}),
                    );
                }
                let memory_deleted = self.state.delete_api_domain(&domain);
                let store_deleted = match &self.route_store {
                    Some(store) => match store.delete_domain(&domain).await {
                        Ok(deleted) => deleted,
                        Err(error) => {
                            return json_response(
                                StatusCode::BAD_GATEWAY,
                                json!({"error": format!("failed to delete Redis route: {error}")}),
                            );
                        }
                    },
                    None => false,
                };
                json_response(
                    StatusCode::OK,
                    json!({
                        "status": "deleted",
                        "domain": domain,
                        "memory_deleted": memory_deleted,
                        "store_deleted": store_deleted
                    }),
                )
            }
            (Method::GET, "/v1/upstreams") => {
                if let Some(response) = require_scope(&principal, SCOPE_ROUTES_READ) {
                    return response;
                }
                let upstreams = self
                    .state
                    .routes
                    .snapshot()
                    .into_iter()
                    .flat_map(|route| {
                        route.paths.into_iter().flat_map(move |path| {
                            let route_id = route.id.clone();
                            let domain = route.domain.clone();
                            let prefix = path.prefix.clone();
                            path.upstreams
                                .into_iter()
                                .map(move |upstream| UpstreamView {
                                    route_id: route_id.clone(),
                                    domain: domain.clone(),
                                    path: prefix.clone(),
                                    url: upstream.url,
                                    healthy: upstream.healthy,
                                    weight: upstream.weight,
                                })
                        })
                    })
                    .collect::<Vec<_>>();
                json_response(StatusCode::OK, json!({ "upstreams": upstreams }))
            }
            (Method::GET, "/v1/database-routes") => {
                if let Some(response) = require_scope(&principal, SCOPE_ROUTES_READ) {
                    return response;
                }
                self.list_database_routes()
            }
            (Method::POST, "/v1/database-routes") => {
                if let Some(response) = require_scope(&principal, SCOPE_ROUTES_WRITE) {
                    return response;
                }
                self.upsert_database_route(req).await
            }
            (Method::GET, path)
                if path.starts_with("/v1/domains/") && path.ends_with("/bandwidth") =>
            {
                if let Some(response) = require_scope(&principal, SCOPE_ANALYTICS_READ) {
                    return response;
                }
                let domain = path
                    .trim_start_matches("/v1/domains/")
                    .trim_end_matches("/bandwidth")
                    .trim_matches('/');
                if domain.is_empty() {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        json!({"error": "missing domain"}),
                    );
                }
                self.get_bandwidth_usage(&normalize_domain(domain)).await
            }
            (Method::GET, path)
                if path.starts_with("/v1/domains/") && path.ends_with("/bandwidth/history") =>
            {
                if let Some(response) = require_scope(&principal, SCOPE_ANALYTICS_READ) {
                    return response;
                }
                let domain = path
                    .trim_start_matches("/v1/domains/")
                    .trim_end_matches("/bandwidth/history")
                    .trim_matches('/');
                if domain.is_empty() {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        json!({"error": "missing domain"}),
                    );
                }
                let months = query_value(&query, "months")
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(6);
                self.get_bandwidth_history(&normalize_domain(domain), months)
                    .await
            }
            (Method::GET, path)
                if path.starts_with("/v1/domains/") && path.ends_with("/bandwidth/realtime") =>
            {
                if let Some(response) = require_scope(&principal, SCOPE_ANALYTICS_READ) {
                    return response;
                }
                let domain = path
                    .trim_start_matches("/v1/domains/")
                    .trim_end_matches("/bandwidth/realtime")
                    .trim_matches('/');
                if domain.is_empty() {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        json!({"error": "missing domain"}),
                    );
                }
                let hours = query_value(&query, "hours")
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(24);
                self.get_bandwidth_realtime(&normalize_domain(domain), hours)
                    .await
            }
            (Method::DELETE, path) if path.starts_with("/v1/database-routes/") => {
                if let Some(response) = require_scope(&principal, SCOPE_ROUTES_WRITE) {
                    return response;
                }
                self.delete_database_route(path).await
            }
            (Method::GET, "/v1/certs") => json_response(
                StatusCode::OK,
                json!({ "certificate": self.certificate_status(None).await }),
            ),
            (Method::GET, "/v1/certs/public") => {
                if let Some(response) = require_scope(&principal, SCOPE_ROUTES_READ) {
                    return response;
                }
                self.download_public_certificate().await
            }
            (Method::POST, path) if path.starts_with("/v1/blacklist/") => {
                if let Some(response) = require_scope(&principal, SCOPE_ROUTES_WRITE) {
                    return response;
                }
                let domain_id = path.trim_start_matches("/v1/blacklist/").trim_matches('/');
                if domain_id.is_empty() {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        json!({"error": "missing domain_id"}),
                    );
                }

                match collect_admin_body(req.into_body()).await {
                    Ok(collected) => match serde_json::from_slice::<BlacklistBody>(&collected) {
                        Ok(body) => {
                            self.state.security.blacklist().add(domain_id, body.ip);
                            json_response(
                                StatusCode::OK,
                                json!({"status": "added", "domain_id": domain_id, "ip": body.ip}),
                            )
                        }
                        Err(error) => json_response(
                            StatusCode::BAD_REQUEST,
                            json!({"error": error.to_string()}),
                        ),
                    },
                    Err(ApiBodyError::TooLarge) => json_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        json!({"error": "request body is too large"}),
                    ),
                    Err(ApiBodyError::Body(error)) => {
                        json_response(StatusCode::BAD_REQUEST, json!({"error": error}))
                    }
                }
            }
            (Method::DELETE, path) if path.starts_with("/v1/blacklist/") => {
                if let Some(response) = require_scope(&principal, SCOPE_ROUTES_WRITE) {
                    return response;
                }
                let parts = path
                    .trim_start_matches("/v1/blacklist/")
                    .split('/')
                    .collect::<Vec<_>>();
                if parts.len() != 2 {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        json!({"error": "expected /v1/blacklist/{domain_id}/{ip}"}),
                    );
                }

                match parts[1].parse::<IpAddr>() {
                    Ok(ip) => {
                        self.state.security.blacklist().remove(parts[0], &ip);
                        json_response(
                            StatusCode::OK,
                            json!({"status": "removed", "domain_id": parts[0], "ip": ip}),
                        )
                    }
                    Err(error) => {
                        json_response(StatusCode::BAD_REQUEST, json!({"error": error.to_string()}))
                    }
                }
            }
            _ => json_response(StatusCode::NOT_FOUND, json!({"error": "not found"})),
        }
    }

    fn list_database_routes(&self) -> Response<BoxBody> {
        let Some(registry) = &self.database_routes else {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "database proxy is not configured"}),
            );
        };
        json_response(StatusCode::OK, json!({ "routes": registry.list() }))
    }

    async fn upsert_database_route(&self, req: Request<Incoming>) -> Response<BoxBody> {
        let Some(registry) = &self.database_routes else {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "database proxy is not configured"}),
            );
        };
        let collected = match collect_admin_body(req.into_body()).await {
            Ok(collected) => collected,
            Err(ApiBodyError::TooLarge) => {
                return json_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    json!({"error": "request body is too large"}),
                );
            }
            Err(ApiBodyError::Body(error)) => {
                return json_response(StatusCode::BAD_REQUEST, json!({"error": error}));
            }
        };
        let body = match serde_json::from_slice::<DatabaseRouteBody>(&collected) {
            Ok(body) => body,
            Err(error) => {
                return json_response(StatusCode::BAD_REQUEST, json!({"error": error.to_string()}));
            }
        };
        if body.database_type.trim().is_empty()
            || body.key.trim().is_empty()
            || body.upstream.trim().is_empty()
        {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": "database_type, key, and upstream are required"}),
            );
        }

        let route = DatabaseProxyRoute {
            database_type: body.database_type,
            key: body.key,
            upstream: body.upstream,
        };
        registry.upsert(route.clone());
        json_response(
            StatusCode::OK,
            json!({ "status": "upserted", "route": route }),
        )
    }

    async fn delete_database_route(&self, path: &str) -> Response<BoxBody> {
        let Some(registry) = &self.database_routes else {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "database proxy is not configured"}),
            );
        };
        let parts = path
            .trim_start_matches("/v1/database-routes/")
            .split('/')
            .collect::<Vec<_>>();
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": "expected /v1/database-routes/{type}/{key}"}),
            );
        }
        let deleted = registry.delete(parts[0], parts[1]);
        json_response(
            StatusCode::OK,
            json!({"status": if deleted { "deleted" } else { "not_found" }}),
        )
    }

    async fn create_domain(&self, req: Request<Incoming>) -> Response<BoxBody> {
        let collected = match collect_admin_body(req.into_body()).await {
            Ok(collected) => collected,
            Err(ApiBodyError::TooLarge) => {
                return json_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    json!({"error": "request body is too large"}),
                );
            }
            Err(ApiBodyError::Body(error)) => {
                return json_response(StatusCode::BAD_REQUEST, json!({"error": error}));
            }
        };
        let body = match serde_json::from_slice::<DomainRouteBody>(&collected) {
            Ok(body) => body,
            Err(error) => {
                return json_response(StatusCode::BAD_REQUEST, json!({"error": error.to_string()}));
            }
        };
        let route = match body.into_route() {
            Ok(route) => route,
            Err(error) => return json_response(StatusCode::BAD_REQUEST, json!({"error": error})),
        };
        if let Err(error) = validate_api_route_network_safety(&route).await {
            return json_response(StatusCode::BAD_REQUEST, json!({"error": error}));
        }
        let existing_api_routes = self
            .state
            .routes
            .snapshot()
            .into_iter()
            .filter(|existing| existing.source == RouteSource::Api)
            .collect::<Vec<_>>();
        let route_exists = existing_api_routes
            .iter()
            .any(|existing| existing.domain == route.domain);
        if !route_exists && existing_api_routes.len() >= MAX_ROUTES_PER_SOURCE {
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({"error": format!("api route quota exceeded: max {MAX_ROUTES_PER_SOURCE}")}),
            );
        }

        if let Some(store) = &self.route_store {
            if let Err(error) = store.upsert_route(&route).await {
                return json_response(
                    StatusCode::BAD_GATEWAY,
                    json!({"error": format!("failed to persist Redis route: {error}")}),
                );
            }
        }

        self.state.upsert_api_route(route.clone());
        let certificate = self.certificate_status(Some(&route.domain)).await;
        json_response(
            StatusCode::CREATED,
            json!({
                "status": "created",
                "domain": redact_route(route),
                "certificate": certificate
            }),
        )
    }

    async fn resync_domain_certificate(&self, domain: &str) -> Response<BoxBody> {
        let domain = normalize_domain(domain);
        if domain.is_empty()
            || domain == "localhost"
            || domain.ends_with(".local")
            || domain.ends_with(".test")
            || domain.contains('*')
            || domain.parse::<IpAddr>().is_ok()
        {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid certificate domain"}),
            );
        }

        let certbot = std::env::var("PXXL_CERTBOT_BIN").unwrap_or_else(|_| "certbot".to_string());
        let email =
            std::env::var("PXXL_ACME_EMAIL").unwrap_or_else(|_| "admin@pxxl.app".to_string());
        let webroot = PathBuf::from(
            std::env::var("PXXL_ACME_CHALLENGE_DIR")
                .unwrap_or_else(|_| "/data/acme-challenges".to_string()),
        );
        let certbot_config = PathBuf::from(
            std::env::var("PXXL_CERTBOT_CONFIG_DIR")
                .unwrap_or_else(|_| "/data/letsencrypt".to_string()),
        );
        let certbot_work = PathBuf::from(
            std::env::var("PXXL_CERTBOT_WORK_DIR")
                .unwrap_or_else(|_| "/data/letsencrypt-work".to_string()),
        );
        let certbot_logs = PathBuf::from(
            std::env::var("PXXL_CERTBOT_LOGS_DIR")
                .unwrap_or_else(|_| "/data/letsencrypt-logs".to_string()),
        );

        for dir in [&webroot, &certbot_config, &certbot_work, &certbot_logs] {
            if let Err(error) = tokio::fs::create_dir_all(dir).await {
                return json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"error": format!("failed to create certificate directory: {error}")}),
                );
            }
        }

        let cert_name = format!("pxxl-domain-{}", safe_domain_cert_name(&domain));
        let args = vec![
            "certonly".to_string(),
            "--webroot".to_string(),
            "-w".to_string(),
            webroot.display().to_string(),
            "--config-dir".to_string(),
            certbot_config.display().to_string(),
            "--work-dir".to_string(),
            certbot_work.display().to_string(),
            "--logs-dir".to_string(),
            certbot_logs.display().to_string(),
            "--cert-name".to_string(),
            cert_name.to_string(),
            "--agree-tos".to_string(),
            "--non-interactive".to_string(),
            "--email".to_string(),
            email,
            "--keep-until-expiring".to_string(),
            "-d".to_string(),
            domain.clone(),
        ];

        let output = match time::timeout(
            Duration::from_secs(180),
            Command::new(&certbot).args(&args).output(),
        )
        .await
        {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                return json_response(
                    StatusCode::BAD_GATEWAY,
                    json!({"error": format!("failed to run certbot: {error}")}),
                )
            }
            Err(_) => {
                return json_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    json!({"error": "certbot timed out while issuing certificate"}),
                )
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if !output.status.success() {
            return json_response(
                StatusCode::BAD_GATEWAY,
                json!({
                    "error": "certificate issuance failed",
                    "stdout": stdout,
                    "stderr": stderr
                }),
            );
        }

        let live_dir = certbot_config.join("live").join(cert_name);
        let domain_dir = PathBuf::from(&self.cert_dir)
            .join("domains")
            .join(safe_domain_cert_name(&domain));
        if let Err(error) = tokio::fs::create_dir_all(&domain_dir).await {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": format!("failed to create domain certificate directory: {error}")}),
            );
        }
        let cert_path = domain_dir.join("fullchain.pem");
        let key_path = domain_dir.join("privkey.pem");
        if let Err(error) = copy_certbot_bundle(&live_dir, &cert_path, &key_path).await {
            return json_response(
                StatusCode::BAD_GATEWAY,
                json!({"error": format!("certificate issued but could not be installed: {error}")}),
            );
        }

        json_response(
            StatusCode::OK,
            json!({
                "status": "issued",
                "domain": domain,
                "certPath": cert_path.display().to_string(),
                "certificate": self.certificate_status(Some(&domain)).await,
                "stdout": stdout
            }),
        )
    }

    async fn certificate_status(&self, domain_filter: Option<&str>) -> CertificateStatusResponse {
        let cert_path = PathBuf::from(&self.cert_dir).join("local-dev-cert.pem");
        let key_path = PathBuf::from(&self.cert_dir).join("local-dev-key.pem");
        let cert_meta = tokio::fs::metadata(&cert_path).await.ok();
        let key_exists = tokio::fs::metadata(&key_path).await.is_ok();
        let generated = cert_meta.is_some() && key_exists;
        let cert_modified_unix_ms = cert_meta
            .as_ref()
            .and_then(|metadata| metadata.modified().ok())
            .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_millis());

        let routes = self.state.routes.snapshot();
        let domains = match domain_filter.map(normalize_domain) {
            Some(domain) => {
                let maybe_route = routes.into_iter().find(|route| route.domain == domain);
                let dedicated = domain_certificate_exists(&self.cert_dir, &domain).await;
                vec![certificate_domain_status(
                    &domain,
                    maybe_route.as_ref(),
                    generated,
                    dedicated,
                )]
            }
            None => routes
                .iter()
                .map(|route| {
                    let dedicated = domain_certificate_exists_sync(&self.cert_dir, &route.domain);
                    certificate_domain_status(&route.domain, Some(route), generated, dedicated)
                })
                .collect(),
        };

        CertificateStatusResponse {
            mode: "sni_domain_certs",
            cert_dir: self.cert_dir.clone(),
            cert_path: cert_path.display().to_string(),
            key_path: key_path.display().to_string(),
            generated,
            cert_modified_unix_ms,
            domains,
            runtime: self.tls_status.snapshot(),
        }
    }

    async fn download_public_certificate(&self) -> Response<BoxBody> {
        let cert_path = PathBuf::from(&self.cert_dir).join("local-dev-cert.pem");
        match tokio::fs::read_to_string(&cert_path).await {
            Ok(pem) => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/x-pem-file")
                .header(
                    "content-disposition",
                    "attachment; filename=\"pxxl-proxy-public-cert.pem\"",
                )
                .body(
                    Full::new(Bytes::from(pem))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap(),
            Err(error) => json_response(
                StatusCode::NOT_FOUND,
                json!({"error": format!("public certificate is not available: {error}")}),
            ),
        }
    }

    async fn login(&self, req: Request<Incoming>, remote_ip: IpAddr) -> Response<BoxBody> {
        let Some(account) = &self.auth.login_account else {
            return json_response(
                StatusCode::NOT_FOUND,
                json!({"error": "initial admin account is not configured"}),
            );
        };
        let Some(store) = &self.auth.token_store else {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "admin token store is not configured"}),
            );
        };

        if login_attempts_exceeded(remote_ip) {
            return json_response(
                StatusCode::TOO_MANY_REQUESTS,
                json!({"error": "too many failed login attempts"}),
            );
        }

        let collected = match collect_admin_body(req.into_body()).await {
            Ok(collected) => collected,
            Err(ApiBodyError::TooLarge) => {
                return json_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    json!({"error": "request body is too large"}),
                );
            }
            Err(ApiBodyError::Body(error)) => {
                return json_response(StatusCode::BAD_REQUEST, json!({"error": error}));
            }
        };
        let body = match serde_json::from_slice::<LoginBody>(&collected) {
            Ok(body) => body,
            Err(error) => {
                return json_response(StatusCode::BAD_REQUEST, json!({"error": error.to_string()}));
            }
        };

        if !account.verify(&body.email, &body.password) {
            tokio::time::sleep(Duration::from_millis(300)).await;
            record_failed_login_attempt(remote_ip);
            return json_response(
                StatusCode::UNAUTHORIZED,
                json!({"error": "invalid email or password"}),
            );
        }
        clear_login_attempts(remote_ip);

        let token_name = account.token_name();
        if let Err(error) = store.revoke_tokens_by_name(&token_name).await {
            return json_response(
                StatusCode::BAD_GATEWAY,
                json!({"error": format!("failed to rotate previous login token: {error}")}),
            );
        }

        match store
            .create_token_with_scopes(token_name, vec![SCOPE_ADMIN.to_string()])
            .await
        {
            Ok(created) => json_response(
                StatusCode::CREATED,
                json!({
                    "account": account.email(),
                    "token": created.token,
                    "record": created.record,
                    "message": "token is shown once; log in again to rotate it"
                }),
            ),
            Err(error) => json_response(
                StatusCode::BAD_GATEWAY,
                json!({"error": format!("failed to create login token: {error}")}),
            ),
        }
    }

    async fn create_auth_token(&self, req: Request<Incoming>) -> Response<BoxBody> {
        let collected = match collect_admin_body(req.into_body()).await {
            Ok(collected) => collected,
            Err(ApiBodyError::TooLarge) => {
                return json_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    json!({"error": "request body is too large"}),
                );
            }
            Err(ApiBodyError::Body(error)) => {
                return json_response(StatusCode::BAD_REQUEST, json!({"error": error}));
            }
        };
        let body = match serde_json::from_slice::<TokenCreateBody>(&collected) {
            Ok(body) => body,
            Err(error) => {
                return json_response(StatusCode::BAD_REQUEST, json!({"error": error.to_string()}));
            }
        };
        if body.name.len() > ADMIN_TOKEN_NAME_MAX_BYTES {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": "token name is too long"}),
            );
        }

        let Some(store) = &self.auth.token_store else {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "admin token store is not configured"}),
            );
        };

        let scopes = match validate_token_scopes(body.scopes) {
            Ok(scopes) => scopes,
            Err(error) => return json_response(StatusCode::BAD_REQUEST, json!({"error": error})),
        };

        match store.create_token_with_scopes(body.name, scopes).await {
            Ok(created) => json_response(StatusCode::CREATED, json!(created)),
            Err(error) => json_response(
                StatusCode::BAD_GATEWAY,
                json!({"error": format!("failed to create admin token: {error}")}),
            ),
        }
    }

    async fn list_auth_tokens(&self) -> Response<BoxBody> {
        let Some(store) = &self.auth.token_store else {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "admin token store is not configured"}),
            );
        };

        match store.list_tokens().await {
            Ok(tokens) => json_response(StatusCode::OK, json!({ "tokens": tokens })),
            Err(error) => json_response(
                StatusCode::BAD_GATEWAY,
                json!({"error": format!("failed to list admin tokens: {error}")}),
            ),
        }
    }

    async fn revoke_auth_token(&self, path: &str) -> Response<BoxBody> {
        let id = path
            .trim_start_matches("/v1/auth/tokens/")
            .trim_matches('/');
        if id.is_empty() {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": "missing token id"}),
            );
        }

        let Some(store) = &self.auth.token_store else {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "admin token store is not configured"}),
            );
        };

        match store.revoke_token(id).await {
            Ok(deleted) => json_response(StatusCode::OK, json!({ "deleted": deleted, "id": id })),
            Err(error) => json_response(
                StatusCode::BAD_GATEWAY,
                json!({"error": format!("failed to revoke admin token: {error}")}),
            ),
        }
    }
}

impl DomainRouteBody {
    fn into_route(self) -> Result<Route, String> {
        let domain = normalize_domain(&self.domain);
        if domain.is_empty() {
            return Err("domain is required".to_string());
        }

        let paths = if self.paths.is_empty() {
            if self.upstreams.is_empty() {
                return Err("at least one upstream is required".to_string());
            }
            vec![PathRoute {
                prefix: normalize_path_prefix(self.path.unwrap_or_else(root_path)),
                upstreams: self
                    .upstreams
                    .into_iter()
                    .map(UpstreamBody::into_upstream)
                    .collect(),
                middlewares: Vec::new(),
            }]
        } else {
            self.paths
                .into_iter()
                .map(|path| {
                    if path.upstreams.is_empty() {
                        return Err("each path needs at least one upstream".to_string());
                    }
                    Ok(PathRoute {
                        prefix: normalize_path_prefix(path.prefix),
                        upstreams: path
                            .upstreams
                            .into_iter()
                            .map(UpstreamBody::into_upstream)
                            .collect(),
                        middlewares: path.middlewares,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        let mut route = Route::new(domain.clone(), paths, RouteSource::Api);
        route.id = self.id.unwrap_or_else(|| format!("api-{domain}"));
        route.tls = self.tls.unwrap_or(true);
        route.algorithm = self.algorithm;
        route.rules = self.rules;
        route.validate_for_dynamic_control_plane()?;
        Ok(route)
    }
}

impl UpstreamBody {
    fn into_upstream(self) -> Upstream {
        Upstream {
            url: self.url,
            weight: self.weight.max(1),
            healthy: true,
            backup: self.backup,
            transport: self.transport,
        }
    }
}

fn default_weight() -> u32 {
    1
}

fn root_path() -> String {
    "/".to_string()
}

fn require_scope(principal: &AdminPrincipal, scope: &str) -> Option<Response<BoxBody>> {
    (!principal.has_scope(scope)).then(|| {
        json_response(
            StatusCode::FORBIDDEN,
            json!({"error": format!("missing required scope: {scope}")}),
        )
    })
}

fn validate_token_scopes(scopes: Vec<String>) -> Result<Vec<String>, String> {
    let scopes = normalize_scopes(scopes);
    if scopes.is_empty() {
        return Err("at least one token scope is required".to_string());
    }
    for scope in &scopes {
        if !matches!(
            scope.as_str(),
            SCOPE_ADMIN
                | SCOPE_ROUTES_READ
                | SCOPE_ROUTES_WRITE
                | SCOPE_TOKENS_READ
                | SCOPE_TOKENS_WRITE
                | SCOPE_ANALYTICS_READ
        ) {
            return Err(format!("unsupported token scope: {scope}"));
        }
    }
    Ok(scopes)
}

fn normalize_scopes(scopes: Vec<String>) -> Vec<String> {
    let mut scopes = scopes
        .into_iter()
        .map(|scope| scope.trim().to_ascii_lowercase())
        .filter(|scope| !scope.is_empty())
        .collect::<Vec<_>>();
    scopes.sort();
    scopes.dedup();
    scopes
}

fn normalize_login_email(email: &str) -> Option<String> {
    let email = email.trim().to_ascii_lowercase();
    let valid = email.len() <= 254
        && email.contains('@')
        && !email.starts_with('@')
        && !email.ends_with('@')
        && !email.bytes().any(|byte| byte.is_ascii_control())
        && !email.bytes().any(|byte| byte.is_ascii_whitespace());
    valid.then_some(email)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("hex value must have an even length".to_string());
    }

    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])
                .ok_or_else(|| "hex value contains invalid characters".to_string())?;
            let low = hex_nibble(pair[1])
                .ok_or_else(|| "hex value contains invalid characters".to_string())?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, output_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(output_len);
    let mut block_index = 1_u32;

    while output.len() < output_len {
        let mut block_salt = Vec::with_capacity(salt.len() + 4);
        block_salt.extend_from_slice(salt);
        block_salt.extend_from_slice(&block_index.to_be_bytes());

        let mut previous = hmac_sha256(password, &block_salt);
        let mut block = previous;
        for _ in 1..iterations {
            previous = hmac_sha256(password, &previous);
            for (left, right) in block.iter_mut().zip(previous) {
                *left ^= right;
            }
        }

        output.extend_from_slice(&block);
        block_index = block_index.saturating_add(1);
    }

    output.truncate(output_len);
    output
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut normalized_key = [0_u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        normalized_key[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut outer = [0x5c_u8; BLOCK_SIZE];
    let mut inner = [0x36_u8; BLOCK_SIZE];
    for index in 0..BLOCK_SIZE {
        outer[index] ^= normalized_key[index];
        inner[index] ^= normalized_key[index];
    }

    let mut inner_hasher = Sha256::new();
    inner_hasher.update(inner);
    inner_hasher.update(data);
    let inner_digest = inner_hasher.finalize();

    let mut outer_hasher = Sha256::new();
    outer_hasher.update(outer);
    outer_hasher.update(inner_digest);
    outer_hasher.finalize().into()
}

fn redact_routes(routes: Vec<Route>) -> Vec<Route> {
    routes.into_iter().map(redact_route).collect()
}

async fn copy_certbot_bundle(
    live_dir: &Path,
    cert_path: &Path,
    key_path: &Path,
) -> std::io::Result<()> {
    let fullchain = tokio::fs::read(live_dir.join("fullchain.pem")).await?;
    let private_key = tokio::fs::read(live_dir.join("privkey.pem")).await?;
    if let Some(parent) = cert_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(cert_path, fullchain).await?;
    tokio::fs::write(key_path, private_key).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(cert_path, std::fs::Permissions::from_mode(0o644)).await?;
        tokio::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600)).await?;
    }
    Ok(())
}

fn certificate_domain_status(
    domain: &str,
    route: Option<&Route>,
    generated: bool,
    dedicated: bool,
) -> CertificateDomainStatus {
    match route {
        Some(route) if !route.tls => CertificateDomainStatus {
            domain: domain.to_string(),
            tls_enabled: false,
            covered: false,
            status: "disabled",
            reason: "route_tls_disabled",
            dedicated: false,
        },
        Some(_) if dedicated => CertificateDomainStatus {
            domain: domain.to_string(),
            tls_enabled: true,
            covered: true,
            status: "covered",
            reason: "dedicated_sni_certificate",
            dedicated: true,
        },
        Some(_) if generated => CertificateDomainStatus {
            domain: domain.to_string(),
            tls_enabled: true,
            covered: true,
            status: "covered",
            reason: "fallback_certificate_bundle",
            dedicated: false,
        },
        Some(_) => CertificateDomainStatus {
            domain: domain.to_string(),
            tls_enabled: true,
            covered: false,
            status: "pending",
            reason: "certificate_bundle_not_generated_yet",
            dedicated: false,
        },
        None => CertificateDomainStatus {
            domain: domain.to_string(),
            tls_enabled: false,
            covered: false,
            status: "not_found",
            reason: "domain_not_registered",
            dedicated,
        },
    }
}

async fn domain_certificate_exists(cert_dir: &str, domain: &str) -> bool {
    tokio::fs::metadata(domain_certificate_path(cert_dir, domain))
        .await
        .is_ok()
        && tokio::fs::metadata(domain_private_key_path(cert_dir, domain))
            .await
            .is_ok()
}

fn domain_certificate_exists_sync(cert_dir: &str, domain: &str) -> bool {
    domain_certificate_path(cert_dir, domain).exists()
        && domain_private_key_path(cert_dir, domain).exists()
}

fn domain_certificate_path(cert_dir: &str, domain: &str) -> PathBuf {
    PathBuf::from(cert_dir)
        .join("domains")
        .join(safe_domain_cert_name(domain))
        .join("fullchain.pem")
}

fn domain_private_key_path(cert_dir: &str, domain: &str) -> PathBuf {
    PathBuf::from(cert_dir)
        .join("domains")
        .join(safe_domain_cert_name(domain))
        .join("privkey.pem")
}

fn safe_domain_cert_name(domain: &str) -> String {
    domain
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn redact_route(mut route: Route) -> Route {
    redact_rules(&mut route.rules);
    route
}

fn redact_rules(rules: &mut DomainRules) {
    for value in rules.add_request_headers.values_mut() {
        *value = "[redacted]".to_string();
    }
    for (name, value) in rules.response_headers.iter_mut() {
        if sensitive_header_name(name) {
            *value = "[redacted]".to_string();
        }
    }
    for middleware in rules.middlewares.values_mut() {
        redact_middleware(middleware);
    }
}

fn redact_middleware(middleware: &mut MiddlewareDefinition) {
    if let Some(config) = &mut middleware.basic_auth {
        for value in config.users.values_mut() {
            *value = "[redacted]".to_string();
        }
    }
    if let Some(config) = &mut middleware.digest_auth {
        for value in config.users.values_mut() {
            *value = "[redacted]".to_string();
        }
    }
}

fn sensitive_header_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key"
    )
}

async fn validate_api_route_network_safety(route: &Route) -> Result<(), String> {
    for path in &route.paths {
        for upstream in &path.upstreams {
            validate_api_upstream_network_safety(&upstream.url).await?;
        }
    }
    for rule in &route.rules.location_routes {
        for upstream in &rule.upstreams {
            validate_api_upstream_network_safety(&upstream.url).await?;
        }
    }
    for split in &route.rules.traffic_splits {
        for upstream in &split.upstreams {
            validate_api_upstream_network_safety(&upstream.url).await?;
        }
    }
    for upstream in &route.rules.traffic_mirroring.upstreams {
        validate_api_upstream_network_safety(&upstream.url).await?;
    }
    for middleware in route.rules.middlewares.values() {
        if let Some(forward_auth) = &middleware.forward_auth {
            if forward_auth.enabled {
                validate_api_upstream_network_safety(&forward_auth.url).await?;
            }
        }
    }
    Ok(())
}

async fn validate_api_upstream_network_safety(raw: &str) -> Result<(), String> {
    let parsed = url::Url::parse(raw).map_err(|error| format!("invalid upstream URL: {error}"))?;
    let Some(host) = parsed.host_str() else {
        return Err("upstream URL needs a host".to_string());
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if reserved_host_gateway(&host) {
        if host_gateway_upstreams_allowed() {
            return Ok(());
        }
        return Err(format!(
            "reserved host-gateway upstream is not allowed: {host}"
        ));
    }
    if private_upstreams_allowed() {
        return Ok(());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !ip_allowed_for_upstream(ip) {
            return Err("unsafe upstream IP is not allowed".to_string());
        }
        return Ok(());
    }
    let Some(port) = parsed.port_or_known_default() else {
        return Err("upstream URL needs a port or known scheme default".to_string());
    };
    let lookup = time::timeout(
        Duration::from_secs(2),
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await;
    match lookup {
        Ok(Ok(addresses)) => {
            for address in addresses {
                if !ip_allowed_for_upstream(address.ip()) {
                    return Err(format!(
                        "upstream host resolves to unsafe IP: {}",
                        address.ip()
                    ));
                }
            }
            Ok(())
        }
        Ok(Err(_)) | Err(_) => Ok(()),
    }
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

fn reserved_host_gateway(host: &str) -> bool {
    matches!(host, "host.docker.internal" | "gateway.docker.internal")
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

fn query_limit(query: &str, default: usize, max: usize) -> usize {
    query
        .split('&')
        .filter_map(|part| part.split_once('='))
        .find_map(|(key, value)| {
            if key == "limit" {
                value.parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(default)
        .clamp(1, max)
}

fn query_value(query: &str, name: &str) -> Option<String> {
    url::form_urlencoded::parse(query.as_bytes()).find_map(|(key, value)| {
        if key == name && !value.is_empty() {
            Some(value.into_owned())
        } else {
            None
        }
    })
}

fn is_public_admin_path(method: &Method, path: &str) -> bool {
    (*method == Method::GET && matches!(path, "/healthz" | "/readyz"))
        || (*method == Method::POST && path == "/v1/auth/login")
}

fn bearer_token(req: &Request<Incoming>) -> Option<&str> {
    req.headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

#[derive(Debug)]
enum ApiBodyError {
    TooLarge,
    Body(String),
}

async fn collect_admin_body(mut body: Incoming) -> Result<Bytes, ApiBodyError> {
    let mut collected = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| ApiBodyError::Body(error.to_string()))?;
        if let Some(data) = frame.data_ref() {
            if collected.len() as u64 + data.len() as u64 > ADMIN_BODY_LIMIT_BYTES {
                return Err(ApiBodyError::TooLarge);
            }
            collected.extend_from_slice(data);
        }
    }
    Ok(collected.freeze())
}

impl ApiServer {
    async fn get_bandwidth_usage(&self, domain: &str) -> Response<BoxBody> {
        // Get current month bandwidth from in-memory stats
        let stats = self.state.stats.snapshot_domain(domain);

        if let Some(stats) = stats {
            json_response(
                StatusCode::OK,
                json!({
                    "domain": domain,
                    "current_month": chrono::Utc::now().format("%Y-%m").to_string(),
                    "bytes_sent": stats.total_bytes_sent,
                    "bytes_received": stats.total_bytes_received,
                    "total_bandwidth": stats.total_bandwidth,
                    "requests": stats.requests_total,
                }),
            )
        } else {
            json_response(
                StatusCode::OK,
                json!({
                    "domain": domain,
                    "current_month": chrono::Utc::now().format("%Y-%m").to_string(),
                    "bytes_sent": 0,
                    "bytes_received": 0,
                    "total_bandwidth": 0,
                    "requests": 0,
                }),
            )
        }
    }

    async fn get_bandwidth_history(&self, domain: &str, _months: u32) -> Response<BoxBody> {
        // For now, return current month data from in-memory stats
        // In production, this would query ClickHouse for historical data
        let stats = self.state.stats.snapshot_domain(domain);

        let history = if let Some(stats) = stats {
            vec![json!({
                "month": chrono::Utc::now().format("%Y-%m").to_string(),
                "bytes_sent": stats.total_bytes_sent,
                "bytes_received": stats.total_bytes_received,
                "total_bandwidth": stats.total_bandwidth,
                "requests": stats.requests_total,
            })]
        } else {
            vec![]
        };

        json_response(
            StatusCode::OK,
            json!({
                "domain": domain,
                "history": history,
            }),
        )
    }

    async fn get_bandwidth_realtime(&self, domain: &str, _hours: u32) -> Response<BoxBody> {
        // Return current stats from in-memory
        // In production, this would query ClickHouse for hourly aggregates
        let stats = self.state.stats.snapshot_domain(domain);

        let data = if let Some(stats) = stats {
            vec![json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "bytes_sent": stats.total_bytes_sent,
                "bytes_received": stats.total_bytes_received,
                "total_bandwidth": stats.total_bandwidth,
                "requests": stats.requests_total,
            })]
        } else {
            vec![]
        };

        json_response(
            StatusCode::OK,
            json!({
                "domain": domain,
                "interval": "hourly",
                "data": data,
            }),
        )
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let left = Sha256::digest(left);
    let right = Sha256::digest(right);
    left.iter()
        .zip(right)
        .fold(0_u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}

fn login_attempts() -> &'static Mutex<HashMap<String, LoginAttemptWindow>> {
    ADMIN_LOGIN_ATTEMPTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn login_attempts_exceeded(remote_ip: IpAddr) -> bool {
    let key = remote_ip.to_string();
    let now = std::time::Instant::now();
    let mut attempts = login_attempts()
        .lock()
        .expect("login attempts lock poisoned");
    attempts.retain(|_, window| now < window.expires_at);
    attempts
        .get(&key)
        .is_some_and(|window| window.failures >= ADMIN_LOGIN_MAX_ATTEMPTS)
}

fn record_failed_login_attempt(remote_ip: IpAddr) {
    let key = remote_ip.to_string();
    let now = std::time::Instant::now();
    let mut attempts = login_attempts()
        .lock()
        .expect("login attempts lock poisoned");
    attempts.retain(|_, window| now < window.expires_at);
    let window = attempts.entry(key).or_insert(LoginAttemptWindow {
        failures: 0,
        expires_at: now + ADMIN_LOGIN_WINDOW,
    });
    if now >= window.expires_at {
        window.failures = 0;
        window.expires_at = now + ADMIN_LOGIN_WINDOW;
    }
    window.failures += 1;
}

fn clear_login_attempts(remote_ip: IpAddr) {
    let key = remote_ip.to_string();
    let mut attempts = login_attempts()
        .lock()
        .expect("login attempts lock poisoned");
    attempts.remove(&key);
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response<BoxBody> {
    text_response(status, "application/json", value.to_string())
}

fn text_response(
    status: StatusCode,
    content_type: &'static str,
    body: impl Into<String>,
) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(
            Full::new(Bytes::from(body.into()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pxxl_common::{BasicAuthConfig, MiddlewareDefinition};
    use std::collections::HashMap;

    #[tokio::test]
    async fn api_network_safety_rejects_host_gateway_upstream() {
        let error = validate_api_upstream_network_safety("http://host.docker.internal:8080")
            .await
            .unwrap_err();

        assert!(error.contains("host-gateway"));
    }

    #[test]
    fn route_redaction_removes_middleware_passwords_and_added_headers() {
        let mut route = Route::new(
            "redact.example.com",
            vec![PathRoute::new(
                "/",
                vec![Upstream::new("http://example.com")],
            )],
            RouteSource::Api,
        );
        route
            .rules
            .add_request_headers
            .insert("authorization".to_string(), "Bearer secret".to_string());
        route.rules.middlewares.insert(
            "auth".to_string(),
            MiddlewareDefinition {
                basic_auth: Some(BasicAuthConfig {
                    users: HashMap::from([("robin".to_string(), "pxxl".to_string())]),
                    ..BasicAuthConfig::default()
                }),
                ..MiddlewareDefinition::default()
            },
        );

        let redacted = redact_route(route);
        let middleware = redacted.rules.middlewares.get("auth").unwrap();

        assert_eq!(
            redacted
                .rules
                .add_request_headers
                .get("authorization")
                .map(String::as_str),
            Some("[redacted]")
        );
        assert_eq!(
            middleware
                .basic_auth
                .as_ref()
                .and_then(|config| config.users.get("robin"))
                .map(String::as_str),
            Some("[redacted]")
        );
    }

    #[test]
    fn validates_token_scopes() {
        let scopes = validate_token_scopes(vec![
            "routes:read".to_string(),
            "analytics:read".to_string(),
        ])
        .unwrap();

        assert_eq!(scopes, vec!["analytics:read", "routes:read"]);
        assert!(validate_token_scopes(vec!["root".to_string()]).is_err());
    }

    #[test]
    fn verifies_initial_admin_account_password_hash() {
        let account = AdminLoginAccount::new(
            "Owner@Example.com",
            "pbkdf2-sha256:200000:0011223344556677:b8902efe5e8915505b74f56b9ede5f79346e2ca7aefd413fcf1a3794feadbed7",
        )
        .unwrap();

        assert_eq!(account.email(), "owner@example.com");
        assert!(account.verify("owner@example.com", "test-password"));
        assert!(!account.verify("owner@example.com", "wrong-password"));
        assert!(!account.verify("other@example.com", "test-password"));
    }
}
