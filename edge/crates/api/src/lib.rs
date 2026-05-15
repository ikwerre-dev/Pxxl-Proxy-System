use bytes::{Bytes, BytesMut};
use http::{header::AUTHORIZATION, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as AutoBuilder,
};
use ipnet::IpNet;
use pxxl_common::{
    normalize_domain, normalize_path_prefix, DomainRules, LoadBalancingAlgorithm, PathRoute, Route,
    RouteSource, Upstream, UpstreamTransport, MAX_ROUTES_PER_SOURCE,
};
use pxxl_core::EdgeState;
use pxxl_metrics::PxxlMetrics;
use pxxl_redis_sync::{RedisRouteStore, RedisTokenStore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::TcpListener,
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

#[derive(Clone)]
struct ApiServer {
    state: EdgeState,
    cert_dir: String,
    route_store: Option<RedisRouteStore>,
    auth: AdminApiAuth,
}

#[derive(Debug, Deserialize)]
struct BlacklistBody {
    ip: IpAddr,
}

#[derive(Clone)]
pub struct AdminApiAuth {
    enabled: bool,
    bootstrap_token: Option<String>,
    ip_allowlist: Vec<IpNet>,
    token_store: Option<RedisTokenStore>,
}

#[derive(Debug, Deserialize)]
struct TokenCreateBody {
    name: String,
}

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

pub async fn run_admin_api(
    addr: SocketAddr,
    state: EdgeState,
    cert_dir: impl Into<String>,
    route_store: Option<RedisRouteStore>,
    auth: AdminApiAuth,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let server = ApiServer {
        state,
        cert_dir: cert_dir.into(),
        route_store,
        auth,
    };
    info!(%addr, "admin API listening");
    run_api_listener(listener, server, shutdown).await
}

pub async fn run_metrics_server(
    addr: SocketAddr,
    metrics: Arc<PxxlMetrics>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "metrics endpoint listening");
    run_metrics_listener(listener, metrics, shutdown).await
}

impl AdminApiAuth {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            bootstrap_token: None,
            ip_allowlist: Vec::new(),
            token_store: None,
        }
    }

    pub fn new(
        enabled: bool,
        bootstrap_token: Option<String>,
        ip_allowlist: Vec<IpNet>,
        token_store: Option<RedisTokenStore>,
    ) -> Self {
        Self {
            enabled,
            bootstrap_token,
            ip_allowlist,
            token_store,
        }
    }

    async fn authorize(
        &self,
        req: &Request<Incoming>,
        remote_ip: IpAddr,
    ) -> Option<Response<BoxBody>> {
        if !self.ip_allowlist.is_empty()
            && !self
                .ip_allowlist
                .iter()
                .any(|network| network.contains(&remote_ip))
        {
            return Some(json_response(
                StatusCode::FORBIDDEN,
                json!({"error": "admin api ip is not allowed"}),
            ));
        }

        if !self.enabled || is_public_admin_path(req.method(), req.uri().path()) {
            return None;
        }

        let Some(token) = bearer_token(req) else {
            return Some(json_response(
                StatusCode::UNAUTHORIZED,
                json!({"error": "missing bearer token"}),
            ));
        };

        if self
            .bootstrap_token
            .as_deref()
            .is_some_and(|bootstrap| constant_time_eq(bootstrap.as_bytes(), token.as_bytes()))
        {
            return None;
        }

        match &self.token_store {
            Some(store) => match store.verify_token(token).await {
                Ok(true) => None,
                Ok(false) => Some(json_response(
                    StatusCode::UNAUTHORIZED,
                    json!({"error": "invalid bearer token"}),
                )),
                Err(error) => {
                    debug!(%error, "failed to verify bearer token");
                    Some(json_response(
                        StatusCode::BAD_GATEWAY,
                        json!({"error": "authentication backend unavailable"}),
                    ))
                }
            },
            None => Some(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "admin token store is not configured"}),
            )),
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
                    let builder = AutoBuilder::new(TokioExecutor::new());
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
                tokio::spawn(async move {
                    let _permit = permit;
                    let service = service_fn(move |_req| {
                        let metrics = metrics.clone();
                        async move {
                            let response = match metrics.gather() {
                                Ok(body) => text_response(StatusCode::OK, "text/plain; version=0.0.4", body),
                                Err(error) => text_response(StatusCode::INTERNAL_SERVER_ERROR, "text/plain", error.to_string()),
                            };
                            Ok::<_, Infallible>(response)
                        }
                    });
                    let io = TokioIo::new(stream);
                    let builder = AutoBuilder::new(TokioExecutor::new());
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
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("").to_string();

        if let Some(response) = self.auth.authorize(&req, remote_ip).await {
            return response;
        }

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
            (Method::GET, "/v1/routes") => json_response(
                StatusCode::OK,
                json!({ "routes": self.state.routes.snapshot() }),
            ),
            (Method::GET, "/v1/domains") => json_response(
                StatusCode::OK,
                json!({ "domains": self.state.routes.snapshot() }),
            ),
            (Method::POST, "/v1/domains") => self.create_domain(req).await,
            (Method::POST, "/v1/auth/tokens") => self.create_auth_token(req).await,
            (Method::GET, "/v1/auth/tokens") => self.list_auth_tokens().await,
            (Method::DELETE, path) if path.starts_with("/v1/auth/tokens/") => {
                self.revoke_auth_token(path).await
            }
            (Method::GET, "/v1/stats/domains") => json_response(
                StatusCode::OK,
                json!({ "domains": self.state.stats.snapshots() }),
            ),
            (Method::GET, "/v1/analytics/routes") => json_response(
                StatusCode::OK,
                json!({ "routes": self.state.stats.snapshots() }),
            ),
            (Method::GET, "/v1/analytics/visits") => {
                let limit = query_limit(&query, 50, 200);
                json_response(
                    StatusCode::OK,
                    json!({ "visits": self.state.stats.recent_visits_all(limit) }),
                )
            }
            (Method::GET, "/v1/analytics/logs") => {
                let limit = query_limit(&query, 50, 200);
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
                let limit = query_limit(&query, 50, 200);
                json_response(
                    StatusCode::OK,
                    json!({
                        "domain": normalized,
                        "visits": self.state.stats.recent_visits(&normalized, limit)
                    }),
                )
            }
            (Method::GET, path) if path.starts_with("/v1/domains/") && path.ends_with("/logs") => {
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
                let limit = query_limit(&query, 50, 200);
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
            (Method::GET, path) if path.starts_with("/v1/domains/") => {
                let domain = path.trim_start_matches("/v1/domains/").trim_matches('/');
                if domain.is_empty() {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        json!({"error": "missing domain"}),
                    );
                }
                match self.state.routes.find_domain(&normalize_domain(domain)) {
                    Some(route) => json_response(StatusCode::OK, json!({ "domain": route })),
                    None => {
                        json_response(StatusCode::NOT_FOUND, json!({"error": "domain not found"}))
                    }
                }
            }
            (Method::DELETE, path) if path.starts_with("/v1/domains/") => {
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
            (Method::GET, "/v1/certs") => json_response(
                StatusCode::OK,
                json!({
                    "mode": "local",
                    "cert_dir": self.cert_dir.clone()
                }),
            ),
            (Method::POST, path) if path.starts_with("/v1/blacklist/") => {
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
        json_response(
            StatusCode::CREATED,
            json!({
                "status": "created",
                "domain": route
            }),
        )
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

        match store.create_token(body.name).await {
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
    query
        .split('&')
        .filter_map(|part| part.split_once('='))
        .find_map(|(key, value)| {
            if key == name && !value.is_empty() {
                Some(value.to_string())
            } else {
                None
            }
        })
}

fn is_public_admin_path(method: &Method, path: &str) -> bool {
    *method == Method::GET && matches!(path, "/healthz" | "/readyz")
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

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    left.iter()
        .zip(right)
        .fold(0_u8, |acc, (left, right)| acc | (left ^ right))
        == 0
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
