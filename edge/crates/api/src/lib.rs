use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as AutoBuilder,
};
use pxxl_core::EdgeState;
use pxxl_metrics::PxxlMetrics;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::{net::TcpListener, sync::watch};
use tracing::{debug, info};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type BoxBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

#[derive(Clone)]
struct ApiServer {
    state: EdgeState,
    cert_dir: String,
}

#[derive(Debug, Deserialize)]
struct BlacklistBody {
    ip: IpAddr,
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
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let server = ApiServer {
        state,
        cert_dir: cert_dir.into(),
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

async fn run_api_listener(
    listener: TcpListener,
    server: ApiServer,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let server = server.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        let server = server.clone();
                        async move { Ok::<_, Infallible>(server.handle(req).await) }
                    });
                    let io = TokioIo::new(stream);
                    let builder = AutoBuilder::new(TokioExecutor::new());
                    if let Err(error) = builder.serve_connection_with_upgrades(io, service).await {
                        debug!(%error, "admin API connection ended with error");
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
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let metrics = metrics.clone();
                tokio::spawn(async move {
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
                    if let Err(error) = builder.serve_connection_with_upgrades(io, service).await {
                        debug!(%error, "metrics connection ended with error");
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
    async fn handle(&self, req: Request<Incoming>) -> Response<BoxBody> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();

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
                json_response(StatusCode::OK, json!({ "routes": self.state.routes.snapshot() }))
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
                            path.upstreams.into_iter().map(move |upstream| UpstreamView {
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
                    return json_response(StatusCode::BAD_REQUEST, json!({"error": "missing domain_id"}));
                }

                match req.into_body().collect().await {
                    Ok(collected) => match serde_json::from_slice::<BlacklistBody>(&collected.to_bytes()) {
                        Ok(body) => {
                            self.state.security.blacklist().add(domain_id, body.ip);
                            json_response(StatusCode::OK, json!({"status": "added", "domain_id": domain_id, "ip": body.ip}))
                        }
                        Err(error) => json_response(StatusCode::BAD_REQUEST, json!({"error": error.to_string()})),
                    },
                    Err(error) => json_response(StatusCode::BAD_REQUEST, json!({"error": error.to_string()})),
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
                        json_response(StatusCode::OK, json!({"status": "removed", "domain_id": parts[0], "ip": ip}))
                    }
                    Err(error) => json_response(StatusCode::BAD_REQUEST, json!({"error": error.to_string()})),
                }
            }
            _ => json_response(StatusCode::NOT_FOUND, json!({"error": "not found"})),
        }
    }
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
