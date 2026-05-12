use bytes::Bytes;
use http::{
    header::{HeaderName, HeaderValue, HOST},
    Request, Response, StatusCode, Uri,
};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as AutoBuilder,
};
use pxxl_common::{normalize_domain, PxxlError, RouteMatch, Upstream};
use pxxl_core::EdgeState;
use pxxl_ddos::SecurityDecision;
use rustls::ServerConfig;
use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
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

#[derive(Clone)]
pub struct ProxyServer {
    state: EdgeState,
    client: Client<HttpConnector, Incoming>,
}

impl ProxyServer {
    pub fn new(state: EdgeState) -> Self {
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Self { state, client }
    }

    pub async fn handle(
        &self,
        req: Request<Incoming>,
        remote_ip: Option<IpAddr>,
    ) -> Response<BoxBody> {
        let started = Instant::now();
        let method = req.method().clone();
        let host = match req.headers().get(HOST).and_then(|value| value.to_str().ok()) {
            Some(host) => host.to_string(),
            None => return text_response(StatusCode::BAD_REQUEST, "missing host header"),
        };
        let path = req
            .uri()
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
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
                    return text_response(StatusCode::FORBIDDEN, "request blocked");
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
                    let mut response = text_response(StatusCode::TOO_MANY_REQUESTS, "rate limited");
                    if let Ok(value) = HeaderValue::from_str(&retry_after.as_secs().max(1).to_string()) {
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
                return text_response(StatusCode::NOT_FOUND, "no route matched this host/path");
            }
        };

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
                return text_response(StatusCode::SERVICE_UNAVAILABLE, "no healthy upstreams");
            }
        };

        match self.forward(req, &matched, &upstream, remote_ip).await {
            Ok(response) => {
                let status = response.status();
                self.observe_request(&domain, method.as_str(), status, started, Some(&upstream.url));
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
                text_response(StatusCode::BAD_GATEWAY, "upstream request failed")
            }
        }
    }

    async fn forward(
        &self,
        mut req: Request<Incoming>,
        matched: &RouteMatch,
        upstream: &Upstream,
        remote_ip: Option<IpAddr>,
    ) -> Result<Response<BoxBody>, PxxlError> {
        let uri = build_upstream_uri(upstream, req.uri())?;
        *req.uri_mut() = uri;

        let authority = upstream.authority()?;
        req.headers_mut().insert(
            HOST,
            HeaderValue::from_str(&authority).map_err(|_| PxxlError::InvalidUpstream(upstream.url.clone()))?,
        );
        req.headers_mut().insert(
            HeaderName::from_static("x-forwarded-host"),
            HeaderValue::from_str(&matched.route.domain).map_err(|_| PxxlError::InvalidHost)?,
        );
        req.headers_mut().insert(
            HeaderName::from_static("x-forwarded-proto"),
            HeaderValue::from_static("http"),
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
            body.map_err(|error| -> BoxError { Box::new(error) }).boxed(),
        ))
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
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "HTTP proxy listening");
    run_plain_listener(listener, state, shutdown).await
}

pub async fn run_http_proxy_on_listener(
    listener: TcpListener,
    state: EdgeState,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    info!(addr = %listener.local_addr()?, "HTTP proxy listening");
    run_plain_listener(listener, state, shutdown).await
}

pub async fn run_https_proxy(
    addr: SocketAddr,
    state: EdgeState,
    tls_config: Arc<ServerConfig>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let acceptor = TlsAcceptor::from(tls_config);
    info!(%addr, "HTTPS proxy listening");
    run_tls_listener(listener, acceptor, state, shutdown).await
}

async fn run_plain_listener(
    listener: TcpListener,
    state: EdgeState,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let server = ProxyServer::new(state);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                spawn_connection(stream, peer, server.clone());
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
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let server = ProxyServer::new(state);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let acceptor = acceptor.clone();
                let server = server.clone();
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => serve_stream(tls_stream, peer, server).await,
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

fn spawn_connection(stream: TcpStream, peer: SocketAddr, server: ProxyServer) {
    tokio::spawn(async move {
        serve_stream(stream, peer, server).await;
    });
}

async fn serve_stream<S>(stream: S, peer: SocketAddr, server: ProxyServer)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let state = server.state.clone();
    state.metrics.active_connections.inc();
    let remote_ip = peer.ip();
    let service_server = server.clone();
    let service = service_fn(move |req| {
        let server = service_server.clone();
        async move { Ok::<_, Infallible>(server.handle(req, Some(remote_ip)).await) }
    });
    let io = TokioIo::new(stream);
    let builder = AutoBuilder::new(TokioExecutor::new());

    if let Err(error) = builder.serve_connection_with_upgrades(io, service).await {
        debug!(%error, "connection ended with error");
    }

    state.metrics.active_connections.dec();
}

fn text_response(status: StatusCode, message: &str) -> Response<BoxBody> {
    let body = Full::new(Bytes::from(message.to_string()))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
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
}
