use anyhow::Context;
use bytes::Bytes;
use http::{
    header::{HeaderName, HeaderValue, CACHE_CONTROL, CONTENT_TYPE, HOST},
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
    collections::HashMap,
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
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

#[derive(Clone)]
pub struct ProxyServer {
    state: EdgeState,
    client: Client<HttpConnector, Incoming>,
    error_pages: ErrorPageRenderer,
}

impl ProxyServer {
    pub fn new(state: EdgeState) -> Self {
        Self::with_error_pages(state, ErrorPageRenderer::default())
    }

    pub fn with_error_pages(state: EdgeState, error_pages: ErrorPageRenderer) -> Self {
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Self {
            state,
            client,
            error_pages,
        }
    }

    pub async fn handle(
        &self,
        req: Request<Incoming>,
        remote_ip: Option<IpAddr>,
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

        match self.forward(req, &matched, &upstream, remote_ip).await {
            Ok(response) => {
                let status = response.status();
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
    ) -> Result<Response<BoxBody>, PxxlError> {
        let uri = build_upstream_uri(upstream, req.uri())?;
        *req.uri_mut() = uri;

        let authority = upstream.authority()?;
        req.headers_mut().insert(
            HOST,
            HeaderValue::from_str(&authority)
                .map_err(|_| PxxlError::InvalidUpstream(upstream.url.clone()))?,
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
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "HTTP proxy listening");
    run_plain_listener(listener, state, error_pages, shutdown).await
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
    info!(addr = %listener.local_addr()?, "HTTP proxy listening");
    run_plain_listener(listener, state, error_pages, shutdown).await
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
    let listener = TcpListener::bind(addr).await?;
    let acceptor = TlsAcceptor::from(tls_config);
    info!(%addr, "HTTPS proxy listening");
    run_tls_listener(listener, acceptor, state, error_pages, shutdown).await
}

async fn run_plain_listener(
    listener: TcpListener,
    state: EdgeState,
    error_pages: ErrorPageRenderer,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let server = ProxyServer::with_error_pages(state, error_pages);

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
    error_pages: ErrorPageRenderer,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let server = ProxyServer::with_error_pages(state, error_pages);

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
