use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::service::service_fn;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as AutoBuilder,
};
use pxxl_common::{
    DomainRateLimit, DomainRules, LocationRouteRule, PathRoute, Route, RouteSource, Upstream,
};
use pxxl_core::{EdgeState, RouteRegistry};
use pxxl_ddos::{BlacklistEngine, RateLimitConfig, RateLimiter, SecurityEngine};
use pxxl_http_proxy::run_http_proxy_on_listener;
use pxxl_load_balancer::LoadBalancer;
use pxxl_metrics::PxxlMetrics;
use std::{convert::Infallible, net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, sync::watch};

#[tokio::test]
async fn proxies_http_request_by_host() {
    let upstream_addr = spawn_upstream("hello from upstream").await;
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let route = Route::new(
        "app.pxxlhost",
        vec![PathRoute::new(
            "/",
            vec![Upstream::new(format!("http://{upstream_addr}"))],
        )],
        RouteSource::Static,
    );
    let state = test_state(vec![route]);
    let server = tokio::spawn(run_http_proxy_on_listener(
        proxy_listener,
        state,
        shutdown_rx,
    ));

    let client: Client<HttpConnector, Empty<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("GET")
        .uri(format!("http://{proxy_addr}/hello"))
        .header("host", "app.pxxlhost")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let response = client.request(req).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();

    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();

    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"hello from upstream");
}

#[tokio::test]
async fn rejects_websocket_when_domain_rule_disables_it() {
    let upstream_addr = spawn_upstream("should not proxy").await;
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut route = Route::new(
        "ws.pxxlhost",
        vec![PathRoute::new(
            "/",
            vec![Upstream::new(format!("http://{upstream_addr}"))],
        )],
        RouteSource::Static,
    );
    route.rules = DomainRules {
        allow_websocket: false,
        ..DomainRules::default()
    };
    let state = test_state(vec![route]);
    let server = tokio::spawn(run_http_proxy_on_listener(
        proxy_listener,
        state,
        shutdown_rx,
    ));

    let client: Client<HttpConnector, Empty<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("GET")
        .uri(format!("http://{proxy_addr}/socket"))
        .header("host", "ws.pxxlhost")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let response = client.request(req).await.unwrap();
    let status = response.status();

    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn enforces_domain_rate_limit_rule() {
    let upstream_addr = spawn_upstream("limited").await;
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut route = Route::new(
        "limited.pxxlhost",
        vec![PathRoute::new(
            "/",
            vec![Upstream::new(format!("http://{upstream_addr}"))],
        )],
        RouteSource::Static,
    );
    route.rules = DomainRules {
        rate_limit: Some(DomainRateLimit {
            requests_per_second: Some(1),
            burst: 1,
            ..DomainRateLimit::default()
        }),
        ..DomainRules::default()
    };
    let state = test_state(vec![route]);
    let server = tokio::spawn(run_http_proxy_on_listener(
        proxy_listener,
        state,
        shutdown_rx,
    ));

    let client: Client<HttpConnector, Empty<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let first = Request::builder()
        .method("GET")
        .uri(format!("http://{proxy_addr}/"))
        .header("host", "limited.pxxlhost")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let second = Request::builder()
        .method("GET")
        .uri(format!("http://{proxy_addr}/"))
        .header("host", "limited.pxxlhost")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let first_status = client.request(first).await.unwrap().status();
    let second_status = client.request(second).await.unwrap().status();

    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();

    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(second_status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn blocks_requests_by_country_rule() {
    let upstream_addr = spawn_upstream("should not proxy").await;
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut route = Route::new(
        "geo-block.pxxlhost",
        vec![PathRoute::new(
            "/",
            vec![Upstream::new(format!("http://{upstream_addr}"))],
        )],
        RouteSource::Static,
    );
    route.rules = DomainRules {
        country_blocklist: vec!["LO".to_string()],
        ..DomainRules::default()
    };
    let state = test_state(vec![route]);
    let stats_state = state.clone();
    let server = tokio::spawn(run_http_proxy_on_listener(
        proxy_listener,
        state,
        shutdown_rx,
    ));

    let client: Client<HttpConnector, Empty<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("GET")
        .uri(format!("http://{proxy_addr}/blocked"))
        .header("host", "geo-block.pxxlhost")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let response = client.request(req).await.unwrap();
    let status = response.status();

    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();

    let visits = stats_state.stats.recent_visits("geo-block.pxxlhost", 1);
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(visits[0].location.country_code.as_deref(), Some("LO"));
}

#[tokio::test]
async fn routes_requests_by_country_rule() {
    let default_upstream_addr = spawn_upstream("default upstream").await;
    let local_upstream_addr = spawn_upstream("local upstream").await;
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut route = Route::new(
        "geo-route.pxxlhost",
        vec![PathRoute::new(
            "/",
            vec![Upstream::new(format!("http://{default_upstream_addr}"))],
        )],
        RouteSource::Static,
    );
    route.rules = DomainRules {
        location_routes: vec![LocationRouteRule {
            name: Some("local".to_string()),
            countries: vec!["LO".to_string()],
            continents: Vec::new(),
            upstreams: vec![Upstream::new(format!("http://{local_upstream_addr}"))],
        }],
        ..DomainRules::default()
    };
    let state = test_state(vec![route]);
    let server = tokio::spawn(run_http_proxy_on_listener(
        proxy_listener,
        state,
        shutdown_rx,
    ));

    let client: Client<HttpConnector, Empty<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("GET")
        .uri(format!("http://{proxy_addr}/"))
        .header("host", "geo-route.pxxlhost")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let response = client.request(req).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();

    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();

    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"local upstream");
}

async fn spawn_upstream(body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service = service_fn(move |_req| async move {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                        body.as_bytes(),
                    ))))
                });
                let io = TokioIo::new(stream);
                let builder = AutoBuilder::new(TokioExecutor::new());
                let _ = builder.serve_connection_with_upgrades(io, service).await;
            });
        }
    });

    addr
}

fn test_state(routes: Vec<Route>) -> EdgeState {
    let metrics = Arc::new(PxxlMetrics::new().unwrap());
    let blacklist = Arc::new(BlacklistEngine::new());
    let rate_limiter = Arc::new(RateLimiter::new(RateLimitConfig {
        requests_per_second: 1000,
        burst: 1000,
    }));
    let security = Arc::new(SecurityEngine::new(blacklist, rate_limiter));
    let registry = Arc::new(RouteRegistry::new(routes));
    let load_balancer = Arc::new(LoadBalancer::new());

    EdgeState::new(registry, security, load_balancer, metrics)
}
