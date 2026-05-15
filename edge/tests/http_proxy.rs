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
    BasicAuthConfig, CompressionConfig, DomainRateLimit, DomainRules, DomainWafRules,
    LocationRouteRule, MiddlewareDefinition, PathRoute, RetryConfig, Route, RouteSource,
    StickySessionConfig, TrafficSplitRule, Upstream,
};
use pxxl_core::{EdgeState, RouteRegistry};
use pxxl_ddos::{BlacklistEngine, RateLimitConfig, RateLimiter, SecurityEngine};
use pxxl_http_proxy::run_http_proxy_on_listener;
use pxxl_load_balancer::LoadBalancer;
use pxxl_metrics::PxxlMetrics;
use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
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

#[tokio::test]
async fn routes_requests_by_weighted_traffic_split() {
    let stable_addr = spawn_upstream("stable").await;
    let canary_addr = spawn_upstream("canary").await;
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut route = Route::new(
        "split.pxxlhost",
        vec![PathRoute::new(
            "/",
            vec![Upstream::new("http://unused:3000")],
        )],
        RouteSource::Static,
    );
    route.rules = DomainRules {
        traffic_splits: vec![
            TrafficSplitRule {
                name: Some("stable".to_string()),
                weight: 2,
                countries: Vec::new(),
                continents: Vec::new(),
                upstreams: vec![Upstream::new(format!("http://{stable_addr}"))],
            },
            TrafficSplitRule {
                name: Some("canary".to_string()),
                weight: 1,
                countries: Vec::new(),
                continents: Vec::new(),
                upstreams: vec![Upstream::new(format!("http://{canary_addr}"))],
            },
        ],
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

    let mut bodies = Vec::new();
    for _ in 0..3 {
        let req = Request::builder()
            .method("GET")
            .uri(format!("http://{proxy_addr}/"))
            .header("host", "split.pxxlhost")
            .body(Empty::<Bytes>::new())
            .unwrap();
        bodies.push(
            client
                .request(req)
                .await
                .unwrap()
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes(),
        );
    }

    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();

    assert_eq!(&bodies[0][..], b"stable");
    assert_eq!(&bodies[1][..], b"stable");
    assert_eq!(&bodies[2][..], b"canary");
}

#[tokio::test]
async fn blocks_waf_sql_injection_pattern() {
    let upstream_addr = spawn_upstream("should not proxy").await;
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut route = Route::new(
        "waf.pxxlhost",
        vec![PathRoute::new(
            "/",
            vec![Upstream::new(format!("http://{upstream_addr}"))],
        )],
        RouteSource::Static,
    );
    route.rules = DomainRules {
        waf: DomainWafRules {
            enabled: true,
            ..DomainWafRules::default()
        },
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
        .uri(format!("http://{proxy_addr}/?q=%27%20or%201=1"))
        .header("host", "waf.pxxlhost")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let status = client.request(req).await.unwrap().status();

    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn executes_basic_auth_middleware_by_path() {
    let upstream_addr = spawn_upstream("secret").await;
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut path = PathRoute::new("/", vec![Upstream::new(format!("http://{upstream_addr}"))]);
    path.middlewares = vec!["auth".to_string()];
    let mut route = Route::new("auth.pxxlhost", vec![path], RouteSource::Static);
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
    let state = test_state(vec![route]);
    let server = tokio::spawn(run_http_proxy_on_listener(
        proxy_listener,
        state,
        shutdown_rx,
    ));
    let client: Client<HttpConnector, Empty<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();

    let unauthorized = Request::builder()
        .method("GET")
        .uri(format!("http://{proxy_addr}/"))
        .header("host", "auth.pxxlhost")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let authorized = Request::builder()
        .method("GET")
        .uri(format!("http://{proxy_addr}/"))
        .header("host", "auth.pxxlhost")
        .header("authorization", "Basic cm9iaW46cHh4bA==")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let unauthorized_status = client.request(unauthorized).await.unwrap().status();
    let authorized_status = client.request(authorized).await.unwrap().status();

    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();

    assert_eq!(unauthorized_status, StatusCode::UNAUTHORIZED);
    assert_eq!(authorized_status, StatusCode::OK);
}

#[tokio::test]
async fn retry_middleware_retries_retryable_statuses() {
    let upstream_addr = spawn_flaky_upstream().await;
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut route = Route::new(
        "retry.pxxlhost",
        vec![PathRoute::new(
            "/",
            vec![Upstream::new(format!("http://{upstream_addr}"))],
        )],
        RouteSource::Static,
    );
    route.rules.retry = RetryConfig {
        enabled: true,
        attempts: 2,
        retry_statuses: vec![503],
        ..RetryConfig::default()
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
        .header("host", "retry.pxxlhost")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let response = client.request(req).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();

    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();

    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"recovered");
}

#[tokio::test]
async fn sticky_session_cookie_keeps_same_upstream() {
    let a_addr = spawn_upstream("a").await;
    let b_addr = spawn_upstream("b").await;
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut route = Route::new(
        "sticky.pxxlhost",
        vec![PathRoute::new(
            "/",
            vec![
                Upstream::new(format!("http://{a_addr}")),
                Upstream::new(format!("http://{b_addr}")),
            ],
        )],
        RouteSource::Static,
    );
    route.rules.sticky_sessions = StickySessionConfig {
        enabled: true,
        cookie_name: "pxxl_test".to_string(),
        ..StickySessionConfig::default()
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
        .header("host", "sticky.pxxlhost")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let first_response = client.request(first).await.unwrap();
    let cookie = first_response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let first_body = first_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let second = Request::builder()
        .method("GET")
        .uri(format!("http://{proxy_addr}/"))
        .header("host", "sticky.pxxlhost")
        .header("cookie", cookie)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let second_body = client
        .request(second)
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();

    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();

    assert_eq!(first_body, second_body);
}

#[tokio::test]
async fn compression_middleware_gzips_text_response() {
    let upstream_addr =
        spawn_upstream_with_content_type("text/plain", "hello ".repeat(300).leak()).await;
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut route = Route::new(
        "gzip.pxxlhost",
        vec![PathRoute::new(
            "/",
            vec![Upstream::new(format!("http://{upstream_addr}"))],
        )],
        RouteSource::Static,
    );
    route.rules.compression = CompressionConfig {
        enabled: true,
        min_bytes: 10,
        ..CompressionConfig::default()
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
        .header("host", "gzip.pxxlhost")
        .header("accept-encoding", "gzip")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let response = client.request(req).await.unwrap();
    let encoding = response.headers().get("content-encoding").cloned();
    let body = response.into_body().collect().await.unwrap().to_bytes();

    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();

    assert_eq!(
        encoding.as_ref().and_then(|value| value.to_str().ok()),
        Some("gzip")
    );
    assert_eq!(&body[..2], &[0x1f, 0x8b]);
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

async fn spawn_upstream_with_content_type(
    content_type: &'static str,
    body: &'static str,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service = service_fn(move |_req| async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header("content-type", content_type)
                            .body(Full::new(Bytes::from_static(body.as_bytes())))
                            .unwrap(),
                    )
                });
                let io = TokioIo::new(stream);
                let builder = AutoBuilder::new(TokioExecutor::new());
                let _ = builder.serve_connection_with_upgrades(io, service).await;
            });
        }
    });

    addr
}

async fn spawn_flaky_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let count = count.clone();
            tokio::spawn(async move {
                let service = service_fn(move |_req| {
                    let count = count.clone();
                    async move {
                        let attempt = count.fetch_add(1, Ordering::Relaxed);
                        if attempt == 0 {
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::SERVICE_UNAVAILABLE)
                                    .body(Full::new(Bytes::from_static(b"try again")))
                                    .unwrap(),
                            )
                        } else {
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                                b"recovered",
                            ))))
                        }
                    }
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
