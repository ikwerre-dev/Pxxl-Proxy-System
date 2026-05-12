use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::service::service_fn;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as AutoBuilder,
};
use pxxl_common::{PathRoute, Route, RouteSource, Upstream};
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
