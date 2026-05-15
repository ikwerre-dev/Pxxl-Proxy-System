use anyhow::{Context, Result};
use pxxl_api::{run_admin_api, run_metrics_server};
use pxxl_config::PxxlConfig;
use pxxl_core::{EdgeState, RouteRegistry};
use pxxl_ddos::{BlacklistEngine, RateLimitConfig, RateLimiter, SecurityEngine};
use pxxl_docker_discovery::{run_docker_polling, DockerDiscovery};
use pxxl_http_proxy::{run_http_proxy, run_https_proxy};
use pxxl_load_balancer::LoadBalancer;
use pxxl_metrics::PxxlMetrics;
use pxxl_redis_sync::RedisRouteStore;
use pxxl_tls::{CertificateIssuer, LocalCertificateStore};
use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::{sync::watch, task::JoinHandle, time};
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config_path =
        std::env::var("PXXL_CONFIG").unwrap_or_else(|_| "config/pxxl.toml".to_string());
    let mut config = if Path::new(&config_path).exists() {
        PxxlConfig::load(&config_path)
            .await
            .with_context(|| format!("loading config from {config_path}"))?
    } else {
        warn!(%config_path, "config file not found, starting with defaults");
        PxxlConfig::default()
    };
    apply_env_overrides(&mut config);

    let mut initial_routes = config.static_routes()?;
    let route_store = RedisRouteStore::new(config.redis.url.clone(), "pxxl:routes");
    match route_store.load_routes().await {
        Ok(routes) => {
            info!(count = routes.len(), "loaded API routes from Redis");
            initial_routes.extend(routes);
        }
        Err(error) => {
            warn!(%error, "could not load API routes from Redis; starting with static routes only");
        }
    }

    let route_domains = initial_routes
        .iter()
        .map(|route| route.domain.clone())
        .collect::<Vec<_>>();

    let metrics = Arc::new(PxxlMetrics::new()?);
    let blacklist = Arc::new(BlacklistEngine::with_cidrs(
        config.security.blacklists.cidrs.clone(),
    ));
    let rate_limiter = Arc::new(RateLimiter::new(RateLimitConfig {
        requests_per_second: config.security.rate_limits.requests_per_second,
        burst: config.security.rate_limits.burst,
    }));
    let security = Arc::new(SecurityEngine::new(blacklist, rate_limiter));
    let routes = Arc::new(RouteRegistry::new(initial_routes));
    let load_balancer = Arc::new(LoadBalancer::new());
    let state = EdgeState::new(routes, security, load_balancer, metrics.clone());

    let mut cert_domains = config.tls.local_subject_alt_names.clone();
    cert_domains.extend(route_domains);
    cert_domains.sort();
    cert_domains.dedup();

    let cert_store = LocalCertificateStore::new(config.tls.cert_dir.clone());
    cert_store.ensure_certificate(&cert_domains).await?;
    let tls_config = cert_store.server_config(&cert_domains).await?;
    metrics
        .tls_certificates_total
        .with_label_values(&["local", "ready"])
        .inc();

    let http_addr = parse_addr("listeners.http", &config.listeners.http)?;
    let https_addr = parse_addr("listeners.https", &config.listeners.https)?;
    let admin_addr = parse_addr("listeners.admin", &config.listeners.admin)?;
    let metrics_addr = parse_addr("listeners.metrics", &config.listeners.metrics)?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks: Vec<JoinHandle<Result<()>>> = Vec::new();

    tasks.push(tokio::spawn(run_http_proxy(
        http_addr,
        state.clone(),
        shutdown_rx.clone(),
    )));
    tasks.push(tokio::spawn(run_https_proxy(
        https_addr,
        state.clone(),
        tls_config,
        shutdown_rx.clone(),
    )));
    tasks.push(tokio::spawn(run_admin_api(
        admin_addr,
        state.clone(),
        config.tls.cert_dir.clone(),
        Some(route_store.clone()),
        shutdown_rx.clone(),
    )));
    tasks.push(tokio::spawn(run_metrics_server(
        metrics_addr,
        metrics.clone(),
        shutdown_rx.clone(),
    )));

    if config.docker.enabled {
        let discovery = DockerDiscovery::new(config.docker.socket_path.clone());
        let poll_interval = config.docker.poll_interval();
        let state = state.clone();
        let shutdown_rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            run_docker_polling(discovery, state, poll_interval, shutdown_rx.clone()).await;
            Ok(())
        }));
    }

    if config.podman.enabled {
        let discovery = DockerDiscovery::podman(
            config.podman.socket_path.clone(),
            config.podman.published_host.clone(),
        );
        let poll_interval = config.podman.poll_interval();
        let state = state.clone();
        let shutdown_rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            run_docker_polling(discovery, state, poll_interval, shutdown_rx.clone()).await;
            Ok(())
        }));
    }

    info!(
        http = %http_addr,
        https = %https_addr,
        admin = %admin_addr,
        metrics = %metrics_addr,
        "Pxxl Proxy started"
    );

    tokio::signal::ctrl_c()
        .await
        .context("failed waiting for shutdown signal")?;
    info!("shutdown signal received");
    let _ = shutdown_tx.send(true);

    for task in tasks {
        match time::timeout(Duration::from_secs(10), task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => warn!(%error, "server task exited with error"),
            Ok(Err(error)) => warn!(%error, "server task join failed"),
            Err(_) => warn!("server task did not stop before timeout"),
        }
    }

    info!("Pxxl Proxy stopped");
    Ok(())
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("pxxl_edge=info,pxxl=info,tower_http=info"));
    let fmt = tracing_subscriber::fmt::layer().json();
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt)
        .init();
}

fn apply_env_overrides(config: &mut PxxlConfig) {
    if let Ok(value) = std::env::var("PXXL_HTTP_ADDR") {
        config.listeners.http = value;
    }
    if let Ok(value) = std::env::var("PXXL_HTTPS_ADDR") {
        config.listeners.https = value;
    }
    if let Ok(value) = std::env::var("PXXL_ADMIN_ADDR") {
        config.listeners.admin = value;
    }
    if let Ok(value) = std::env::var("PXXL_METRICS_ADDR") {
        config.listeners.metrics = value;
    }
    if let Ok(value) = std::env::var("PXXL_CERT_DIR") {
        config.tls.cert_dir = value;
    }
}

fn parse_addr(name: &str, value: &str) -> Result<SocketAddr> {
    value
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid socket address for {name}: {value}"))
}
