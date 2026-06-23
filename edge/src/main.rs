use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Request, Uri};
use http_body_util::Empty;
use hyper_rustls::HttpsConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use pxxl_api::{
    run_admin_api, run_metrics_server, AdminApiAuth, AdminApiRuntime, AdminLoginAccount,
    DatabasePortProxyManager, MetricsAuth, TlsCertificateRuntimeStatus,
};
use pxxl_common::{ip_allowed_for_upstream, parse_ip_net, PathRoute, Route, RouteSource, Upstream};
use pxxl_config::{HealthCheckConfig, PxxlConfig};
use pxxl_core::{route_allows_www_alias, EdgeState, RouteRegistry};
use pxxl_database_proxy::{
    load_database_routes_from_file, run_database_proxy, DatabaseProxyRoute, DatabaseRouteRegistry,
};
use pxxl_ddos::{BlacklistEngine, RateLimitConfig, RateLimiter, SecurityEngine};
use pxxl_docker_discovery::{run_docker_polling, DockerDiscovery};
use pxxl_geo::GeoIpResolver;
use pxxl_http_proxy::{
    run_http_proxy_with_error_pages_policy_and_geoip,
    run_https_proxy_with_reloadable_error_pages_policy_and_geoip, ErrorPageRenderer,
    PolicyEnforcer, ReloadableTlsConfig,
};
use pxxl_load_balancer::LoadBalancer;
use pxxl_metrics::PxxlMetrics;
use pxxl_redis_sync::{RedisRouteStore, RedisTokenStore};
use pxxl_storage::{run_clickhouse_writer, ClickHouseAnalytics};
use pxxl_tls::{CertificateBundle, CertificateIssuer, LocalCertificateStore};
use redis::streams::StreamReadReply;
use serde::Deserialize;
use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
    time,
};
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

const DEFAULT_STATS_SNAPSHOT_PATH: &str = "/data/stats/domain-stats.json";
const DEFAULT_ANALYTICS_SPOOL_DIR: &str = "/data/analytics-spool";
const DEFAULT_DATABASE_ROUTES_PATH: &str = "/data/database-routes/routes.json";

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config_path =
        std::env::var("PXXL_CONFIG").unwrap_or_else(|_| "config/pxxl.toml".to_string());
    let mut config = if Path::new(&config_path).exists() {
        PxxlConfig::load(&config_path)
            .await
            .with_context(|| format!("loading config from {config_path}"))?
    } else if env_flag("PXXL_ALLOW_DEFAULT_CONFIG") {
        warn!(%config_path, "config file not found, using defaults because PXXL_ALLOW_DEFAULT_CONFIG is enabled");
        PxxlConfig::default()
    } else {
        anyhow::bail!(
            "config file not found at {config_path}; set PXXL_CONFIG to a valid file or set PXXL_ALLOW_DEFAULT_CONFIG=true for local-only defaults"
        );
    };
    apply_env_overrides(&mut config);
    ensure_production_safe_config(&config)?;

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
    let (analytics_tx, analytics_rx) = if config.storage.analytics_enabled {
        let (tx, rx) = mpsc::channel(65_536);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let analytics_spool_dir = if config.storage.analytics_enabled {
        Some(analytics_spool_dir())
    } else {
        None
    };
    let state = EdgeState::new_with_stats_sink(
        routes,
        security,
        load_balancer,
        metrics.clone(),
        analytics_tx,
        analytics_spool_dir,
    );
    let analytics_store = if config.storage.analytics_enabled {
        match ClickHouseAnalytics::new(config.storage.clickhouse_url.clone()) {
            Ok(store) => Some(store),
            Err(error) => {
                warn!(%error, "analytics store unavailable for admin API reads");
                None
            }
        }
    } else {
        None
    };
    let stats_snapshot_path = stats_snapshot_path();
    match load_domain_stats_snapshot(&state, &stats_snapshot_path).await {
        Ok(count) if count > 0 => {
            info!(
                count,
                path = %stats_snapshot_path.display(),
                "restored edge metrics snapshot"
            );
        }
        Ok(_) => {}
        Err(error) => {
            warn!(
                %error,
                path = %stats_snapshot_path.display(),
                "could not restore edge metrics snapshot"
            );
        }
    }
    let error_pages =
        match ErrorPageRenderer::load_from_dir(config.error_pages.enabled, &config.error_pages.dir)
        {
            Ok(error_pages) => error_pages,
            Err(error) => {
                warn!(%error, "could not load configured error pages; using built-in defaults");
                ErrorPageRenderer::default()
            }
        };
    let policy = PolicyEnforcer::default();
    let geoip = match GeoIpResolver::load_from_path(
        config.geoip.enabled,
        &config.geoip.database_path,
    ) {
        Ok(geoip) => geoip,
        Err(error) => {
            warn!(%error, "could not load GeoIP database; using built-in private/local ranges only");
            GeoIpResolver::default()
        }
    };

    let cert_domains = certificate_domains(&config.tls.local_subject_alt_names, &state);

    let cert_store = LocalCertificateStore::new(config.tls.cert_dir.clone());
    let tls_status = TlsCertificateRuntimeStatus::new();
    let bundle = cert_store.ensure_certificate(&cert_domains).await?;
    tls_status.mark_success(cert_domains.clone());
    let tls_config = cert_store.server_config_with_domain_certs(&bundle)?;
    let reloadable_tls = ReloadableTlsConfig::new(tls_config);
    metrics
        .tls_certificates_total
        .with_label_values(&["local", "ready"])
        .inc();

    let http_addr = parse_addr("listeners.http", &config.listeners.http)?;
    let https_addr = parse_addr("listeners.https", &config.listeners.https)?;
    let admin_addr = parse_addr("listeners.admin", &config.listeners.admin)?;
    let metrics_addr = parse_addr("listeners.metrics", &config.listeners.metrics)?;
    let database_routes_store_path = database_routes_store_path();
    let database_routes =
        DatabaseRouteRegistry::new(config.database_proxy.routes.iter().map(|route| {
            DatabaseProxyRoute {
                database_type: route.database_type.clone(),
                key: route.key.clone(),
                upstream: route.upstream.clone(),
                route_host: route.route_host.clone(),
                public_port: route.public_port,
            }
        }));
    match load_database_routes_from_file(&database_routes_store_path).await {
        Ok(routes) => {
            let count = routes.len();
            for route in routes {
                database_routes.upsert(route);
            }
            if count > 0 {
                info!(
                    path = %database_routes_store_path.display(),
                    count,
                    "loaded persisted database proxy routes"
                );
            }
        }
        Err(error) => {
            warn!(
                path = %database_routes_store_path.display(),
                %error,
                "could not load persisted database proxy routes"
            );
        }
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let database_port_proxy =
        database_port_proxy_manager(&config, &database_routes, shutdown_rx.clone());
    let token_store = RedisTokenStore::new(
        config.redis.url.clone(),
        config.admin.token_store_key.clone(),
    );
    let admin_login_account = admin_login_account_from_env()?;
    let admin_auth = AdminApiAuth::new(
        config.admin.auth_enabled,
        config.admin.bootstrap_token.clone(),
        config.admin.bootstrap_token_permanent,
        config.admin.ip_allowlist.clone(),
        Some(token_store),
        admin_login_account,
    );
    let mut tasks: Vec<JoinHandle<Result<()>>> = vec![
        tokio::spawn(run_http_proxy_with_error_pages_policy_and_geoip(
            http_addr,
            state.clone(),
            error_pages.clone(),
            policy.clone(),
            geoip.clone(),
            shutdown_rx.clone(),
        )),
        tokio::spawn(
            run_https_proxy_with_reloadable_error_pages_policy_and_geoip(
                https_addr,
                state.clone(),
                reloadable_tls.clone(),
                error_pages.clone(),
                policy.clone(),
                geoip.clone(),
                shutdown_rx.clone(),
            ),
        ),
        tokio::spawn(run_admin_api(
            admin_addr,
            AdminApiRuntime {
                state: state.clone(),
                cert_dir: config.tls.cert_dir.clone(),
                tls_status: tls_status.clone(),
                route_store: Some(route_store.clone()),
                database_routes: Some(database_routes.clone()),
                database_routes_store_path: Some(database_routes_store_path.clone()),
                database_port_proxy: database_port_proxy.clone(),
                analytics: analytics_store.clone(),
                auth: admin_auth,
            },
            shutdown_rx.clone(),
        )),
        tokio::spawn(run_metrics_server(
            metrics_addr,
            metrics.clone(),
            MetricsAuth::new(
                config
                    .metrics
                    .bearer_token
                    .clone()
                    .filter(|token| !token.trim().is_empty()),
            ),
            shutdown_rx.clone(),
        )),
    ];

    if let Some(analytics_rx) = analytics_rx {
        tasks.push(tokio::spawn(run_clickhouse_writer(
            config.storage.clickhouse_url.clone(),
            analytics_rx,
            shutdown_rx.clone(),
        )));
    }

    tasks.push(tokio::spawn(run_domain_stats_snapshotter(
        state.clone(),
        stats_snapshot_path,
        shutdown_rx.clone(),
    )));

    if env_flag_default("PXXL_ROUTE_EVENTS_ENABLED", true) {
        tasks.push(tokio::spawn(run_route_event_consumer(
            config.redis.url.clone(),
            "pxxl:route_events".to_string(),
            state.clone(),
            route_store.clone(),
            shutdown_rx.clone(),
        )));
    }

    if config.database_proxy.enabled {
        for listener in &config.database_proxy.listeners {
            let addr = parse_addr("database_proxy.listeners.listen", &listener.listen)?;
            tasks.push(tokio::spawn(run_database_proxy(
                listener.database_type.clone(),
                addr,
                database_routes.clone(),
                shutdown_rx.clone(),
            )));
        }
        if let Some(manager) = &database_port_proxy {
            for route in database_routes.list() {
                if let Some(public_port) = route.public_port {
                    manager.ensure_listener(public_port);
                }
            }
        }
    }

    if config.health_checks.enabled {
        tasks.push(tokio::spawn(run_health_checks(
            state.clone(),
            config.health_checks.clone(),
            shutdown_rx.clone(),
        )));
    }

    tasks.push(tokio::spawn(run_tls_reloader(
        cert_store.clone(),
        reloadable_tls,
        tls_status,
        state.clone(),
        config.tls.local_subject_alt_names.clone(),
        shutdown_rx.clone(),
    )));

    if config.docker.enabled {
        let discovery = DockerDiscovery::new(config.docker.socket_path.clone());
        if unix_socket_available(&config.docker.socket_path) {
            let poll_interval = config.docker.poll_interval();
            let state = state.clone();
            let shutdown_rx = shutdown_rx.clone();
            tasks.push(tokio::spawn(async move {
                run_docker_polling(discovery, state, poll_interval, shutdown_rx.clone()).await;
                Ok(())
            }));
        } else {
            warn!(
                socket_path = %config.docker.socket_path,
                "docker discovery enabled but socket path is not available"
            );
        }
    }

    if config.podman.enabled {
        let discovery = DockerDiscovery::podman(
            config.podman.socket_path.clone(),
            config.podman.published_host.clone(),
        );
        if unix_socket_available(&config.podman.socket_path) {
            let poll_interval = config.podman.poll_interval();
            let state = state.clone();
            let shutdown_rx = shutdown_rx.clone();
            tasks.push(tokio::spawn(async move {
                run_docker_polling(discovery, state, poll_interval, shutdown_rx.clone()).await;
                Ok(())
            }));
        } else {
            warn!(
                socket_path = %config.podman.socket_path,
                "podman discovery enabled but socket path is not available"
            );
        }
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

#[derive(Debug, Clone, Default, Deserialize)]
struct RuntimeRouteEvent {
    #[serde(default)]
    event_type: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    upstream_url: String,
    #[serde(default)]
    runtime_server_ip: String,
    #[serde(default)]
    published_port: String,
    #[serde(default)]
    project_id: String,
    #[serde(default)]
    deployment_id: String,
    #[serde(default)]
    container_id: String,
}

fn stats_snapshot_path() -> PathBuf {
    std::env::var("PXXL_STATS_SNAPSHOT_PATH")
        .ok()
        .filter(|path| !path.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATS_SNAPSHOT_PATH))
}

fn analytics_spool_dir() -> PathBuf {
    std::env::var("PXXL_ANALYTICS_SPOOL_DIR")
        .ok()
        .filter(|path| !path.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ANALYTICS_SPOOL_DIR))
}

async fn load_domain_stats_snapshot(state: &EdgeState, path: &Path) -> Result<usize> {
    if !path.exists() {
        return Ok(0);
    }
    let bytes = tokio::fs::read(path).await?;
    if bytes.is_empty() {
        return Ok(0);
    }
    let snapshots = serde_json::from_slice::<Vec<pxxl_core::DomainStatsSnapshot>>(&bytes)
        .context("parsing edge metrics snapshot")?;
    let count = snapshots.len();
    state.stats.restore_snapshots(snapshots);
    Ok(count)
}

async fn run_domain_stats_snapshotter(
    state: EdgeState,
    path: PathBuf,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let interval_seconds = std::env::var("PXXL_STATS_SNAPSHOT_INTERVAL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(10)
        .max(2);
    let mut interval = time::interval(Duration::from_secs(interval_seconds));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(error) = write_domain_stats_snapshot(&state, &path).await {
                    warn!(%error, path = %path.display(), "could not persist edge metrics snapshot");
                }
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    if let Err(error) = write_domain_stats_snapshot(&state, &path).await {
                        warn!(%error, path = %path.display(), "could not persist final edge metrics snapshot");
                    }
                    break;
                }
            }
        }
    }

    Ok(())
}

async fn write_domain_stats_snapshot(state: &EdgeState, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let snapshots = state.stats.snapshots();
    let bytes = serde_json::to_vec(&snapshots)?;
    let temp_path = path.with_extension("json.tmp");
    tokio::fs::write(&temp_path, bytes).await?;
    tokio::fs::rename(&temp_path, path).await?;
    Ok(())
}

async fn run_route_event_consumer(
    redis_url: String,
    stream: String,
    state: EdgeState,
    route_store: RedisRouteStore,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let client = redis::Client::open(redis_url.as_str())?;
    let mut connection = client.get_multiplexed_async_connection().await?;
    let mut last_id = "$".to_string();

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    break;
                }
            }
            result = async {
                redis::cmd("XREAD")
                    .arg("BLOCK").arg(5000)
                    .arg("COUNT").arg(50)
                    .arg("STREAMS").arg(&stream).arg(&last_id)
                    .query_async::<StreamReadReply>(&mut connection)
                    .await
            } => {
                match result {
                    Ok(reply) => {
                        for key in reply.keys {
                            for id in key.ids {
                                last_id = id.id.clone();
                                if let Some(event) = runtime_route_event_from_fields(id.map) {
                                    if let Err(error) = apply_runtime_route_event(&state, &route_store, event).await {
                                        warn!(%error, "failed to apply runtime route event");
                                    }
                                }
                            }
                        }
                    }
                    Err(error) => {
                        warn!(%error, "runtime route event stream read failed");
                        time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }
    }
    Ok(())
}

fn runtime_route_event_from_fields(
    fields: HashMap<String, redis::Value>,
) -> Option<RuntimeRouteEvent> {
    let mut json = serde_json::Map::new();
    for (key, value) in fields {
        if let Ok(value) = redis::from_redis_value::<String>(&value) {
            json.insert(key, serde_json::Value::String(value));
        }
    }
    serde_json::from_value(serde_json::Value::Object(json)).ok()
}

async fn apply_runtime_route_event(
    state: &EdgeState,
    route_store: &RedisRouteStore,
    event: RuntimeRouteEvent,
) -> Result<()> {
    let event_type = event.event_type.trim();
    if !matches!(event_type, "container.healthy" | "route.promote") {
        return Ok(());
    }
    let domain = event
        .domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if domain.is_empty() {
        return Ok(());
    }
    let upstream_url = runtime_route_upstream_url(&event);
    if upstream_url.is_empty() {
        return Ok(());
    }
    let path = if event.path.trim().is_empty() {
        "/"
    } else {
        event.path.trim()
    };
    let mut route = Route::new(
        domain.clone(),
        vec![PathRoute::new(
            path,
            vec![Upstream::new(upstream_url.clone())],
        )],
        RouteSource::Api,
    )
    .with_id(format!("runtime-{domain}"));
    route.tls = true;
    route
        .validate_for_dynamic_control_plane()
        .map_err(|reason| anyhow::anyhow!("invalid runtime route event for {domain}: {reason}"))?;
    state.routes.upsert_api_route(route.clone());
    route_store.upsert_route(&route).await?;
    info!(
        domain = %domain,
        upstream = %upstream_url,
        project_id = %event.project_id,
        deployment_id = %event.deployment_id,
        container_id = %event.container_id,
        "applied runtime route event"
    );
    Ok(())
}

fn runtime_route_upstream_url(event: &RuntimeRouteEvent) -> String {
    let upstream_url = event.upstream_url.trim();
    if !upstream_url.is_empty() {
        return upstream_url.to_string();
    }
    let host = event.runtime_server_ip.trim();
    let port = event.published_port.trim();
    if host.is_empty() || port.is_empty() {
        return String::new();
    }
    format!("http://{host}:{port}")
}

async fn run_health_checks(
    state: EdgeState,
    config: HealthCheckConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let client: Client<HttpsConnector<HttpConnector>, Empty<Bytes>> =
        Client::builder(TokioExecutor::new()).build(https_connector());
    let mut interval = time::interval(Duration::from_secs(config.interval_seconds.max(1)));
    let timeout = Duration::from_millis(config.timeout_ms.max(100));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let upstreams = collect_upstream_checks(&state.routes.snapshot());
                let mut health = HashMap::new();
                for upstream in upstreams {
                    let healthy = check_upstream(&client, &upstream, &config.path, timeout).await;
                    health.insert(upstream.url.clone(), healthy);
                }
                state.set_upstream_health(&health);
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    break;
                }
            }
        }
    }

    Ok(())
}

async fn check_upstream(
    client: &Client<HttpsConnector<HttpConnector>, Empty<Bytes>>,
    upstream: &UpstreamCheck,
    health_path: &str,
    timeout: Duration,
) -> bool {
    if upstream.source == RouteSource::Api && !dynamic_upstream_network_allowed(&upstream.url).await
    {
        return false;
    }
    let Some(uri) = build_health_uri(&upstream.url, health_path) else {
        return false;
    };
    let request = match Request::builder()
        .method("GET")
        .uri(uri)
        .body(Empty::<Bytes>::new())
    {
        Ok(request) => request,
        Err(_) => return false,
    };

    match time::timeout(timeout, client.request(request)).await {
        Ok(Ok(response)) => response.status().as_u16() < 500,
        _ => false,
    }
}

fn https_connector() -> HttpsConnector<HttpConnector> {
    let mut http = HttpConnector::new();
    http.enforce_http(false);

    hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("native TLS roots should be available")
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http)
}

fn build_health_uri(upstream: &str, health_path: &str) -> Option<Uri> {
    let health_path = if health_path.starts_with('/') {
        health_path.to_string()
    } else {
        format!("/{health_path}")
    };
    format!("{}{}", upstream.trim_end_matches('/'), health_path)
        .parse()
        .ok()
}

async fn dynamic_upstream_network_allowed(raw: &str) -> bool {
    let Ok(parsed) = url::Url::parse(raw) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if reserved_host_gateway(&host) {
        return host_gateway_upstreams_allowed();
    }
    if private_upstreams_allowed() {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip_allowed_for_upstream(ip);
    }
    let Some(port) = parsed.port_or_known_default() else {
        return false;
    };
    let lookup = time::timeout(
        Duration::from_secs(2),
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await;
    match lookup {
        Ok(Ok(addresses)) => addresses
            .into_iter()
            .all(|address| ip_allowed_for_upstream(address.ip())),
        Ok(Err(_)) | Err(_) => true,
    }
}

fn reserved_host_gateway(host: &str) -> bool {
    matches!(host, "host.docker.internal" | "gateway.docker.internal")
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct UpstreamCheck {
    source: RouteSource,
    url: String,
}

fn collect_upstream_checks(routes: &[Route]) -> BTreeSet<UpstreamCheck> {
    let mut upstreams = BTreeSet::new();
    for route in routes {
        for path in &route.paths {
            upstreams.extend(path.upstreams.iter().map(|upstream| UpstreamCheck {
                source: route.source.clone(),
                url: upstream.url.clone(),
            }));
        }
        for location_route in &route.rules.location_routes {
            upstreams.extend(
                location_route
                    .upstreams
                    .iter()
                    .map(|upstream| UpstreamCheck {
                        source: route.source.clone(),
                        url: upstream.url.clone(),
                    }),
            );
        }
        for split in &route.rules.traffic_splits {
            upstreams.extend(split.upstreams.iter().map(|upstream| UpstreamCheck {
                source: route.source.clone(),
                url: upstream.url.clone(),
            }));
        }
    }
    upstreams
}

async fn run_tls_reloader(
    cert_store: LocalCertificateStore,
    tls_config: ReloadableTlsConfig,
    tls_status: TlsCertificateRuntimeStatus,
    state: EdgeState,
    local_subject_alt_names: Vec<String>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    const TLS_RELOAD_INTERVAL: Duration = Duration::from_secs(5);
    const TLS_RELOAD_MAX_ATTEMPTS: u8 = 10;

    let mut interval = time::interval(TLS_RELOAD_INTERVAL);
    let mut current_domains = certificate_domains(&local_subject_alt_names, &state);
    let mut pending_domains: Option<Vec<String>> = None;
    let mut exhausted_domains: Option<Vec<String>> = None;
    let mut attempts = 0_u8;
    let mut current_cert_fingerprint = cert_fingerprint(&cert_store).await;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let latest_cert_fingerprint = cert_fingerprint(&cert_store).await;
                if latest_cert_fingerprint != current_cert_fingerprint {
                    let bundle = CertificateBundle {
                        cert_path: cert_store.cert_path(),
                        key_path: cert_store.key_path(),
                        domains: current_domains.clone(),
                    };
                    match cert_store.server_config_with_domain_certs(&bundle) {
                        Ok(config) => {
                            tls_config.store(config);
                            current_cert_fingerprint = latest_cert_fingerprint;
                            tls_status.mark_success(current_domains.clone());
                            info!("reloaded TLS certificate from updated certificate files");
                        }
                        Err(error) => {
                            tls_status.mark_error("file_reload", error.to_string(), current_domains.clone());
                            warn!(%error, "failed to reload TLS certificate from updated files");
                        }
                    }
                }

                let domains = certificate_domains(&local_subject_alt_names, &state);
                if domains != current_domains
                    && pending_domains.as_ref() != Some(&domains)
                    && exhausted_domains.as_ref() != Some(&domains)
                {
                    pending_domains = Some(domains);
                    attempts = 0;
                }

                if let Some(domains) = pending_domains.clone() {
                    if attempts >= TLS_RELOAD_MAX_ATTEMPTS {
                        warn!(
                            max_attempts = TLS_RELOAD_MAX_ATTEMPTS,
                            domains = ?domains,
                            "exhausted local TLS certificate reload attempts for dynamic route domains"
                        );
                        exhausted_domains = Some(domains);
                        tls_status.mark_exhausted(exhausted_domains.clone().unwrap_or_default());
                        pending_domains = None;
                        continue;
                    }

                    attempts += 1;
                    match cert_store.regenerate_certificate(&domains).await {
                        Ok(bundle) => match cert_store.server_config_with_domain_certs(&bundle) {
                            Ok(config) => {
                                tls_config.store(config);
                                tls_status.mark_success(domains.clone());
                                exhausted_domains = None;
                                pending_domains = None;
                                attempts = 0;
                                current_domains = domains;
                                current_cert_fingerprint = cert_fingerprint(&cert_store).await;
                                info!("reloaded local TLS certificate for dynamic route domains");
                            }
                            Err(error) => {
                                tls_status.mark_error("server_config", error.to_string(), domains.clone());
                                warn!(
                                    %error,
                                    attempt = attempts,
                                    max_attempts = TLS_RELOAD_MAX_ATTEMPTS,
                                    "failed to rebuild TLS server config"
                                )
                            }
                        },
                        Err(error) => {
                            tls_status.mark_error("regenerate", error.to_string(), domains.clone());
                            warn!(
                                %error,
                                attempt = attempts,
                                max_attempts = TLS_RELOAD_MAX_ATTEMPTS,
                                "failed to regenerate local TLS certificate"
                            )
                        }
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    break;
                }
            }
        }
    }

    Ok(())
}

fn certificate_domains(local_subject_alt_names: &[String], state: &EdgeState) -> Vec<String> {
    const MAX_CERT_DOMAINS: usize = 100;
    let mut domains = local_subject_alt_names.to_vec();
    for route in state.routes.snapshot() {
        if safe_certificate_domain(&route.domain) {
            domains.push(route.domain.clone());
        }
        if route_allows_www_alias(&route.domain, route.rules.www_alias) {
            let alias = format!("www.{}", route.domain);
            if safe_certificate_domain(&alias) {
                domains.push(alias);
            }
        }
    }
    domains.sort();
    domains.dedup();
    domains.truncate(MAX_CERT_DOMAINS);
    domains
}

async fn cert_fingerprint(cert_store: &LocalCertificateStore) -> String {
    let mut values = Vec::new();
    push_cert_file_fingerprint(&mut values, &cert_store.cert_path());
    push_cert_file_fingerprint(&mut values, &cert_store.key_path());
    collect_cert_dir_fingerprints(&mut values, &cert_store.domain_certs_dir());
    values.sort();
    values.join("|")
}

fn collect_cert_dir_fingerprints(values: &mut Vec<String>, dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_cert_dir_fingerprints(values, &path);
        } else {
            push_cert_file_fingerprint(values, &path);
        }
    }
}

fn push_cert_file_fingerprint(values: &mut Vec<String>, path: &Path) {
    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    let modified = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    values.push(format!(
        "{}:{}:{}",
        path.display(),
        metadata.len(),
        modified
    ));
}

fn safe_certificate_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && !domain.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
}

fn unix_socket_available(path: &str) -> bool {
    std::fs::metadata(path)
        .map(|metadata| metadata.file_type().is_socket())
        .unwrap_or(false)
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
    if let Ok(value) = std::env::var("PXXL_DOCKER_ENABLED") {
        config.docker.enabled = parse_bool(&value);
    }
    if let Ok(value) = std::env::var("PXXL_DOCKER_SOCKET_PATH") {
        config.docker.socket_path = value;
    }
    if let Ok(value) = std::env::var("PXXL_PODMAN_ENABLED") {
        config.podman.enabled = parse_bool(&value);
    }
    if let Ok(value) = std::env::var("PXXL_PODMAN_SOCKET_PATH") {
        config.podman.socket_path = value;
    }
    if let Ok(value) = std::env::var("PXXL_PODMAN_PUBLISHED_HOST") {
        config.podman.published_host = value;
    }
    if let Ok(value) = std::env::var("PXXL_DATABASE_PROXY_ENABLED") {
        config.database_proxy.enabled = parse_bool(&value);
    }
    if let Ok(value) = std::env::var("PXXL_DATABASE_PROXY_POSTGRES_ADDR") {
        upsert_database_proxy_listener(config, "postgres", value);
    }
    if let Ok(value) = std::env::var("PXXL_ERROR_PAGES_DIR") {
        config.error_pages.dir = value;
    }
    if let Ok(value) = std::env::var("PXXL_ERROR_PAGES_ENABLED") {
        config.error_pages.enabled = matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        );
    }
    if let Ok(value) = std::env::var("PXXL_GEOIP_DATABASE") {
        config.geoip.database_path = value;
    }
    if let Ok(value) = std::env::var("PXXL_GEOIP_ENABLED") {
        config.geoip.enabled = parse_bool(&value);
    }
    if let Ok(value) = std::env::var("PXXL_ADMIN_AUTH_ENABLED") {
        config.admin.auth_enabled = parse_bool(&value);
    }
    if let Ok(value) = std::env::var("PXXL_ADMIN_BOOTSTRAP_TOKEN") {
        config.admin.bootstrap_token = (!value.trim().is_empty()).then_some(value);
    }
    if let Ok(value) = std::env::var("PXXL_ADMIN_BOOTSTRAP_TOKEN_PERMANENT") {
        config.admin.bootstrap_token_permanent = parse_bool(&value);
    }
    if let Ok(value) = std::env::var("PXXL_REDIS_URL") {
        config.redis.url = value;
    }
    if let Ok(value) = std::env::var("PXXL_ADMIN_IP_ALLOWLIST") {
        config.admin.ip_allowlist = value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .filter_map(|value| match parse_ip_net(value) {
                Ok(network) => Some(network),
                Err(error) => {
                    warn!(%value, %error, "ignoring invalid admin IP allowlist entry");
                    None
                }
            })
            .collect();
    }
    if let Ok(value) = std::env::var("PXXL_CLICKHOUSE_URL") {
        config.storage.clickhouse_url = value;
    }
    if let Ok(value) = std::env::var("PXXL_METRICS_BEARER_TOKEN") {
        config.metrics.bearer_token = (!value.trim().is_empty()).then_some(value);
    }
    if let Ok(value) = std::env::var("PXXL_ANALYTICS_ENABLED") {
        config.storage.analytics_enabled = parse_bool(&value);
    }
    if let Ok(value) = std::env::var("PXXL_HEALTH_CHECKS_ENABLED") {
        config.health_checks.enabled = parse_bool(&value);
    }
}

fn admin_login_account_from_env() -> Result<Option<AdminLoginAccount>> {
    let email = std::env::var("PXXL_ADMIN_EMAIL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let password_hash = std::env::var("PXXL_ADMIN_PASSWORD_HASH")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    match (email, password_hash) {
        (Some(email), Some(password_hash)) => AdminLoginAccount::new(email, password_hash)
            .map(Some)
            .map_err(|error| anyhow::anyhow!("invalid initial admin account config: {error}")),
        (None, None) => Ok(None),
        _ => anyhow::bail!(
            "PXXL_ADMIN_EMAIL and PXXL_ADMIN_PASSWORD_HASH must be configured together"
        ),
    }
}

fn upsert_database_proxy_listener(config: &mut PxxlConfig, database_type: &str, listen: String) {
    if let Some(listener) = config
        .database_proxy
        .listeners
        .iter_mut()
        .find(|listener| listener.database_type.eq_ignore_ascii_case(database_type))
    {
        listener.listen = listen;
    } else {
        config
            .database_proxy
            .listeners
            .push(pxxl_config::DatabaseProxyListenerConfig {
                database_type: database_type.to_string(),
                listen,
            });
    }
}

fn database_port_proxy_manager(
    config: &PxxlConfig,
    database_routes: &DatabaseRouteRegistry,
    shutdown: watch::Receiver<bool>,
) -> Option<DatabasePortProxyManager> {
    if !config.database_proxy.enabled {
        return None;
    }
    let bind_host = std::env::var("PXXL_DATABASE_PROXY_PUBLIC_BIND_HOST")
        .ok()
        .and_then(|value| value.trim().parse::<IpAddr>().ok())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let (min_port, max_port) = database_proxy_public_port_range();
    Some(DatabasePortProxyManager::new(
        bind_host,
        min_port,
        max_port,
        database_routes.clone(),
        shutdown,
    ))
}

fn database_routes_store_path() -> PathBuf {
    std::env::var("PXXL_DATABASE_PROXY_ROUTES_PATH")
        .unwrap_or_else(|_| DEFAULT_DATABASE_ROUTES_PATH.to_string())
        .into()
}

fn database_proxy_public_port_range() -> (u16, u16) {
    let raw = std::env::var("PXXL_DATABASE_PROXY_PUBLIC_PORT_RANGE")
        .unwrap_or_else(|_| "10000-65000".to_string());
    let mut parts = raw.splitn(2, '-');
    let min = parts
        .next()
        .and_then(|value| value.trim().parse::<u16>().ok())
        .unwrap_or(10000);
    let max = parts
        .next()
        .and_then(|value| value.trim().parse::<u16>().ok())
        .unwrap_or(65000);
    if min > max {
        return (10000, 65000);
    }
    (min, max)
}

fn ensure_production_safe_config(config: &PxxlConfig) -> Result<()> {
    let is_production = std::env::var("PXXL_ENV")
        .map(|value| value.eq_ignore_ascii_case("production"))
        .unwrap_or(false);
    if !is_production {
        return Ok(());
    }

    if !config.admin.auth_enabled {
        anyhow::bail!("admin auth must be enabled in production");
    }
    if config
        .admin
        .bootstrap_token
        .as_deref()
        .is_some_and(|token| token == "pxxl-dev-token" || token.len() < 32)
    {
        anyhow::bail!("production bootstrap token must be unique and at least 32 bytes");
    }
    for (name, value) in [
        ("listeners.admin", &config.listeners.admin),
        ("listeners.metrics", &config.listeners.metrics),
    ] {
        if value.starts_with("0.0.0.0:") || value.starts_with("[::]:") {
            anyhow::bail!("{name} must not bind a wildcard address in production");
        }
    }
    Ok(())
}

fn parse_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|value| parse_bool(&value))
        .unwrap_or(false)
}

fn env_flag_default(name: &str, fallback: bool) -> bool {
    std::env::var(name)
        .map(|value| parse_bool(&value))
        .unwrap_or(fallback)
}

fn parse_addr(name: &str, value: &str) -> Result<SocketAddr> {
    value
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid socket address for {name}: {value}"))
}
