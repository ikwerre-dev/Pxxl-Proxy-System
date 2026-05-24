use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Request, Uri};
use http_body_util::Empty;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use pxxl_api::{run_admin_api, run_metrics_server, AdminApiAuth, AdminLoginAccount, MetricsAuth};
use pxxl_common::{ip_allowed_for_upstream, parse_ip_net, Route, RouteSource};
use pxxl_config::{HealthCheckConfig, PxxlConfig};
use pxxl_core::{route_allows_www_alias, EdgeState, RouteRegistry};
use pxxl_database_proxy::{run_database_proxy, DatabaseProxyRoute, DatabaseRouteRegistry};
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
use pxxl_storage::run_clickhouse_writer;
use pxxl_tls::LocalCertificateStore;
use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    os::unix::fs::FileTypeExt,
    path::Path,
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
        let (tx, rx) = mpsc::channel(4096);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let state = EdgeState::new_with_stats_sink(
        routes,
        security,
        load_balancer,
        metrics.clone(),
        analytics_tx,
    );
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
    let bundle = cert_store.regenerate_certificate(&cert_domains).await?;
    let tls_config = cert_store.server_config_from_bundle(&bundle)?;
    let reloadable_tls = ReloadableTlsConfig::new(tls_config);
    metrics
        .tls_certificates_total
        .with_label_values(&["local", "ready"])
        .inc();

    let http_addr = parse_addr("listeners.http", &config.listeners.http)?;
    let https_addr = parse_addr("listeners.https", &config.listeners.https)?;
    let admin_addr = parse_addr("listeners.admin", &config.listeners.admin)?;
    let metrics_addr = parse_addr("listeners.metrics", &config.listeners.metrics)?;
    let database_routes =
        DatabaseRouteRegistry::new(config.database_proxy.routes.iter().map(|route| {
            DatabaseProxyRoute {
                database_type: route.database_type.clone(),
                key: route.key.clone(),
                upstream: route.upstream.clone(),
            }
        }));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
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
            state.clone(),
            config.tls.cert_dir.clone(),
            Some(route_store.clone()),
            Some(database_routes.clone()),
            admin_auth,
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

async fn run_health_checks(
    state: EdgeState,
    config: HealthCheckConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Empty<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);
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
    client: &Client<HttpConnector, Empty<Bytes>>,
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

    loop {
        tokio::select! {
            _ = interval.tick() => {
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
                        pending_domains = None;
                        continue;
                    }

                    attempts += 1;
                    match cert_store.regenerate_certificate(&domains).await {
                        Ok(bundle) => match cert_store.server_config_from_bundle(&bundle) {
                            Ok(config) => {
                                tls_config.store(config);
                                exhausted_domains = None;
                                pending_domains = None;
                                attempts = 0;
                                current_domains = domains;
                                info!("reloaded local TLS certificate for dynamic route domains");
                            }
                            Err(error) => warn!(
                                %error,
                                attempt = attempts,
                                max_attempts = TLS_RELOAD_MAX_ATTEMPTS,
                                "failed to rebuild TLS server config"
                            ),
                        },
                        Err(error) => warn!(
                            %error,
                            attempt = attempts,
                            max_attempts = TLS_RELOAD_MAX_ATTEMPTS,
                            "failed to regenerate local TLS certificate"
                        ),
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

fn parse_addr(name: &str, value: &str) -> Result<SocketAddr> {
    value
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid socket address for {name}: {value}"))
}
