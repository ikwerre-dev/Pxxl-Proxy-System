use ipnet::IpNet;
use pxxl_common::{
    normalize_path_prefix, DomainRules, ListenerConfig, LoadBalancingAlgorithm, PathRoute, Route,
    RouteSource, Upstream,
};
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse TOML config {path}: {source}")]
    Parse {
        path: String,
        source: toml::de::Error,
    },
    #[error("route for domain {domain} has no upstreams")]
    MissingUpstreams { domain: String },
}

pub type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PxxlConfig {
    #[serde(default)]
    pub listeners: ListenerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub docker: DockerConfig,
    #[serde(default)]
    pub podman: PodmanConfig,
    #[serde(default)]
    pub error_pages: ErrorPagesConfig,
    #[serde(default)]
    pub geoip: GeoIpConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub redis: RedisConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

impl PxxlConfig {
    pub async fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content =
            tokio::fs::read_to_string(path)
                .await
                .map_err(|source| ConfigError::Read {
                    path: path.display().to_string(),
                    source,
                })?;
        toml::from_str(&content).map_err(|source| ConfigError::Parse {
            path: path.display().to_string(),
            source,
        })
    }

    pub fn static_routes(&self) -> Result<Vec<Route>> {
        self.routes
            .iter()
            .map(RouteConfig::to_route)
            .collect::<Result<Vec<_>>>()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default = "default_tls_mode")]
    pub mode: String,
    #[serde(default = "default_cert_dir")]
    pub cert_dir: String,
    #[serde(default)]
    pub local_subject_alt_names: Vec<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            mode: default_tls_mode(),
            cert_dir: default_cert_dir(),
            local_subject_alt_names: vec![
                "localhost".to_string(),
                "pxxlhost".to_string(),
                "*.pxxlhost".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_docker_socket")]
    pub socket_path: String,
    #[serde(default = "default_docker_poll_seconds")]
    pub poll_seconds: u64,
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socket_path: default_docker_socket(),
            poll_seconds: default_docker_poll_seconds(),
        }
    }
}

impl DockerConfig {
    pub fn poll_interval(&self) -> Duration {
        Duration::from_secs(self.poll_seconds.max(1))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodmanConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_podman_socket")]
    pub socket_path: String,
    #[serde(default = "default_podman_published_host")]
    pub published_host: String,
    #[serde(default = "default_docker_poll_seconds")]
    pub poll_seconds: u64,
}

impl Default for PodmanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socket_path: default_podman_socket(),
            published_host: default_podman_published_host(),
            poll_seconds: default_docker_poll_seconds(),
        }
    }
}

impl PodmanConfig {
    pub fn poll_interval(&self) -> Duration {
        Duration::from_secs(self.poll_seconds.max(1))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPagesConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_error_pages_dir")]
    pub dir: String,
}

impl Default for ErrorPagesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: default_error_pages_dir(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_geoip_database_path")]
    pub database_path: String,
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            database_path: default_geoip_database_path(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default)]
    pub rate_limits: RateLimitConfig,
    #[serde(default)]
    pub blacklists: BlacklistConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: u32,
    #[serde(default = "default_burst")]
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: default_requests_per_second(),
            burst: default_burst(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlacklistConfig {
    #[serde(default)]
    pub cidrs: Vec<IpNet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    #[serde(default = "default_redis_url")]
    pub url: String,
    #[serde(default = "default_blacklist_channel")]
    pub blacklist_channel: String,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: default_redis_url(),
            blacklist_channel: default_blacklist_channel(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_postgres_url")]
    pub postgres_url: String,
    #[serde(default = "default_clickhouse_url")]
    pub clickhouse_url: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            postgres_url: default_postgres_url(),
            clickhouse_url: default_clickhouse_url(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    pub domain: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub tls: Option<bool>,
    #[serde(default)]
    pub algorithm: LoadBalancingAlgorithm,
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default)]
    pub paths: Vec<PathConfig>,
    #[serde(default)]
    pub rules: DomainRules,
}

impl RouteConfig {
    pub fn to_route(&self) -> Result<Route> {
        let paths = if self.paths.is_empty() {
            if self.upstreams.is_empty() {
                return Err(ConfigError::MissingUpstreams {
                    domain: self.domain.clone(),
                });
            }
            vec![PathRoute::new(
                "/",
                self.upstreams
                    .iter()
                    .map(UpstreamConfig::to_upstream)
                    .collect(),
            )]
        } else {
            self.paths
                .iter()
                .map(|path| {
                    let upstreams: Vec<Upstream> = if path.upstreams.is_empty() {
                        self.upstreams
                            .iter()
                            .map(UpstreamConfig::to_upstream)
                            .collect()
                    } else {
                        path.upstreams
                            .iter()
                            .map(UpstreamConfig::to_upstream)
                            .collect()
                    };

                    if upstreams.is_empty() {
                        return Err(ConfigError::MissingUpstreams {
                            domain: self.domain.clone(),
                        });
                    }

                    Ok(PathRoute {
                        prefix: normalize_path_prefix(path.prefix.as_str()),
                        upstreams,
                        middlewares: path.middlewares.clone(),
                    })
                })
                .collect::<Result<Vec<_>>>()?
        };

        let mut route = Route::new(self.domain.as_str(), paths, RouteSource::Static);
        route.tls = self.tls.unwrap_or(true);
        route.algorithm = self.algorithm.clone();
        route.rules = self.rules.clone();

        if let Some(id) = &self.id {
            route = route.with_id(id);
        }

        Ok(route)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathConfig {
    #[serde(default = "root_path")]
    pub prefix: String,
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default)]
    pub middlewares: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub url: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

impl UpstreamConfig {
    pub fn to_upstream(&self) -> Upstream {
        Upstream {
            url: self.url.clone(),
            weight: self.weight,
            healthy: true,
        }
    }
}

fn default_tls_mode() -> String {
    "local".to_string()
}

fn default_cert_dir() -> String {
    "/data/certs".to_string()
}

fn default_docker_socket() -> String {
    "/var/run/docker.sock".to_string()
}

fn default_podman_socket() -> String {
    "/var/run/podman/podman.sock".to_string()
}

fn default_podman_published_host() -> String {
    "host.docker.internal".to_string()
}

fn default_docker_poll_seconds() -> u64 {
    5
}

fn default_error_pages_dir() -> String {
    "config/error-pages".to_string()
}

fn default_geoip_database_path() -> String {
    "config/geoip/geoip.csv".to_string()
}

fn default_requests_per_second() -> u32 {
    120
}

fn default_burst() -> u32 {
    240
}

fn default_redis_url() -> String {
    "redis://redis:6379".to_string()
}

fn default_blacklist_channel() -> String {
    "pxxl:blacklist".to_string()
}

fn default_postgres_url() -> String {
    "postgres://pxxl:pxxl@postgres:5432/pxxl".to_string()
}

fn default_clickhouse_url() -> String {
    "http://clickhouse:8123".to_string()
}

fn default_weight() -> u32 {
    1
}

fn default_false() -> bool {
    false
}

fn default_true() -> bool {
    true
}

fn root_path() -> String {
    "/".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_static_route_with_root_upstreams() {
        let raw = r#"
            [listeners]
            http = "127.0.0.1:8080"
            https = "127.0.0.1:8443"
            admin = "127.0.0.1:8081"
            metrics = "127.0.0.1:9090"

            [[routes]]
            id = "app"
            domain = "app.pxxlhost"
            [[routes.upstreams]]
            url = "http://web:3000"
        "#;

        let config: PxxlConfig = toml::from_str(raw).unwrap();
        let routes = config.static_routes().unwrap();

        assert_eq!(routes[0].id, "app");
        assert_eq!(routes[0].domain, "app.pxxlhost");
        assert_eq!(routes[0].paths[0].upstreams[0].url, "http://web:3000");
    }

    #[test]
    fn parses_path_specific_upstreams() {
        let raw = r#"
            [[routes]]
            domain = "api.pxxlhost"

            [[routes.paths]]
            prefix = "/v1"
            [[routes.paths.upstreams]]
            url = "http://api:3000"
        "#;

        let config: PxxlConfig = toml::from_str(raw).unwrap();
        let routes = config.static_routes().unwrap();

        assert_eq!(routes[0].paths[0].prefix, "/v1");
    }

    #[test]
    fn parses_podman_discovery_config() {
        let raw = r#"
            [podman]
            enabled = true
            socket_path = "/var/run/podman/podman.sock"
            published_host = "host.docker.internal"
            poll_seconds = 2
        "#;

        let config: PxxlConfig = toml::from_str(raw).unwrap();

        assert!(config.podman.enabled);
        assert_eq!(config.podman.socket_path, "/var/run/podman/podman.sock");
        assert_eq!(config.podman.published_host, "host.docker.internal");
        assert_eq!(config.podman.poll_interval(), Duration::from_secs(2));
    }

    #[test]
    fn parses_error_pages_config() {
        let raw = r#"
            [error_pages]
            enabled = true
            dir = "/etc/pxxl/errors"
        "#;

        let config: PxxlConfig = toml::from_str(raw).unwrap();

        assert!(config.error_pages.enabled);
        assert_eq!(config.error_pages.dir, "/etc/pxxl/errors");
    }

    #[test]
    fn parses_geoip_config() {
        let raw = r#"
            [geoip]
            enabled = true
            database_path = "/etc/pxxl/geoip.csv"
        "#;

        let config: PxxlConfig = toml::from_str(raw).unwrap();

        assert!(config.geoip.enabled);
        assert_eq!(config.geoip.database_path, "/etc/pxxl/geoip.csv");
    }

    #[test]
    fn parses_route_rules_config() {
        let allowed_ip: std::net::IpAddr = "203.0.113.10".parse().unwrap();
        let raw = r#"
            [[routes]]
            domain = "secure.pxxlhost"
            [[routes.upstreams]]
            url = "http://secure:3000"

            [routes.rules]
            allow_websocket = false
            require_https = true
            allowed_methods = ["GET", "POST"]
            blocked_headers = ["x-debug-token"]
            ip_allowlist = ["203.0.113.10"]
            add_security_headers = true

            [routes.rules.rate_limit]
            requests_per_minute = 60
            burst = 10
            scope = "per_ip_path"
        "#;

        let config: PxxlConfig = toml::from_str(raw).unwrap();
        let route = config.static_routes().unwrap().remove(0);

        assert!(!route.rules.allow_websocket);
        assert!(route.rules.require_https);
        assert_eq!(route.rules.allowed_methods, vec!["GET", "POST"]);
        assert!(route.rules.ip_allowlist[0].contains(&allowed_ip));
        assert!(route.rules.rate_limit.is_some());
    }
}
