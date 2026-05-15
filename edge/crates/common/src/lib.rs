use chrono::{DateTime, Utc};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{de, Deserialize, Deserializer, Serialize};
use std::{collections::HashMap, fmt, net::IpAddr, str::FromStr};
use url::Url;
use uuid::Uuid;

pub type DomainId = String;

#[derive(Debug, thiserror::Error)]
pub enum PxxlError {
    #[error("route not found for host {host} and path {path}")]
    RouteNotFound { host: String, path: String },
    #[error("route {route_id} has no healthy upstreams")]
    NoHealthyUpstreams { route_id: String },
    #[error("invalid upstream URL {0}")]
    InvalidUpstream(String),
    #[error("invalid host header")]
    InvalidHost,
}

pub type Result<T> = std::result::Result<T, PxxlError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListenerConfig {
    pub http: String,
    pub https: String,
    pub admin: String,
    pub metrics: String,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            http: "0.0.0.0:80".to_string(),
            https: "0.0.0.0:443".to_string(),
            admin: "0.0.0.0:8081".to_string(),
            metrics: "0.0.0.0:9090".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteSource {
    Static,
    Docker,
    Podman,
    Api,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingAlgorithm {
    RoundRobin,
    LeastConnections,
    IpHash,
    WeightedRoundRobin,
    EwmaLatency,
}

impl Default for LoadBalancingAlgorithm {
    fn default() -> Self {
        Self::RoundRobin
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Upstream {
    pub url: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default = "default_true")]
    pub healthy: bool,
}

impl Upstream {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            weight: default_weight(),
            healthy: true,
        }
    }

    pub fn authority(&self) -> Result<String> {
        let parsed =
            Url::parse(&self.url).map_err(|_| PxxlError::InvalidUpstream(self.url.clone()))?;
        parsed
            .host_str()
            .map(|host| match parsed.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            })
            .ok_or_else(|| PxxlError::InvalidUpstream(self.url.clone()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathRoute {
    pub prefix: String,
    pub upstreams: Vec<Upstream>,
    #[serde(default)]
    pub middlewares: Vec<String>,
}

impl PathRoute {
    pub fn new(prefix: impl Into<String>, upstreams: Vec<Upstream>) -> Self {
        Self {
            prefix: normalize_path_prefix(prefix),
            upstreams,
            middlewares: Vec::new(),
        }
    }

    pub fn matches(&self, path: &str) -> bool {
        if self.prefix == "/" {
            return true;
        }
        path == self.prefix || path.starts_with(&format!("{}/", self.prefix.trim_end_matches('/')))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainRules {
    #[serde(default = "default_true")]
    pub allow_websocket: bool,
    #[serde(default)]
    pub require_https: bool,
    #[serde(default)]
    pub redirect_http_to_https: bool,
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub blocked_methods: Vec<String>,
    #[serde(default)]
    pub allowed_headers: Vec<String>,
    #[serde(default)]
    pub blocked_headers: Vec<String>,
    #[serde(default)]
    pub required_headers: Vec<RequiredHeaderRule>,
    #[serde(default)]
    pub strip_request_headers: Vec<String>,
    #[serde(default)]
    pub add_request_headers: HashMap<String, String>,
    #[serde(default)]
    pub response_headers: HashMap<String, String>,
    #[serde(
        default,
        alias = "whitelist_ips",
        alias = "allowed_ips",
        deserialize_with = "deserialize_ip_nets"
    )]
    pub ip_allowlist: Vec<IpNet>,
    #[serde(
        default,
        alias = "blacklist_ips",
        alias = "blocked_ips",
        deserialize_with = "deserialize_ip_nets"
    )]
    pub ip_blocklist: Vec<IpNet>,
    #[serde(default)]
    pub rate_limit: Option<DomainRateLimit>,
    #[serde(default)]
    pub max_body_bytes: Option<u64>,
    #[serde(default)]
    pub max_uri_length: Option<usize>,
    #[serde(default)]
    pub allowed_content_types: Vec<String>,
    #[serde(default)]
    pub maintenance_mode: bool,
    #[serde(default)]
    pub preserve_host_header: bool,
    #[serde(default)]
    pub add_security_headers: bool,
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
    #[serde(default)]
    pub cors_allow_credentials: bool,
    #[serde(default)]
    pub cors_allowed_methods: Vec<String>,
    #[serde(default)]
    pub cors_allowed_headers: Vec<String>,
    #[serde(default = "default_true")]
    pub cors_preflight_enabled: bool,
}

impl Default for DomainRules {
    fn default() -> Self {
        Self {
            allow_websocket: true,
            require_https: false,
            redirect_http_to_https: false,
            allowed_methods: Vec::new(),
            blocked_methods: Vec::new(),
            allowed_headers: Vec::new(),
            blocked_headers: Vec::new(),
            required_headers: Vec::new(),
            strip_request_headers: Vec::new(),
            add_request_headers: HashMap::new(),
            response_headers: HashMap::new(),
            ip_allowlist: Vec::new(),
            ip_blocklist: Vec::new(),
            rate_limit: None,
            max_body_bytes: None,
            max_uri_length: None,
            allowed_content_types: Vec::new(),
            maintenance_mode: false,
            preserve_host_header: false,
            add_security_headers: false,
            cors_allowed_origins: Vec::new(),
            cors_allow_credentials: false,
            cors_allowed_methods: Vec::new(),
            cors_allowed_headers: Vec::new(),
            cors_preflight_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequiredHeaderRule {
    pub name: String,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainRateLimit {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub requests_per_second: Option<u32>,
    #[serde(default)]
    pub requests_per_minute: Option<u32>,
    #[serde(default = "default_domain_rate_burst")]
    pub burst: u32,
    #[serde(default)]
    pub scope: RateLimitScope,
    #[serde(default = "default_rate_limit_status_code")]
    pub status_code: u16,
    #[serde(default)]
    pub retry_after_seconds: Option<u64>,
}

impl Default for DomainRateLimit {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: None,
            requests_per_minute: None,
            burst: default_domain_rate_burst(),
            scope: RateLimitScope::default(),
            status_code: default_rate_limit_status_code(),
            retry_after_seconds: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitScope {
    PerIp,
    PerDomain,
    PerIpPath,
}

impl Default for RateLimitScope {
    fn default() -> Self {
        Self::PerIp
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Route {
    pub id: String,
    pub domain: String,
    #[serde(default)]
    pub paths: Vec<PathRoute>,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub algorithm: LoadBalancingAlgorithm,
    #[serde(default)]
    pub rules: DomainRules,
    pub source: RouteSource,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Route {
    pub fn new(domain: impl Into<String>, paths: Vec<PathRoute>, source: RouteSource) -> Self {
        let now = Utc::now();
        let domain = normalize_domain(&domain.into());
        Self {
            id: Uuid::new_v4().to_string(),
            domain,
            paths: if paths.is_empty() {
                vec![PathRoute::new("/", Vec::new())]
            } else {
                paths
            },
            tls: true,
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            rules: DomainRules::default(),
            source,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    pub fn matches_host(&self, host: &str) -> bool {
        host_without_port(host)
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(&self.domain))
    }

    pub fn best_path(&self, path: &str) -> Option<&PathRoute> {
        self.paths
            .iter()
            .filter(|route| route.matches(path))
            .max_by_key(|route| route.prefix.len())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteMatch {
    pub route: Route,
    pub path: PathRoute,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLogRecord {
    pub request_id: String,
    pub domain: String,
    pub path: String,
    pub upstream: Option<String>,
    pub status: u16,
    pub latency_ms: u128,
    pub remote_ip: Option<String>,
    pub timestamp: DateTime<Utc>,
}

impl fmt::Display for AccessLogRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {}ms",
            self.request_id, self.domain, self.path, self.status, self.latency_ms
        )
    }
}

pub fn normalize_domain(domain: &str) -> String {
    host_without_port(domain)
        .unwrap_or(domain)
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

pub fn host_without_port(host: &str) -> Option<&str> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.starts_with('[') {
        return trimmed
            .split(']')
            .next()
            .map(|part| part.trim_start_matches('['));
    }

    trimmed.split(':').next()
}

pub fn normalize_path_prefix(prefix: impl Into<String>) -> String {
    let raw = prefix.into();
    if raw.trim().is_empty() || raw == "/" {
        return "/".to_string();
    }
    let with_slash = if raw.starts_with('/') {
        raw
    } else {
        format!("/{raw}")
    };
    with_slash.trim_end_matches('/').to_string()
}

fn default_weight() -> u32 {
    1
}

fn default_true() -> bool {
    true
}

fn default_domain_rate_burst() -> u32 {
    240
}

fn default_rate_limit_status_code() -> u16 {
    429
}

fn deserialize_ip_nets<'de, D>(deserializer: D) -> std::result::Result<Vec<IpNet>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    values
        .into_iter()
        .map(|value| parse_ip_net(&value).map_err(de::Error::custom))
        .collect()
}

fn parse_ip_net(value: &str) -> std::result::Result<IpNet, String> {
    if let Ok(network) = IpNet::from_str(value) {
        return Ok(network);
    }

    match value.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => Ipv4Net::new(ip, 32)
            .map(IpNet::V4)
            .map_err(|error| error.to_string()),
        Ok(IpAddr::V6(ip)) => Ipv6Net::new(ip, 128)
            .map(IpNet::V6)
            .map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_matches_host_without_port() {
        let route = Route::new(
            "App.Example.Com",
            vec![PathRoute::new("/", vec![Upstream::new("http://app:3000")])],
            RouteSource::Static,
        );

        assert!(route.matches_host("app.example.com:443"));
        assert!(route.matches_host("APP.EXAMPLE.COM"));
        assert!(!route.matches_host("api.example.com"));
    }

    #[test]
    fn best_path_prefers_longest_prefix() {
        let route = Route::new(
            "api.example.com",
            vec![
                PathRoute::new("/", vec![Upstream::new("http://root:3000")]),
                PathRoute::new("/v1", vec![Upstream::new("http://v1:3000")]),
                PathRoute::new("/v1/admin", vec![Upstream::new("http://admin:3000")]),
            ],
            RouteSource::Static,
        );

        assert_eq!(
            route.best_path("/v1/admin/users").unwrap().prefix,
            "/v1/admin"
        );
        assert_eq!(route.best_path("/v1/users").unwrap().prefix, "/v1");
        assert_eq!(route.best_path("/health").unwrap().prefix, "/");
    }

    #[test]
    fn route_rules_default_to_permissive() {
        let route = Route::new(
            "app.example.com",
            vec![PathRoute::new("/", vec![Upstream::new("http://app:3000")])],
            RouteSource::Static,
        );

        assert!(route.rules.allow_websocket);
        assert!(route.rules.allowed_methods.is_empty());
        assert!(route.rules.ip_allowlist.is_empty());
        assert!(route.rules.rate_limit.is_none());
    }

    #[test]
    fn route_rules_parse_bare_ips_as_single_host_networks() {
        let allowed_ip: IpAddr = "203.0.113.10".parse().unwrap();
        let blocked_ip: IpAddr = "198.51.100.44".parse().unwrap();
        let raw = r#"
            {
              "domain": "app.example.com",
              "paths": [],
              "source": "api",
              "id": "api-app",
              "tls": true,
              "algorithm": "round_robin",
              "created_at": "2026-01-01T00:00:00Z",
              "updated_at": "2026-01-01T00:00:00Z",
              "rules": {
                "ip_allowlist": ["203.0.113.10"],
                "ip_blocklist": ["198.51.100.0/24"]
              }
            }
        "#;

        let route: Route = serde_json::from_str(raw).unwrap();

        assert!(route.rules.ip_allowlist[0].contains(&allowed_ip));
        assert!(route.rules.ip_blocklist[0].contains(&blocked_ip));
    }
}
