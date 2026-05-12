use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
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
        let parsed = Url::parse(&self.url).map_err(|_| PxxlError::InvalidUpstream(self.url.clone()))?;
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
pub struct Route {
    pub id: String,
    pub domain: String,
    #[serde(default)]
    pub paths: Vec<PathRoute>,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub algorithm: LoadBalancingAlgorithm,
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
        host_without_port(host).is_some_and(|candidate| candidate.eq_ignore_ascii_case(&self.domain))
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
    host_without_port(domain).unwrap_or(domain).trim_end_matches('.').to_ascii_lowercase()
}

pub fn host_without_port(host: &str) -> Option<&str> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.starts_with('[') {
        return trimmed.split(']').next().map(|part| part.trim_start_matches('['));
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

        assert_eq!(route.best_path("/v1/admin/users").unwrap().prefix, "/v1/admin");
        assert_eq!(route.best_path("/v1/users").unwrap().prefix, "/v1");
        assert_eq!(route.best_path("/health").unwrap().prefix, "/");
    }
}
