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

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingAlgorithm {
    #[default]
    RoundRobin,
    LeastConnections,
    IpHash,
    WeightedRoundRobin,
    EwmaLatency,
    P2c,
    Hrw,
    LatencyAware,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Upstream {
    pub url: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default = "default_true")]
    pub healthy: bool,
    #[serde(default)]
    pub backup: bool,
    #[serde(default)]
    pub transport: UpstreamTransport,
}

impl Upstream {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            weight: default_weight(),
            healthy: true,
            backup: false,
            transport: UpstreamTransport::default(),
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
pub struct GeoLocation {
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub country_name: Option<String>,
    #[serde(default)]
    pub continent_code: Option<String>,
    #[serde(default)]
    pub continent_name: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default = "unknown_geo_source")]
    pub source: String,
}

impl GeoLocation {
    pub fn unknown() -> Self {
        Self {
            country_code: None,
            country_name: None,
            continent_code: None,
            continent_name: None,
            region: None,
            city: None,
            source: unknown_geo_source(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainRules {
    #[serde(default)]
    pub www_alias: bool,
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
    #[serde(default, alias = "country_allowlist", alias = "allowed_countries")]
    pub country_allowlist: Vec<String>,
    #[serde(default, alias = "country_blocklist", alias = "blocked_countries")]
    pub country_blocklist: Vec<String>,
    #[serde(default, alias = "continent_allowlist", alias = "allowed_continents")]
    pub continent_allowlist: Vec<String>,
    #[serde(default, alias = "continent_blocklist", alias = "blocked_continents")]
    pub continent_blocklist: Vec<String>,
    #[serde(default)]
    pub location_routes: Vec<LocationRouteRule>,
    #[serde(default)]
    pub traffic_splits: Vec<TrafficSplitRule>,
    #[serde(default)]
    pub waf: DomainWafRules,
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
    #[serde(default)]
    pub middlewares: HashMap<String, MiddlewareDefinition>,
    #[serde(default)]
    pub middleware_chains: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub request_buffering: BufferingConfig,
    #[serde(default)]
    pub response_buffering: BufferingConfig,
    #[serde(default)]
    pub compression: CompressionConfig,
    #[serde(default)]
    pub content_type_autodetect: ContentTypeAutoDetectConfig,
    #[serde(default)]
    pub retry: RetryConfig,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    #[serde(default)]
    pub in_flight_limit: InFlightLimitConfig,
    #[serde(default)]
    pub sticky_sessions: StickySessionConfig,
    #[serde(default)]
    pub passive_health: PassiveHealthConfig,
    #[serde(default)]
    pub traffic_mirroring: TrafficMirrorConfig,
    #[serde(default)]
    pub client_cert_forwarding: ClientCertForwardingConfig,
    #[serde(default)]
    pub services: HashMap<String, ServiceDefinition>,
    #[serde(default)]
    pub upstream_transport: UpstreamTransport,
    #[serde(default)]
    pub tls_options: RouterTlsOptions,
    #[serde(default)]
    pub acme: AcmeConfig,
    #[serde(default)]
    pub tcp: TcpRoutingConfig,
    #[serde(default)]
    pub udp: UdpRoutingConfig,
    #[serde(default)]
    pub http3: Http3Config,
}

impl Default for DomainRules {
    fn default() -> Self {
        Self {
            www_alias: false,
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
            country_allowlist: Vec::new(),
            country_blocklist: Vec::new(),
            continent_allowlist: Vec::new(),
            continent_blocklist: Vec::new(),
            location_routes: Vec::new(),
            traffic_splits: Vec::new(),
            waf: DomainWafRules::default(),
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
            middlewares: HashMap::new(),
            middleware_chains: HashMap::new(),
            request_buffering: BufferingConfig::default(),
            response_buffering: BufferingConfig::default(),
            compression: CompressionConfig::default(),
            content_type_autodetect: ContentTypeAutoDetectConfig::default(),
            retry: RetryConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            in_flight_limit: InFlightLimitConfig::default(),
            sticky_sessions: StickySessionConfig::default(),
            passive_health: PassiveHealthConfig::default(),
            traffic_mirroring: TrafficMirrorConfig::default(),
            client_cert_forwarding: ClientCertForwardingConfig::default(),
            services: HashMap::new(),
            upstream_transport: UpstreamTransport::default(),
            tls_options: RouterTlsOptions::default(),
            acme: AcmeConfig::default(),
            tcp: TcpRoutingConfig::default(),
            udp: UdpRoutingConfig::default(),
            http3: Http3Config::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MiddlewareDefinition {
    #[serde(default)]
    pub chain: Vec<String>,
    #[serde(default)]
    pub basic_auth: Option<BasicAuthConfig>,
    #[serde(default)]
    pub digest_auth: Option<DigestAuthConfig>,
    #[serde(default)]
    pub forward_auth: Option<ForwardAuthConfig>,
    #[serde(default)]
    pub request_buffering: Option<BufferingConfig>,
    #[serde(default)]
    pub response_buffering: Option<BufferingConfig>,
    #[serde(default)]
    pub compression: Option<CompressionConfig>,
    #[serde(default)]
    pub content_type_autodetect: Option<ContentTypeAutoDetectConfig>,
    #[serde(default)]
    pub retry: Option<RetryConfig>,
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,
    #[serde(default)]
    pub in_flight_limit: Option<InFlightLimitConfig>,
    #[serde(default)]
    pub pass_tls_client_cert: Option<ClientCertForwardingConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BasicAuthConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_auth_realm")]
    pub realm: String,
    #[serde(default)]
    pub users: HashMap<String, String>,
}

impl Default for BasicAuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            realm: default_auth_realm(),
            users: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DigestAuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_auth_realm")]
    pub realm: String,
    #[serde(default)]
    pub users: HashMap<String, String>,
}

impl Default for DigestAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            realm: default_auth_realm(),
            users: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForwardAuthConfig {
    #[serde(default)]
    pub enabled: bool,
    pub url: String,
    #[serde(default)]
    pub request_headers: Vec<String>,
    #[serde(default)]
    pub response_headers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BufferingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_request_buffer_bytes")]
    pub max_request_bytes: u64,
    #[serde(default = "default_response_buffer_bytes")]
    pub max_response_bytes: u64,
}

impl Default for BufferingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_request_bytes: default_request_buffer_bytes(),
            max_response_bytes: default_response_buffer_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompressionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_min_compress_bytes")]
    pub min_bytes: usize,
    #[serde(default)]
    pub content_types: Vec<String>,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_bytes: default_min_compress_bytes(),
            content_types: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentTypeAutoDetectConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_retry_attempts")]
    pub attempts: u32,
    #[serde(default = "default_retry_backoff_ms")]
    pub backoff_ms: u64,
    #[serde(default)]
    pub retry_statuses: Vec<u16>,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            attempts: default_retry_attempts(),
            backoff_ms: default_retry_backoff_ms(),
            retry_statuses: vec![502, 503, 504],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircuitBreakerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_circuit_failures")]
    pub failure_threshold: u32,
    #[serde(default = "default_circuit_open_seconds")]
    pub open_seconds: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            failure_threshold: default_circuit_failures(),
            open_seconds: default_circuit_open_seconds(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct InFlightLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub max: Option<u32>,
    #[serde(default)]
    pub scope: InFlightLimitScope,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InFlightLimitScope {
    #[default]
    Route,
    Domain,
    Upstream,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StickySessionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_sticky_cookie_name")]
    pub cookie_name: String,
    #[serde(default = "default_true")]
    pub http_only: bool,
    #[serde(default)]
    pub secure: bool,
    #[serde(default)]
    pub same_site: Option<String>,
    #[serde(default)]
    pub max_age_seconds: Option<u64>,
}

impl Default for StickySessionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cookie_name: default_sticky_cookie_name(),
            http_only: true,
            secure: false,
            same_site: None,
            max_age_seconds: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PassiveHealthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_passive_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_passive_recovery_seconds")]
    pub recovery_seconds: u64,
    #[serde(default)]
    pub failure_statuses: Vec<u16>,
}

impl Default for PassiveHealthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            failure_threshold: default_passive_failure_threshold(),
            recovery_seconds: default_passive_recovery_seconds(),
            failure_statuses: vec![500, 502, 503, 504],
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrafficMirrorConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    #[serde(default = "default_mirror_percent")]
    pub percent: u8,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientCertForwardingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_client_cert_header")]
    pub header_name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceDefinition {
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    #[serde(default)]
    pub weighted: Vec<WeightedServiceTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WeightedServiceTarget {
    pub service: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpstreamTransport {
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub insecure_skip_verify: bool,
    #[serde(default)]
    pub ca_roots: Vec<String>,
    #[serde(default)]
    pub mtls_cert_path: Option<String>,
    #[serde(default)]
    pub mtls_key_path: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouterTlsOptions {
    #[serde(default)]
    pub min_version: Option<String>,
    #[serde(default)]
    pub cipher_suites: Vec<String>,
    #[serde(default)]
    pub client_auth: ClientAuthConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientAuthConfig {
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub ca_roots: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub directory_url: Option<String>,
    #[serde(default)]
    pub challenge: AcmeChallenge,
    #[serde(default)]
    pub dns_provider: Option<String>,
    #[serde(default)]
    pub wildcard: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AcmeChallenge {
    #[default]
    Http01,
    Dns01,
    TlsAlpn01,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TcpRoutingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub host_sni: Vec<String>,
    #[serde(default)]
    pub tls_passthrough: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UdpRoutingConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Http3Config {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocationRouteRule {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, alias = "country_codes")]
    pub countries: Vec<String>,
    #[serde(default, alias = "continent_codes")]
    pub continents: Vec<String>,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrafficSplitRule {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default, alias = "country_codes")]
    pub countries: Vec<String>,
    #[serde(default, alias = "continent_codes")]
    pub continents: Vec<String>,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainWafRules {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub block_path_traversal: bool,
    #[serde(default = "default_true")]
    pub block_sql_injection: bool,
    #[serde(default = "default_true")]
    pub block_xss: bool,
    #[serde(default)]
    pub block_bad_bots: bool,
    #[serde(default)]
    pub blocked_user_agents: Vec<String>,
    #[serde(default)]
    pub blocked_path_patterns: Vec<String>,
    #[serde(default)]
    pub blocked_query_patterns: Vec<String>,
}

impl Default for DomainWafRules {
    fn default() -> Self {
        Self {
            enabled: false,
            block_path_traversal: true,
            block_sql_injection: true,
            block_xss: true,
            block_bad_bots: false,
            blocked_user_agents: Vec::new(),
            blocked_path_patterns: Vec::new(),
            blocked_query_patterns: Vec::new(),
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

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitScope {
    #[default]
    PerIp,
    PerDomain,
    PerIpPath,
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

fn unknown_geo_source() -> String {
    "unknown".to_string()
}

fn default_domain_rate_burst() -> u32 {
    240
}

fn default_rate_limit_status_code() -> u16 {
    429
}

fn default_auth_realm() -> String {
    "Pxxl".to_string()
}

fn default_request_buffer_bytes() -> u64 {
    16 * 1024 * 1024
}

fn default_response_buffer_bytes() -> u64 {
    32 * 1024 * 1024
}

fn default_min_compress_bytes() -> usize {
    1024
}

fn default_retry_attempts() -> u32 {
    2
}

fn default_retry_backoff_ms() -> u64 {
    50
}

fn default_circuit_failures() -> u32 {
    5
}

fn default_circuit_open_seconds() -> u64 {
    30
}

fn default_sticky_cookie_name() -> String {
    "pxxl_upstream".to_string()
}

fn default_passive_failure_threshold() -> u32 {
    3
}

fn default_passive_recovery_seconds() -> u64 {
    30
}

fn default_mirror_percent() -> u8 {
    100
}

fn default_client_cert_header() -> String {
    "x-forwarded-tls-client-cert".to_string()
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

pub fn parse_ip_net(value: &str) -> std::result::Result<IpNet, String> {
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
