use anyhow::{bail, Context, Result};
use pxxl_common::{
    normalize_domain, normalize_path_prefix, PathRoute, Route, RouteSource, Upstream,
};
use pxxl_core::EdgeState;
use serde::{Deserialize, Deserializer};
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::watch,
    time,
};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct DockerDiscovery {
    provider: ContainerProvider,
    socket_path: PathBuf,
    published_port_host: Option<String>,
}

const DOCKER_API_RESPONSE_LIMIT_BYTES: usize = 5 * 1024 * 1024;

impl DockerDiscovery {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self::with_provider(ContainerProvider::Docker, socket_path)
    }

    pub fn podman(socket_path: impl Into<PathBuf>, published_port_host: impl Into<String>) -> Self {
        Self {
            provider: ContainerProvider::Podman,
            socket_path: socket_path.into(),
            published_port_host: Some(published_port_host.into()),
        }
    }

    pub fn with_provider(provider: ContainerProvider, socket_path: impl Into<PathBuf>) -> Self {
        Self {
            provider,
            socket_path: socket_path.into(),
            published_port_host: None,
        }
    }

    pub async fn discover_once(&self) -> Result<Vec<Route>> {
        let body = self.docker_get("/containers/json").await.with_context(|| {
            format!(
                "failed to query Docker socket {}",
                self.socket_path.display()
            )
        })?;
        let containers: Vec<DockerContainerSummary> =
            serde_json::from_slice(&body).context("failed to parse Docker containers JSON")?;

        let targets = containers
            .into_iter()
            .filter_map(|container| {
                let name = container.primary_name();
                route_target_from_container(&container, &name, self.published_port_host.as_deref())
            })
            .collect::<Vec<_>>();

        Ok(routes_from_targets(targets, self.provider))
    }

    async fn docker_get(&self, path: &str) -> Result<Vec<u8>> {
        let mut stream = UnixStream::connect(&self.socket_path).await?;
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: docker\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;

        let mut response = Vec::new();
        let mut buffer = [0_u8; 8192];
        loop {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            if response.len() + read > DOCKER_API_RESPONSE_LIMIT_BYTES {
                bail!(
                    "Docker API response exceeded {} bytes",
                    DOCKER_API_RESPONSE_LIMIT_BYTES
                );
            }
            response.extend_from_slice(&buffer[..read]);
        }
        parse_http_response_body(&response).context("Docker HTTP response did not include a body")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerProvider {
    Docker,
    Podman,
}

impl ContainerProvider {
    fn label(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }

    fn route_source(self) -> RouteSource {
        match self {
            Self::Docker => RouteSource::Docker,
            Self::Podman => RouteSource::Podman,
        }
    }
}

pub async fn run_docker_polling(
    discovery: DockerDiscovery,
    state: EdgeState,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = time::interval(interval);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                match discovery.discover_once().await {
                    Ok(routes) => {
                        let provider = discovery.provider;
                        debug!(provider = provider.label(), count = routes.len(), "discovered container routes");
                        state.replace_routes_from_source(provider.route_source(), routes);
                        state
                            .metrics
                            .container_route_changes_total
                            .with_label_values(&[provider.label()])
                            .inc();
                        if provider == ContainerProvider::Docker {
                            state.metrics.docker_route_changes_total.inc();
                        }
                    }
                    Err(error) => {
                        warn!(provider = discovery.provider.label(), %error, "container discovery failed");
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    info!(provider = discovery.provider.label(), "stopping container discovery");
                    break;
                }
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerContainerSummary {
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    labels: HashMap<String, String>,
    #[serde(default, deserialize_with = "null_as_default")]
    ports: Vec<DockerPort>,
}

impl DockerContainerSummary {
    fn primary_name(&self) -> String {
        self.names
            .first()
            .map(|name| name.trim_start_matches('/').to_string())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "localhost".to_string())
    }

    fn published_port_for(&self, private_port: u16) -> Option<u16> {
        self.ports
            .iter()
            .find(|port| port.private_port == private_port && port.public_port.is_some())
            .and_then(|port| port.public_port)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerPort {
    private_port: u16,
    #[serde(default)]
    public_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerRouteTarget {
    domain: String,
    path: String,
    upstream: Upstream,
}

pub fn route_from_labels(labels: &HashMap<String, String>, container_name: &str) -> Option<Route> {
    route_target_from_labels(labels, container_name)
        .and_then(|target| route_from_target(target, ContainerProvider::Docker).ok())
}

fn route_target_from_labels(
    labels: &HashMap<String, String>,
    container_name: &str,
) -> Option<DockerRouteTarget> {
    let label_config = label_route_config(labels)?;
    let host = label_config.host.unwrap_or(container_name);
    Some(route_target_from_label_config(
        &label_config,
        host,
        label_config.port,
    ))
}

fn route_target_from_container(
    container: &DockerContainerSummary,
    container_name: &str,
    published_port_host: Option<&str>,
) -> Option<DockerRouteTarget> {
    let label_config = label_route_config(&container.labels)?;
    let (host, port) = match label_config.host {
        Some(host) => (host, label_config.port),
        None => match published_port_host {
            Some(host) => (
                host,
                container
                    .published_port_for(label_config.port)
                    .unwrap_or(label_config.port),
            ),
            None => (container_name, label_config.port),
        },
    };

    Some(route_target_from_label_config(&label_config, host, port))
}

struct LabelRouteConfig<'a> {
    domain: &'a str,
    path: &'a str,
    scheme: &'a str,
    host: Option<&'a str>,
    port: u16,
}

fn label_route_config(labels: &HashMap<String, String>) -> Option<LabelRouteConfig<'_>> {
    let enabled = labels
        .get("pxxl.enable")
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
    if !enabled {
        return None;
    }

    let domain = labels.get("pxxl.domain")?;
    let port = labels.get("pxxl.port")?.parse::<u16>().ok()?;
    let path = labels.get("pxxl.path").map(String::as_str).unwrap_or("/");
    let scheme = labels
        .get("pxxl.scheme")
        .map(String::as_str)
        .unwrap_or("http");
    let host = labels.get("pxxl.host").map(String::as_str);

    Some(LabelRouteConfig {
        domain,
        path,
        scheme,
        host,
        port,
    })
}

fn route_target_from_label_config(
    label_config: &LabelRouteConfig<'_>,
    host: &str,
    port: u16,
) -> DockerRouteTarget {
    DockerRouteTarget {
        domain: normalize_domain(label_config.domain),
        path: normalize_path_prefix(label_config.path),
        upstream: Upstream::new(format!("{}://{}:{}", label_config.scheme, host, port)),
    }
}

fn route_from_target(target: DockerRouteTarget, provider: ContainerProvider) -> Result<Route> {
    let id = container_route_id(provider, &target.domain, Some(&target.path));
    let route = Route::new(
        target.domain,
        vec![PathRoute::new(target.path, vec![target.upstream])],
        provider.route_source(),
    )
    .with_id(id);
    route
        .validate_for_dynamic_control_plane()
        .map_err(|reason| anyhow::anyhow!("invalid container route: {reason}"))?;
    Ok(route)
}

fn routes_from_targets(
    targets: impl IntoIterator<Item = DockerRouteTarget>,
    provider: ContainerProvider,
) -> Vec<Route> {
    let mut grouped: BTreeMap<String, BTreeMap<String, Vec<Upstream>>> = BTreeMap::new();

    for target in targets {
        let upstreams = grouped
            .entry(target.domain)
            .or_default()
            .entry(target.path)
            .or_default();

        if !upstreams
            .iter()
            .any(|upstream| upstream.url == target.upstream.url)
        {
            upstreams.push(target.upstream);
        }
    }

    grouped
        .into_iter()
        .filter_map(|(domain, paths_by_prefix)| {
            let paths = paths_by_prefix
                .into_iter()
                .map(|(prefix, mut upstreams)| {
                    upstreams.sort_by(|left, right| left.url.cmp(&right.url));
                    PathRoute::new(prefix, upstreams)
                })
                .collect::<Vec<_>>();

            let route = Route::new(domain.clone(), paths, provider.route_source())
                .with_id(container_route_id(provider, &domain, None));
            match route.validate_for_dynamic_control_plane() {
                Ok(()) => Some(route),
                Err(reason) => {
                    warn!(provider = provider.label(), %domain, %reason, "ignoring invalid container route");
                    None
                }
            }
        })
        .collect()
}

fn container_route_id(provider: ContainerProvider, domain: &str, path: Option<&str>) -> String {
    match path {
        Some(path) => format!("{}-{}-{}", provider.label(), domain, path.replace('/', "_")),
        None => format!("{}-{domain}", provider.label()),
    }
}

fn parse_http_response_body(response: &[u8]) -> Result<Vec<u8>> {
    let separator = b"\r\n\r\n";
    let split = response
        .windows(separator.len())
        .position(|window| window == separator)
        .context("missing HTTP header separator")?;
    let headers = std::str::from_utf8(&response[..split])
        .context("Docker response headers were not UTF-8")?;
    let body = &response[split + separator.len()..];

    let status_line = headers.lines().next().unwrap_or_default();
    if !status_line.contains(" 200 ") {
        bail!("Docker API returned non-200 response: {status_line}");
    }

    if has_header_value(headers, "transfer-encoding", "chunked") {
        decode_chunked_body(body)
    } else {
        Ok(body.to_vec())
    }
}

fn has_header_value(headers: &str, header_name: &str, expected_value: &str) -> bool {
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.trim().eq_ignore_ascii_case(header_name)
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(expected_value))
    })
}

fn decode_chunked_body(body: &[u8]) -> Result<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut cursor = 0;

    loop {
        let line_end = find_crlf(&body[cursor..])
            .context("invalid chunked body: missing chunk size")?
            + cursor;
        let size_line = std::str::from_utf8(&body[cursor..line_end])
            .context("invalid chunked body: chunk size was not UTF-8")?;
        let size_hex = size_line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16)
            .with_context(|| format!("invalid chunk size {size_hex}"))?;
        cursor = line_end + 2;

        if size == 0 {
            break;
        }

        let end = cursor + size;
        if end + 2 > body.len() {
            bail!("invalid chunked body: chunk exceeded response length");
        }
        if decoded.len() + size > DOCKER_API_RESPONSE_LIMIT_BYTES {
            bail!(
                "decoded Docker API response exceeded {} bytes",
                DOCKER_API_RESPONSE_LIMIT_BYTES
            );
        }
        decoded.extend_from_slice(&body[cursor..end]);
        cursor = end + 2;
    }

    Ok(decoded)
}

fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|window| window == b"\r\n")
}

fn null_as_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_enabled_container_labels() {
        let labels = HashMap::from([
            ("pxxl.enable".to_string(), "true".to_string()),
            ("pxxl.domain".to_string(), "app.pxxlhost".to_string()),
            ("pxxl.port".to_string(), "3000".to_string()),
            ("pxxl.path".to_string(), "/api".to_string()),
        ]);

        let route = route_from_labels(&labels, "web").unwrap();

        assert_eq!(route.domain, "app.pxxlhost");
        assert_eq!(route.paths[0].prefix, "/api");
        assert_eq!(route.paths[0].upstreams[0].url, "http://web:3000");
    }

    #[test]
    fn aggregates_same_domain_and_path_into_multiple_upstreams() {
        let labels = HashMap::from([
            ("pxxl.enable".to_string(), "true".to_string()),
            ("pxxl.domain".to_string(), "app.pxxlhost".to_string()),
            ("pxxl.port".to_string(), "3000".to_string()),
            ("pxxl.path".to_string(), "/".to_string()),
        ]);

        let routes = routes_from_targets(
            [
                route_target_from_labels(&labels, "web-1").unwrap(),
                route_target_from_labels(&labels, "web-2").unwrap(),
            ],
            ContainerProvider::Docker,
        );

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].domain, "app.pxxlhost");
        assert_eq!(routes[0].paths.len(), 1);
        assert_eq!(
            routes[0].paths[0]
                .upstreams
                .iter()
                .map(|upstream| upstream.url.as_str())
                .collect::<Vec<_>>(),
            vec!["http://web-1:3000", "http://web-2:3000"]
        );
    }

    #[test]
    fn aggregates_same_domain_paths_into_one_route() {
        let root_labels = HashMap::from([
            ("pxxl.enable".to_string(), "true".to_string()),
            ("pxxl.domain".to_string(), "app.pxxlhost".to_string()),
            ("pxxl.port".to_string(), "3000".to_string()),
            ("pxxl.path".to_string(), "/".to_string()),
        ]);
        let api_labels = HashMap::from([
            ("pxxl.enable".to_string(), "true".to_string()),
            ("pxxl.domain".to_string(), "app.pxxlhost".to_string()),
            ("pxxl.port".to_string(), "4000".to_string()),
            ("pxxl.path".to_string(), "/api".to_string()),
        ]);

        let routes = routes_from_targets(
            [
                route_target_from_labels(&root_labels, "web").unwrap(),
                route_target_from_labels(&api_labels, "api").unwrap(),
            ],
            ContainerProvider::Docker,
        );

        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0]
                .paths
                .iter()
                .map(|path| path.prefix.as_str())
                .collect::<Vec<_>>(),
            vec!["/", "/api"]
        );
    }

    #[test]
    fn podman_provider_uses_podman_route_source_and_ids() {
        let labels = HashMap::from([
            ("pxxl.enable".to_string(), "true".to_string()),
            ("pxxl.domain".to_string(), "app.pxxlhost".to_string()),
            ("pxxl.port".to_string(), "8080".to_string()),
        ]);

        let routes = routes_from_targets(
            [route_target_from_labels(&labels, "podman-web").unwrap()],
            ContainerProvider::Podman,
        );

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].id, "podman-app.pxxlhost");
        assert_eq!(routes[0].source, RouteSource::Podman);
        assert_eq!(
            routes[0].paths[0].upstreams[0].url,
            "http://podman-web:8080"
        );
    }

    #[test]
    fn podman_container_uses_published_host_port_when_host_label_is_absent() {
        let container = DockerContainerSummary {
            names: vec!["/my-html-site".to_string()],
            labels: HashMap::from([
                ("pxxl.enable".to_string(), "true".to_string()),
                ("pxxl.domain".to_string(), "app.pxxlhost".to_string()),
                ("pxxl.port".to_string(), "80".to_string()),
            ]),
            ports: vec![DockerPort {
                private_port: 80,
                public_port: Some(8080),
            }],
        };

        let target = route_target_from_container(
            &container,
            &container.primary_name(),
            Some("host.docker.internal"),
        )
        .unwrap();

        assert_eq!(target.upstream.url, "http://host.docker.internal:8080");
    }

    #[test]
    fn explicit_host_label_skips_published_port_rewrite() {
        let container = DockerContainerSummary {
            names: vec!["/my-html-site".to_string()],
            labels: HashMap::from([
                ("pxxl.enable".to_string(), "true".to_string()),
                ("pxxl.domain".to_string(), "app.pxxlhost".to_string()),
                ("pxxl.port".to_string(), "80".to_string()),
                ("pxxl.host".to_string(), "my-html-site".to_string()),
            ]),
            ports: vec![DockerPort {
                private_port: 80,
                public_port: Some(8080),
            }],
        };

        let target = route_target_from_container(
            &container,
            &container.primary_name(),
            Some("host.docker.internal"),
        )
        .unwrap();

        assert_eq!(target.upstream.url, "http://my-html-site:80");
    }

    #[test]
    fn parses_container_with_null_ports_as_empty_ports() {
        let containers: Vec<DockerContainerSummary> = serde_json::from_str(
            r#"[{"Names":["/worker"],"Labels":{"pxxl.enable":"true"},"Ports":null}]"#,
        )
        .unwrap();

        assert!(containers[0].ports.is_empty());
    }

    #[test]
    fn disabled_container_is_ignored() {
        let labels = HashMap::from([
            ("pxxl.enable".to_string(), "false".to_string()),
            ("pxxl.domain".to_string(), "app.pxxlhost".to_string()),
            ("pxxl.port".to_string(), "3000".to_string()),
        ]);

        assert!(route_from_labels(&labels, "web").is_none());
    }

    #[test]
    fn decodes_chunked_docker_response() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n[{\"x\"\r\n4\r\n:1}]\r\n0\r\n\r\n";

        let body = parse_http_response_body(response).unwrap();

        assert_eq!(body, br#"[{"x":1}]"#);
    }
}
