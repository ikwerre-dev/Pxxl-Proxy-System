use anyhow::{Context, Result};
use pxxl_common::{normalize_domain, normalize_path_prefix, PathRoute, Route, RouteSource, Upstream};
use pxxl_core::EdgeState;
use serde::Deserialize;
use std::{collections::HashMap, path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::watch,
    time,
};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct DockerDiscovery {
    socket_path: PathBuf,
}

impl DockerDiscovery {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub async fn discover_once(&self) -> Result<Vec<Route>> {
        let body = self
            .docker_get("/containers/json")
            .await
            .with_context(|| format!("failed to query Docker socket {}", self.socket_path.display()))?;
        let containers: Vec<DockerContainerSummary> =
            serde_json::from_slice(&body).context("failed to parse Docker containers JSON")?;

        Ok(containers
            .into_iter()
            .filter_map(|container| {
                let name = container.primary_name();
                route_from_labels(&container.labels, &name)
            })
            .collect())
    }

    async fn docker_get(&self, path: &str) -> Result<Vec<u8>> {
        let mut stream = UnixStream::connect(&self.socket_path).await?;
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: docker\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        split_http_body(&response).context("Docker HTTP response did not include a body")
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
                        debug!(count = routes.len(), "discovered Docker routes");
                        state.replace_routes_from_source(RouteSource::Docker, routes);
                        state.metrics.docker_route_changes_total.inc();
                    }
                    Err(error) => {
                        warn!(%error, "Docker discovery failed");
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    info!("stopping Docker discovery");
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
}

impl DockerContainerSummary {
    fn primary_name(&self) -> String {
        self.names
            .first()
            .map(|name| name.trim_start_matches('/').to_string())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "localhost".to_string())
    }
}

pub fn route_from_labels(labels: &HashMap<String, String>, container_name: &str) -> Option<Route> {
    let enabled = labels
        .get("pxxl.enable")
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
    if !enabled {
        return None;
    }

    let domain = labels.get("pxxl.domain")?;
    let port = labels.get("pxxl.port")?.parse::<u16>().ok()?;
    let path = labels
        .get("pxxl.path")
        .map(String::as_str)
        .unwrap_or("/");
    let scheme = labels
        .get("pxxl.scheme")
        .map(String::as_str)
        .unwrap_or("http");
    let host = labels
        .get("pxxl.host")
        .map(String::as_str)
        .unwrap_or(container_name);

    let upstream = Upstream::new(format!("{scheme}://{host}:{port}"));
    let id = format!(
        "docker-{}-{}",
        normalize_domain(domain),
        normalize_path_prefix(path).replace('/', "_")
    );

    Some(
        Route::new(
            domain.as_str(),
            vec![PathRoute::new(path, vec![upstream])],
            RouteSource::Docker,
        )
        .with_id(id),
    )
}

fn split_http_body(response: &[u8]) -> Option<Vec<u8>> {
    let separator = b"\r\n\r\n";
    response
        .windows(separator.len())
        .position(|window| window == separator)
        .map(|index| response[index + separator.len()..].to_vec())
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
    fn disabled_container_is_ignored() {
        let labels = HashMap::from([
            ("pxxl.enable".to_string(), "false".to_string()),
            ("pxxl.domain".to_string(), "app.pxxlhost".to_string()),
            ("pxxl.port".to_string(), "3000".to_string()),
        ]);

        assert!(route_from_labels(&labels, "web").is_none());
    }
}
