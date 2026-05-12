use arc_swap::ArcSwap;
use pxxl_common::{host_without_port, PxxlError, Route, RouteMatch, RouteSource};
use pxxl_ddos::SecurityEngine;
use pxxl_load_balancer::LoadBalancer;
use pxxl_metrics::PxxlMetrics;
use std::{collections::HashMap, sync::Arc};
use tracing::info;

#[derive(Debug)]
pub struct RouteRegistry {
    routes: ArcSwap<Vec<Route>>,
}

impl Default for RouteRegistry {
    fn default() -> Self {
        Self::empty()
    }
}

impl RouteRegistry {
    pub fn new(routes: Vec<Route>) -> Self {
        Self {
            routes: ArcSwap::from_pointee(routes),
        }
    }

    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    pub fn snapshot(&self) -> Vec<Route> {
        self.routes.load_full().as_ref().clone()
    }

    pub fn replace_all(&self, routes: Vec<Route>) {
        self.routes.store(Arc::new(routes));
    }

    pub fn replace_source(&self, source: RouteSource, routes: Vec<Route>) {
        let mut merged: Vec<Route> = self
            .snapshot()
            .into_iter()
            .filter(|route| route.source != source)
            .collect();
        merged.extend(routes);
        self.replace_all(merged);
    }

    pub fn find(&self, host: &str, path: &str) -> Option<RouteMatch> {
        let normalized_host = host_without_port(host)?;
        self.routes
            .load()
            .iter()
            .filter(|route| route.matches_host(normalized_host))
            .filter_map(|route| {
                route.best_path(path).map(|path_route| RouteMatch {
                    route: route.clone(),
                    path: path_route.clone(),
                })
            })
            .max_by_key(|matched| matched.path.prefix.len())
    }

    pub fn required_match(&self, host: &str, path: &str) -> pxxl_common::Result<RouteMatch> {
        self.find(host, path).ok_or_else(|| PxxlError::RouteNotFound {
            host: host.to_string(),
            path: path.to_string(),
        })
    }
}

#[derive(Clone)]
pub struct EdgeState {
    pub routes: Arc<RouteRegistry>,
    pub security: Arc<SecurityEngine>,
    pub load_balancer: Arc<LoadBalancer>,
    pub metrics: Arc<PxxlMetrics>,
}

impl EdgeState {
    pub fn new(
        routes: Arc<RouteRegistry>,
        security: Arc<SecurityEngine>,
        load_balancer: Arc<LoadBalancer>,
        metrics: Arc<PxxlMetrics>,
    ) -> Self {
        refresh_route_metrics(&routes, &metrics);
        Self {
            routes,
            security,
            load_balancer,
            metrics,
        }
    }

    pub fn replace_routes_from_source(&self, source: RouteSource, routes: Vec<Route>) {
        info!(source = ?source, count = routes.len(), "replacing route source");
        self.routes.replace_source(source, routes);
        refresh_route_metrics(&self.routes, &self.metrics);
    }
}

fn refresh_route_metrics(routes: &RouteRegistry, metrics: &PxxlMetrics) {
    let mut counts: HashMap<&'static str, i64> = HashMap::from([
        ("static", 0),
        ("docker", 0),
        ("api", 0),
    ]);

    for route in routes.snapshot() {
        let key = match route.source {
            RouteSource::Static => "static",
            RouteSource::Docker => "docker",
            RouteSource::Api => "api",
        };
        *counts.entry(key).or_default() += 1;
    }

    for (source, count) in counts {
        metrics.routes_total.with_label_values(&[source]).set(count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pxxl_common::{PathRoute, Route, RouteSource, Upstream};

    #[test]
    fn registry_matches_domain_and_longest_path() {
        let route = Route::new(
            "app.pxxlhost",
            vec![
                PathRoute::new("/", vec![Upstream::new("http://root:3000")]),
                PathRoute::new("/api", vec![Upstream::new("http://api:3000")]),
            ],
            RouteSource::Static,
        );
        let registry = RouteRegistry::new(vec![route]);

        let matched = registry.find("app.pxxlhost:443", "/api/users").unwrap();

        assert_eq!(matched.path.prefix, "/api");
    }

    #[test]
    fn replace_source_preserves_other_sources() {
        let static_route = Route::new(
            "app.pxxlhost",
            vec![PathRoute::new("/", vec![Upstream::new("http://app:3000")])],
            RouteSource::Static,
        );
        let old_docker = Route::new(
            "old.pxxlhost",
            vec![PathRoute::new("/", vec![Upstream::new("http://old:3000")])],
            RouteSource::Docker,
        );
        let new_docker = Route::new(
            "new.pxxlhost",
            vec![PathRoute::new("/", vec![Upstream::new("http://new:3000")])],
            RouteSource::Docker,
        );
        let registry = RouteRegistry::new(vec![static_route]);
        registry.replace_source(RouteSource::Docker, vec![old_docker]);
        registry.replace_source(RouteSource::Docker, vec![new_docker]);

        let routes = registry.snapshot();
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().any(|route| route.domain == "app.pxxlhost"));
        assert!(routes.iter().any(|route| route.domain == "new.pxxlhost"));
        assert!(!routes.iter().any(|route| route.domain == "old.pxxlhost"));
    }
}
