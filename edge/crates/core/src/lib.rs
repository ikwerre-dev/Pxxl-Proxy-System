use arc_swap::ArcSwap;
use dashmap::DashMap;
use pxxl_common::{normalize_domain, PxxlError, Route, RouteMatch, RouteSource};
use pxxl_ddos::SecurityEngine;
use pxxl_load_balancer::LoadBalancer;
use pxxl_metrics::PxxlMetrics;
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::info;

#[derive(Debug)]
pub struct RouteRegistry {
    routes: ArcSwap<RouteTable>,
}

#[derive(Debug, Clone, Default)]
struct RouteTable {
    routes: Vec<Route>,
    by_domain: HashMap<String, Vec<Route>>,
}

impl RouteTable {
    fn new(routes: Vec<Route>) -> Self {
        let mut by_domain: HashMap<String, Vec<Route>> = HashMap::new();
        for route in &routes {
            by_domain
                .entry(route.domain.clone())
                .or_default()
                .push(route.clone());
        }

        Self { routes, by_domain }
    }
}

impl Default for RouteRegistry {
    fn default() -> Self {
        Self::empty()
    }
}

impl RouteRegistry {
    pub fn new(routes: Vec<Route>) -> Self {
        Self {
            routes: ArcSwap::from_pointee(RouteTable::new(routes)),
        }
    }

    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    pub fn snapshot(&self) -> Vec<Route> {
        self.routes.load().routes.clone()
    }

    pub fn replace_all(&self, routes: Vec<Route>) {
        self.routes.store(Arc::new(RouteTable::new(routes)));
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

    pub fn upsert_api_route(&self, route: Route) {
        let mut merged: Vec<Route> = self
            .snapshot()
            .into_iter()
            .filter(|existing| {
                !(existing.source == RouteSource::Api && existing.domain == route.domain)
            })
            .collect();
        merged.push(route);
        self.replace_all(merged);
    }

    pub fn delete_api_domain(&self, domain: &str) -> bool {
        let before = self.snapshot();
        let after: Vec<Route> = before
            .iter()
            .filter(|route| !(route.source == RouteSource::Api && route.domain == domain))
            .cloned()
            .collect();
        let deleted = before.len() != after.len();
        self.replace_all(after);
        deleted
    }

    pub fn find_domain(&self, domain: &str) -> Option<Route> {
        let table = self.routes.load();
        table
            .by_domain
            .get(&normalize_domain(domain))
            .into_iter()
            .flatten()
            .max_by_key(|route| source_priority(&route.source))
            .cloned()
    }

    pub fn find(&self, host: &str, path: &str) -> Option<RouteMatch> {
        let normalized_host = normalize_domain(host);
        if normalized_host.is_empty() {
            return None;
        }
        let table = self.routes.load();
        table
            .by_domain
            .get(&normalized_host)
            .into_iter()
            .flatten()
            .filter_map(|route| {
                route.best_path(path).map(|path_route| RouteMatch {
                    route: route.clone(),
                    path: path_route.clone(),
                })
            })
            .max_by_key(|matched| {
                (
                    matched.path.prefix.len(),
                    source_priority(&matched.route.source),
                )
            })
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
    pub stats: Arc<DomainStatsRegistry>,
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
            stats: Arc::new(DomainStatsRegistry::new()),
        }
    }

    pub fn replace_routes_from_source(&self, source: RouteSource, routes: Vec<Route>) {
        info!(source = ?source, count = routes.len(), "replacing route source");
        self.routes.replace_source(source, routes);
        refresh_route_metrics(&self.routes, &self.metrics);
    }

    pub fn upsert_api_route(&self, route: Route) {
        info!(domain = %route.domain, "upserting API route");
        self.routes.upsert_api_route(route);
        refresh_route_metrics(&self.routes, &self.metrics);
    }

    pub fn delete_api_domain(&self, domain: &str) -> bool {
        let deleted = self.routes.delete_api_domain(domain);
        refresh_route_metrics(&self.routes, &self.metrics);
        deleted
    }
}

#[derive(Debug, Default)]
pub struct DomainStatsRegistry {
    domains: DashMap<String, Arc<DomainStatsCounters>>,
}

impl DomainStatsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, domain: &str, status: u16, latency_ms: u64, upstream: Option<&str>) {
        let counters = self
            .domains
            .entry(domain.to_string())
            .or_insert_with(|| Arc::new(DomainStatsCounters::default()))
            .clone();
        counters.record(status, latency_ms, upstream);
    }

    pub fn snapshot_domain(&self, domain: &str) -> Option<DomainStatsSnapshot> {
        self.domains
            .get(domain)
            .map(|entry| entry.value().snapshot(domain))
    }

    pub fn snapshots(&self) -> Vec<DomainStatsSnapshot> {
        let mut snapshots = self
            .domains
            .iter()
            .map(|entry| entry.value().snapshot(entry.key()))
            .collect::<Vec<_>>();
        snapshots.sort_by(|left, right| left.domain.cmp(&right.domain));
        snapshots
    }
}

#[derive(Debug, Default)]
struct DomainStatsCounters {
    requests_total: AtomicU64,
    responses_2xx: AtomicU64,
    responses_3xx: AtomicU64,
    responses_4xx: AtomicU64,
    responses_5xx: AtomicU64,
    total_latency_ms: AtomicU64,
    last_status: AtomicU64,
    last_seen_unix_ms: AtomicU64,
}

impl DomainStatsCounters {
    fn record(&self, status: u16, latency_ms: u64, _upstream: Option<&str>) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
        self.last_status.store(status as u64, Ordering::Relaxed);
        self.last_seen_unix_ms
            .store(now_unix_ms(), Ordering::Relaxed);

        match status {
            200..=299 => self.responses_2xx.fetch_add(1, Ordering::Relaxed),
            300..=399 => self.responses_3xx.fetch_add(1, Ordering::Relaxed),
            400..=499 => self.responses_4xx.fetch_add(1, Ordering::Relaxed),
            _ => self.responses_5xx.fetch_add(1, Ordering::Relaxed),
        };
    }

    fn snapshot(&self, domain: &str) -> DomainStatsSnapshot {
        let requests_total = self.requests_total.load(Ordering::Relaxed);
        let total_latency_ms = self.total_latency_ms.load(Ordering::Relaxed);
        let average_latency_ms = if requests_total == 0 {
            0.0
        } else {
            total_latency_ms as f64 / requests_total as f64
        };

        DomainStatsSnapshot {
            domain: domain.to_string(),
            requests_total,
            responses_2xx: self.responses_2xx.load(Ordering::Relaxed),
            responses_3xx: self.responses_3xx.load(Ordering::Relaxed),
            responses_4xx: self.responses_4xx.load(Ordering::Relaxed),
            responses_5xx: self.responses_5xx.load(Ordering::Relaxed),
            average_latency_ms,
            last_status: nonzero_u16(self.last_status.load(Ordering::Relaxed)),
            last_seen_unix_ms: nonzero_u64(self.last_seen_unix_ms.load(Ordering::Relaxed)),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainStatsSnapshot {
    pub domain: String,
    pub requests_total: u64,
    pub responses_2xx: u64,
    pub responses_3xx: u64,
    pub responses_4xx: u64,
    pub responses_5xx: u64,
    pub average_latency_ms: f64,
    pub last_status: Option<u16>,
    pub last_seen_unix_ms: Option<u64>,
}

fn source_priority(source: &RouteSource) -> usize {
    match source {
        RouteSource::Static => 1,
        RouteSource::Docker => 2,
        RouteSource::Api => 3,
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn nonzero_u16(value: u64) -> Option<u16> {
    if value == 0 {
        None
    } else {
        Some(value as u16)
    }
}

fn nonzero_u64(value: u64) -> Option<u64> {
    if value == 0 {
        None
    } else {
        Some(value)
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
    fn registry_domain_index_matches_case_insensitive_host() {
        let route = Route::new(
            "app.pxxlhost",
            vec![PathRoute::new("/", vec![Upstream::new("http://app:3000")])],
            RouteSource::Static,
        );
        let registry = RouteRegistry::new(vec![route]);

        let matched = registry.find("APP.PXXLHOST:80", "/").unwrap();

        assert_eq!(matched.route.domain, "app.pxxlhost");
    }

    #[test]
    fn registry_prefers_api_route_for_same_domain() {
        let static_route = Route::new(
            "app.pxxlhost",
            vec![PathRoute::new("/", vec![Upstream::new("http://static:3000")])],
            RouteSource::Static,
        );
        let api_route = Route::new(
            "app.pxxlhost",
            vec![PathRoute::new("/", vec![Upstream::new("http://api:3000")])],
            RouteSource::Api,
        );
        let registry = RouteRegistry::new(vec![static_route, api_route]);

        let matched = registry.find("app.pxxlhost", "/").unwrap();

        assert_eq!(matched.route.source, RouteSource::Api);
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
