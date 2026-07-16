use arc_swap::ArcSwap;
use dashmap::DashMap;
use parking_lot::Mutex;
use pxxl_common::{
    normalize_domain, GeoLocation, PathRoute, PxxlError, Route, RouteMatch, RouteSource, Upstream,
};
use pxxl_ddos::SecurityEngine;
use pxxl_load_balancer::LoadBalancer;
use pxxl_metrics::PxxlMetrics;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fs::{self, OpenOptions},
    io::Write,
    net::IpAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

const RECENT_VISIT_LIMIT: usize = 5000;
const MAX_COUNTER_KEYS: usize = 1_000;
const OVERFLOW_COUNTER_KEY: &str = "__other__";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteUpstreamHealth {
    pub domain: String,
    pub path_prefix: String,
    pub upstream_url: String,
    pub healthy: bool,
}

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
        let routes = dedupe_routes(routes);
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

fn dedupe_routes(routes: Vec<Route>) -> Vec<Route> {
    let mut merged = Vec::with_capacity(routes.len());
    let mut positions: HashMap<String, usize> = HashMap::new();

    for route in routes {
        let key = match route.source {
            RouteSource::Api => format!("api:{}", route.domain),
            _ => format!("{:?}:{}:{}", route.source, route.domain, route.id),
        };
        if let Some(index) = positions.get(&key).copied() {
            merged[index] = route;
        } else {
            positions.insert(key, merged.len());
            merged.push(route);
        }
    }

    merged
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
        if self
            .snapshot()
            .into_iter()
            .any(|existing| api_routes_equivalent(&existing, &route))
        {
            return;
        }

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
        let normalized = normalize_domain(domain);
        let routes = table.by_domain.get(&normalized).into_iter().flatten();
        let matched = merge_best_domain_routes(routes);
        if matched.is_some() {
            return matched;
        }

        www_alias_base(&normalized).and_then(|base_domain| {
            let routes = table
                .by_domain
                .get(&base_domain)
                .into_iter()
                .flatten()
                .filter(|route| route_allows_www_alias(&route.domain, route.rules.www_alias));
            merge_best_domain_routes(routes)
        })
    }

    pub fn find(&self, host: &str, path: &str) -> Option<RouteMatch> {
        let normalized_host = normalize_domain(host);
        if normalized_host.is_empty() {
            return None;
        }
        let table = self.routes.load();
        let mut matches = matching_routes(table.as_ref(), &normalized_host, path, false);

        if matches.is_empty() {
            if let Some(base_domain) = www_alias_base(&normalized_host) {
                matches = matching_routes(table.as_ref(), &base_domain, path, true);
            }
        }

        merge_best_route_matches(matches)
    }

    pub fn required_match(&self, host: &str, path: &str) -> pxxl_common::Result<RouteMatch> {
        self.find(host, path)
            .ok_or_else(|| PxxlError::RouteNotFound {
                host: host.to_string(),
                path: path.to_string(),
            })
    }

    pub fn set_upstream_health(&self, health: &HashMap<String, bool>) {
        if health.is_empty() {
            return;
        }

        let mut routes = self.snapshot();
        for route in &mut routes {
            for path in &mut route.paths {
                for upstream in &mut path.upstreams {
                    if let Some(healthy) = health.get(&upstream.url) {
                        upstream.healthy = *healthy;
                    }
                }
            }
            for split in &mut route.rules.traffic_splits {
                for upstream in &mut split.upstreams {
                    if let Some(healthy) = health.get(&upstream.url) {
                        upstream.healthy = *healthy;
                    }
                }
            }
            for location_route in &mut route.rules.location_routes {
                for upstream in &mut location_route.upstreams {
                    if let Some(healthy) = health.get(&upstream.url) {
                        upstream.healthy = *healthy;
                    }
                }
            }
        }
        self.replace_all(routes);
    }

    pub fn set_single_upstream_health(&self, upstream_url: &str, healthy: bool) {
        self.set_upstream_health(&HashMap::from([(upstream_url.to_string(), healthy)]));
    }

    pub fn set_route_upstream_health(&self, update: &RouteUpstreamHealth) {
        let domain = normalize_domain(&update.domain);
        if domain.is_empty() || update.upstream_url.trim().is_empty() {
            return;
        }
        let mut routes = self.snapshot();
        for route in &mut routes {
            if route.domain != domain {
                continue;
            }
            for path in &mut route.paths {
                if path.prefix == update.path_prefix {
                    for upstream in &mut path.upstreams {
                        if upstream.url == update.upstream_url {
                            upstream.healthy = update.healthy;
                        }
                    }
                }
            }
            for split in &mut route.rules.traffic_splits {
                for upstream in &mut split.upstreams {
                    if upstream.url == update.upstream_url {
                        upstream.healthy = update.healthy;
                    }
                }
            }
            for location_route in &mut route.rules.location_routes {
                for upstream in &mut location_route.upstreams {
                    if upstream.url == update.upstream_url {
                        upstream.healthy = update.healthy;
                    }
                }
            }
        }
        self.replace_all(routes);
    }

    pub fn set_route_upstream_health_many(&self, updates: &[RouteUpstreamHealth]) {
        if updates.is_empty() {
            return;
        }
        let mut routes = self.snapshot();
        for update in updates {
            let domain = normalize_domain(&update.domain);
            if domain.is_empty() || update.upstream_url.trim().is_empty() {
                continue;
            }
            for route in &mut routes {
                if route.domain != domain {
                    continue;
                }
                for path in &mut route.paths {
                    if path.prefix == update.path_prefix {
                        for upstream in &mut path.upstreams {
                            if upstream.url == update.upstream_url {
                                upstream.healthy = update.healthy;
                            }
                        }
                    }
                }
                for split in &mut route.rules.traffic_splits {
                    for upstream in &mut split.upstreams {
                        if upstream.url == update.upstream_url {
                            upstream.healthy = update.healthy;
                        }
                    }
                }
                for location_route in &mut route.rules.location_routes {
                    for upstream in &mut location_route.upstreams {
                        if upstream.url == update.upstream_url {
                            upstream.healthy = update.healthy;
                        }
                    }
                }
            }
        }
        self.replace_all(routes);
    }
}

fn api_routes_equivalent(existing: &Route, next: &Route) -> bool {
    existing.source == RouteSource::Api
        && next.source == RouteSource::Api
        && existing.id == next.id
        && existing.domain == next.domain
        && existing.paths == next.paths
        && existing.tls == next.tls
        && existing.algorithm == next.algorithm
        && existing.rules == next.rules
        && existing.route_version == next.route_version
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
        Self::new_with_stats_sink(routes, security, load_balancer, metrics, None, None)
    }

    pub fn new_with_stats_sink(
        routes: Arc<RouteRegistry>,
        security: Arc<SecurityEngine>,
        load_balancer: Arc<LoadBalancer>,
        metrics: Arc<PxxlMetrics>,
        stats_sink: Option<mpsc::Sender<RequestObservation>>,
        analytics_overflow_spool_dir: Option<PathBuf>,
    ) -> Self {
        refresh_route_metrics(&routes, &metrics);
        Self {
            routes,
            security,
            load_balancer,
            metrics,
            stats: Arc::new(DomainStatsRegistry::new_with_sink_and_spool(
                stats_sink,
                analytics_overflow_spool_dir,
            )),
        }
    }

    pub fn replace_routes_from_source(&self, source: RouteSource, routes: Vec<Route>) {
        info!(source = ?source, count = routes.len(), "replacing route source");
        self.routes.replace_source(source, routes);
        refresh_route_metrics(&self.routes, &self.metrics);
    }

    pub fn upsert_api_route(&self, route: Route) -> bool {
        if self
            .routes
            .snapshot()
            .into_iter()
            .any(|existing| api_routes_equivalent(&existing, &route))
        {
            debug!(domain = %route.domain, "skipping unchanged API route");
            return false;
        }

        info!(domain = %route.domain, "upserting API route");
        self.routes.upsert_api_route(route);
        refresh_route_metrics(&self.routes, &self.metrics);
        true
    }

    pub fn delete_api_domain(&self, domain: &str) -> bool {
        let deleted = self.routes.delete_api_domain(domain);
        refresh_route_metrics(&self.routes, &self.metrics);
        deleted
    }

    pub fn set_upstream_health(&self, health: &HashMap<String, bool>) {
        self.routes.set_upstream_health(health);
        for (upstream, healthy) in health {
            self.metrics
                .upstream_health_status
                .with_label_values(&[upstream])
                .set(i64::from(*healthy));
        }
    }

    pub fn set_single_upstream_health(&self, upstream_url: &str, healthy: bool) {
        self.routes
            .set_single_upstream_health(upstream_url, healthy);
        self.metrics
            .upstream_health_status
            .with_label_values(&[upstream_url])
            .set(i64::from(healthy));
    }

    pub fn set_route_upstream_health(&self, update: RouteUpstreamHealth) {
        self.routes.set_route_upstream_health(&update);
        let label = route_upstream_health_label(&update.domain, &update.path_prefix, &update.upstream_url);
        self.metrics
            .upstream_health_status
            .with_label_values(&[&label])
            .set(i64::from(update.healthy));
    }

    pub fn set_route_upstream_health_many(&self, updates: &[RouteUpstreamHealth]) {
        self.routes.set_route_upstream_health_many(updates);
        for update in updates {
            let label = route_upstream_health_label(&update.domain, &update.path_prefix, &update.upstream_url);
            self.metrics
                .upstream_health_status
                .with_label_values(&[&label])
                .set(i64::from(update.healthy));
        }
    }
}

fn route_upstream_health_label(domain: &str, path_prefix: &str, upstream_url: &str) -> String {
    format!("{domain}|{path_prefix}|{upstream_url}")
}

#[derive(Debug, Default)]
pub struct DomainStatsRegistry {
    domains: DashMap<String, Arc<DomainStatsCounters>>,
    sink: Option<mpsc::Sender<RequestObservation>>,
    overflow_spool: Option<Arc<AnalyticsOverflowSpool>>,
}

impl DomainStatsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_sink(sink: Option<mpsc::Sender<RequestObservation>>) -> Self {
        Self::new_with_sink_and_spool(sink, None)
    }

    pub fn new_with_sink_and_spool(
        sink: Option<mpsc::Sender<RequestObservation>>,
        overflow_spool_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            domains: DashMap::new(),
            sink,
            overflow_spool: overflow_spool_dir
                .map(AnalyticsOverflowSpool::new)
                .map(Arc::new),
        }
    }

    pub fn record(&self, event: RequestObservation) {
        if let Some(sink) = &self.sink {
            if let Err(error) = sink.try_send(event.clone()) {
                match error {
                    mpsc::error::TrySendError::Full(event) => {
                        if let Some(spool) = &self.overflow_spool {
                            if let Err(error) = spool.append(&event) {
                                warn!(%error, "failed to spool analytics event after queue overflow");
                            }
                        } else {
                            warn!("analytics queue full and no overflow spool is configured");
                        }
                    }
                    mpsc::error::TrySendError::Closed(_) => {
                        warn!("analytics queue closed before request event was persisted");
                    }
                }
            }
        }
        let counters = self
            .domains
            .entry(event.domain.clone())
            .or_insert_with(|| Arc::new(DomainStatsCounters::default()))
            .clone();
        counters.record(event);
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

    pub fn restore_snapshots(&self, snapshots: Vec<DomainStatsSnapshot>) {
        for snapshot in snapshots {
            if snapshot.domain.trim().is_empty() {
                continue;
            }
            let counters = Arc::new(DomainStatsCounters::default());
            counters.restore(snapshot.clone());
            self.domains.insert(snapshot.domain, counters);
        }
    }

    pub fn recent_visits(&self, domain: &str, limit: usize) -> Vec<VisitSnapshot> {
        self.domains
            .get(domain)
            .map(|entry| entry.value().recent_visits(limit))
            .unwrap_or_default()
    }

    pub fn recent_visits_all(&self, limit: usize) -> Vec<VisitSnapshot> {
        let mut visits = self
            .domains
            .iter()
            .flat_map(|entry| entry.value().recent_visits(limit))
            .collect::<Vec<_>>();
        visits.sort_by_key(|visit| std::cmp::Reverse(visit.timestamp_unix_ms));
        visits.truncate(limit);
        visits
    }

    pub fn recent_visits_by_request_id(
        &self,
        request_id: &str,
        limit: usize,
    ) -> Vec<VisitSnapshot> {
        let mut visits = self
            .domains
            .iter()
            .flat_map(|entry| entry.value().recent_visits_by_request_id(request_id, limit))
            .collect::<Vec<_>>();
        visits.sort_by_key(|visit| std::cmp::Reverse(visit.timestamp_unix_ms));
        visits.truncate(limit);
        visits
    }

    pub fn recent_visits_for_domain_by_request_id(
        &self,
        domain: &str,
        request_id: &str,
        limit: usize,
    ) -> Vec<VisitSnapshot> {
        self.domains
            .get(domain)
            .map(|entry| entry.value().recent_visits_by_request_id(request_id, limit))
            .unwrap_or_default()
    }
}

#[derive(Debug)]
struct AnalyticsOverflowSpool {
    dir: PathBuf,
    file: Mutex<Option<std::fs::File>>,
}

impl AnalyticsOverflowSpool {
    fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            file: Mutex::new(None),
        }
    }

    fn append(&self, event: &RequestObservation) -> std::io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        let mut file_guard = self.file.lock();
        if file_guard.is_none() {
            let filename = format!(
                "analytics-overflow-{}-{}.jsonl",
                std::process::id(),
                unix_day_bucket()
            );
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.dir.join(filename))?;
            *file_guard = Some(file);
        }
        if let Some(file) = file_guard.as_mut() {
            serde_json::to_writer(&mut *file, event)?;
            file.write_all(b"\n")?;
            file.flush()?;
        }
        Ok(())
    }
}

fn unix_day_bucket() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() / 86_400)
        .unwrap_or_default()
}

#[derive(Debug, Default)]
struct DomainStatsCounters {
    requests_total: AtomicU64,
    responses_2xx: AtomicU64,
    responses_3xx: AtomicU64,
    responses_4xx: AtomicU64,
    responses_5xx: AtomicU64,
    total_latency_ms: AtomicU64,
    total_bytes_sent: AtomicU64,
    total_bytes_received: AtomicU64,
    last_status: AtomicU64,
    last_seen_unix_ms: AtomicU64,
    recent_visits: Mutex<VecDeque<VisitSnapshot>>,
    country_counts: Mutex<HashMap<String, LocationCount>>,
    continent_counts: Mutex<HashMap<String, LocationCount>>,
    path_counts: Mutex<HashMap<String, u64>>,
    upstream_counts: Mutex<HashMap<String, u64>>,
}

impl DomainStatsCounters {
    fn record(&self, event: RequestObservation) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ms
            .fetch_add(event.latency_ms, Ordering::Relaxed);
        self.total_bytes_sent
            .fetch_add(event.bytes_sent, Ordering::Relaxed);
        self.total_bytes_received
            .fetch_add(event.bytes_received, Ordering::Relaxed);
        self.last_status
            .store(event.status as u64, Ordering::Relaxed);
        let timestamp_unix_ms = event.timestamp_unix_ms;
        self.last_seen_unix_ms
            .store(timestamp_unix_ms, Ordering::Relaxed);

        match event.status {
            200..=299 => self.responses_2xx.fetch_add(1, Ordering::Relaxed),
            300..=399 => self.responses_3xx.fetch_add(1, Ordering::Relaxed),
            400..=499 => self.responses_4xx.fetch_add(1, Ordering::Relaxed),
            _ => self.responses_5xx.fetch_add(1, Ordering::Relaxed),
        };

        increment_count(&self.path_counts, event.path.clone());
        increment_count(
            &self.upstream_counts,
            event.upstream.clone().unwrap_or_else(|| "none".to_string()),
        );
        increment_location_count(
            &self.country_counts,
            event.location.country_code.as_deref(),
            event.location.country_name.as_deref(),
        );
        increment_location_count(
            &self.continent_counts,
            event.location.continent_code.as_deref(),
            event.location.continent_name.as_deref(),
        );

        let visit = VisitSnapshot {
            request_id: event.request_id,
            domain: event.domain,
            method: event.method,
            path: event.path,
            status: event.status,
            latency_ms: event.latency_ms,
            upstream: event.upstream,
            remote_ip: event.remote_ip.map(|ip| ip.to_string()),
            location: event.location,
            timestamp_unix_ms,
            bytes_sent: event.bytes_sent,
            bytes_received: event.bytes_received,
        };

        let mut recent = self.recent_visits.lock();
        recent.push_front(visit);
        while recent.len() > RECENT_VISIT_LIMIT {
            recent.pop_back();
        }
    }

    fn snapshot(&self, domain: &str) -> DomainStatsSnapshot {
        let requests_total = self.requests_total.load(Ordering::Relaxed);
        let total_latency_ms = self.total_latency_ms.load(Ordering::Relaxed);
        let average_latency_ms = if requests_total == 0 {
            0.0
        } else {
            total_latency_ms as f64 / requests_total as f64
        };
        let total_bytes_sent = self.total_bytes_sent.load(Ordering::Relaxed);
        let total_bytes_received = self.total_bytes_received.load(Ordering::Relaxed);

        DomainStatsSnapshot {
            domain: domain.to_string(),
            requests_total,
            responses_2xx: self.responses_2xx.load(Ordering::Relaxed),
            responses_3xx: self.responses_3xx.load(Ordering::Relaxed),
            responses_4xx: self.responses_4xx.load(Ordering::Relaxed),
            responses_5xx: self.responses_5xx.load(Ordering::Relaxed),
            average_latency_ms,
            total_bytes_sent,
            total_bytes_received,
            total_bandwidth: total_bytes_sent + total_bytes_received,
            last_status: nonzero_u16(self.last_status.load(Ordering::Relaxed)),
            last_seen_unix_ms: nonzero_u64(self.last_seen_unix_ms.load(Ordering::Relaxed)),
            top_countries: top_location_counts(&self.country_counts, 10),
            top_continents: top_location_counts(&self.continent_counts, 10),
            top_paths: top_string_counts(&self.path_counts, 10),
            top_upstreams: top_string_counts(&self.upstream_counts, 10),
        }
    }

    fn restore(&self, snapshot: DomainStatsSnapshot) {
        self.requests_total
            .store(snapshot.requests_total, Ordering::Relaxed);
        self.responses_2xx
            .store(snapshot.responses_2xx, Ordering::Relaxed);
        self.responses_3xx
            .store(snapshot.responses_3xx, Ordering::Relaxed);
        self.responses_4xx
            .store(snapshot.responses_4xx, Ordering::Relaxed);
        self.responses_5xx
            .store(snapshot.responses_5xx, Ordering::Relaxed);
        self.total_latency_ms.store(
            (snapshot.average_latency_ms.max(0.0) * snapshot.requests_total as f64).round() as u64,
            Ordering::Relaxed,
        );
        self.total_bytes_sent
            .store(snapshot.total_bytes_sent, Ordering::Relaxed);
        self.total_bytes_received
            .store(snapshot.total_bytes_received, Ordering::Relaxed);
        self.last_status.store(
            snapshot.last_status.unwrap_or_default() as u64,
            Ordering::Relaxed,
        );
        self.last_seen_unix_ms.store(
            snapshot.last_seen_unix_ms.unwrap_or_default(),
            Ordering::Relaxed,
        );

        {
            let mut countries = self.country_counts.lock();
            for item in snapshot.top_countries {
                countries.insert(item.code.clone(), item);
            }
        }
        {
            let mut continents = self.continent_counts.lock();
            for item in snapshot.top_continents {
                continents.insert(item.code.clone(), item);
            }
        }
        restore_string_counts(&self.path_counts, snapshot.top_paths);
        restore_string_counts(&self.upstream_counts, snapshot.top_upstreams);
    }

    fn recent_visits(&self, limit: usize) -> Vec<VisitSnapshot> {
        self.recent_visits
            .lock()
            .iter()
            .take(limit)
            .cloned()
            .collect()
    }

    fn recent_visits_by_request_id(&self, request_id: &str, limit: usize) -> Vec<VisitSnapshot> {
        self.recent_visits
            .lock()
            .iter()
            .filter(|visit| visit.request_id == request_id)
            .take(limit)
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestObservation {
    pub request_id: String,
    pub domain: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub latency_ms: u64,
    pub upstream: Option<String>,
    pub remote_ip: Option<IpAddr>,
    pub location: GeoLocation,
    pub timestamp_unix_ms: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainStatsSnapshot {
    pub domain: String,
    pub requests_total: u64,
    pub responses_2xx: u64,
    pub responses_3xx: u64,
    pub responses_4xx: u64,
    pub responses_5xx: u64,
    pub average_latency_ms: f64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub total_bandwidth: u64,
    pub last_status: Option<u16>,
    pub last_seen_unix_ms: Option<u64>,
    pub top_countries: Vec<LocationCount>,
    pub top_continents: Vec<LocationCount>,
    pub top_paths: Vec<StringCount>,
    pub top_upstreams: Vec<StringCount>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VisitSnapshot {
    pub request_id: String,
    pub domain: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub latency_ms: u64,
    pub upstream: Option<String>,
    pub remote_ip: Option<String>,
    pub location: GeoLocation,
    pub timestamp_unix_ms: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationCount {
    pub code: String,
    pub name: Option<String>,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringCount {
    pub value: String,
    pub count: u64,
}

fn restore_string_counts(counts: &Mutex<HashMap<String, u64>>, values: Vec<StringCount>) {
    let mut counts = counts.lock();
    for item in values {
        counts.insert(item.value, item.count);
    }
}

fn increment_count(counts: &Mutex<HashMap<String, u64>>, value: String) {
    let mut counts = counts.lock();
    if counts.contains_key(&value) || counts.len() < MAX_COUNTER_KEYS {
        *counts.entry(value).or_default() += 1;
    } else {
        *counts.entry(OVERFLOW_COUNTER_KEY.to_string()).or_default() += 1;
    }
}

fn increment_location_count(
    counts: &Mutex<HashMap<String, LocationCount>>,
    code: Option<&str>,
    name: Option<&str>,
) {
    let code = code.unwrap_or("UNKNOWN").to_ascii_uppercase();
    let mut counts = counts.lock();
    let entry = counts.entry(code.clone()).or_insert_with(|| LocationCount {
        code,
        name: name.map(str::to_string),
        count: 0,
    });
    if entry.name.is_none() {
        entry.name = name.map(str::to_string);
    }
    entry.count += 1;
}

fn top_location_counts(
    counts: &Mutex<HashMap<String, LocationCount>>,
    limit: usize,
) -> Vec<LocationCount> {
    let mut values = counts.lock().values().cloned().collect::<Vec<_>>();
    values.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.code.cmp(&right.code))
    });
    values.truncate(limit);
    values
}

fn top_string_counts(counts: &Mutex<HashMap<String, u64>>, limit: usize) -> Vec<StringCount> {
    let mut values = counts
        .lock()
        .iter()
        .map(|(value, count)| StringCount {
            value: value.clone(),
            count: *count,
        })
        .collect::<Vec<_>>();
    values.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.value.cmp(&right.value))
    });
    values.truncate(limit);
    values
}

fn source_priority(source: &RouteSource) -> usize {
    match source {
        RouteSource::Static => 1,
        RouteSource::Docker => 2,
        RouteSource::Podman => 2,
        RouteSource::Api => 3,
    }
}

fn matching_routes(
    table: &RouteTable,
    domain: &str,
    path: &str,
    require_www_alias: bool,
) -> Vec<RouteMatch> {
    table
        .by_domain
        .get(domain)
        .into_iter()
        .flatten()
        .filter(|route| {
            !require_www_alias || route_allows_www_alias(&route.domain, route.rules.www_alias)
        })
        .filter_map(|route| {
            route.best_path(path).map(|path_route| RouteMatch {
                route: route.clone(),
                path: path_route.clone(),
            })
        })
        .collect()
}

fn www_alias_base(domain: &str) -> Option<String> {
    domain
        .strip_prefix("www.")
        .filter(|base| !base.is_empty() && !base.starts_with("www."))
        .map(str::to_string)
}

pub fn route_allows_www_alias(domain: &str, www_alias: bool) -> bool {
    www_alias && !domain.starts_with("www.") && is_apex_like_domain(domain)
}

fn is_apex_like_domain(domain: &str) -> bool {
    domain.split('.').filter(|part| !part.is_empty()).count() == 2
}

fn merge_best_domain_routes<'a>(routes: impl Iterator<Item = &'a Route>) -> Option<Route> {
    let routes = routes.collect::<Vec<_>>();
    let best_priority = routes
        .iter()
        .map(|route| source_priority(&route.source))
        .max()?;
    let selected = routes
        .into_iter()
        .filter(|route| source_priority(&route.source) == best_priority)
        .collect::<Vec<_>>();

    if selected.len() == 1 {
        return selected.first().map(|route| (*route).clone());
    }

    let mut merged = (*selected.first()?).clone();
    let mut paths = BTreeMap::<String, PathRoute>::new();

    for route in selected {
        for path in &route.paths {
            let entry = paths
                .entry(path.prefix.clone())
                .or_insert_with(|| PathRoute {
                    prefix: path.prefix.clone(),
                    upstreams: Vec::new(),
                    middlewares: path.middlewares.clone(),
                });
            extend_unique_upstreams(&mut entry.upstreams, &path.upstreams);
            extend_unique_middlewares(&mut entry.middlewares, &path.middlewares);
        }
    }

    merged.paths = paths.into_values().collect();
    Some(merged)
}

fn merge_best_route_matches(matches: Vec<RouteMatch>) -> Option<RouteMatch> {
    let best_prefix_len = matches
        .iter()
        .map(|matched| matched.path.prefix.len())
        .max()?;
    let best_priority = matches
        .iter()
        .filter(|matched| matched.path.prefix.len() == best_prefix_len)
        .map(|matched| source_priority(&matched.route.source))
        .max()?;
    let selected = matches
        .into_iter()
        .filter(|matched| {
            matched.path.prefix.len() == best_prefix_len
                && source_priority(&matched.route.source) == best_priority
        })
        .collect::<Vec<_>>();

    let mut merged = selected.first()?.clone();
    for matched in selected.iter().skip(1) {
        extend_unique_upstreams(&mut merged.path.upstreams, &matched.path.upstreams);
        extend_unique_middlewares(&mut merged.path.middlewares, &matched.path.middlewares);
    }
    merged.route.paths = vec![merged.path.clone()];

    Some(merged)
}

fn extend_unique_upstreams(target: &mut Vec<Upstream>, upstreams: &[Upstream]) {
    for upstream in upstreams {
        if !target.iter().any(|existing| existing.url == upstream.url) {
            target.push(upstream.clone());
        }
    }
}

fn extend_unique_middlewares(target: &mut Vec<String>, middlewares: &[String]) {
    for middleware in middlewares {
        if !target.iter().any(|existing| existing == middleware) {
            target.push(middleware.clone());
        }
    }
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
    let mut counts: HashMap<&'static str, i64> =
        HashMap::from([("static", 0), ("docker", 0), ("podman", 0), ("api", 0)]);

    for route in routes.snapshot() {
        let key = match route.source {
            RouteSource::Static => "static",
            RouteSource::Docker => "docker",
            RouteSource::Podman => "podman",
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
            vec![PathRoute::new(
                "/",
                vec![Upstream::new("http://static:3000")],
            )],
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
    fn registry_dedupes_api_routes_by_domain_with_latest_winning() {
        let old_api_route = Route::new(
            "app.pxxlhost",
            vec![PathRoute::new("/", vec![Upstream::new("http://old:3000")])],
            RouteSource::Api,
        )
        .with_id("old-route");
        let new_api_route = Route::new(
            "app.pxxlhost",
            vec![PathRoute::new("/", vec![Upstream::new("http://new:3000")])],
            RouteSource::Api,
        )
        .with_id("new-route");
        let registry = RouteRegistry::new(vec![old_api_route, new_api_route]);

        let routes = registry.snapshot();
        let matched = registry.find("app.pxxlhost", "/").unwrap();

        assert_eq!(routes.len(), 1);
        assert_eq!(matched.path.upstreams[0].url, "http://new:3000");
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

    #[test]
    fn registry_merges_equal_priority_container_routes() {
        let docker_route = Route::new(
            "app.pxxlhost",
            vec![PathRoute::new("/", vec![Upstream::new("http://docker:80")])],
            RouteSource::Docker,
        );
        let podman_route = Route::new(
            "app.pxxlhost",
            vec![PathRoute::new("/", vec![Upstream::new("http://podman:80")])],
            RouteSource::Podman,
        );
        let registry = RouteRegistry::new(vec![docker_route, podman_route]);

        let matched = registry.find("app.pxxlhost", "/").unwrap();

        assert_eq!(
            matched
                .path
                .upstreams
                .iter()
                .map(|upstream| upstream.url.as_str())
                .collect::<Vec<_>>(),
            vec!["http://docker:80", "http://podman:80"]
        );
    }

    #[test]
    fn registry_matches_www_alias_when_enabled() {
        let mut route = Route::new(
            "example.com",
            vec![PathRoute::new("/", vec![Upstream::new("http://app:3000")])],
            RouteSource::Static,
        );
        route.rules.www_alias = true;
        let registry = RouteRegistry::new(vec![route]);

        let matched = registry.find("www.example.com", "/").unwrap();

        assert_eq!(matched.route.domain, "example.com");
    }

    #[test]
    fn registry_does_not_match_www_alias_by_default() {
        let route = Route::new(
            "example.com",
            vec![PathRoute::new("/", vec![Upstream::new("http://app:3000")])],
            RouteSource::Static,
        );
        let registry = RouteRegistry::new(vec![route]);

        assert!(registry.find("www.example.com", "/").is_none());
    }

    #[test]
    fn registry_does_not_add_www_alias_to_existing_subdomain() {
        let mut route = Route::new(
            "api.example.com",
            vec![PathRoute::new("/", vec![Upstream::new("http://api:3000")])],
            RouteSource::Static,
        );
        route.rules.www_alias = true;
        let registry = RouteRegistry::new(vec![route]);

        assert!(registry.find("www.api.example.com", "/").is_none());
    }

    #[test]
    fn health_updates_cover_route_and_rule_upstreams() {
        let mut route = Route::new(
            "example.com",
            vec![PathRoute::new("/", vec![Upstream::new("http://app:3000")])],
            RouteSource::Static,
        );
        route.rules.location_routes = vec![pxxl_common::LocationRouteRule {
            name: Some("local".to_string()),
            countries: Vec::new(),
            continents: Vec::new(),
            upstreams: vec![Upstream::new("http://local:3000")],
        }];
        let registry = RouteRegistry::new(vec![route]);

        registry.set_upstream_health(&HashMap::from([
            ("http://app:3000".to_string(), false),
            ("http://local:3000".to_string(), false),
        ]));
        let route = registry.find_domain("example.com").unwrap();

        assert!(!route.paths[0].upstreams[0].healthy);
        assert!(!route.rules.location_routes[0].upstreams[0].healthy);
    }

    #[test]
    fn stats_registry_restores_persisted_snapshots() {
        let registry = DomainStatsRegistry::new();
        registry.restore_snapshots(vec![DomainStatsSnapshot {
            domain: "app.example.com".to_string(),
            requests_total: 42,
            responses_2xx: 40,
            responses_3xx: 1,
            responses_4xx: 1,
            responses_5xx: 0,
            average_latency_ms: 12.5,
            total_bytes_sent: 2048,
            total_bytes_received: 512,
            total_bandwidth: 2560,
            last_status: Some(200),
            last_seen_unix_ms: Some(1_800_000),
            top_countries: vec![LocationCount {
                code: "NG".to_string(),
                name: Some("Nigeria".to_string()),
                count: 7,
            }],
            top_continents: Vec::new(),
            top_paths: vec![StringCount {
                value: "/".to_string(),
                count: 42,
            }],
            top_upstreams: vec![StringCount {
                value: "http://10.88.0.11:3000".to_string(),
                count: 42,
            }],
        }]);

        let snapshot = registry.snapshot_domain("app.example.com").unwrap();

        assert_eq!(snapshot.requests_total, 42);
        assert_eq!(snapshot.responses_2xx, 40);
        assert_eq!(snapshot.total_bandwidth, 2560);
        assert_eq!(snapshot.last_status, Some(200));
        assert_eq!(snapshot.top_paths[0].value, "/");
        assert_eq!(snapshot.top_countries[0].code, "NG");
    }
}
