use dashmap::{DashMap, DashSet};
use ipnet::IpNet;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashSet, VecDeque},
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlacklistAction {
    Add,
    Remove,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlacklistCommand {
    pub action: BlacklistAction,
    pub domain_id: String,
    pub ip: IpAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityDecision {
    Allowed,
    Blocked { reason: String },
    RateLimited { retry_after: Duration },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveBlockConfig {
    #[serde(default = "default_auto_block_enabled")]
    pub enabled: bool,
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
    #[serde(default = "default_block_seconds")]
    pub block_seconds: u64,
    #[serde(default = "default_request_threshold")]
    pub request_threshold: u64,
    #[serde(default = "default_domain_threshold")]
    pub domain_threshold: usize,
    #[serde(default = "default_high_request_threshold")]
    pub high_request_threshold: u64,
    #[serde(default = "default_high_request_domain_threshold")]
    pub high_request_domain_threshold: usize,
    #[serde(default = "default_suspicious_path_threshold")]
    pub suspicious_path_threshold: u64,
    #[serde(default = "default_suspicious_path_domain_threshold")]
    pub suspicious_path_domain_threshold: usize,
    #[serde(default = "default_watchlist_suspicious_path_threshold")]
    pub watchlist_suspicious_path_threshold: u64,
    #[serde(default = "default_watchlist_suspicious_path_domain_threshold")]
    pub watchlist_suspicious_path_domain_threshold: usize,
    #[serde(default = "default_watchlist_ttl_seconds")]
    pub watchlist_ttl_seconds: u64,
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u64,
    #[serde(default = "default_failure_domain_threshold")]
    pub failure_domain_threshold: usize,
    #[serde(default = "default_max_tracked_ips")]
    pub max_tracked_ips: usize,
    #[serde(default = "default_bucket_seconds")]
    pub bucket_seconds: u64,
    #[serde(default = "default_snapshot_path")]
    pub snapshot_path: PathBuf,
    #[serde(default = "default_watchlist_snapshot_path")]
    pub watchlist_snapshot_path: PathBuf,
    #[serde(default = "default_exempt_cidrs")]
    pub exempt_cidrs: Vec<IpNet>,
    #[serde(default)]
    pub suspicious_path_prefixes: Vec<String>,
}

impl Default for AdaptiveBlockConfig {
    fn default() -> Self {
        Self {
            enabled: default_auto_block_enabled(),
            window_seconds: default_window_seconds(),
            block_seconds: default_block_seconds(),
            request_threshold: default_request_threshold(),
            domain_threshold: default_domain_threshold(),
            high_request_threshold: default_high_request_threshold(),
            high_request_domain_threshold: default_high_request_domain_threshold(),
            suspicious_path_threshold: default_suspicious_path_threshold(),
            suspicious_path_domain_threshold: default_suspicious_path_domain_threshold(),
            watchlist_suspicious_path_threshold: default_watchlist_suspicious_path_threshold(),
            watchlist_suspicious_path_domain_threshold:
                default_watchlist_suspicious_path_domain_threshold(),
            watchlist_ttl_seconds: default_watchlist_ttl_seconds(),
            failure_threshold: default_failure_threshold(),
            failure_domain_threshold: default_failure_domain_threshold(),
            max_tracked_ips: default_max_tracked_ips(),
            bucket_seconds: default_bucket_seconds(),
            snapshot_path: default_snapshot_path(),
            watchlist_snapshot_path: default_watchlist_snapshot_path(),
            exempt_cidrs: default_exempt_cidrs(),
            suspicious_path_prefixes: Vec::new(),
        }
    }
}

fn default_auto_block_enabled() -> bool {
    true
}

fn default_window_seconds() -> u64 {
    300
}

fn default_block_seconds() -> u64 {
    1800
}

fn default_request_threshold() -> u64 {
    300
}

fn default_domain_threshold() -> usize {
    25
}

fn default_high_request_threshold() -> u64 {
    1200
}

fn default_high_request_domain_threshold() -> usize {
    8
}

fn default_suspicious_path_threshold() -> u64 {
    25
}

fn default_suspicious_path_domain_threshold() -> usize {
    5
}

fn default_watchlist_suspicious_path_threshold() -> u64 {
    5
}

fn default_watchlist_suspicious_path_domain_threshold() -> usize {
    3
}

fn default_watchlist_ttl_seconds() -> u64 {
    86_400
}

fn default_failure_threshold() -> u64 {
    200
}

fn default_failure_domain_threshold() -> usize {
    15
}

fn default_max_tracked_ips() -> usize {
    100_000
}

fn default_bucket_seconds() -> u64 {
    10
}

fn default_snapshot_path() -> PathBuf {
    PathBuf::from("/data/security/auto-blocks.json")
}

fn default_watchlist_snapshot_path() -> PathBuf {
    PathBuf::from("/data/security/watchlist.json")
}

fn default_exempt_cidrs() -> Vec<IpNet> {
    ["127.0.0.0/8", "::1/128", "10.88.0.0/24"]
        .into_iter()
        .filter_map(|cidr| cidr.parse().ok())
        .collect()
}

#[derive(Debug, Clone)]
pub struct RequestObservationInput<'a> {
    pub ip: IpAddr,
    pub domain: &'a str,
    pub path: &'a str,
    pub status: u16,
    pub timestamp_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveBlockSnapshot {
    pub ip: IpAddr,
    pub reason: String,
    pub blocked_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub requests: u64,
    pub domains: usize,
    pub failures: u64,
    pub failure_domains: usize,
    pub suspicious_paths: u64,
    pub suspicious_domains: usize,
    pub sample_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousIpWatchlistEntry {
    pub ip: IpAddr,
    pub reason: String,
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub requests: u64,
    pub domains: usize,
    pub failures: u64,
    pub failure_domains: usize,
    pub suspicious_paths: u64,
    pub suspicious_domains: usize,
    pub sample_domains: Vec<String>,
    pub sample_paths: Vec<String>,
}

#[derive(Debug, Default)]
struct TrafficBucket {
    start_ms: u64,
    requests: u64,
    failures: u64,
    suspicious_paths: u64,
    domains: HashSet<String>,
    failure_domains: HashSet<String>,
    suspicious_domains: HashSet<String>,
    suspicious_path_samples: HashSet<String>,
}

#[derive(Debug, Default)]
struct IpWindow {
    buckets: VecDeque<TrafficBucket>,
    last_seen_ms: u64,
}

#[derive(Debug, Clone)]
struct WindowTotals {
    requests: u64,
    domains: usize,
    failures: u64,
    failure_domains: usize,
    suspicious_paths: u64,
    suspicious_domains: usize,
    sample_domains: Vec<String>,
    sample_paths: Vec<String>,
}

#[derive(Debug)]
pub struct AdaptiveBlocker {
    config: AdaptiveBlockConfig,
    windows: DashMap<IpAddr, Mutex<IpWindow>>,
    blocks: DashMap<IpAddr, AdaptiveBlockSnapshot>,
    watchlist: DashMap<IpAddr, SuspiciousIpWatchlistEntry>,
    last_eviction: Mutex<Instant>,
    last_snapshot: Mutex<Instant>,
}

const ADAPTIVE_BLOCK_REASON: &str = "adaptive_ip_block";

impl AdaptiveBlocker {
    pub fn new(config: AdaptiveBlockConfig) -> Self {
        let blocker = Self {
            config,
            windows: DashMap::new(),
            blocks: DashMap::new(),
            watchlist: DashMap::new(),
            last_eviction: Mutex::new(Instant::now()),
            last_snapshot: Mutex::new(Instant::now()),
        };
        blocker.load_snapshot();
        blocker.load_watchlist_snapshot();
        blocker
    }

    pub fn disabled() -> Self {
        let config = AdaptiveBlockConfig {
            enabled: false,
            ..AdaptiveBlockConfig::default()
        };
        Self::new(config)
    }

    pub fn check(&self, ip: IpAddr) -> Option<SecurityDecision> {
        if !self.config.enabled {
            return None;
        }
        if self.is_exempt(ip) {
            return None;
        }

        let now_ms = now_unix_ms();
        if let Some(block) = self.blocks.get(&ip) {
            if block.expires_at_unix_ms > now_ms {
                return Some(SecurityDecision::Blocked {
                    reason: ADAPTIVE_BLOCK_REASON.to_string(),
                });
            }
            drop(block);
            self.blocks.remove(&ip);
            self.persist_snapshot();
        }
        None
    }

    pub fn record(&self, event: RequestObservationInput<'_>) -> Option<AdaptiveBlockSnapshot> {
        if !self.config.enabled || self.is_exempt(event.ip) {
            return None;
        }
        self.evict_if_due(event.timestamp_unix_ms);
        self.persist_if_due();

        if self.check(event.ip).is_some() {
            return None;
        }

        if self.windows.len() >= self.config.max_tracked_ips
            && !self.windows.contains_key(&event.ip)
        {
            self.evict_stale(event.timestamp_unix_ms);
            if self.windows.len() >= self.config.max_tracked_ips {
                return None;
            }
        }

        let bucket_seconds = self.config.bucket_seconds.max(1);
        let bucket_ms = bucket_seconds * 1000;
        let bucket_start = event.timestamp_unix_ms / bucket_ms * bucket_ms;
        let window_ms = self.config.window_seconds.max(bucket_seconds) * 1000;
        let oldest_allowed = event.timestamp_unix_ms.saturating_sub(window_ms);
        let domain = normalize_domain_for_tracking(event.domain);
        let suspicious = is_suspicious_path(event.path, &self.config.suspicious_path_prefixes);
        let failed = event.status >= 400;

        let entry = self.windows.entry(event.ip).or_default();
        let mut window = entry.lock();
        window.last_seen_ms = event.timestamp_unix_ms;
        trim_buckets(&mut window, oldest_allowed);

        let bucket = if let Some(bucket) = window
            .buckets
            .iter_mut()
            .find(|bucket| bucket.start_ms == bucket_start)
        {
            bucket
        } else {
            window.buckets.push_back(TrafficBucket {
                start_ms: bucket_start,
                ..TrafficBucket::default()
            });
            window.buckets.back_mut().expect("bucket was inserted")
        };
        bucket.requests += 1;
        bucket.domains.insert(domain.clone());
        if failed {
            bucket.failures += 1;
            bucket.failure_domains.insert(domain.clone());
        }
        if suspicious {
            bucket.suspicious_paths += 1;
            bucket.suspicious_domains.insert(domain);
            bucket
                .suspicious_path_samples
                .insert(normalize_path_for_tracking(event.path));
        }

        let totals = window_totals(&window);
        if self.should_watch(&totals) {
            self.watch_ip(event.ip, "suspicious_path_watch".to_string(), &totals, event.timestamp_unix_ms);
        }
        let reason = self.trigger_reason(&totals);
        drop(window);

        reason.map(|reason| self.block_ip(event.ip, reason, totals, event.timestamp_unix_ms))
    }

    pub fn unblock(&self, ip: IpAddr) -> bool {
        let removed = self.blocks.remove(&ip).is_some();
        if removed {
            self.persist_snapshot();
        }
        removed
    }

    pub fn unwatch(&self, ip: IpAddr) -> bool {
        let removed = self.watchlist.remove(&ip).is_some();
        if removed {
            self.persist_watchlist_snapshot();
        }
        removed
    }

    pub fn active_blocks(&self) -> Vec<AdaptiveBlockSnapshot> {
        let now_ms = now_unix_ms();
        self.blocks
            .iter()
            .filter_map(|entry| {
                let block = entry.value();
                (block.expires_at_unix_ms > now_ms).then(|| block.clone())
            })
            .collect()
    }

    pub fn active_block_count(&self) -> usize {
        self.blocks.len()
    }

    pub fn watchlist(&self) -> Vec<SuspiciousIpWatchlistEntry> {
        let now_ms = now_unix_ms();
        self.watchlist
            .iter()
            .filter_map(|entry| {
                let watch = entry.value();
                (watch.expires_at_unix_ms > now_ms).then(|| watch.clone())
            })
            .collect()
    }

    pub fn watchlist_count(&self) -> usize {
        self.watchlist.len()
    }

    pub fn observed_ip_count(&self) -> usize {
        self.windows.len()
    }

    pub fn is_exempt(&self, ip: IpAddr) -> bool {
        self.config
            .exempt_cidrs
            .iter()
            .any(|network| network.contains(&ip))
    }

    fn trigger_reason(&self, totals: &WindowTotals) -> Option<String> {
        if totals.requests >= self.config.request_threshold
            && totals.domains >= self.config.domain_threshold
        {
            return Some("cross_domain_request_volume".to_string());
        }
        if totals.requests >= self.config.high_request_threshold
            && totals.domains >= self.config.high_request_domain_threshold
        {
            return Some("high_request_volume".to_string());
        }
        if totals.suspicious_paths >= self.config.suspicious_path_threshold
            && totals.suspicious_domains >= self.config.suspicious_path_domain_threshold
        {
            return Some("suspicious_path_scanner".to_string());
        }
        if totals.failures >= self.config.failure_threshold
            && totals.failure_domains >= self.config.failure_domain_threshold
        {
            return Some("cross_domain_failures".to_string());
        }
        None
    }

    fn should_watch(&self, totals: &WindowTotals) -> bool {
        totals.suspicious_paths >= self.config.watchlist_suspicious_path_threshold
            && totals.suspicious_domains
                >= self.config.watchlist_suspicious_path_domain_threshold
    }

    fn watch_ip(
        &self,
        ip: IpAddr,
        reason: String,
        totals: &WindowTotals,
        now_ms: u64,
    ) -> SuspiciousIpWatchlistEntry {
        let expires_at_unix_ms = now_ms + self.config.watchlist_ttl_seconds.max(60) * 1000;
        let first_seen_unix_ms = self
            .watchlist
            .get(&ip)
            .map(|existing| existing.first_seen_unix_ms)
            .unwrap_or(now_ms);
        let entry = SuspiciousIpWatchlistEntry {
            ip,
            reason,
            first_seen_unix_ms,
            last_seen_unix_ms: now_ms,
            expires_at_unix_ms,
            requests: totals.requests,
            domains: totals.domains,
            failures: totals.failures,
            failure_domains: totals.failure_domains,
            suspicious_paths: totals.suspicious_paths,
            suspicious_domains: totals.suspicious_domains,
            sample_domains: totals.sample_domains.clone(),
            sample_paths: totals.sample_paths.clone(),
        };
        let is_new = !self.watchlist.contains_key(&ip);
        self.watchlist.insert(ip, entry.clone());
        if is_new {
            self.persist_watchlist_snapshot();
            info!(
                ip = %entry.ip,
                reason = %entry.reason,
                suspicious_paths = entry.suspicious_paths,
                suspicious_domains = entry.suspicious_domains,
                sample_domains = ?entry.sample_domains,
                sample_paths = ?entry.sample_paths,
                "suspicious IP added to watchlist"
            );
        }
        entry
    }

    fn block_ip(
        &self,
        ip: IpAddr,
        reason: String,
        totals: WindowTotals,
        now_ms: u64,
    ) -> AdaptiveBlockSnapshot {
        let block = AdaptiveBlockSnapshot {
            ip,
            reason,
            blocked_at_unix_ms: now_ms,
            expires_at_unix_ms: now_ms + self.config.block_seconds.max(1) * 1000,
            requests: totals.requests,
            domains: totals.domains,
            failures: totals.failures,
            failure_domains: totals.failure_domains,
            suspicious_paths: totals.suspicious_paths,
            suspicious_domains: totals.suspicious_domains,
            sample_domains: totals.sample_domains,
        };
        self.blocks.insert(ip, block.clone());
        self.persist_snapshot();
        info!(
            ip = %block.ip,
            reason = %block.reason,
            requests = block.requests,
            domains = block.domains,
            failures = block.failures,
            suspicious_paths = block.suspicious_paths,
            expires_at_unix_ms = block.expires_at_unix_ms,
            sample_domains = ?block.sample_domains,
            "adaptive IP block added"
        );
        block
    }

    fn evict_if_due(&self, now_ms: u64) {
        let now = Instant::now();
        let mut last = self.last_eviction.lock();
        if now.duration_since(*last) < Duration::from_secs(30) {
            return;
        }
        *last = now;
        self.evict_stale(now_ms);
        self.blocks
            .retain(|_, block| block.expires_at_unix_ms > now_ms);
        self.watchlist
            .retain(|_, entry| entry.expires_at_unix_ms > now_ms);
    }

    fn evict_stale(&self, now_ms: u64) {
        let stale_after_ms = (self.config.window_seconds.max(1) + 300) * 1000;
        self.windows.retain(|_, window| {
            now_ms.saturating_sub(window.lock().last_seen_ms) <= stale_after_ms
        });
    }

    fn persist_if_due(&self) {
        let now = Instant::now();
        let mut last = self.last_snapshot.lock();
        if now.duration_since(*last) < Duration::from_secs(30) {
            return;
        }
        *last = now;
        self.persist_snapshot();
        self.persist_watchlist_snapshot();
    }

    fn load_snapshot(&self) {
        let path = &self.config.snapshot_path;
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        match serde_json::from_slice::<Vec<AdaptiveBlockSnapshot>>(&bytes) {
            Ok(blocks) => {
                let now_ms = now_unix_ms();
                let mut loaded = 0usize;
                for block in blocks {
                    if block.expires_at_unix_ms > now_ms && !self.is_exempt(block.ip) {
                        self.blocks.insert(block.ip, block);
                        loaded += 1;
                    }
                }
                if loaded > 0 {
                    info!(loaded, path = %path.display(), "loaded adaptive IP block snapshot");
                }
            }
            Err(error) => {
                warn!(%error, path = %path.display(), "could not parse adaptive IP block snapshot");
            }
        }
    }

    fn persist_snapshot(&self) {
        let path = &self.config.snapshot_path;
        let now_ms = now_unix_ms();
        let blocks = self
            .blocks
            .iter()
            .filter_map(|entry| {
                let block = entry.value();
                (block.expires_at_unix_ms > now_ms).then(|| block.clone())
            })
            .collect::<Vec<_>>();

        if let Some(parent) = path.parent() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                warn!(%error, path = %parent.display(), "could not create adaptive block snapshot directory");
                return;
            }
        }

        let tmp_path = path.with_extension("json.tmp");
        let payload = match serde_json::to_vec_pretty(&blocks) {
            Ok(payload) => payload,
            Err(error) => {
                warn!(%error, "could not serialize adaptive IP block snapshot");
                return;
            }
        };
        if let Err(error) = std::fs::write(&tmp_path, payload) {
            warn!(%error, path = %tmp_path.display(), "could not write adaptive IP block snapshot");
            return;
        }
        if let Err(error) = std::fs::rename(&tmp_path, path) {
            warn!(%error, path = %path.display(), "could not replace adaptive IP block snapshot");
        }
    }

    fn load_watchlist_snapshot(&self) {
        let path = &self.config.watchlist_snapshot_path;
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        match serde_json::from_slice::<Vec<SuspiciousIpWatchlistEntry>>(&bytes) {
            Ok(entries) => {
                let now_ms = now_unix_ms();
                let mut loaded = 0usize;
                for entry in entries {
                    if entry.expires_at_unix_ms > now_ms && !self.is_exempt(entry.ip) {
                        self.watchlist.insert(entry.ip, entry);
                        loaded += 1;
                    }
                }
                if loaded > 0 {
                    info!(loaded, path = %path.display(), "loaded suspicious IP watchlist snapshot");
                }
            }
            Err(error) => {
                warn!(%error, path = %path.display(), "could not parse suspicious IP watchlist snapshot");
            }
        }
    }

    fn persist_watchlist_snapshot(&self) {
        let path = &self.config.watchlist_snapshot_path;
        let now_ms = now_unix_ms();
        let entries = self
            .watchlist
            .iter()
            .filter_map(|entry| {
                let watch = entry.value();
                (watch.expires_at_unix_ms > now_ms).then(|| watch.clone())
            })
            .collect::<Vec<_>>();

        if let Some(parent) = path.parent() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                warn!(%error, path = %parent.display(), "could not create suspicious IP watchlist directory");
                return;
            }
        }

        let tmp_path = path.with_extension("json.tmp");
        let payload = match serde_json::to_vec_pretty(&entries) {
            Ok(payload) => payload,
            Err(error) => {
                warn!(%error, "could not serialize suspicious IP watchlist snapshot");
                return;
            }
        };
        if let Err(error) = std::fs::write(&tmp_path, payload) {
            warn!(%error, path = %tmp_path.display(), "could not write suspicious IP watchlist snapshot");
            return;
        }
        if let Err(error) = std::fs::rename(&tmp_path, path) {
            warn!(%error, path = %path.display(), "could not replace suspicious IP watchlist snapshot");
        }
    }
}

fn trim_buckets(window: &mut IpWindow, oldest_allowed: u64) {
    while window
        .buckets
        .front()
        .is_some_and(|bucket| bucket.start_ms < oldest_allowed)
    {
        window.buckets.pop_front();
    }
}

fn window_totals(window: &IpWindow) -> WindowTotals {
    let mut domains = HashSet::new();
    let mut failure_domains = HashSet::new();
    let mut suspicious_domains = HashSet::new();
    let mut suspicious_path_samples = HashSet::new();
    let mut requests = 0;
    let mut failures = 0;
    let mut suspicious_paths = 0;

    for bucket in &window.buckets {
        requests += bucket.requests;
        failures += bucket.failures;
        suspicious_paths += bucket.suspicious_paths;
        domains.extend(bucket.domains.iter().cloned());
        failure_domains.extend(bucket.failure_domains.iter().cloned());
        suspicious_domains.extend(bucket.suspicious_domains.iter().cloned());
        suspicious_path_samples.extend(bucket.suspicious_path_samples.iter().cloned());
    }

    let mut sample_domains = domains.iter().take(8).cloned().collect::<Vec<_>>();
    sample_domains.sort();
    let mut sample_paths = suspicious_path_samples.iter().take(8).cloned().collect::<Vec<_>>();
    sample_paths.sort();

    WindowTotals {
        requests,
        domains: domains.len(),
        failures,
        failure_domains: failure_domains.len(),
        suspicious_paths,
        suspicious_domains: suspicious_domains.len(),
        sample_domains,
        sample_paths,
    }
}

fn normalize_domain_for_tracking(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_path_for_tracking(path: &str) -> String {
    let value = path.trim();
    if value.is_empty() {
        return "/".to_string();
    }
    let without_query = value.split('?').next().unwrap_or(value);
    let normalized = if without_query.starts_with('/') {
        without_query.to_string()
    } else {
        format!("/{without_query}")
    };
    normalized.chars().take(160).collect::<String>()
}

fn is_suspicious_path(path: &str, configured_prefixes: &[String]) -> bool {
    let path = path.to_ascii_lowercase();
    const PREFIXES: &[&str] = &[
        "/.env",
        "/.git/",
        "/api/.git/",
        "/wp-admin/install.php",
        "/wp-cron.php",
        "/xmlrpc.php",
        "/admin.php",
        "/shell.php",
        "/cmd.php",
        "/wso.php",
        "/c99.php",
        "/r57.php",
        "/wp-content/plugins/",
        "/wp-content/uploads/",
        "/vendor/phpunit/",
    ];
    PREFIXES.iter().any(|prefix| path.starts_with(prefix))
        || configured_prefixes
            .iter()
            .any(|prefix| path.starts_with(&prefix.to_ascii_lowercase()))
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug, Default)]
pub struct BlacklistEngine {
    domains: DashMap<String, Arc<DashSet<IpAddr>>>,
    cidr_blocks: RwLock<Vec<IpNet>>,
}

impl BlacklistEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_cidrs(cidrs: Vec<IpNet>) -> Self {
        Self {
            domains: DashMap::new(),
            cidr_blocks: RwLock::new(cidrs),
        }
    }

    pub fn add(&self, domain_id: impl Into<String>, ip: IpAddr) {
        let domain_id = domain_id.into();
        let set = self
            .domains
            .entry(domain_id)
            .or_insert_with(|| Arc::new(DashSet::new()))
            .clone();
        set.insert(ip);
    }

    pub fn remove(&self, domain_id: &str, ip: &IpAddr) {
        if let Some(set) = self.domains.get(domain_id) {
            set.remove(ip);
        }
    }

    pub fn contains(&self, domain_id: &str, ip: &IpAddr) -> bool {
        if self
            .cidr_blocks
            .read()
            .iter()
            .any(|network| network.contains(ip))
        {
            return true;
        }

        self.domains
            .get(domain_id)
            .is_some_and(|set| set.contains(ip))
    }

    pub fn apply(&self, command: BlacklistCommand) {
        match command.action {
            BlacklistAction::Add => self.add(command.domain_id, command.ip),
            BlacklistAction::Remove => self.remove(&command.domain_id, &command.ip),
        }
    }

    pub fn replace_cidrs(&self, cidrs: Vec<IpNet>) {
        *self.cidr_blocks.write() = cidrs;
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 120,
            burst: 240,
        }
    }
}

#[derive(Debug)]
struct RateBucket {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: DashMap<IpAddr, Mutex<RateBucket>>,
    last_eviction: Mutex<Instant>,
}

const RATE_BUCKET_TTL_SECONDS: u64 = 600;
const RATE_BUCKET_EVICT_AT: usize = 100_000;

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: DashMap::new(),
            last_eviction: Mutex::new(Instant::now()),
        }
    }

    pub fn allow(&self, ip: IpAddr) -> SecurityDecision {
        self.evict_if_due();
        self.evict_stale();
        let entry = self.buckets.entry(ip).or_insert_with(|| {
            Mutex::new(RateBucket {
                tokens: self.config.burst as f64,
                last_refill: Instant::now(),
            })
        });

        let mut bucket = entry.lock();
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        let refill = elapsed * self.config.requests_per_second as f64;

        if refill > 0.0 {
            bucket.tokens = (bucket.tokens + refill).min(self.config.burst as f64);
            bucket.last_refill = now;
        }

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            SecurityDecision::Allowed
        } else {
            let seconds = 1.0 / self.config.requests_per_second.max(1) as f64;
            SecurityDecision::RateLimited {
                retry_after: Duration::from_secs_f64(seconds),
            }
        }
    }

    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    fn evict_stale(&self) {
        if self.buckets.len() < RATE_BUCKET_EVICT_AT {
            return;
        }
        let now = Instant::now();
        let ttl = Duration::from_secs(RATE_BUCKET_TTL_SECONDS);
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.lock().last_refill) <= ttl);
    }

    fn evict_if_due(&self) {
        let now = Instant::now();
        let mut last = self.last_eviction.lock();
        if now.duration_since(*last) < Duration::from_secs(30) {
            return;
        }
        *last = now;
        let ttl = Duration::from_secs(RATE_BUCKET_TTL_SECONDS);
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.lock().last_refill) <= ttl);
    }
}

#[derive(Debug)]
pub struct SecurityEngine {
    blacklist: Arc<BlacklistEngine>,
    rate_limiter: Arc<RateLimiter>,
    adaptive_blocker: Arc<AdaptiveBlocker>,
}

impl SecurityEngine {
    pub fn new(blacklist: Arc<BlacklistEngine>, rate_limiter: Arc<RateLimiter>) -> Self {
        Self::new_with_adaptive_blocker(
            blacklist,
            rate_limiter,
            Arc::new(AdaptiveBlocker::disabled()),
        )
    }

    pub fn new_with_adaptive_blocker(
        blacklist: Arc<BlacklistEngine>,
        rate_limiter: Arc<RateLimiter>,
        adaptive_blocker: Arc<AdaptiveBlocker>,
    ) -> Self {
        Self {
            blacklist,
            rate_limiter,
            adaptive_blocker,
        }
    }

    pub fn check(&self, domain_id: &str, ip: IpAddr) -> SecurityDecision {
        if self.blacklist.contains(domain_id, &ip) {
            return SecurityDecision::Blocked {
                reason: "ip_blacklisted".to_string(),
            };
        }

        if let Some(decision) = self.adaptive_blocker.check(ip) {
            return decision;
        }

        self.rate_limiter.allow(ip)
    }

    pub fn record_request(
        &self,
        event: RequestObservationInput<'_>,
    ) -> Option<AdaptiveBlockSnapshot> {
        self.adaptive_blocker.record(event)
    }

    pub fn blacklist(&self) -> Arc<BlacklistEngine> {
        self.blacklist.clone()
    }

    pub fn adaptive_blocker(&self) -> Arc<AdaptiveBlocker> {
        self.adaptive_blocker.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn blacklist_lookup_is_domain_scoped() {
        let engine = BlacklistEngine::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));

        engine.add("app", ip);

        assert!(engine.contains("app", &ip));
        assert!(!engine.contains("api", &ip));
    }

    #[test]
    fn cidr_block_applies_globally() {
        let engine = BlacklistEngine::with_cidrs(vec!["10.0.0.0/24".parse().unwrap()]);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 44));

        assert!(engine.contains("anything", &ip));
    }

    #[test]
    fn rate_limiter_enforces_burst() {
        let limiter = RateLimiter::new(RateLimitConfig {
            requests_per_second: 1,
            burst: 2,
        });
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        assert_eq!(limiter.allow(ip), SecurityDecision::Allowed);
        assert_eq!(limiter.allow(ip), SecurityDecision::Allowed);
        assert!(matches!(
            limiter.allow(ip),
            SecurityDecision::RateLimited { .. }
        ));
    }

    fn test_blocker() -> AdaptiveBlocker {
        let suffix = format!("{}-{}", std::process::id(), now_unix_ms());
        AdaptiveBlocker::new(AdaptiveBlockConfig {
            snapshot_path: std::env::temp_dir()
                .join(format!("pxxl-auto-block-test-{suffix}.json")),
            watchlist_snapshot_path: std::env::temp_dir()
                .join(format!("pxxl-watchlist-test-{suffix}.json")),
            exempt_cidrs: vec!["10.88.0.0/24".parse().unwrap()],
            ..AdaptiveBlockConfig::default()
        })
    }

    #[test]
    fn adaptive_blocker_blocks_cross_domain_volume() {
        let blocker = test_blocker();
        let ip = "203.0.113.10".parse().unwrap();
        let start = now_unix_ms();

        for i in 0..300 {
            blocker.record(RequestObservationInput {
                ip,
                domain: &format!("site-{}.example", i % 25),
                path: "/",
                status: 200,
                timestamp_unix_ms: start + i,
            });
        }

        assert!(matches!(
            blocker.check(ip),
            Some(SecurityDecision::Blocked { reason }) if reason == ADAPTIVE_BLOCK_REASON
        ));
    }

    #[test]
    fn adaptive_blocker_blocks_suspicious_path_scanner() {
        let blocker = test_blocker();
        let ip = "203.0.113.11".parse().unwrap();
        let start = now_unix_ms();

        for i in 0..25 {
            blocker.record(RequestObservationInput {
                ip,
                domain: &format!("site-{}.example", i % 5),
                path: "/.env",
                status: 404,
                timestamp_unix_ms: start + i,
            });
        }

        assert!(blocker.active_blocks().iter().any(|block| block.ip == ip));
    }

    #[test]
    fn adaptive_blocker_watchlists_suspicious_path_scanner_before_blocking() {
        let blocker = AdaptiveBlocker::new(AdaptiveBlockConfig {
            suspicious_path_threshold: 25,
            suspicious_path_domain_threshold: 5,
            watchlist_suspicious_path_threshold: 3,
            watchlist_suspicious_path_domain_threshold: 3,
            snapshot_path: std::env::temp_dir().join(format!(
                "pxxl-auto-block-watch-test-{}-{}.json",
                std::process::id(),
                now_unix_ms()
            )),
            watchlist_snapshot_path: std::env::temp_dir().join(format!(
                "pxxl-watchlist-watch-test-{}-{}.json",
                std::process::id(),
                now_unix_ms()
            )),
            exempt_cidrs: Vec::new(),
            ..AdaptiveBlockConfig::default()
        });
        let ip = "203.0.113.14".parse().unwrap();
        let start = now_unix_ms();

        for i in 0..3 {
            blocker.record(RequestObservationInput {
                ip,
                domain: &format!("site-{i}.example"),
                path: "/.env",
                status: 404,
                timestamp_unix_ms: start + i,
            });
        }

        assert!(blocker.check(ip).is_none());
        let watched = blocker
            .watchlist()
            .into_iter()
            .find(|entry| entry.ip == ip)
            .expect("ip should be watchlisted");
        assert_eq!(watched.reason, "suspicious_path_watch");
        assert_eq!(watched.suspicious_paths, 3);
        assert_eq!(watched.suspicious_domains, 3);
        assert!(watched.sample_paths.iter().any(|path| path == "/.env"));
    }

    #[test]
    fn adaptive_blocker_blocks_high_volume_with_fewer_domains() {
        let suffix = format!("{}-{}", std::process::id(), now_unix_ms());
        let blocker = AdaptiveBlocker::new(AdaptiveBlockConfig {
            high_request_threshold: 10,
            high_request_domain_threshold: 2,
            request_threshold: 1000,
            suspicious_path_threshold: 1000,
            failure_threshold: 1000,
            snapshot_path: std::env::temp_dir()
                .join(format!("pxxl-auto-block-high-volume-test-{suffix}.json")),
            watchlist_snapshot_path: std::env::temp_dir()
                .join(format!("pxxl-watchlist-high-volume-test-{suffix}.json")),
            exempt_cidrs: Vec::new(),
            ..AdaptiveBlockConfig::default()
        });
        let ip = "203.0.113.13".parse().unwrap();
        let start = now_unix_ms();

        for i in 0..10 {
            blocker.record(RequestObservationInput {
                ip,
                domain: &format!("site-{}.example", i % 2),
                path: "/",
                status: 200,
                timestamp_unix_ms: start + i,
            });
        }

        assert!(blocker
            .active_blocks()
            .iter()
            .any(|block| block.ip == ip && block.reason == "high_request_volume"));
    }

    #[test]
    fn adaptive_blocker_exempts_configured_internal_cidrs() {
        let blocker = test_blocker();
        let ip = "10.88.0.31".parse().unwrap();

        for i in 0..500 {
            blocker.record(RequestObservationInput {
                ip,
                domain: &format!("site-{}.example", i % 40),
                path: "/.env",
                status: 404,
                timestamp_unix_ms: now_unix_ms() + i,
            });
        }

        assert!(blocker.check(ip).is_none());
    }

    #[test]
    fn adaptive_blocker_unblocks_manually() {
        let blocker = test_blocker();
        let ip = "203.0.113.12".parse().unwrap();
        let start = now_unix_ms();

        for i in 0..25 {
            blocker.record(RequestObservationInput {
                ip,
                domain: &format!("site-{}.example", i % 5),
                path: "/.git/config",
                status: 404,
                timestamp_unix_ms: start + i,
            });
        }

        assert!(blocker.unblock(ip));
        assert!(blocker.check(ip).is_none());
    }

    #[test]
    fn adaptive_blocker_reloads_unexpired_snapshot_and_ignores_expired() {
        let path = std::env::temp_dir().join(format!(
            "pxxl-auto-block-reload-test-{}-{}.json",
            std::process::id(),
            now_unix_ms()
        ));
        let now = now_unix_ms();
        let active_ip: IpAddr = "203.0.113.20".parse().unwrap();
        let expired_ip: IpAddr = "203.0.113.21".parse().unwrap();
        let blocks = vec![
            AdaptiveBlockSnapshot {
                ip: active_ip,
                reason: "test".to_string(),
                blocked_at_unix_ms: now,
                expires_at_unix_ms: now + 60_000,
                requests: 10,
                domains: 2,
                failures: 0,
                failure_domains: 0,
                suspicious_paths: 0,
                suspicious_domains: 0,
                sample_domains: vec!["active.example".to_string()],
            },
            AdaptiveBlockSnapshot {
                ip: expired_ip,
                reason: "expired".to_string(),
                blocked_at_unix_ms: now.saturating_sub(120_000),
                expires_at_unix_ms: now.saturating_sub(60_000),
                requests: 10,
                domains: 2,
                failures: 0,
                failure_domains: 0,
                suspicious_paths: 0,
                suspicious_domains: 0,
                sample_domains: vec!["expired.example".to_string()],
            },
        ];
        std::fs::write(&path, serde_json::to_vec(&blocks).unwrap()).unwrap();

        let blocker = AdaptiveBlocker::new(AdaptiveBlockConfig {
            snapshot_path: path,
            watchlist_snapshot_path: std::env::temp_dir().join(format!(
                "pxxl-watchlist-reload-test-{}-{}.json",
                std::process::id(),
                now_unix_ms()
            )),
            exempt_cidrs: Vec::new(),
            ..AdaptiveBlockConfig::default()
        });

        assert!(matches!(
            blocker.check(active_ip),
            Some(SecurityDecision::Blocked { .. })
        ));
        assert!(blocker.check(expired_ip).is_none());
    }

    #[test]
    fn adaptive_blocker_reloads_watchlist_snapshot_and_ignores_expired() {
        let path = std::env::temp_dir().join(format!(
            "pxxl-watchlist-reload-only-test-{}-{}.json",
            std::process::id(),
            now_unix_ms()
        ));
        let now = now_unix_ms();
        let active_ip: IpAddr = "203.0.113.30".parse().unwrap();
        let expired_ip: IpAddr = "203.0.113.31".parse().unwrap();
        let entries = vec![
            SuspiciousIpWatchlistEntry {
                ip: active_ip,
                reason: "suspicious_path_watch".to_string(),
                first_seen_unix_ms: now,
                last_seen_unix_ms: now,
                expires_at_unix_ms: now + 60_000,
                requests: 5,
                domains: 3,
                failures: 5,
                failure_domains: 3,
                suspicious_paths: 5,
                suspicious_domains: 3,
                sample_domains: vec!["active.example".to_string()],
                sample_paths: vec!["/.env".to_string()],
            },
            SuspiciousIpWatchlistEntry {
                ip: expired_ip,
                reason: "expired".to_string(),
                first_seen_unix_ms: now.saturating_sub(120_000),
                last_seen_unix_ms: now.saturating_sub(120_000),
                expires_at_unix_ms: now.saturating_sub(60_000),
                requests: 5,
                domains: 3,
                failures: 5,
                failure_domains: 3,
                suspicious_paths: 5,
                suspicious_domains: 3,
                sample_domains: vec!["expired.example".to_string()],
                sample_paths: vec!["/.git/config".to_string()],
            },
        ];
        std::fs::write(&path, serde_json::to_vec(&entries).unwrap()).unwrap();

        let blocker = AdaptiveBlocker::new(AdaptiveBlockConfig {
            snapshot_path: std::env::temp_dir().join(format!(
                "pxxl-auto-block-watchlist-reload-test-{}-{}.json",
                std::process::id(),
                now_unix_ms()
            )),
            watchlist_snapshot_path: path,
            exempt_cidrs: Vec::new(),
            ..AdaptiveBlockConfig::default()
        });

        let watchlist = blocker.watchlist();
        assert!(watchlist.iter().any(|entry| entry.ip == active_ip));
        assert!(!watchlist.iter().any(|entry| entry.ip == expired_ip));
    }
}
