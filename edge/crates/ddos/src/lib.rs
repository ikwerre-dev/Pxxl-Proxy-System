use dashmap::{DashMap, DashSet};
use ipnet::IpNet;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

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
}

const RATE_BUCKET_TTL_SECONDS: u64 = 600;
const RATE_BUCKET_EVICT_AT: usize = 100_000;

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: DashMap::new(),
        }
    }

    pub fn allow(&self, ip: IpAddr) -> SecurityDecision {
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
}

#[derive(Debug)]
pub struct SecurityEngine {
    blacklist: Arc<BlacklistEngine>,
    rate_limiter: Arc<RateLimiter>,
}

impl SecurityEngine {
    pub fn new(blacklist: Arc<BlacklistEngine>, rate_limiter: Arc<RateLimiter>) -> Self {
        Self {
            blacklist,
            rate_limiter,
        }
    }

    pub fn check(&self, domain_id: &str, ip: IpAddr) -> SecurityDecision {
        if self.blacklist.contains(domain_id, &ip) {
            return SecurityDecision::Blocked {
                reason: "ip_blacklisted".to_string(),
            };
        }

        self.rate_limiter.allow(ip)
    }

    pub fn blacklist(&self) -> Arc<BlacklistEngine> {
        self.blacklist.clone()
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
}
