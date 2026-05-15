use dashmap::DashMap;
use pxxl_common::{LoadBalancingAlgorithm, Upstream};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

#[derive(Debug, Default)]
pub struct LoadBalancer {
    counters: DashMap<String, AtomicUsize>,
    in_flight: DashMap<String, AtomicUsize>,
    ewma_latency_micros: DashMap<String, AtomicU64>,
}

impl LoadBalancer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn select(
        &self,
        route_key: &str,
        algorithm: &LoadBalancingAlgorithm,
        upstreams: &[Upstream],
        client_ip: Option<IpAddr>,
    ) -> Option<Upstream> {
        let healthy: Vec<Upstream> = upstreams
            .iter()
            .filter(|upstream| upstream.healthy)
            .cloned()
            .collect();

        if healthy.is_empty() {
            return None;
        }

        match algorithm {
            LoadBalancingAlgorithm::IpHash => {
                let ip = client_ip?;
                let mut hasher = DefaultHasher::new();
                ip.hash(&mut hasher);
                let index = hasher.finish() as usize % healthy.len();
                healthy.get(index).cloned()
            }
            LoadBalancingAlgorithm::WeightedRoundRobin => {
                let weighted = weighted_upstreams(&healthy);
                self.round_robin(route_key, &weighted)
            }
            LoadBalancingAlgorithm::LeastConnections => self.least_connections(route_key, &healthy),
            LoadBalancingAlgorithm::P2c => self.power_of_two_choices(route_key, &healthy),
            LoadBalancingAlgorithm::Hrw => {
                self.highest_random_weight(route_key, &healthy, client_ip)
            }
            LoadBalancingAlgorithm::EwmaLatency | LoadBalancingAlgorithm::LatencyAware => {
                self.latency_aware(route_key, &healthy)
            }
            LoadBalancingAlgorithm::RoundRobin => self.round_robin(route_key, &healthy),
        }
    }

    pub fn begin_request(&self, route_key: &str, upstream: &str) {
        self.in_flight
            .entry(upstream_key(route_key, upstream))
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn end_request(&self, route_key: &str, upstream: &str, latency_micros: u64) {
        let key = upstream_key(route_key, upstream);
        if let Some(counter) = self.in_flight.get(&key) {
            counter
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    Some(value.saturating_sub(1))
                })
                .ok();
        }

        self.ewma_latency_micros
            .entry(key)
            .or_insert_with(|| AtomicU64::new(latency_micros))
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                let next = if current == 0 {
                    latency_micros
                } else {
                    ((current as f64 * 0.8) + (latency_micros as f64 * 0.2)) as u64
                };
                Some(next.max(1))
            })
            .ok();
    }

    pub fn upstream_in_flight(&self, route_key: &str, upstream: &str) -> usize {
        self.in_flight
            .get(&upstream_key(route_key, upstream))
            .map(|counter| counter.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn select_weighted_index(&self, route_key: &str, weights: &[u32]) -> Option<usize> {
        if weights.is_empty() {
            return None;
        }

        let weighted = weights
            .iter()
            .enumerate()
            .flat_map(|(index, weight)| std::iter::repeat_n(index, (*weight).max(1) as usize))
            .collect::<Vec<_>>();

        let counter = self
            .counters
            .entry(route_key.to_string())
            .or_insert_with(|| AtomicUsize::new(0));
        let index = counter.fetch_add(1, Ordering::Relaxed) % weighted.len();
        weighted.get(index).copied()
    }

    fn round_robin(&self, route_key: &str, upstreams: &[Upstream]) -> Option<Upstream> {
        let counter = self
            .counters
            .entry(route_key.to_string())
            .or_insert_with(|| AtomicUsize::new(0));
        let index = counter.fetch_add(1, Ordering::Relaxed) % upstreams.len();
        upstreams.get(index).cloned()
    }

    fn least_connections(&self, route_key: &str, upstreams: &[Upstream]) -> Option<Upstream> {
        upstreams
            .iter()
            .min_by_key(|upstream| self.upstream_in_flight(route_key, &upstream.url))
            .cloned()
    }

    fn power_of_two_choices(&self, route_key: &str, upstreams: &[Upstream]) -> Option<Upstream> {
        if upstreams.len() <= 2 {
            return self.least_connections(route_key, upstreams);
        }

        let counter = self
            .counters
            .entry(format!("{route_key}:p2c"))
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed);
        let first = counter % upstreams.len();
        let second = hash_index(&(route_key, counter, "second"), upstreams.len());
        let second = if second == first {
            (second + 1) % upstreams.len()
        } else {
            second
        };
        let left = &upstreams[first];
        let right = &upstreams[second];
        if self.upstream_in_flight(route_key, &left.url)
            <= self.upstream_in_flight(route_key, &right.url)
        {
            Some(left.clone())
        } else {
            Some(right.clone())
        }
    }

    fn highest_random_weight(
        &self,
        route_key: &str,
        upstreams: &[Upstream],
        client_ip: Option<IpAddr>,
    ) -> Option<Upstream> {
        let identity = client_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| route_key.to_string());
        upstreams
            .iter()
            .max_by_key(|upstream| {
                let mut hasher = DefaultHasher::new();
                identity.hash(&mut hasher);
                upstream.url.hash(&mut hasher);
                hasher
                    .finish()
                    .saturating_mul(upstream.weight.max(1) as u64)
            })
            .cloned()
    }

    fn latency_aware(&self, route_key: &str, upstreams: &[Upstream]) -> Option<Upstream> {
        upstreams
            .iter()
            .min_by_key(|upstream| {
                self.ewma_latency_micros
                    .get(&upstream_key(route_key, &upstream.url))
                    .map(|latency| latency.load(Ordering::Relaxed))
                    .unwrap_or(0)
            })
            .cloned()
    }
}

fn weighted_upstreams(upstreams: &[Upstream]) -> Vec<Upstream> {
    upstreams
        .iter()
        .flat_map(|upstream| {
            let weight = upstream.weight.max(1);
            std::iter::repeat_n(upstream.clone(), weight as usize)
        })
        .collect()
}

fn upstream_key(route_key: &str, upstream: &str) -> String {
    format!("{route_key}|{upstream}")
}

fn hash_index<T: Hash>(value: &T, len: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish() as usize % len
}

#[cfg(test)]
mod tests {
    use super::*;
    use pxxl_common::Upstream;

    #[test]
    fn round_robin_rotates_healthy_upstreams() {
        let lb = LoadBalancer::new();
        let upstreams = vec![
            Upstream::new("http://a:3000"),
            Upstream::new("http://b:3000"),
        ];

        assert_eq!(
            lb.select(
                "route",
                &LoadBalancingAlgorithm::RoundRobin,
                &upstreams,
                None
            )
            .unwrap()
            .url,
            "http://a:3000"
        );
        assert_eq!(
            lb.select(
                "route",
                &LoadBalancingAlgorithm::RoundRobin,
                &upstreams,
                None
            )
            .unwrap()
            .url,
            "http://b:3000"
        );
    }

    #[test]
    fn ignores_unhealthy_upstreams() {
        let lb = LoadBalancer::new();
        let mut bad = Upstream::new("http://bad:3000");
        bad.healthy = false;
        let good = Upstream::new("http://good:3000");

        assert_eq!(
            lb.select(
                "route",
                &LoadBalancingAlgorithm::RoundRobin,
                &[bad, good],
                None
            )
            .unwrap()
            .url,
            "http://good:3000"
        );
    }

    #[test]
    fn weighted_index_honors_weights() {
        let lb = LoadBalancer::new();
        let weights = vec![2, 1];

        assert_eq!(lb.select_weighted_index("split", &weights), Some(0));
        assert_eq!(lb.select_weighted_index("split", &weights), Some(0));
        assert_eq!(lb.select_weighted_index("split", &weights), Some(1));
    }
}
