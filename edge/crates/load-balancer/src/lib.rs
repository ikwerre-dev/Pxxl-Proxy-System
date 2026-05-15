use dashmap::DashMap;
use pxxl_common::{LoadBalancingAlgorithm, Upstream};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::atomic::{AtomicUsize, Ordering},
};

#[derive(Debug, Default)]
pub struct LoadBalancer {
    counters: DashMap<String, AtomicUsize>,
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
            LoadBalancingAlgorithm::RoundRobin
            | LoadBalancingAlgorithm::LeastConnections
            | LoadBalancingAlgorithm::EwmaLatency => self.round_robin(route_key, &healthy),
        }
    }

    fn round_robin(&self, route_key: &str, upstreams: &[Upstream]) -> Option<Upstream> {
        let counter = self
            .counters
            .entry(route_key.to_string())
            .or_insert_with(|| AtomicUsize::new(0));
        let index = counter.fetch_add(1, Ordering::Relaxed) % upstreams.len();
        upstreams.get(index).cloned()
    }
}

fn weighted_upstreams(upstreams: &[Upstream]) -> Vec<Upstream> {
    upstreams
        .iter()
        .flat_map(|upstream| {
            let weight = upstream.weight.max(1);
            std::iter::repeat(upstream.clone()).take(weight as usize)
        })
        .collect()
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
}
