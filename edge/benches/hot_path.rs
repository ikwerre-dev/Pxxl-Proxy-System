use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pxxl_common::{LoadBalancingAlgorithm, PathRoute, Route, RouteSource, Upstream};
use pxxl_core::RouteRegistry;
use pxxl_ddos::BlacklistEngine;
use pxxl_load_balancer::LoadBalancer;
use std::net::{IpAddr, Ipv4Addr};

fn route_lookup(c: &mut Criterion) {
    let routes = (0..1000)
        .map(|index| {
            Route::new(
                format!("app-{index}.pxxlhost"),
                vec![PathRoute::new(
                    "/api",
                    vec![Upstream::new(format!("http://app-{index}:3000"))],
                )],
                RouteSource::Static,
            )
        })
        .collect();
    let registry = RouteRegistry::new(routes);

    c.bench_function("route_lookup_1000_routes", |bench| {
        bench.iter(|| {
            black_box(
                registry
                    .find(black_box("app-500.pxxlhost"), black_box("/api/users"))
                    .unwrap(),
            )
        })
    });
}

fn blacklist_lookup(c: &mut Criterion) {
    let engine = BlacklistEngine::new();
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    engine.add("app", ip);

    c.bench_function("blacklist_lookup", |bench| {
        bench.iter(|| black_box(engine.contains(black_box("app"), black_box(&ip))))
    });
}

fn load_balancer_selection(c: &mut Criterion) {
    let lb = LoadBalancer::new();
    let upstreams = vec![
        Upstream::new("http://api-1:3000"),
        Upstream::new("http://api-2:3000"),
        Upstream::new("http://api-3:3000"),
    ];

    c.bench_function("round_robin_selection", |bench| {
        bench.iter(|| {
            black_box(lb.select(
                black_box("api"),
                black_box(&LoadBalancingAlgorithm::RoundRobin),
                black_box(&upstreams),
                None,
            ))
        })
    });
}

criterion_group!(
    benches,
    route_lookup,
    blacklist_lookup,
    load_balancer_selection
);
criterion_main!(benches);
