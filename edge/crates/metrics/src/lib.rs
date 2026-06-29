use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry, TextEncoder,
};

#[derive(Debug, thiserror::Error)]
pub enum MetricsError {
    #[error("failed to register prometheus metric: {0}")]
    Register(#[from] prometheus::Error),
    #[error("failed to encode prometheus metrics: {0}")]
    Encode(String),
}

#[derive(Clone)]
pub struct PxxlMetrics {
    registry: Registry,
    pub requests_total: IntCounterVec,
    pub active_connections: IntGauge,
    pub upstream_latency_seconds: HistogramVec,
    pub rate_limited_total: IntCounterVec,
    pub blocked_total: IntCounterVec,
    pub container_route_changes_total: IntCounterVec,
    pub docker_route_changes_total: IntCounter,
    pub tls_certificates_total: IntCounterVec,
    pub routes_total: IntGaugeVec,
    pub router_request_duration_seconds: HistogramVec,
    pub upstream_in_flight: IntGaugeVec,
    pub middleware_executions_total: IntCounterVec,
    pub upstream_health_status: IntGaugeVec,
    pub passive_health_events_total: IntCounterVec,
    pub retries_total: IntCounterVec,
    pub mirror_requests_total: IntCounterVec,
    pub circuit_breaker_open_total: IntCounterVec,
    pub in_flight_limited_total: IntCounterVec,
    pub adaptive_blocks_total: IntCounterVec,
    pub adaptive_active_blocks: IntGauge,
    pub adaptive_observed_ips: IntGauge,
}

impl PxxlMetrics {
    pub fn new() -> Result<Self, MetricsError> {
        let registry = Registry::new();

        let requests_total = IntCounterVec::new(
            Opts::new("pxxl_requests_total", "Total proxied HTTP requests"),
            &["domain", "method", "status"],
        )?;
        let active_connections =
            IntGauge::new("pxxl_active_connections", "Active edge connections")?;
        let upstream_latency_seconds = HistogramVec::new(
            HistogramOpts::new(
                "pxxl_upstream_latency_seconds",
                "Observed upstream response latency",
            ),
            &["domain", "upstream"],
        )?;
        let rate_limited_total = IntCounterVec::new(
            Opts::new("pxxl_rate_limited_total", "Rate-limited requests"),
            &["domain"],
        )?;
        let blocked_total = IntCounterVec::new(
            Opts::new("pxxl_blocked_total", "Blocked requests"),
            &["domain", "reason"],
        )?;
        let container_route_changes_total = IntCounterVec::new(
            Opts::new(
                "pxxl_container_route_changes_total",
                "Container provider route registry updates",
            ),
            &["provider"],
        )?;
        let docker_route_changes_total = IntCounter::with_opts(Opts::new(
            "pxxl_docker_route_changes_total",
            "Docker route registry updates",
        ))?;
        let tls_certificates_total = IntCounterVec::new(
            Opts::new(
                "pxxl_tls_certificates_total",
                "TLS certificates generated or loaded",
            ),
            &["mode", "result"],
        )?;
        let routes_total = IntGaugeVec::new(
            Opts::new("pxxl_routes_total", "Current configured routes"),
            &["source"],
        )?;
        let router_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "pxxl_router_request_duration_seconds",
                "End-to-end router request duration",
            ),
            &["domain", "route_id", "path_prefix", "upstream", "status"],
        )?;
        let upstream_in_flight = IntGaugeVec::new(
            Opts::new(
                "pxxl_upstream_in_flight",
                "Current in-flight requests by route and upstream",
            ),
            &["domain", "route_id", "path_prefix", "upstream"],
        )?;
        let middleware_executions_total = IntCounterVec::new(
            Opts::new(
                "pxxl_middleware_executions_total",
                "Middleware executions by result",
            ),
            &["domain", "middleware", "result"],
        )?;
        let upstream_health_status = IntGaugeVec::new(
            Opts::new(
                "pxxl_upstream_health_status",
                "Current upstream health status, 1 for healthy and 0 for unhealthy",
            ),
            &["upstream"],
        )?;
        let passive_health_events_total = IntCounterVec::new(
            Opts::new(
                "pxxl_passive_health_events_total",
                "Passive health state changes and failure observations",
            ),
            &["upstream", "event"],
        )?;
        let retries_total = IntCounterVec::new(
            Opts::new("pxxl_retries_total", "Retry attempts by route and upstream"),
            &["domain", "upstream", "result"],
        )?;
        let mirror_requests_total = IntCounterVec::new(
            Opts::new(
                "pxxl_mirror_requests_total",
                "Traffic mirror requests by route and mirror upstream",
            ),
            &["domain", "upstream", "result"],
        )?;
        let circuit_breaker_open_total = IntCounterVec::new(
            Opts::new(
                "pxxl_circuit_breaker_open_total",
                "Circuit breaker openings by route and upstream",
            ),
            &["domain", "upstream"],
        )?;
        let in_flight_limited_total = IntCounterVec::new(
            Opts::new(
                "pxxl_in_flight_limited_total",
                "Requests rejected by in-flight limit",
            ),
            &["domain", "scope"],
        )?;
        let adaptive_blocks_total = IntCounterVec::new(
            Opts::new(
                "pxxl_adaptive_blocks_total",
                "Temporary adaptive IP blocks created by reason",
            ),
            &["reason"],
        )?;
        let adaptive_active_blocks = IntGauge::new(
            "pxxl_adaptive_active_blocks",
            "Currently active adaptive IP blocks",
        )?;
        let adaptive_observed_ips = IntGauge::new(
            "pxxl_adaptive_observed_ips",
            "Currently tracked IP windows for adaptive blocking",
        )?;

        registry.register(Box::new(requests_total.clone()))?;
        registry.register(Box::new(active_connections.clone()))?;
        registry.register(Box::new(upstream_latency_seconds.clone()))?;
        registry.register(Box::new(rate_limited_total.clone()))?;
        registry.register(Box::new(blocked_total.clone()))?;
        registry.register(Box::new(container_route_changes_total.clone()))?;
        registry.register(Box::new(docker_route_changes_total.clone()))?;
        registry.register(Box::new(tls_certificates_total.clone()))?;
        registry.register(Box::new(routes_total.clone()))?;
        registry.register(Box::new(router_request_duration_seconds.clone()))?;
        registry.register(Box::new(upstream_in_flight.clone()))?;
        registry.register(Box::new(middleware_executions_total.clone()))?;
        registry.register(Box::new(upstream_health_status.clone()))?;
        registry.register(Box::new(passive_health_events_total.clone()))?;
        registry.register(Box::new(retries_total.clone()))?;
        registry.register(Box::new(mirror_requests_total.clone()))?;
        registry.register(Box::new(circuit_breaker_open_total.clone()))?;
        registry.register(Box::new(in_flight_limited_total.clone()))?;
        registry.register(Box::new(adaptive_blocks_total.clone()))?;
        registry.register(Box::new(adaptive_active_blocks.clone()))?;
        registry.register(Box::new(adaptive_observed_ips.clone()))?;

        Ok(Self {
            registry,
            requests_total,
            active_connections,
            upstream_latency_seconds,
            rate_limited_total,
            blocked_total,
            container_route_changes_total,
            docker_route_changes_total,
            tls_certificates_total,
            routes_total,
            router_request_duration_seconds,
            upstream_in_flight,
            middleware_executions_total,
            upstream_health_status,
            passive_health_events_total,
            retries_total,
            mirror_requests_total,
            circuit_breaker_open_total,
            in_flight_limited_total,
            adaptive_blocks_total,
            adaptive_active_blocks,
            adaptive_observed_ips,
        })
    }

    pub fn gather(&self) -> Result<String, MetricsError> {
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        encoder
            .encode(&self.registry.gather(), &mut buffer)
            .map_err(|error| MetricsError::Encode(error.to_string()))?;
        String::from_utf8(buffer).map_err(|error| MetricsError::Encode(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_prometheus_text() {
        let metrics = PxxlMetrics::new().unwrap();
        metrics
            .requests_total
            .with_label_values(&["app.pxxlhost", "GET", "200"])
            .inc();

        let body = metrics.gather().unwrap();
        assert!(body.contains("pxxl_requests_total"));
    }
}
