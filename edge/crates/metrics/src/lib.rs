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
    pub docker_route_changes_total: IntCounter,
    pub tls_certificates_total: IntCounterVec,
    pub routes_total: IntGaugeVec,
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

        registry.register(Box::new(requests_total.clone()))?;
        registry.register(Box::new(active_connections.clone()))?;
        registry.register(Box::new(upstream_latency_seconds.clone()))?;
        registry.register(Box::new(rate_limited_total.clone()))?;
        registry.register(Box::new(blocked_total.clone()))?;
        registry.register(Box::new(docker_route_changes_total.clone()))?;
        registry.register(Box::new(tls_certificates_total.clone()))?;
        registry.register(Box::new(routes_total.clone()))?;

        Ok(Self {
            registry,
            requests_total,
            active_connections,
            upstream_latency_seconds,
            rate_limited_total,
            blocked_total,
            docker_route_changes_total,
            tls_certificates_total,
            routes_total,
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
