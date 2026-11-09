//! Prometheus 指标。

use std::sync::Arc;

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry, TextEncoder,
};

/// 网关指标集合。
pub struct Metrics {
    registry: Registry,
    requests_total: IntCounterVec,
    request_duration: HistogramVec,
    upstream_total: IntCounterVec,
    rate_limited_total: IntCounterVec,
    circuit_breaker_state: IntGaugeVec,
    cache_hits: IntCounter,
    cache_misses: IntCounter,
    cache_entries: IntGauge,
    active_connections: IntGauge,
    inflight_requests: IntGauge,
    discovery_up: IntGaugeVec,
    service_instances: IntGaugeVec,
    websocket_connections: IntGauge,
}

impl Metrics {
    pub fn new() -> Result<Arc<Self>, prometheus::Error> {
        let registry = Registry::new();

        let requests_total = IntCounterVec::new(
            Opts::new(
                "gateway_requests_total",
                "Total number of requests handled by the gateway",
            ),
            &["route", "method", "status"],
        )?;
        let request_duration = HistogramVec::new(
            HistogramOpts::new(
                "gateway_request_duration_seconds",
                "Request latency in seconds",
            )
            .buckets(vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
            ]),
            &["route"],
        )?;
        let upstream_total = IntCounterVec::new(
            Opts::new(
                "gateway_upstream_requests_total",
                "Upstream requests grouped by service and result",
            ),
            &["service", "result"],
        )?;
        let rate_limited_total = IntCounterVec::new(
            Opts::new(
                "gateway_rate_limited_total",
                "Requests rejected by rate limiting",
            ),
            &["route"],
        )?;
        let circuit_breaker_state = IntGaugeVec::new(
            Opts::new(
                "gateway_circuit_breaker_state",
                "Circuit breaker state (0=closed, 1=half-open, 2=open)",
            ),
            &["route"],
        )?;
        let cache_hits =
            IntCounter::new("gateway_cache_hits_total", "Number of response cache hits")?;
        let cache_misses = IntCounter::new(
            "gateway_cache_misses_total",
            "Number of response cache misses",
        )?;
        let cache_entries = IntGauge::new(
            "gateway_cache_entries",
            "Number of entries in the response cache",
        )?;
        let active_connections = IntGauge::new(
            "gateway_active_connections",
            "Number of currently active client connections",
        )?;
        let inflight_requests = IntGauge::new(
            "gateway_inflight_requests",
            "Number of requests currently being processed",
        )?;
        let discovery_up = IntGaugeVec::new(
            Opts::new(
                "gateway_service_discovery_up",
                "Whether service discovery last succeeded for a service",
            ),
            &["service"],
        )?;
        let service_instances = IntGaugeVec::new(
            Opts::new(
                "gateway_service_instances",
                "Number of instances per service and state",
            ),
            &["service", "state"],
        )?;
        let websocket_connections = IntGauge::new(
            "gateway_websocket_connections",
            "Number of active WebSocket tunnels",
        )?;

        registry.register(Box::new(requests_total.clone()))?;
        registry.register(Box::new(request_duration.clone()))?;
        registry.register(Box::new(upstream_total.clone()))?;
        registry.register(Box::new(rate_limited_total.clone()))?;
        registry.register(Box::new(circuit_breaker_state.clone()))?;
        registry.register(Box::new(cache_hits.clone()))?;
        registry.register(Box::new(cache_misses.clone()))?;
        registry.register(Box::new(cache_entries.clone()))?;
        registry.register(Box::new(active_connections.clone()))?;
        registry.register(Box::new(inflight_requests.clone()))?;
        registry.register(Box::new(discovery_up.clone()))?;
        registry.register(Box::new(service_instances.clone()))?;
        registry.register(Box::new(websocket_connections.clone()))?;

        Ok(Arc::new(Self {
            registry,
            requests_total,
            request_duration,
            upstream_total,
            rate_limited_total,
            circuit_breaker_state,
            cache_hits,
            cache_misses,
            cache_entries,
            active_connections,
            inflight_requests,
            discovery_up,
            service_instances,
            websocket_connections,
        }))
    }

    pub fn record_request(&self, route: &str, method: &str, status: u16, duration_secs: f64) {
        self.requests_total
            .with_label_values(&[route, method, &status.to_string()])
            .inc();
        self.request_duration
            .with_label_values(&[route])
            .observe(duration_secs);
    }

    pub fn record_upstream_result(&self, service: &str, success: bool) {
        let result = if success { "success" } else { "error" };
        self.upstream_total
            .with_label_values(&[service, result])
            .inc();
    }

    pub fn inc_rate_limited(&self, route: &str) {
        self.rate_limited_total.with_label_values(&[route]).inc();
    }

    pub fn set_circuit_breaker_state(&self, route: &str, state: i64) {
        self.circuit_breaker_state
            .with_label_values(&[route])
            .set(state);
    }

    pub fn record_cache(&self, hit: bool) {
        if hit {
            self.cache_hits.inc();
        } else {
            self.cache_misses.inc();
        }
    }

    pub fn set_cache_entries(&self, value: i64) {
        self.cache_entries.set(value);
    }

    pub fn set_active_connections(&self, value: i64) {
        self.active_connections.set(value);
    }

    pub fn add_active_connections(&self, delta: i64) {
        self.active_connections.add(delta);
    }

    pub fn inc_inflight(&self, delta: i64) {
        self.inflight_requests.add(delta);
    }

    pub fn inc_websocket(&self, delta: i64) {
        self.websocket_connections.add(delta);
    }

    pub fn set_discovery_up(&self, service: &str, up: bool) {
        self.discovery_up
            .with_label_values(&[service])
            .set(if up { 1 } else { 0 });
    }

    pub fn set_service_instances(&self, service: &str, healthy: usize, total: usize) {
        self.service_instances
            .with_label_values(&[service, "healthy"])
            .set(healthy as i64);
        self.service_instances
            .with_label_values(&[service, "total"])
            .set(total as i64);
    }

    /// 渲染 Prometheus 文本格式。
    pub fn render(&self) -> String {
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        if encoder
            .encode(&self.registry.gather(), &mut buffer)
            .is_err()
        {
            return String::new();
        }
        String::from_utf8(buffer).unwrap_or_default()
    }

    /// 指标摘要（管理 API）。
    pub fn summary(&self) -> serde_json::Value {
        let mut flat = serde_json::Map::new();
        for metric in self.registry.gather() {
            let name = metric.get_name().to_string();
            let mut total = 0.0;
            for m in metric.get_metric() {
                if m.has_counter() {
                    total += m.get_counter().get_value();
                } else if m.has_gauge() {
                    total += m.get_gauge().get_value();
                } else if m.has_histogram() {
                    total += m.get_histogram().get_sample_count() as f64;
                }
            }
            flat.insert(name, serde_json::json!(total));
        }
        serde_json::Value::Object(flat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_prometheus_text() {
        let metrics = Metrics::new().unwrap();
        metrics.record_request("/api/users", "GET", 200, 0.02);
        metrics.inc_rate_limited("/api/users");
        metrics.set_service_instances("user", 2, 3);
        let text = metrics.render();
        assert!(text.contains("gateway_requests_total"));
        assert!(text.contains("gateway_rate_limited_total"));
        assert!(text.contains("gateway_service_instances"));
    }
}
