//! Prometheus metrics collection and exposition.
//!
//! This module provides application metrics for monitoring:
//! - Connection counts (active, total)
//! - Query processing metrics (count, latency)
//! - Masking operations (fields masked, errors)
//! - Upstream health check latency

use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Initialize the Prometheus metrics recorder.
/// Returns a handle that can be used to render metrics.
pub fn init_metrics() -> PrometheusHandle {
    let builder = PrometheusBuilder::new();
    builder
        .install_recorder()
        .expect("Failed to install Prometheus recorder")
}

/// Record a new connection
pub fn record_connection_opened() {
    counter!("ironveil_connections_total").increment(1);
    gauge!("ironveil_connections_active").increment(1.0);
}

/// Record a connection closed
pub fn record_connection_closed() {
    gauge!("ironveil_connections_active").decrement(1.0);
}

/// Record a connection rejected (rate limit or max connections)
pub fn record_connection_rejected(reason: &str) {
    counter!("ironveil_connections_rejected_total", "reason" => reason.to_string()).increment(1);
}

/// Record query processing
pub fn record_query_processed(protocol: &str, duration_secs: f64) {
    counter!("ironveil_queries_total", "protocol" => protocol.to_string()).increment(1);
    histogram!("ironveil_query_duration_seconds", "protocol" => protocol.to_string()).record(duration_secs);
}

/// Record fields masked
pub fn record_fields_masked(count: u64) {
    counter!("ironveil_fields_masked_total").increment(count);
}

/// Record masking errors
pub fn record_masking_error() {
    counter!("ironveil_masking_errors_total").increment(1);
}

/// Record upstream health check
pub fn record_health_check(healthy: bool, latency_ms: Option<u64>) {
    if let Some(latency) = latency_ms {
        histogram!("ironveil_upstream_health_check_latency_ms").record(latency as f64);
    }
    if healthy {
        gauge!("ironveil_upstream_healthy").set(1.0);
    } else {
        gauge!("ironveil_upstream_healthy").set(0.0);
    }
}

/// Record upstream connection timeout
pub fn record_upstream_timeout() {
    counter!("ironveil_upstream_timeouts_total").increment(1);
}

/// Record idle connection timeout
pub fn record_idle_timeout() {
    counter!("ironveil_idle_timeouts_total").increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_can_be_initialized() {
        // Just test that metrics can be called without panicking
        // (actual initialization requires a recorder)
        // These will be no-ops without a recorder installed
    }
}
