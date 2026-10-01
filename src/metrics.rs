//! Prometheus metrics collection and exposition.
//!
//! This module provides application metrics for monitoring:
//! - Connection counts (active, total)
//! - Query processing metrics (count, latency)
//! - Masking operations (fields masked, errors)
//! - Upstream health check latency
//! - Upstream pool usage and wait time

use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;

static METRICS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Initialize the Prometheus metrics recorder.
/// Returns a handle that can be used to render metrics.
pub fn init_metrics() -> PrometheusHandle {
    METRICS_HANDLE
        .get_or_init(|| {
            PrometheusBuilder::new()
                .install_recorder()
                .expect("Failed to install Prometheus recorder")
        })
        .clone()
}

/// Record a new connection
pub fn record_connection_opened() {
    counter!("ironveil_connections_total").increment(1);
    gauge!("ironveil_connections_active").increment(1.0);
}

/// Record connection closed
pub fn record_connection_closed() {
    gauge!("ironveil_connections_active").decrement(1.0);
}

/// Record a connection rejected (rate limit or max connections)
pub fn record_connection_rejected(reason: &str) {
    counter!("ironveil_connections_rejected_total", "reason" => reason.to_string()).increment(1);
}

/// Record query processed
pub fn record_query_processed(protocol: &str, duration_secs: f64) {
    counter!("ironveil_queries_total", "protocol" => protocol.to_string()).increment(1);
    histogram!("ironveil_query_duration_seconds", "protocol" => protocol.to_string())
        .record(duration_secs);
}

/// Record fields masked
pub fn record_fields_masked(count: u64) {
    counter!("ironveil_fields_masked_total").increment(count);
}

/// Record masking error
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

/// Record wait time while acquiring an upstream pool slot.
pub fn record_upstream_pool_wait(duration_secs: f64) {
    histogram!("ironveil_upstream_pool_wait_seconds").record(duration_secs);
}

/// Record timeout waiting for an upstream pool slot.
pub fn record_upstream_pool_acquire_timeout() {
    counter!("ironveil_upstream_pool_acquire_timeouts_total").increment(1);
}

/// Set upstream pool utilization gauges.
pub fn set_upstream_pool_state(active: usize, max: usize) {
    let utilization = if max == 0 {
        0.0
    } else {
        active as f64 / max as f64
    };
    gauge!("ironveil_upstream_pool_active_connections").set(active as f64);
    gauge!("ironveil_upstream_pool_size").set(max as f64);
    gauge!("ironveil_upstream_pool_utilization_ratio").set(utilization);
}

#[cfg(test)]
mod tests {
    use super::init_metrics;

    #[test]
    fn test_metrics_init_is_idempotent() {
        let first = init_metrics();
        let second = init_metrics();

        // Both handles should point to the same underlying registry. Compare a
        // uniquely named counter rather than the whole render output, which other
        // tests mutate concurrently through the global recorder.
        metrics::counter!("ironveil_test_init_idempotent_total").increment(1);
        assert!(
            first
                .render()
                .contains("ironveil_test_init_idempotent_total 1")
        );
        assert!(
            second
                .render()
                .contains("ironveil_test_init_idempotent_total 1")
        );
    }
}
