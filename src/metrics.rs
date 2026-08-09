//! Prometheus metrics collection and exposition.
//!
//! This module provides application metrics for monitoring:
//! - Connection counts (active, total)
//! - Query processing metrics (count, latency)
//! - Masking operations (fields masked, errors)
//! - Upstream health check latency
//! - Upstream pool usage and wait time

use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;

static METRICS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Initialize the Prometheus metrics recorder.
/// Returns a handle that can be used to render metrics.
pub fn init_metrics() -> PrometheusHandle {
    METRICS_HANDLE
        .get_or_init(|| {
            // Without explicit buckets, metrics-exporter-prometheus exports
            // every histogram! as a summary with no _bucket series, and the
            // shipped Grafana histogram_quantile panels render "No data".
            PrometheusBuilder::new()
                .set_buckets(&[
                    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                ])
                .expect("bucket list is a non-empty constant")
                .set_buckets_for_metric(
                    Matcher::Full("ironveil_upstream_health_check_latency_ms".to_string()),
                    &[
                        1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0,
                    ],
                )
                .expect("bucket list is a non-empty constant")
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

/// Record that a query was seen (counter only).
pub fn record_query_processed(protocol: &str) {
    counter!("ironveil_queries_total", "protocol" => protocol.to_string()).increment(1);
}

/// Record the round trip from the client's query to the result-set terminator.
pub fn record_query_duration(protocol: &str, duration_secs: f64) {
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

/// Record a rejected binary-protocol (prepared statement) command.
/// The MySQL binary protocol is unsupported: rows would bypass masking.
pub fn record_binary_protocol_rejected() {
    counter!("ironveil_binary_protocol_rejected_total").increment(1);
}

/// Record PostgreSQL COPY data forwarded without masking (unmasked path).
pub fn record_copy_passthrough() {
    counter!("ironveil_copy_passthrough_total").increment(1);
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
    fn test_histograms_export_prometheus_bucket_series() {
        // Without explicit buckets the exporter emits summaries with no
        // _bucket series, and every histogram_quantile panel in the shipped
        // Grafana dashboard renders "No data".
        let handle = init_metrics();
        super::record_query_duration("postgres", 0.042);
        let rendered = handle.render();
        assert!(
            rendered.contains("ironveil_query_duration_seconds_bucket"),
            "query duration must export _bucket series, got:\n{rendered}"
        );
        assert!(rendered.contains("# TYPE ironveil_query_duration_seconds histogram"));
    }

    #[test]
    fn test_metrics_init_is_idempotent() {
        let first = init_metrics();
        let second = init_metrics();

        // Both handles must observe the same underlying registry. (Comparing
        // two renders directly is racy: concurrent tests record metrics.)
        super::record_masking_error();
        assert!(first.render().contains("ironveil_masking_errors_total"));
        assert!(second.render().contains("ironveil_masking_errors_total"));
    }
}
