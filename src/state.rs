use crate::audit::AuditLogger;
use crate::config::AppConfig;
use crate::metrics;
use chrono::{DateTime, Utc};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub connection_id: usize,
    pub event_type: String,
    pub content: String,
    pub details: Option<serde_json::Value>,
}

/// Upstream health status information.
/// Defaults to unhealthy/unknown: reporting healthy before the first probe
/// let CI gates and readiness probes pass against a dead upstream.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HealthStatus {
    pub healthy: bool,
    pub last_check: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub latency_ms: Option<u64>,
}

/// Database protocol type for upstream connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbProtocol {
    Postgres,
    MySql,
}

impl DbProtocol {
    fn metrics_label(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::MySql => "mysql",
        }
    }
}

/// Statistics for masking operations by strategy
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MaskingStats {
    pub email: u64,
    pub phone: u64,
    pub address: u64,
    pub credit_card: u64,
    pub ssn: u64,
    pub ip: u64,
    pub dob: u64,
    pub passport: u64,
    pub hash: u64,
    pub json: u64,
    pub other: u64,
}

impl MaskingStats {
    pub fn increment(&mut self, strategy: &str) {
        match strategy {
            "email" => self.email += 1,
            "phone" => self.phone += 1,
            "address" => self.address += 1,
            "credit_card" => self.credit_card += 1,
            "ssn" => self.ssn += 1,
            "ip" => self.ip += 1,
            "dob" => self.dob += 1,
            "passport" => self.passport += 1,
            "hash" => self.hash += 1,
            "json" => self.json += 1,
            _ => self.other += 1,
        }
    }

    pub fn total(&self) -> u64 {
        self.email
            + self.phone
            + self.address
            + self.credit_card
            + self.ssn
            + self.ip
            + self.dob
            + self.passport
            + self.hash
            + self.json
            + self.other
    }
}

/// Query statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueryStats {
    pub total_queries: u64,
    pub select_count: u64,
    pub insert_count: u64,
    pub update_count: u64,
    pub delete_count: u64,
    pub other_count: u64,
}

impl QueryStats {
    pub fn record_query(&mut self, query_type: &str) {
        self.total_queries += 1;
        match query_type.to_uppercase().as_str() {
            "SELECT" => self.select_count += 1,
            "INSERT" => self.insert_count += 1,
            "UPDATE" => self.update_count += 1,
            "DELETE" => self.delete_count += 1,
            _ => self.other_count += 1,
        }
    }
}

/// Connection history data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionDataPoint {
    pub timestamp: DateTime<Utc>,
    pub active_connections: usize,
    pub total_queries: u64,
    pub total_masked: u64,
}

/// Application statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppStats {
    pub masking: MaskingStats,
    pub queries: QueryStats,
    pub total_connections: u64,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RwLock<AppConfig>>,
    pub config_path: Arc<String>,
    pub active_connections: Arc<AtomicUsize>,
    pub logs: Arc<RwLock<VecDeque<LogEntry>>>,
    pub health_status: Arc<RwLock<HealthStatus>>,
    pub metrics_handle: Option<Arc<PrometheusHandle>>,
    /// Upstream database host for scanning
    pub upstream_host: Arc<String>,
    /// Upstream database port for scanning
    pub upstream_port: u16,
    /// Database protocol (Postgres or MySQL)
    pub db_protocol: DbProtocol,
    /// Audit logger for security events
    pub audit_logger: Arc<AuditLogger>,
    /// Application statistics (queries, masking, connections)
    pub stats: Arc<RwLock<AppStats>>,
    /// Connection history for charts (last 60 data points)
    pub connection_history: Arc<RwLock<VecDeque<ConnectionDataPoint>>>,
    /// Key for the deterministic masking functions. Derived from
    /// `masking_secret` when configured, otherwise random per process.
    masking_key: Arc<std::sync::RwLock<[u8; 32]>>,
}

fn to_audit_config(cfg: &crate::config::AuditConfig) -> crate::audit::AuditConfig {
    crate::audit::AuditConfig {
        enabled: cfg.enabled,
        log_to_stdout: cfg.log_to_stdout,
        log_file: cfg.log_file.clone(),
        rotation_enabled: cfg.rotation_enabled,
        max_file_size_bytes: cfg.max_file_size_bytes,
        max_rotated_files: cfg.max_rotated_files,
        events: cfg
            .events
            .iter()
            .map(|e| match e {
                crate::config::AuditEventType::AuthAttempt => {
                    crate::audit::AuditEventType::AuthAttempt
                }
                crate::config::AuditEventType::ConfigChange => {
                    crate::audit::AuditEventType::ConfigChange
                }
                crate::config::AuditEventType::RuleAdded => crate::audit::AuditEventType::RuleAdded,
                crate::config::AuditEventType::RuleDeleted => {
                    crate::audit::AuditEventType::RuleDeleted
                }
                crate::config::AuditEventType::RulesImported => {
                    crate::audit::AuditEventType::RulesImported
                }
                crate::config::AuditEventType::ConfigReload => {
                    crate::audit::AuditEventType::ConfigReload
                }
                crate::config::AuditEventType::DatabaseScan => {
                    crate::audit::AuditEventType::DatabaseScan
                }
                crate::config::AuditEventType::SchemaQuery => {
                    crate::audit::AuditEventType::SchemaQuery
                }
            })
            .collect(),
    }
}

fn derive_masking_key(secret: Option<&str>) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    match secret {
        Some(secret) if !secret.is_empty() => Sha256::digest(secret.as_bytes()).into(),
        _ => {
            tracing::warn!(
                "masking_secret is not configured; using a random per-process key. \
                 Masked output will not be stable across restarts."
            );
            rand::random()
        }
    }
}

impl AppState {
    pub fn new(
        config: AppConfig,
        config_path: String,
        upstream_host: String,
        upstream_port: u16,
        db_protocol: DbProtocol,
    ) -> Self {
        // Create audit logger from config
        let audit_logger = AuditLogger::new(
            config
                .audit
                .as_ref()
                .map(to_audit_config)
                .unwrap_or_default(),
        );

        let masking_key = derive_masking_key(config.masking_secret.as_deref());

        Self {
            config: Arc::new(RwLock::new(config)),
            config_path: Arc::new(config_path),
            active_connections: Arc::new(AtomicUsize::new(0)),
            logs: Arc::new(RwLock::new(VecDeque::with_capacity(100))),
            health_status: Arc::new(RwLock::new(HealthStatus::default())),
            metrics_handle: None,
            upstream_host: Arc::new(upstream_host),
            upstream_port,
            db_protocol,
            audit_logger: Arc::new(audit_logger),
            stats: Arc::new(RwLock::new(AppStats::default())),
            connection_history: Arc::new(RwLock::new(VecDeque::with_capacity(60))),
            masking_key: Arc::new(std::sync::RwLock::new(masking_key)),
        }
    }

    /// Current masking key (copied out; the key is only 32 bytes).
    pub fn masking_key(&self) -> [u8; 32] {
        *self
            .masking_key
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Create a new AppState with default upstream settings (for testing)
    #[cfg(test)]
    pub fn new_for_test(config: AppConfig, config_path: String) -> Self {
        Self::new(
            config,
            config_path,
            "localhost".to_string(),
            5432,
            DbProtocol::Postgres,
        )
    }

    pub fn with_metrics(mut self, handle: PrometheusHandle) -> Self {
        self.metrics_handle = Some(Arc::new(handle));
        self
    }

    /// Atomically persist a new config, then swap it into live state.
    /// Live state is untouched when persistence fails, so the on-disk policy
    /// can never silently diverge from runtime behaviour.
    pub async fn commit_config(&self, new_config: AppConfig) -> Result<(), std::io::Error> {
        let yaml = serde_yaml_ng::to_string(&new_config)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let path = self.config_path.as_ref().clone();
        tokio::task::spawn_blocking(move || {
            let tmp = format!("{}.tmp", path);
            std::fs::write(&tmp, yaml)?;
            std::fs::rename(&tmp, &path)
        })
        .await
        .map_err(std::io::Error::other)??;

        let mut config = self.config.write().await;
        *config = new_config;
        Ok(())
    }

    pub async fn add_log(&self, entry: LogEntry) {
        let mut logs = self.logs.write().await;
        if logs.len() >= 100 {
            logs.pop_back();
        }
        logs.push_front(entry);
    }

    /// Update upstream health status
    pub async fn update_health_status(
        &self,
        healthy: bool,
        latency_ms: Option<u64>,
        error: Option<String>,
    ) {
        let mut status = self.health_status.write().await;

        status.last_check = Some(Utc::now());
        status.latency_ms = latency_ms;

        if healthy {
            status.consecutive_successes += 1;
            status.consecutive_failures = 0;
            status.last_error = None;
        } else {
            status.consecutive_failures += 1;
            status.consecutive_successes = 0;
            status.last_error = error;
        }

        // Read config thresholds
        let config = self.config.read().await;
        let health_config = config.health_check.as_ref();
        let unhealthy_threshold = health_config.map(|h| h.unhealthy_threshold).unwrap_or(3);
        let healthy_threshold = health_config.map(|h| h.healthy_threshold).unwrap_or(1);
        drop(config);

        // Update healthy status based on thresholds
        if status.consecutive_failures >= unhealthy_threshold {
            status.healthy = false;
        } else if status.consecutive_successes >= healthy_threshold {
            status.healthy = true;
        }
    }

    /// Reload configuration from disk
    /// Returns the number of rules in the new config, or an error
    pub async fn reload_config(&self) -> Result<usize, String> {
        let path = self.config_path.as_ref();

        // Load new config from file
        let new_config = AppConfig::load(path)
            .map_err(|e| format!("Failed to load config from {}: {}", path, e))?;

        let rules_count = new_config.rules.len();

        // A reloaded masking_secret takes effect immediately; when the new
        // config has none, keep the existing key so determinism is preserved.
        if let Some(secret) = new_config.masking_secret.as_deref()
            && !secret.is_empty()
        {
            let new_key = derive_masking_key(Some(secret));
            let mut key = self
                .masking_key
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *key = new_key;
        }

        // Re-apply the reloadable audit section; warn about sections that
        // only take effect after a restart so a reload cannot silently claim
        // to have applied them.
        self.audit_logger
            .apply_config(
                new_config
                    .audit
                    .as_ref()
                    .map(to_audit_config)
                    .unwrap_or_default(),
            )
            .await;

        {
            let current = self.config.read().await;
            let mut restart_required = Vec::new();
            if serde_yaml_ng::to_string(&current.tls).ok()
                != serde_yaml_ng::to_string(&new_config.tls).ok()
            {
                restart_required.push("tls");
            }
            if current.upstream_tls != new_config.upstream_tls {
                restart_required.push("upstream_tls");
            }
            if serde_yaml_ng::to_string(&current.limits).ok()
                != serde_yaml_ng::to_string(&new_config.limits).ok()
            {
                restart_required.push("limits");
            }
            if serde_yaml_ng::to_string(&current.telemetry).ok()
                != serde_yaml_ng::to_string(&new_config.telemetry).ok()
            {
                restart_required.push("telemetry");
            }
            if serde_yaml_ng::to_string(&current.api).ok()
                != serde_yaml_ng::to_string(&new_config.api).ok()
            {
                restart_required.push("api");
            }
            if !restart_required.is_empty() {
                tracing::warn!(
                    sections = ?restart_required,
                    "reloaded config changes sections that only take effect after a restart"
                );
            }
        }

        // Update the config
        {
            let mut config = self.config.write().await;
            *config = new_config;
        }

        tracing::info!(
            "Configuration reloaded from {}: {} rules",
            path,
            rules_count
        );
        Ok(rules_count)
    }

    /// Record a masking operation by strategy
    pub async fn record_masking(&self, strategy: &str) {
        self.record_masking_batch(std::slice::from_ref(&strategy))
            .await;
    }

    /// Record every masked field of a row under a single lock acquisition.
    /// One process-global write lock per masked *field* serialized every
    /// concurrent connection on the packet hot path.
    pub async fn record_masking_batch(&self, strategies: &[&str]) {
        if strategies.is_empty() {
            return;
        }
        {
            let mut stats = self.stats.write().await;
            for strategy in strategies {
                stats.masking.increment(strategy);
            }
        }
        metrics::record_fields_masked(strategies.len() as u64);
    }

    /// Record a query by type (SELECT, INSERT, UPDATE, DELETE, etc.).
    /// Counting only — latency is recorded by `record_query_latency` when the
    /// result set terminates. Timing this call measured a lock acquisition,
    /// not the upstream round trip, so the latency panels read ~0 forever.
    pub async fn record_query(&self, query_type: &str) {
        let mut stats = self.stats.write().await;
        stats.queries.record_query(query_type);
        drop(stats);
        metrics::record_query_processed(self.db_protocol.metrics_label());
    }

    /// Record the observed round trip for a completed query.
    pub fn record_query_latency(&self, started_at: std::time::Instant) {
        metrics::record_query_duration(
            self.db_protocol.metrics_label(),
            started_at.elapsed().as_secs_f64(),
        );
    }

    /// Increment connection count
    pub async fn record_connection(&self) {
        let mut stats = self.stats.write().await;
        stats.total_connections += 1;
    }

    /// Record a connection history data point (call periodically)
    pub async fn record_history_snapshot(&self) {
        let stats = self.stats.read().await;
        let active = self.active_connections.load(Ordering::Relaxed);

        let point = ConnectionDataPoint {
            timestamp: Utc::now(),
            active_connections: active,
            total_queries: stats.queries.total_queries,
            total_masked: stats.masking.total(),
        };
        drop(stats);

        let mut history = self.connection_history.write().await;
        if history.len() >= 60 {
            history.pop_back();
        }
        history.push_front(point);
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> AppStats {
        self.stats.read().await.clone()
    }

    /// Get connection history for charts
    pub async fn get_connection_history(&self) -> Vec<ConnectionDataPoint> {
        self.connection_history
            .read()
            .await
            .iter()
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::metrics::init_metrics;

    fn metric_value(rendered: &str, metric_name: &str) -> f64 {
        rendered
            .lines()
            .find_map(|line| {
                if line.starts_with(metric_name) {
                    line.split_whitespace().nth(1)?.parse::<f64>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0.0)
    }

    #[test]
    fn test_masking_stats_increment() {
        let mut stats = MaskingStats::default();

        stats.increment("email");
        stats.increment("email");
        stats.increment("phone");
        stats.increment("credit_card");
        stats.increment("unknown_strategy");

        assert_eq!(stats.email, 2);
        assert_eq!(stats.phone, 1);
        assert_eq!(stats.credit_card, 1);
        assert_eq!(stats.other, 1);
        assert_eq!(stats.total(), 5);
    }

    #[test]
    fn test_masking_stats_all_strategies() {
        let mut stats = MaskingStats::default();

        stats.increment("email");
        stats.increment("phone");
        stats.increment("address");
        stats.increment("credit_card");
        stats.increment("ssn");
        stats.increment("ip");
        stats.increment("dob");
        stats.increment("passport");
        stats.increment("hash");
        stats.increment("json");
        stats.increment("other");

        assert_eq!(stats.email, 1);
        assert_eq!(stats.phone, 1);
        assert_eq!(stats.address, 1);
        assert_eq!(stats.credit_card, 1);
        assert_eq!(stats.ssn, 1);
        assert_eq!(stats.ip, 1);
        assert_eq!(stats.dob, 1);
        assert_eq!(stats.passport, 1);
        assert_eq!(stats.hash, 1);
        assert_eq!(stats.json, 1);
        assert_eq!(stats.other, 1);
        assert_eq!(stats.total(), 11);
    }

    #[test]
    fn test_query_stats_record() {
        let mut stats = QueryStats::default();

        stats.record_query("SELECT");
        stats.record_query("select"); // lowercase should also work
        stats.record_query("INSERT");
        stats.record_query("UPDATE");
        stats.record_query("DELETE");
        stats.record_query("TRUNCATE"); // unknown goes to other

        assert_eq!(stats.total_queries, 6);
        assert_eq!(stats.select_count, 2);
        assert_eq!(stats.insert_count, 1);
        assert_eq!(stats.update_count, 1);
        assert_eq!(stats.delete_count, 1);
        assert_eq!(stats.other_count, 1);
    }

    #[tokio::test]
    async fn test_app_state_record_masking() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());

        state.record_masking("email").await;
        state.record_masking("email").await;
        state.record_masking("phone").await;

        let stats = state.get_stats().await;
        assert_eq!(stats.masking.email, 2);
        assert_eq!(stats.masking.phone, 1);
        assert_eq!(stats.masking.total(), 3);
    }

    #[tokio::test]
    async fn test_app_state_record_query() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());

        state.record_query("SELECT").await;
        state.record_query("INSERT").await;
        state.record_query("SELECT").await;

        let stats = state.get_stats().await;
        assert_eq!(stats.queries.total_queries, 3);
        assert_eq!(stats.queries.select_count, 2);
        assert_eq!(stats.queries.insert_count, 1);
    }

    #[tokio::test]
    async fn test_app_state_record_connection() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());

        state.record_connection().await;
        state.record_connection().await;
        state.record_connection().await;

        let stats = state.get_stats().await;
        assert_eq!(stats.total_connections, 3);
    }

    #[tokio::test]
    async fn test_app_state_history_snapshot() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());

        // Record some stats
        state.record_query("SELECT").await;
        state.record_masking("email").await;

        // Take a snapshot
        state.record_history_snapshot().await;

        let history = state.get_connection_history().await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].total_queries, 1);
        assert_eq!(history[0].total_masked, 1);
    }

    #[tokio::test]
    async fn test_history_max_capacity() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());

        // Record more than 60 snapshots
        for _ in 0..70 {
            state.record_history_snapshot().await;
        }

        let history = state.get_connection_history().await;
        assert_eq!(history.len(), 60, "History should be capped at 60 entries");
    }

    #[tokio::test]
    async fn test_app_state_record_query_emits_prometheus_metric() {
        let handle = init_metrics();
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string()).with_metrics(handle);

        let before = state
            .metrics_handle
            .as_ref()
            .expect("metrics handle should be attached")
            .render();
        let before_total = metric_value(&before, "ironveil_queries_total{protocol=\"postgres\"}");
        let before_duration_count = metric_value(
            &before,
            "ironveil_query_duration_seconds_count{protocol=\"postgres\"}",
        );

        state.record_query("SELECT").await;
        state.record_query_latency(std::time::Instant::now());

        let after = state
            .metrics_handle
            .as_ref()
            .expect("metrics handle should be attached")
            .render();
        let after_total = metric_value(&after, "ironveil_queries_total{protocol=\"postgres\"}");
        let after_duration_count = metric_value(
            &after,
            "ironveil_query_duration_seconds_count{protocol=\"postgres\"}",
        );
        assert!(
            after_total > before_total,
            "query counter should be emitted when recording query stats"
        );
        assert!(
            after_duration_count > before_duration_count,
            "query duration metric should be emitted when a query round trip completes"
        );
    }

    #[tokio::test]
    async fn test_app_state_record_masking_emits_prometheus_metric() {
        let handle = init_metrics();
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string()).with_metrics(handle);

        let before = state
            .metrics_handle
            .as_ref()
            .expect("metrics handle should be attached")
            .render();
        let before_total = metric_value(&before, "ironveil_fields_masked_total");

        state.record_masking("email").await;

        let after = state
            .metrics_handle
            .as_ref()
            .expect("metrics handle should be attached")
            .render();
        let after_total = metric_value(&after, "ironveil_fields_masked_total");
        assert!(
            after_total > before_total,
            "fields-masked counter should be emitted when recording masking stats"
        );
    }

    // ------------------------------------------------------------------
    // Upstream health threshold state machine. It alone decides whether
    // /health answers 200 or 503 (and drives every load-balancer and
    // Kubernetes probe), and had no coverage at all.
    // ------------------------------------------------------------------

    fn health_state(unhealthy_threshold: u32, healthy_threshold: u32) -> AppState {
        AppState::new_for_test(
            AppConfig {
                health_check: Some(crate::config::HealthCheckConfig {
                    enabled: true,
                    interval_secs: 10,
                    timeout_secs: 5,
                    unhealthy_threshold,
                    healthy_threshold,
                }),
                ..Default::default()
            },
            "proxy.yaml".to_string(),
        )
    }

    #[tokio::test]
    async fn test_health_starts_unknown_and_flips_only_on_threshold() {
        let state = health_state(3, 1);
        assert!(
            !state.health_status.read().await.healthy,
            "health must be unknown (not healthy) before the first probe"
        );

        state.update_health_status(true, Some(1), None).await;
        assert!(state.health_status.read().await.healthy);

        // Two failures are not enough with unhealthy_threshold: 3
        state
            .update_health_status(false, None, Some("boom".into()))
            .await;
        assert!(state.health_status.read().await.healthy);
        state
            .update_health_status(false, None, Some("boom".into()))
            .await;
        assert!(state.health_status.read().await.healthy);

        // The third flips it
        state
            .update_health_status(false, None, Some("boom".into()))
            .await;
        let status = state.health_status.read().await;
        assert!(!status.healthy);
        assert_eq!(status.consecutive_failures, 3);
        assert_eq!(status.last_error.as_deref(), Some("boom"));
    }

    #[tokio::test]
    async fn test_health_recovers_after_healthy_threshold_and_resets_counters() {
        let state = health_state(2, 2);

        state
            .update_health_status(false, None, Some("down".into()))
            .await;
        state
            .update_health_status(false, None, Some("down".into()))
            .await;
        assert!(!state.health_status.read().await.healthy);

        // One success is not enough with healthy_threshold: 2, but it must
        // reset the failure counter.
        state.update_health_status(true, Some(2), None).await;
        {
            let status = state.health_status.read().await;
            assert!(!status.healthy);
            assert_eq!(status.consecutive_failures, 0);
            assert!(status.last_error.is_none());
        }

        state.update_health_status(true, Some(2), None).await;
        assert!(state.health_status.read().await.healthy);
    }
}
