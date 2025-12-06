use crate::audit::AuditLogger;
use crate::config::AppConfig;
use chrono::{DateTime, Utc};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
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

/// Upstream health status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub healthy: bool,
    pub last_check: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub latency_ms: Option<u64>,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self {
            healthy: true, // Assume healthy until proven otherwise
            last_check: None,
            last_error: None,
            consecutive_failures: 0,
            consecutive_successes: 0,
            latency_ms: None,
        }
    }
}

/// Database protocol type for upstream connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbProtocol {
    Postgres,
    MySql,
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
    pub upstream_healthy: Arc<AtomicBool>,
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
        let audit_logger = config
            .audit
            .as_ref()
            .map(|cfg| {
                AuditLogger::new(crate::audit::AuditConfig {
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
                            crate::config::AuditEventType::RuleAdded => {
                                crate::audit::AuditEventType::RuleAdded
                            }
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
                            crate::config::AuditEventType::ApiAccess => {
                                crate::audit::AuditEventType::ApiAccess
                            }
                        })
                        .collect(),
                })
            })
            .unwrap_or_else(|| AuditLogger::new(crate::audit::AuditConfig::default()));

        Self {
            config: Arc::new(RwLock::new(config)),
            config_path: Arc::new(config_path),
            active_connections: Arc::new(AtomicUsize::new(0)),
            logs: Arc::new(RwLock::new(VecDeque::with_capacity(100))),
            upstream_healthy: Arc::new(AtomicBool::new(true)),
            health_status: Arc::new(RwLock::new(HealthStatus::default())),
            metrics_handle: None,
            upstream_host: Arc::new(upstream_host),
            upstream_port,
            db_protocol,
            audit_logger: Arc::new(audit_logger),
            stats: Arc::new(RwLock::new(AppStats::default())),
            connection_history: Arc::new(RwLock::new(VecDeque::with_capacity(60))),
        }
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

    /// Save current config to the config file
    pub async fn save_config(&self) -> Result<(), std::io::Error> {
        let config = self.config.read().await;
        let yaml = serde_yaml::to_string(&*config)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&*self.config_path, yaml)
    }

    pub async fn add_log(&self, entry: LogEntry) {
        let mut logs = self.logs.write().await;
        if logs.len() >= 100 {
            logs.pop_back();
        }
        logs.push_front(entry);
    }

    /// Check if upstream is healthy (fast atomic check)
    #[allow(dead_code)]
    pub fn is_upstream_healthy(&self) -> bool {
        self.upstream_healthy.load(Ordering::Relaxed)
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
            self.upstream_healthy.store(false, Ordering::Relaxed);
        } else if status.consecutive_successes >= healthy_threshold {
            status.healthy = true;
            self.upstream_healthy.store(true, Ordering::Relaxed);
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
        let mut stats = self.stats.write().await;
        stats.masking.increment(strategy);
    }

    /// Record a query by type (SELECT, INSERT, UPDATE, DELETE, etc.)
    pub async fn record_query(&self, query_type: &str) {
        let mut stats = self.stats.write().await;
        stats.queries.record_query(query_type);
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
            tls: None,
            upstream_tls: false,
            telemetry: None,
            api: None,
            limits: None,
            health_check: None,
            audit: None,
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
            tls: None,
            upstream_tls: false,
            telemetry: None,
            api: None,
            limits: None,
            health_check: None,
            audit: None,
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
            tls: None,
            upstream_tls: false,
            telemetry: None,
            api: None,
            limits: None,
            health_check: None,
            audit: None,
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
            tls: None,
            upstream_tls: false,
            telemetry: None,
            api: None,
            limits: None,
            health_check: None,
            audit: None,
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
            tls: None,
            upstream_tls: false,
            telemetry: None,
            api: None,
            limits: None,
            health_check: None,
            audit: None,
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());

        // Record more than 60 snapshots
        for _ in 0..70 {
            state.record_history_snapshot().await;
        }

        let history = state.get_connection_history().await;
        assert_eq!(history.len(), 60, "History should be capped at 60 entries");
    }
}
