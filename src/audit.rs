//! Audit Logging for IronVeil
//!
//! This module provides structured audit logging for security-relevant events:
//! - Authentication attempts (success/failure)
//! - Configuration changes (rules, config updates)
//! - Administrative actions
//!
//! Logs can be written to stdout, file, or both with optional rotation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Maximum number of audit entries to keep in memory
const MAX_MEMORY_ENTRIES: usize = 1000;

/// Maximum audit log file size before rotation (10 MB)
const MAX_LOG_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum number of rotated log files to keep
const MAX_ROTATED_FILES: usize = 5;

/// Types of audit events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// Authentication attempt
    AuthAttempt,
    /// Configuration change
    ConfigChange,
    /// Rule added
    RuleAdded,
    /// Rule deleted
    RuleDeleted,
    /// Rules imported
    RulesImported,
    /// Config reloaded from disk
    ConfigReload,
    /// Database scan initiated
    DatabaseScan,
    /// Schema query
    SchemaQuery,
    /// API access (general)
    ApiAccess,
}

/// Outcome of an audit event
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
}

/// Authentication method used
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    ApiKey,
    Jwt,
    None,
}

/// An audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique identifier for the entry
    pub id: String,
    /// Timestamp of the event
    pub timestamp: DateTime<Utc>,
    /// Type of audit event
    pub event_type: AuditEventType,
    /// Outcome of the event
    pub outcome: AuditOutcome,
    /// Client IP address (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    /// Authentication method used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<AuthMethod>,
    /// User identifier (from JWT sub claim or API key hash)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// API endpoint accessed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// HTTP method
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Additional details about the event
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// Error message if outcome is failure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AuditEntry {
    /// Create a new audit entry with the given event type
    pub fn new(event_type: AuditEventType, outcome: AuditOutcome) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            outcome,
            client_ip: None,
            auth_method: None,
            user_id: None,
            endpoint: None,
            method: None,
            details: None,
            error: None,
        }
    }

    /// Set the client IP
    #[allow(dead_code)]
    pub fn with_client_ip(mut self, ip: impl Into<String>) -> Self {
        self.client_ip = Some(ip.into());
        self
    }

    /// Set the authentication method
    pub fn with_auth_method(mut self, method: AuthMethod) -> Self {
        self.auth_method = Some(method);
        self
    }

    /// Set the user ID
    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Set the endpoint
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Set the HTTP method
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    /// Set additional details
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Set the error message
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }
}

/// Configuration for the audit logger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Enable audit logging
    #[serde(default = "default_audit_enabled")]
    pub enabled: bool,

    /// Log to stdout (in addition to file)
    #[serde(default)]
    pub log_to_stdout: bool,

    /// Path to audit log file (if None, only logs to memory/stdout)
    #[serde(default)]
    pub log_file: Option<String>,

    /// Enable log rotation
    #[serde(default = "default_rotation_enabled")]
    pub rotation_enabled: bool,

    /// Maximum log file size in bytes before rotation (default: 10MB)
    #[serde(default = "default_max_file_size")]
    pub max_file_size_bytes: u64,

    /// Maximum number of rotated files to keep (default: 5)
    #[serde(default = "default_max_rotated_files")]
    pub max_rotated_files: usize,

    /// Events to log (if empty, logs all events)
    #[serde(default)]
    pub events: Vec<AuditEventType>,
}

fn default_audit_enabled() -> bool {
    true
}

fn default_rotation_enabled() -> bool {
    true
}

fn default_max_file_size() -> u64 {
    MAX_LOG_FILE_SIZE
}

fn default_max_rotated_files() -> usize {
    MAX_ROTATED_FILES
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_to_stdout: false,
            log_file: None,
            rotation_enabled: true,
            max_file_size_bytes: MAX_LOG_FILE_SIZE,
            max_rotated_files: MAX_ROTATED_FILES,
            events: vec![],
        }
    }
}

/// The audit logger
#[derive(Clone)]
pub struct AuditLogger {
    config: Arc<RwLock<AuditConfig>>,
    entries: Arc<RwLock<VecDeque<AuditEntry>>>,
    log_file_path: Arc<RwLock<Option<PathBuf>>>,
}

impl AuditLogger {
    /// Create a new audit logger with the given configuration
    pub fn new(config: AuditConfig) -> Self {
        let log_file_path = config.log_file.as_ref().map(PathBuf::from);
        Self {
            config: Arc::new(RwLock::new(config)),
            entries: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_MEMORY_ENTRIES))),
            log_file_path: Arc::new(RwLock::new(log_file_path)),
        }
    }

    /// Create a disabled audit logger
    #[allow(dead_code)]
    pub fn disabled() -> Self {
        Self::new(AuditConfig {
            enabled: false,
            ..Default::default()
        })
    }

    /// Update the audit logger configuration
    #[allow(dead_code)]
    pub async fn update_config(&self, config: AuditConfig) {
        let log_file_path = config.log_file.as_ref().map(PathBuf::from);
        *self.config.write().await = config;
        *self.log_file_path.write().await = log_file_path;
    }

    /// Check if a specific event type should be logged
    async fn should_log(&self, event_type: &AuditEventType) -> bool {
        let config = self.config.read().await;
        if !config.enabled {
            return false;
        }
        // If events list is empty, log all events
        if config.events.is_empty() {
            return true;
        }
        config.events.contains(event_type)
    }

    /// Log an audit entry
    pub async fn log(&self, entry: AuditEntry) {
        if !self.should_log(&entry.event_type).await {
            return;
        }

        let config = self.config.read().await;

        // Log to tracing (which goes to stdout via tracing-subscriber)
        if config.log_to_stdout {
            info!(
                audit = true,
                event_type = ?entry.event_type,
                outcome = ?entry.outcome,
                client_ip = ?entry.client_ip,
                user_id = ?entry.user_id,
                endpoint = ?entry.endpoint,
                "{}",
                serde_json::to_string(&entry).unwrap_or_else(|_| format!("{:?}", entry))
            );
        }

        // Log to file
        if let Some(ref path) = *self.log_file_path.read().await
            && let Err(e) = self.write_to_file(path, &entry, &config).await
        {
            warn!("Failed to write audit log to file: {}", e);
        }

        drop(config);

        // Store in memory
        let mut entries = self.entries.write().await;
        if entries.len() >= MAX_MEMORY_ENTRIES {
            entries.pop_back();
        }
        entries.push_front(entry);
    }

    /// Write an audit entry to file with optional rotation
    async fn write_to_file(
        &self,
        path: &Path,
        entry: &AuditEntry,
        config: &AuditConfig,
    ) -> std::io::Result<()> {
        // Check if rotation is needed
        if config.rotation_enabled
            && let Ok(metadata) = std::fs::metadata(path)
            && metadata.len() >= config.max_file_size_bytes
        {
            self.rotate_logs(path, config.max_rotated_files)?;
        }

        // Open file in append mode
        let file = OpenOptions::new().create(true).append(true).open(path)?;

        let mut writer = BufWriter::new(file);
        let json = serde_json::to_string(&entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        writeln!(writer, "{}", json)?;
        writer.flush()?;

        Ok(())
    }

    /// Rotate log files
    fn rotate_logs(&self, path: &Path, max_files: usize) -> std::io::Result<()> {
        // Delete the oldest file if we're at max
        let oldest = format!("{}.{}", path.display(), max_files);
        if Path::new(&oldest).exists() {
            std::fs::remove_file(&oldest)?;
        }

        // Shift all files
        for i in (1..max_files).rev() {
            let current = format!("{}.{}", path.display(), i);
            let next = format!("{}.{}", path.display(), i + 1);
            if Path::new(&current).exists() {
                std::fs::rename(&current, &next)?;
            }
        }

        // Rename current file to .1
        let first_backup = format!("{}.1", path.display());
        if path.exists() {
            std::fs::rename(path, &first_backup)?;
        }

        info!(path = %path.display(), "Audit log rotated");
        Ok(())
    }

    /// Get recent audit entries
    pub async fn get_entries(&self, limit: Option<usize>) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;
        let limit = limit.unwrap_or(100).min(entries.len());
        entries.iter().take(limit).cloned().collect()
    }

    /// Get entries filtered by event type
    pub async fn get_entries_by_type(
        &self,
        event_type: AuditEventType,
        limit: Option<usize>,
    ) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;
        let limit = limit.unwrap_or(100);
        entries
            .iter()
            .filter(|e| e.event_type == event_type)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get entries filtered by outcome
    pub async fn get_entries_by_outcome(
        &self,
        outcome: AuditOutcome,
        limit: Option<usize>,
    ) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;
        let limit = limit.unwrap_or(100);
        entries
            .iter()
            .filter(|e| e.outcome == outcome)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Create an authentication success entry
    pub fn auth_success(method: AuthMethod, user_id: Option<String>) -> AuditEntry {
        let mut entry = AuditEntry::new(AuditEventType::AuthAttempt, AuditOutcome::Success)
            .with_auth_method(method);
        if let Some(uid) = user_id {
            entry = entry.with_user_id(uid);
        }
        entry
    }

    /// Create an authentication failure entry
    pub fn auth_failure(method: AuthMethod, error: impl Into<String>) -> AuditEntry {
        AuditEntry::new(AuditEventType::AuthAttempt, AuditOutcome::Failure)
            .with_auth_method(method)
            .with_error(error)
    }

    /// Create an authentication denied entry (no credentials provided)
    pub fn auth_denied() -> AuditEntry {
        AuditEntry::new(AuditEventType::AuthAttempt, AuditOutcome::Denied)
            .with_auth_method(AuthMethod::None)
            .with_error("No authentication credentials provided")
    }

    /// Create a config change entry
    pub fn config_change(details: serde_json::Value) -> AuditEntry {
        AuditEntry::new(AuditEventType::ConfigChange, AuditOutcome::Success).with_details(details)
    }

    /// Create a rule added entry
    pub fn rule_added(rule: serde_json::Value) -> AuditEntry {
        AuditEntry::new(AuditEventType::RuleAdded, AuditOutcome::Success).with_details(rule)
    }

    /// Create a rule deleted entry
    pub fn rule_deleted(details: serde_json::Value) -> AuditEntry {
        AuditEntry::new(AuditEventType::RuleDeleted, AuditOutcome::Success).with_details(details)
    }

    /// Create a rules imported entry
    pub fn rules_imported(count: usize) -> AuditEntry {
        AuditEntry::new(AuditEventType::RulesImported, AuditOutcome::Success)
            .with_details(serde_json::json!({ "rules_count": count }))
    }

    /// Create a config reload entry
    pub fn config_reload(rules_count: usize) -> AuditEntry {
        AuditEntry::new(AuditEventType::ConfigReload, AuditOutcome::Success)
            .with_details(serde_json::json!({ "rules_count": rules_count }))
    }

    /// Create a database scan entry
    pub fn database_scan(database: &str, findings_count: usize) -> AuditEntry {
        AuditEntry::new(AuditEventType::DatabaseScan, AuditOutcome::Success).with_details(
            serde_json::json!({
                "database": database,
                "findings_count": findings_count
            }),
        )
    }

    /// Create a schema query entry
    pub fn schema_query(database: &str, tables_count: usize) -> AuditEntry {
        AuditEntry::new(AuditEventType::SchemaQuery, AuditOutcome::Success).with_details(
            serde_json::json!({
                "database": database,
                "tables_count": tables_count
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_entry_creation() {
        let entry = AuditEntry::new(AuditEventType::AuthAttempt, AuditOutcome::Success)
            .with_client_ip("127.0.0.1")
            .with_auth_method(AuthMethod::ApiKey)
            .with_endpoint("/rules");

        assert_eq!(entry.event_type, AuditEventType::AuthAttempt);
        assert_eq!(entry.outcome, AuditOutcome::Success);
        assert_eq!(entry.client_ip, Some("127.0.0.1".to_string()));
        assert_eq!(entry.auth_method, Some(AuthMethod::ApiKey));
        assert_eq!(entry.endpoint, Some("/rules".to_string()));
    }

    #[test]
    fn test_audit_entry_serialization() {
        let entry = AuditEntry::new(AuditEventType::ConfigChange, AuditOutcome::Success)
            .with_details(serde_json::json!({"key": "value"}));

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("config_change"));
        assert!(json.contains("success"));
        assert!(json.contains("\"key\":\"value\""));
    }

    #[tokio::test]
    async fn test_audit_logger_memory_storage() {
        let logger = AuditLogger::new(AuditConfig::default());

        logger
            .log(AuditEntry::new(
                AuditEventType::AuthAttempt,
                AuditOutcome::Success,
            ))
            .await;
        logger
            .log(AuditEntry::new(
                AuditEventType::ConfigChange,
                AuditOutcome::Success,
            ))
            .await;

        let entries = logger.get_entries(Some(10)).await;
        assert_eq!(entries.len(), 2);
        // Most recent first
        assert_eq!(entries[0].event_type, AuditEventType::ConfigChange);
        assert_eq!(entries[1].event_type, AuditEventType::AuthAttempt);
    }

    #[tokio::test]
    async fn test_audit_logger_disabled() {
        let logger = AuditLogger::disabled();

        logger
            .log(AuditEntry::new(
                AuditEventType::AuthAttempt,
                AuditOutcome::Success,
            ))
            .await;

        let entries = logger.get_entries(Some(10)).await;
        assert_eq!(entries.len(), 0);
    }

    #[tokio::test]
    async fn test_audit_logger_event_filtering() {
        let config = AuditConfig {
            enabled: true,
            events: vec![AuditEventType::AuthAttempt],
            ..Default::default()
        };
        let logger = AuditLogger::new(config);

        logger
            .log(AuditEntry::new(
                AuditEventType::AuthAttempt,
                AuditOutcome::Success,
            ))
            .await;
        logger
            .log(AuditEntry::new(
                AuditEventType::ConfigChange,
                AuditOutcome::Success,
            ))
            .await;

        let entries = logger.get_entries(Some(10)).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, AuditEventType::AuthAttempt);
    }

    #[tokio::test]
    async fn test_get_entries_by_type() {
        let logger = AuditLogger::new(AuditConfig::default());

        logger
            .log(AuditEntry::new(
                AuditEventType::AuthAttempt,
                AuditOutcome::Success,
            ))
            .await;
        logger
            .log(AuditEntry::new(
                AuditEventType::AuthAttempt,
                AuditOutcome::Failure,
            ))
            .await;
        logger
            .log(AuditEntry::new(
                AuditEventType::ConfigChange,
                AuditOutcome::Success,
            ))
            .await;

        let auth_entries = logger
            .get_entries_by_type(AuditEventType::AuthAttempt, Some(10))
            .await;
        assert_eq!(auth_entries.len(), 2);
    }

    #[tokio::test]
    async fn test_get_entries_by_outcome() {
        let logger = AuditLogger::new(AuditConfig::default());

        logger
            .log(AuditEntry::new(
                AuditEventType::AuthAttempt,
                AuditOutcome::Success,
            ))
            .await;
        logger
            .log(AuditEntry::new(
                AuditEventType::AuthAttempt,
                AuditOutcome::Failure,
            ))
            .await;
        logger
            .log(AuditEntry::new(
                AuditEventType::ConfigChange,
                AuditOutcome::Failure,
            ))
            .await;

        let failures = logger
            .get_entries_by_outcome(AuditOutcome::Failure, Some(10))
            .await;
        assert_eq!(failures.len(), 2);
    }

    #[test]
    fn test_helper_methods() {
        let success = AuditLogger::auth_success(AuthMethod::Jwt, Some("user123".to_string()));
        assert_eq!(success.outcome, AuditOutcome::Success);
        assert_eq!(success.auth_method, Some(AuthMethod::Jwt));
        assert_eq!(success.user_id, Some("user123".to_string()));

        let failure = AuditLogger::auth_failure(AuthMethod::ApiKey, "Invalid key");
        assert_eq!(failure.outcome, AuditOutcome::Failure);
        assert_eq!(failure.error, Some("Invalid key".to_string()));

        let denied = AuditLogger::auth_denied();
        assert_eq!(denied.outcome, AuditOutcome::Denied);

        let config_change = AuditLogger::config_change(serde_json::json!({"test": true}));
        assert_eq!(config_change.event_type, AuditEventType::ConfigChange);

        let rule_added = AuditLogger::rule_added(serde_json::json!({"column": "email"}));
        assert_eq!(rule_added.event_type, AuditEventType::RuleAdded);

        let rule_deleted = AuditLogger::rule_deleted(serde_json::json!({"index": 0}));
        assert_eq!(rule_deleted.event_type, AuditEventType::RuleDeleted);

        let rules_imported = AuditLogger::rules_imported(5);
        assert_eq!(rules_imported.event_type, AuditEventType::RulesImported);

        let config_reload = AuditLogger::config_reload(10);
        assert_eq!(config_reload.event_type, AuditEventType::ConfigReload);

        let db_scan = AuditLogger::database_scan("testdb", 3);
        assert_eq!(db_scan.event_type, AuditEventType::DatabaseScan);

        let schema_query = AuditLogger::schema_query("testdb", 5);
        assert_eq!(schema_query.event_type, AuditEventType::SchemaQuery);
    }

    #[tokio::test]
    async fn test_memory_limit() {
        let logger = AuditLogger::new(AuditConfig::default());

        // Add more than MAX_MEMORY_ENTRIES
        for i in 0..MAX_MEMORY_ENTRIES + 100 {
            let mut entry = AuditEntry::new(AuditEventType::ApiAccess, AuditOutcome::Success);
            entry.id = format!("entry-{}", i);
            logger.log(entry).await;
        }

        let entries = logger.get_entries(None).await;
        assert!(entries.len() <= MAX_MEMORY_ENTRIES);
    }
}
