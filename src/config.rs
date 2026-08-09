use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;

/// Masking strategies understood by the interceptor. Anything else is rejected
/// at config load / rule ingest so a typo cannot silently degrade to "MASKED".
pub const KNOWN_STRATEGIES: &[&str] = &[
    "email",
    "phone",
    "address",
    "name",
    "text",
    "credit_card",
    "ssn",
    "ip",
    "dob",
    "passport",
    "hash",
    "json",
];

/// Heuristic detector names accepted in `heuristics.types`.
pub const KNOWN_HEURISTIC_TYPES: &[&str] = &[
    "email",
    "phone",
    "ssn",
    "credit_card",
    "ip",
    "dob",
    "passport",
];

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    #[serde(default = "default_masking_enabled")]
    pub masking_enabled: bool,
    pub rules: Vec<MaskingRule>,
    /// Secret used to key the deterministic masking functions (fake-data seeds
    /// and the `hash` strategy). When unset, a random per-process key is used,
    /// which keeps masking deterministic within a run but not across restarts.
    /// Can also be supplied via the IRONVEIL_MASKING_SECRET env var, which
    /// takes precedence over this field.
    #[serde(default)]
    pub masking_secret: Option<String>,
    /// Heuristic (rule-less) PII detection settings.
    #[serde(default)]
    pub heuristics: Option<HeuristicsConfig>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub upstream_tls: bool,
    #[serde(default)]
    pub telemetry: Option<TelemetryConfig>,
    #[serde(default)]
    pub api: Option<ApiConfig>,
    #[serde(default)]
    pub limits: Option<LimitsConfig>,
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    #[serde(default)]
    pub audit: Option<AuditConfig>,
}

/// Controls the heuristic scanner that masks values in columns with no
/// explicit rule. Only the detectors listed in `types` run; the ambiguous
/// detectors (`credit_card`, `ip`, `dob`, `passport`) are opt-in because they
/// rewrite legitimate data (order numbers, config addresses, every date
/// column) when enabled on a schema that stores such values.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct HeuristicsConfig {
    #[serde(default = "default_heuristics_enabled")]
    pub enabled: bool,
    #[serde(default = "default_heuristic_types")]
    pub types: Vec<String>,
}

impl Default for HeuristicsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            types: default_heuristic_types(),
        }
    }
}

fn default_heuristics_enabled() -> bool {
    true
}

fn default_heuristic_types() -> Vec<String> {
    vec!["email".to_string(), "phone".to_string(), "ssn".to_string()]
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum number of concurrent connections (default: unlimited)
    #[serde(default)]
    pub max_connections: Option<usize>,

    /// Rate limit: max new connections per second (default: unlimited)
    #[serde(default)]
    pub connections_per_second: Option<u32>,

    /// Timeout for establishing upstream connection in seconds (default: 30)
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,

    /// Idle timeout in seconds - close connection after no activity (default: 300)
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,

    /// Maximum concurrent upstream sessions (default: unlimited)
    #[serde(default)]
    pub upstream_pool_size: Option<usize>,

    /// Max time to wait for an upstream slot before rejecting (default: 5)
    #[serde(default = "default_upstream_pool_wait_timeout")]
    pub upstream_pool_wait_timeout_secs: u64,
}

fn default_connect_timeout() -> u64 {
    30
}

fn default_idle_timeout() -> u64 {
    300 // 5 minutes
}

fn default_upstream_pool_wait_timeout() -> u64 {
    5
}

/// Health check configuration for upstream database
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    /// Enable upstream health checks (default: true)
    #[serde(default = "default_health_enabled")]
    pub enabled: bool,

    /// Interval between health checks in seconds (default: 10)
    #[serde(default = "default_health_interval")]
    pub interval_secs: u64,

    /// Timeout for health check connection in seconds (default: 5)
    #[serde(default = "default_health_timeout")]
    pub timeout_secs: u64,

    /// Number of consecutive failures before marking unhealthy (default: 3)
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,

    /// Number of consecutive successes before marking healthy (default: 1)
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 10,
            timeout_secs: 5,
            unhealthy_threshold: 3,
            healthy_threshold: 1,
        }
    }
}

fn default_health_enabled() -> bool {
    true
}

fn default_health_interval() -> u64 {
    10
}

fn default_health_timeout() -> u64 {
    5
}

fn default_unhealthy_threshold() -> u32 {
    3
}

fn default_healthy_threshold() -> u32 {
    1
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    /// API key for authenticating management API requests.
    /// If set, all sensitive endpoints require `X-API-Key` header.
    #[serde(default)]
    pub api_key: Option<String>,

    /// JWT secret for token-based authentication.
    /// If set, endpoints also accept `Authorization: Bearer <token>` header.
    #[serde(default)]
    pub jwt_secret: Option<String>,

    /// Address the management API binds to (default: 127.0.0.1). Binding a
    /// non-loopback address requires api_key or jwt_secret to be configured.
    #[serde(default)]
    pub bind: Option<String>,

    /// Browser origins allowed to call the management API (CORS). Defaults to
    /// the local dashboard dev origins when unset.
    #[serde(default)]
    pub cors_origins: Option<Vec<String>>,
}

/// Audit event types to log
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    AuthAttempt,
    ConfigChange,
    RuleAdded,
    RuleDeleted,
    RulesImported,
    ConfigReload,
    DatabaseScan,
    SchemaQuery,
}

/// Configuration for audit logging
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Enable audit logging (default: true)
    #[serde(default = "default_audit_enabled")]
    pub enabled: bool,

    /// Log to stdout in addition to file (default: false)
    #[serde(default)]
    pub log_to_stdout: bool,

    /// Path to audit log file (optional)
    #[serde(default)]
    pub log_file: Option<String>,

    /// Enable log rotation (default: true)
    #[serde(default = "default_audit_rotation")]
    pub rotation_enabled: bool,

    /// Maximum log file size in bytes before rotation (default: 10MB)
    #[serde(default = "default_audit_max_size")]
    pub max_file_size_bytes: u64,

    /// Maximum number of rotated files to keep (default: 5)
    #[serde(default = "default_audit_max_files")]
    pub max_rotated_files: usize,

    /// Events to log (if empty, logs all events)
    #[serde(default)]
    pub events: Vec<AuditEventType>,
}

fn default_audit_enabled() -> bool {
    true
}

fn default_audit_rotation() -> bool {
    true
}

fn default_audit_max_size() -> u64 {
    10 * 1024 * 1024 // 10 MB
}

fn default_audit_max_files() -> usize {
    5
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_to_stdout: false,
            log_file: None,
            rotation_enabled: true,
            max_file_size_bytes: default_audit_max_size(),
            max_rotated_files: default_audit_max_files(),
            events: vec![],
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_otlp_endpoint")]
    pub otlp_endpoint: String,
    #[serde(default = "default_service_name")]
    pub service_name: String,
    /// Trace sampling ratio in [0.0, 1.0] (default: 0.05).
    #[serde(default)]
    pub sample_ratio: Option<f64>,
}

fn default_otlp_endpoint() -> String {
    "http://localhost:4317".to_string()
}

fn default_service_name() -> String {
    "iron-veil".to_string()
}

fn default_masking_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct MaskingRule {
    pub table: Option<String>,
    pub column: String,
    pub strategy: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            masking_enabled: true,
            rules: vec![],
            masking_secret: None,
            heuristics: None,
            tls: None,
            upstream_tls: false,
            telemetry: None,
            api: None,
            limits: None,
            health_check: None,
            audit: None,
        }
    }
}

impl AppConfig {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let mut config: AppConfig = serde_yaml_ng::from_str(&content)?;
        if let Ok(secret) = std::env::var("IRONVEIL_MASKING_SECRET")
            && !secret.is_empty()
        {
            config.masking_secret = Some(secret);
        }
        config.validate()?;
        Ok(config)
    }

    /// Reject configs that would silently misbehave at runtime.
    pub fn validate(&self) -> Result<()> {
        for rule in &self.rules {
            if !KNOWN_STRATEGIES.contains(&rule.strategy.as_str()) {
                anyhow::bail!(
                    "unknown masking strategy '{}' for column '{}' (known: {})",
                    rule.strategy,
                    rule.column,
                    KNOWN_STRATEGIES.join(", ")
                );
            }
        }
        if let Some(heuristics) = &self.heuristics {
            for t in &heuristics.types {
                if !KNOWN_HEURISTIC_TYPES.contains(&t.as_str()) {
                    anyhow::bail!(
                        "unknown heuristic type '{}' (known: {})",
                        t,
                        KNOWN_HEURISTIC_TYPES.join(", ")
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_load_valid_yaml() {
        let yaml = r#"
masking_enabled: true
upstream_tls: false
rules:
  - table: "users"
    column: "email"
    strategy: "email"
  - column: "phone"
    strategy: "phone"
"#;
        let config: AppConfig = serde_yaml_ng::from_str(yaml).unwrap();

        assert!(config.masking_enabled);
        assert!(!config.upstream_tls);
        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.rules[0].table, Some("users".to_string()));
        assert_eq!(config.rules[0].column, "email");
        assert_eq!(config.rules[0].strategy, "email");
        assert_eq!(config.rules[1].table, None);
    }

    #[test]
    fn test_config_defaults() {
        let yaml = r#"
rules: []
"#;
        let config: AppConfig = serde_yaml_ng::from_str(yaml).unwrap();

        assert!(config.masking_enabled); // Should default to true
        assert!(!config.upstream_tls); // Should default to false
        assert!(config.tls.is_none()); // Should default to None
    }

    #[test]
    fn test_config_with_tls() {
        let yaml = r#"
masking_enabled: true
upstream_tls: true
tls:
  enabled: true
  cert_path: "certs/server.crt"
  key_path: "certs/server.key"
rules: []
"#;
        let config: AppConfig = serde_yaml_ng::from_str(yaml).unwrap();

        assert!(config.upstream_tls);
        assert!(config.tls.is_some());

        let tls = config.tls.unwrap();
        assert!(tls.enabled);
        assert_eq!(tls.cert_path, "certs/server.crt");
        assert_eq!(tls.key_path, "certs/server.key");
    }

    #[test]
    fn test_invalid_yaml_fails() {
        let yaml = r#"
invalid yaml content {{
"#;
        let result: Result<AppConfig, _> = serde_yaml_ng::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_required_fields_fails() {
        let yaml = r#"
masking_enabled: true
"#;
        let result: Result<AppConfig, _> = serde_yaml_ng::from_str(yaml);
        assert!(result.is_err()); // Should fail because 'rules' is missing
    }

    #[test]
    fn test_limits_defaults_include_upstream_pool_settings() {
        let yaml = r#"
rules: []
limits: {}
"#;
        let config: AppConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let limits = config.limits.expect("limits should be present");

        assert_eq!(limits.connect_timeout_secs, 30);
        assert_eq!(limits.idle_timeout_secs, 300);
        assert_eq!(limits.upstream_pool_wait_timeout_secs, 5);
        assert_eq!(limits.upstream_pool_size, None);
    }

    #[test]
    fn test_limits_parses_upstream_pool_settings() {
        let yaml = r#"
rules: []
limits:
  upstream_pool_size: 50
  upstream_pool_wait_timeout_secs: 12
"#;
        let config: AppConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let limits = config.limits.expect("limits should be present");

        assert_eq!(limits.upstream_pool_size, Some(50));
        assert_eq!(limits.upstream_pool_wait_timeout_secs, 12);
    }
}
