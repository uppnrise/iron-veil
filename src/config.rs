use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AppConfig {
    #[serde(default = "default_masking_enabled")]
    pub masking_enabled: bool,
    pub rules: Vec<MaskingRule>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub upstream_tls: bool,
    #[serde(default)]
    pub telemetry: Option<TelemetryConfig>,
    #[serde(default)]
    pub api: Option<ApiConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ApiConfig {
    /// API key for authenticating management API requests.
    /// If set, all sensitive endpoints require `X-API-Key` header.
    #[serde(default)]
    pub api_key: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_otlp_endpoint")]
    pub otlp_endpoint: String,
    #[serde(default = "default_service_name")]
    pub service_name: String,
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
            tls: None,
            upstream_tls: false,
            telemetry: None,
            api: None,
        }
    }
}

impl AppConfig {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: AppConfig = serde_yaml::from_str(&content)?;
        Ok(config)
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
        let config: AppConfig = serde_yaml::from_str(yaml).unwrap();

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
        let config: AppConfig = serde_yaml::from_str(yaml).unwrap();

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
        let config: AppConfig = serde_yaml::from_str(yaml).unwrap();

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
        let result: Result<AppConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_required_fields_fails() {
        let yaml = r#"
masking_enabled: true
"#;
        let result: Result<AppConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err()); // Should fail because 'rules' is missing
    }
}
