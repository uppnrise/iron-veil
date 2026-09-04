use crate::metrics;
use crate::protocol::mysql::{ColumnDefinition, ResultRow};
use crate::protocol::postgres::{DataRow, RowDescription};
use crate::scanner::{PiiScanner, PiiType};
use anyhow::Result;
use fake::Fake;
use fake::faker::address::en::CityName;
use fake::faker::creditcard::en::CreditCardNumber;
use fake::faker::internet::en::SafeEmail;
use fake::faker::phone_number::en::PhoneNumber;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

fn generate_fake_data(strategy: &str, seed: u64) -> String {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    match strategy {
        "email" => SafeEmail().fake_with_rng(&mut rng),
        "phone" => PhoneNumber().fake_with_rng(&mut rng),
        "address" => CityName().fake_with_rng(&mut rng),
        "credit_card" => CreditCardNumber().fake_with_rng(&mut rng),
        "ssn" => format!("XXX-XX-{:04}", (seed % 10000)),
        "ip" => "0.0.0.0".to_string(),
        "dob" => "1900-01-01".to_string(),
        "passport" => "XXXXXXXX".to_string(),
        _ => "MASKED".to_string(),
    }
}

fn hash_value(value: &[u8]) -> String {
    use std::fmt::Write;
    let digest = Sha256::digest(value);
    let hex = digest.iter().fold(String::new(), |mut acc, byte| {
        let _ = write!(acc, "{byte:02x}");
        acc
    });
    format!("sha256:{hex}")
}

/// Convert PiiType to masking strategy string
fn pii_type_to_strategy(pii_type: PiiType) -> &'static str {
    match pii_type {
        PiiType::Email => "email",
        PiiType::CreditCard => "credit_card",
        PiiType::Ssn => "ssn",
        PiiType::Phone => "phone",
        PiiType::IpAddress => "ip",
        PiiType::DateOfBirth => "dob",
        PiiType::Passport => "passport",
    }
}

fn normalize_identifier(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}

fn mask_json_recursively(val: &mut serde_json::Value, scanner: &PiiScanner) {
    match val {
        serde_json::Value::String(s) => {
            if let Some(pii_type) = scanner.scan(s) {
                let strategy = pii_type_to_strategy(pii_type);

                // Deterministic seed based on the string value
                let mut hasher = DefaultHasher::new();
                s.hash(&mut hasher);
                let seed = hasher.finish();

                *s = generate_fake_data(strategy, seed);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                mask_json_recursively(v, scanner);
            }
        }
        serde_json::Value::Object(map) => {
            for (_, v) in map {
                mask_json_recursively(v, scanner);
            }
        }
        _ => {}
    }
}

fn mask_postgres_array(raw: &str, scanner: &PiiScanner) -> Option<String> {
    if !raw.starts_with('{') || !raw.ends_with('}') {
        return None;
    }

    let content = &raw[1..raw.len() - 1];
    // Simple parser: split by comma, respecting quotes
    let mut elements = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;

    for c in content.chars() {
        if escaped {
            current.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
            current.push(c); // Keep escape char for now
        } else if c == '"' {
            in_quotes = !in_quotes;
            current.push(c);
        } else if c == ',' && !in_quotes {
            elements.push(current.clone());
            current.clear();
        } else {
            current.push(c);
        }
    }
    elements.push(current);

    let mut changed = false;
    let mut new_elements = Vec::new();

    for elem in elements {
        let trimmed = elem.trim();
        // Check if quoted
        let (val, _is_quoted) =
            if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
                (&trimmed[1..trimmed.len() - 1], true)
            } else {
                (trimmed, false)
            };

        // Unescape if needed (simplified)
        let clean_val = val.replace("\\\"", "\"").replace("\\\\", "\\");

        if let Some(pii_type) = scanner.scan(&clean_val) {
            let strategy = pii_type_to_strategy(pii_type);

            let mut hasher = DefaultHasher::new();
            clean_val.hash(&mut hasher);
            let seed = hasher.finish();

            let fake = generate_fake_data(strategy, seed);
            // Always quote masked values to be safe
            new_elements.push(format!("\"{}\"", fake));
            changed = true;
        } else {
            new_elements.push(elem);
        }
    }

    if changed {
        Some(format!("{{{}}}", new_elements.join(",")))
    } else {
        None
    }
}

use crate::state::{AppState, LogEntry};
use chrono::Utc;
use serde_json::json;
use tracing::instrument;

pub trait PacketInterceptor {
    fn on_row_description(
        &mut self,
        msg: &RowDescription,
    ) -> impl std::future::Future<Output = ()> + Send;
    fn on_data_row(
        &mut self,
        msg: DataRow,
    ) -> impl std::future::Future<Output = Result<DataRow>> + Send;
}

pub struct Anonymizer {
    state: AppState,
    scanner: PiiScanner,
    target_cols: Vec<(usize, String)>,
    table_names_by_oid: HashMap<u32, HashSet<String>>,
    connection_id: usize,
}

impl Anonymizer {
    pub fn new(state: AppState, connection_id: usize) -> Self {
        Self {
            state,
            scanner: PiiScanner::new(),
            target_cols: Vec::new(),
            table_names_by_oid: HashMap::new(),
            connection_id,
        }
    }

    pub fn register_postgres_table_oid(&mut self, oid: u32, schema: &str, table: &str) {
        if oid == 0 {
            return;
        }

        let aliases = self.table_names_by_oid.entry(oid).or_default();
        aliases.insert(normalize_identifier(table));
        aliases.insert(normalize_identifier(&format!("{}.{}", schema, table)));
    }

    fn postgres_rule_matches_table(&self, table_oid: u32, rule_table: &str) -> bool {
        if table_oid == 0 {
            return false;
        }

        let normalized_rule_table = normalize_identifier(rule_table);
        self.table_names_by_oid
            .get(&table_oid)
            .is_some_and(|aliases| aliases.contains(&normalized_rule_table))
    }
}

impl PacketInterceptor for Anonymizer {
    #[instrument(skip(self, msg), fields(num_fields = msg.fields.len()))]
    async fn on_row_description(&mut self, msg: &RowDescription) {
        self.target_cols.clear();

        let config = self.state.config.read().await;
        for (i, field) in msg.fields.iter().enumerate() {
            for rule in &config.rules {
                // Check if rule applies to this column.
                let table_match = match rule.table.as_deref() {
                    None => true,
                    Some(rule_table) => {
                        self.postgres_rule_matches_table(field.table_oid, rule_table)
                    }
                };

                // Convert Bytes field name to str for comparison
                let field_name = std::str::from_utf8(&field.name).unwrap_or("");
                if table_match
                    && normalize_identifier(&rule.column) == normalize_identifier(field_name)
                {
                    self.target_cols.push((i, rule.strategy.clone()));
                    break; // Apply first matching rule
                }
            }
        }
    }

    #[instrument(skip(self, msg), fields(num_values = msg.values.len(), connection_id = self.connection_id))]
    async fn on_data_row(&mut self, mut msg: DataRow) -> Result<DataRow> {
        // Check if masking is globally enabled
        {
            let config = self.state.config.read().await;
            if !config.masking_enabled {
                return Ok(msg);
            }
        }

        let mut changes_log = Vec::new();
        let mut changed_any = false;

        for (i, val_opt) in msg.values.iter_mut().enumerate() {
            if let Some(val) = val_opt {
                let original_val_preview = if val.len() > 50 {
                    format!("{}...", String::from_utf8_lossy(&val[..50]))
                } else {
                    String::from_utf8_lossy(val).to_string()
                };

                // 1. Check for explicit rule
                let explicit_strategy = self
                    .target_cols
                    .iter()
                    .find(|(col_idx, _)| *col_idx == i)
                    .map(|(_, strategy)| strategy.as_str());

                // Handle explicit JSON strategy
                if let Some("json") = explicit_strategy {
                    match std::str::from_utf8(val) {
                        Ok(s) => match serde_json::from_str::<serde_json::Value>(s) {
                            Ok(mut json_val) => {
                                mask_json_recursively(&mut json_val, &self.scanner);
                                match serde_json::to_string(&json_val) {
                                    Ok(new_json) => {
                                        if new_json.as_bytes() != &val[..] {
                                            val.clear();
                                            val.extend_from_slice(new_json.as_bytes());
                                            changed_any = true;
                                            // Record masking stats for JSON
                                            self.state.record_masking("json").await;
                                            changes_log.push(json!({
                                                "column_idx": i,
                                                "strategy": "json",
                                                "original": original_val_preview,
                                                "masked": "(JSON Masked)"
                                            }));
                                        }
                                    }
                                    Err(_) => metrics::record_masking_error(),
                                }
                            }
                            Err(_) => metrics::record_masking_error(),
                        },
                        Err(_) => metrics::record_masking_error(),
                    }
                    continue;
                }

                let strategy = if let Some(s) = explicit_strategy {
                    Some(s)
                } else {
                    // 2. Heuristic scan
                    if let Ok(s) = std::str::from_utf8(val) {
                        // Try JSON heuristic first if it looks like JSON
                        let trimmed = s.trim();
                        if (trimmed.starts_with('{') && trimmed.ends_with('}'))
                            || (trimmed.starts_with('[') && trimmed.ends_with(']'))
                        {
                            // Attempt JSON parsing
                            match serde_json::from_str::<serde_json::Value>(s) {
                                Ok(mut json_val) => {
                                    mask_json_recursively(&mut json_val, &self.scanner);
                                    if let Ok(new_json) = serde_json::to_string(&json_val) {
                                        if new_json.as_bytes() != &val[..] {
                                            val.clear();
                                            val.extend_from_slice(new_json.as_bytes());
                                            changed_any = true;
                                            // Record masking stats for heuristic JSON
                                            self.state.record_masking("json").await;
                                            changes_log.push(json!({
                                                "column_idx": i,
                                                "strategy": "json (heuristic)",
                                                "original": original_val_preview,
                                                "masked": "(JSON Masked)"
                                            }));
                                        }
                                        continue;
                                    }
                                }
                                Err(_) => {
                                    // Not valid JSON, maybe Postgres Array?
                                    if trimmed.starts_with('{')
                                        && trimmed.ends_with('}')
                                        && let Some(masked_array) =
                                            mask_postgres_array(s, &self.scanner)
                                    {
                                        val.clear();
                                        val.extend_from_slice(masked_array.as_bytes());
                                        changed_any = true;
                                        // Record masking stats for array (count as other)
                                        self.state.record_masking("other").await;
                                        changes_log.push(json!({
                                            "column_idx": i,
                                            "strategy": "array (heuristic)",
                                            "original": original_val_preview,
                                            "masked": masked_array
                                        }));
                                        continue;
                                    }
                                }
                            }
                        }

                        self.scanner.scan(s).map(pii_type_to_strategy)
                    } else {
                        None
                    }
                };

                if let Some(strat) = strategy {
                    let fake_val = if strat == "hash" {
                        hash_value(&val[..])
                    } else {
                        // Apply deterministic fake-data masking
                        let mut hasher = DefaultHasher::new();
                        val.hash(&mut hasher);
                        let seed = hasher.finish();
                        generate_fake_data(strat, seed)
                    };

                    val.clear();
                    val.extend_from_slice(fake_val.as_bytes());
                    changed_any = true;

                    // Record masking stats
                    self.state.record_masking(strat).await;

                    changes_log.push(json!({
                        "column_idx": i,
                        "strategy": strat,
                        "original": original_val_preview,
                        "masked": fake_val
                    }));
                }
            }
        }

        if changed_any {
            // Log the change
            let id = format!("{:x}", rand::random::<u128>());
            self.state
                .add_log(LogEntry {
                    id,
                    timestamp: Utc::now(),
                    connection_id: self.connection_id,
                    event_type: "DataMasked".to_string(),
                    content: format!("Masked {} fields in DataRow", changes_log.len()),
                    details: Some(json!(changes_log)),
                })
                .await;
        }

        Ok(msg)
    }
}

// ============================================================================
// MySQL Interceptor
// ============================================================================

/// Trait for intercepting MySQL packets
pub trait MySqlPacketInterceptor {
    fn on_column_definition(
        &mut self,
        col: &ColumnDefinition,
    ) -> impl std::future::Future<Output = ()> + Send;
    fn on_result_row(
        &mut self,
        row: ResultRow,
    ) -> impl std::future::Future<Output = Result<ResultRow>> + Send;
}

/// MySQL-specific anonymizer that reuses the core masking logic
pub struct MySqlAnonymizer {
    state: AppState,
    scanner: PiiScanner,
    target_cols: Vec<(usize, String)>,
    column_names: Vec<String>,
    connection_id: usize,
}

impl MySqlAnonymizer {
    pub fn new(state: AppState, connection_id: usize) -> Self {
        Self {
            state,
            scanner: PiiScanner::new(),
            target_cols: Vec::new(),
            column_names: Vec::new(),
            connection_id,
        }
    }

    /// Reset column tracking for a new result set
    pub fn reset_columns(&mut self) {
        self.target_cols.clear();
        self.column_names.clear();
    }
}

impl MySqlPacketInterceptor for MySqlAnonymizer {
    #[instrument(skip(self, col), fields(column_name = %String::from_utf8_lossy(&col.name)))]
    async fn on_column_definition(&mut self, col: &ColumnDefinition) {
        let col_name = String::from_utf8_lossy(&col.name).to_string();
        let col_idx = self.column_names.len();
        self.column_names.push(col_name.clone());

        let config = self.state.config.read().await;
        for rule in &config.rules {
            // Table match (MySQL provides table name in column def)
            let table_name = String::from_utf8_lossy(&col.table);
            let table_match = rule.table.as_ref().is_none_or(|t| t == &*table_name);

            if table_match && rule.column == col_name {
                self.target_cols.push((col_idx, rule.strategy.clone()));
                tracing::debug!(column = %col_name, strategy = %rule.strategy, "MySQL column matched rule");
                break;
            }
        }
    }

    #[instrument(skip(self, row), fields(num_values = row.values.len(), connection_id = self.connection_id))]
    async fn on_result_row(&mut self, mut row: ResultRow) -> Result<ResultRow> {
        // Check if masking is globally enabled
        {
            let config = self.state.config.read().await;
            if !config.masking_enabled {
                return Ok(row);
            }
        }

        let mut changes_log = Vec::new();
        let mut changed_any = false;

        for (i, val_opt) in row.values.iter_mut().enumerate() {
            if let Some(val) = val_opt {
                let original_val_preview = if val.len() > 50 {
                    format!("{}...", String::from_utf8_lossy(&val[..50]))
                } else {
                    String::from_utf8_lossy(val).to_string()
                };

                // Check for explicit rule
                let explicit_strategy = self
                    .target_cols
                    .iter()
                    .find(|(col_idx, _)| *col_idx == i)
                    .map(|(_, strategy)| strategy.as_str());

                // Handle explicit JSON strategy
                if let Some("json") = explicit_strategy {
                    match std::str::from_utf8(val) {
                        Ok(s) => match serde_json::from_str::<serde_json::Value>(s) {
                            Ok(mut json_val) => {
                                mask_json_recursively(&mut json_val, &self.scanner);
                                match serde_json::to_string(&json_val) {
                                    Ok(new_json) => {
                                        if new_json.as_bytes() != &val[..] {
                                            val.clear();
                                            val.extend_from_slice(new_json.as_bytes());
                                            changed_any = true;
                                            // Record masking stats for JSON
                                            self.state.record_masking("json").await;
                                            changes_log.push(json!({
                                                "column_idx": i,
                                                "column_name": self.column_names.get(i).unwrap_or(&"?".to_string()),
                                                "strategy": "json",
                                                "original": original_val_preview,
                                                "masked": "(JSON Masked)"
                                            }));
                                        }
                                    }
                                    Err(_) => metrics::record_masking_error(),
                                }
                            }
                            Err(_) => metrics::record_masking_error(),
                        },
                        Err(_) => metrics::record_masking_error(),
                    }
                    continue;
                }

                let strategy = if let Some(s) = explicit_strategy {
                    Some(s)
                } else {
                    // Heuristic scan
                    if let Ok(s) = std::str::from_utf8(val) {
                        self.scanner.scan(s).map(pii_type_to_strategy)
                    } else {
                        None
                    }
                };

                if let Some(strat) = strategy {
                    let fake_val = if strat == "hash" {
                        hash_value(&val[..])
                    } else {
                        let mut hasher = DefaultHasher::new();
                        val.hash(&mut hasher);
                        let seed = hasher.finish();
                        generate_fake_data(strat, seed)
                    };

                    val.clear();
                    val.extend_from_slice(fake_val.as_bytes());
                    changed_any = true;

                    // Record masking stats
                    self.state.record_masking(strat).await;

                    changes_log.push(json!({
                        "column_idx": i,
                        "column_name": self.column_names.get(i).unwrap_or(&"?".to_string()),
                        "strategy": strat,
                        "original": original_val_preview,
                        "masked": fake_val
                    }));
                }
            }
        }

        if changed_any {
            let id = format!("{:x}", rand::random::<u128>());
            self.state
                .add_log(LogEntry {
                    id,
                    timestamp: Utc::now(),
                    connection_id: self.connection_id,
                    event_type: "MySqlDataMasked".to_string(),
                    content: format!("Masked {} fields in MySQL ResultRow", changes_log.len()),
                    details: Some(json!(changes_log)),
                })
                .await;
        }

        Ok(row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, MaskingRule};
    use crate::protocol::postgres::{FieldDescription, RowDescription};
    use crate::state::AppState;
    use bytes::BytesMut;

    #[tokio::test]
    async fn test_heuristic_detection() {
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
        let mut anonymizer = Anonymizer::new(state, 1);

        // Create a DataRow with an email
        let email = "test@example.com";
        let other = "some data";
        let mut row = DataRow {
            values: vec![
                Some(BytesMut::from(email.as_bytes())),
                Some(BytesMut::from(other.as_bytes())),
            ],
        };

        // Process the row
        row = anonymizer.on_data_row(row).await.unwrap();

        // Check results
        let val0 = std::str::from_utf8(row.values[0].as_ref().unwrap()).unwrap();
        let val1 = std::str::from_utf8(row.values[1].as_ref().unwrap()).unwrap();

        assert_ne!(val0, email, "Email should be masked");
        assert!(val0.contains("@"), "Masked value should still be an email");
        assert_eq!(val1, other, "Non-PII data should be unchanged");
    }

    #[tokio::test]
    async fn test_explicit_rule_overrides_heuristic() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![MaskingRule {
                table: None,
                column: "email_col".to_string(),
                strategy: "address".to_string(), // Intentionally wrong strategy to prove override
            }],
            tls: None,
            upstream_tls: false,
            telemetry: None,
            api: None,
            limits: None,
            health_check: None,
            audit: None,
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let mut anonymizer = Anonymizer::new(state, 1);

        let desc = RowDescription {
            fields: vec![FieldDescription {
                name: bytes::Bytes::from_static(b"email_col"),
                table_oid: 0,
                column_index: 0,
                type_oid: 0,
                type_len: 0,
                type_modifier: 0,
                format_code: 0,
            }],
        };

        anonymizer.on_row_description(&desc).await;

        let email = "test@example.com";
        let mut row = DataRow {
            values: vec![Some(BytesMut::from(email.as_bytes()))],
        };

        row = anonymizer.on_data_row(row).await.unwrap();
        let val0 = std::str::from_utf8(row.values[0].as_ref().unwrap()).unwrap();

        // Should look like a city, not an email
        assert!(
            !val0.contains("@"),
            "Should be masked as address, not email"
        );
    }

    #[tokio::test]
    async fn test_postgres_table_scoped_rule_applies_when_table_oid_is_present() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![MaskingRule {
                table: Some("users".to_string()),
                column: "email_col".to_string(),
                strategy: "address".to_string(),
            }],
            tls: None,
            upstream_tls: false,
            telemetry: None,
            api: None,
            limits: None,
            health_check: None,
            audit: None,
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let mut anonymizer = Anonymizer::new(state, 1);
        anonymizer.register_postgres_table_oid(123, "public", "users");

        let desc = RowDescription {
            fields: vec![FieldDescription {
                name: bytes::Bytes::from_static(b"email_col"),
                table_oid: 123,
                column_index: 1,
                type_oid: 0,
                type_len: 0,
                type_modifier: 0,
                format_code: 0,
            }],
        };

        anonymizer.on_row_description(&desc).await;

        let original = "test@example.com";
        let mut row = DataRow {
            values: vec![Some(BytesMut::from(original.as_bytes()))],
        };

        row = anonymizer.on_data_row(row).await.unwrap();
        let masked = std::str::from_utf8(row.values[0].as_ref().unwrap()).unwrap();

        assert_ne!(
            masked, original,
            "PostgreSQL table-scoped rules should apply after OID-to-table resolution"
        );
        assert!(
            !masked.contains("@"),
            "Table-scoped address strategy should override heuristic email masking"
        );
    }

    #[tokio::test]
    async fn test_postgres_table_scoped_rule_not_applied_without_table_resolution() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![MaskingRule {
                table: Some("users".to_string()),
                column: "email_col".to_string(),
                strategy: "address".to_string(),
            }],
            tls: None,
            upstream_tls: false,
            telemetry: None,
            api: None,
            limits: None,
            health_check: None,
            audit: None,
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let mut anonymizer = Anonymizer::new(state, 1);

        let desc = RowDescription {
            fields: vec![FieldDescription {
                name: bytes::Bytes::from_static(b"email_col"),
                table_oid: 123,
                column_index: 1,
                type_oid: 0,
                type_len: 0,
                type_modifier: 0,
                format_code: 0,
            }],
        };

        anonymizer.on_row_description(&desc).await;

        let original = "plain_value";
        let mut row = DataRow {
            values: vec![Some(BytesMut::from(original.as_bytes()))],
        };

        row = anonymizer.on_data_row(row).await.unwrap();
        let masked = std::str::from_utf8(row.values[0].as_ref().unwrap()).unwrap();

        assert_eq!(
            masked, original,
            "PostgreSQL table-scoped rules must not apply without OID-to-table resolution"
        );
    }

    #[tokio::test]
    async fn test_explicit_hash_strategy_returns_sha256_value() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![MaskingRule {
                table: None,
                column: "secret_col".to_string(),
                strategy: "hash".to_string(),
            }],
            tls: None,
            upstream_tls: false,
            telemetry: None,
            api: None,
            limits: None,
            health_check: None,
            audit: None,
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let mut anonymizer = Anonymizer::new(state, 1);

        let desc = RowDescription {
            fields: vec![FieldDescription {
                name: bytes::Bytes::from_static(b"secret_col"),
                table_oid: 0,
                column_index: 0,
                type_oid: 0,
                type_len: 0,
                type_modifier: 0,
                format_code: 0,
            }],
        };
        anonymizer.on_row_description(&desc).await;

        let original = "sensitive-value";
        let mut row = DataRow {
            values: vec![Some(BytesMut::from(original.as_bytes()))],
        };

        row = anonymizer.on_data_row(row).await.unwrap();
        let masked = std::str::from_utf8(row.values[0].as_ref().unwrap()).unwrap();

        assert_ne!(masked, original);
        assert!(
            masked.starts_with("sha256:"),
            "hash strategy should output sha256-prefixed value"
        );
    }

    #[tokio::test]
    async fn test_json_masking() {
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
        let mut anonymizer = Anonymizer::new(state, 1);

        let json_data = r#"
        {
            "user": {
                "email": "test@example.com",
                "name": "John Doe"
            },
            "payment": {
                "cc": "4532-1234-5678-9012"
            },
            "tags": ["valid@email.com", "not-pii"]
        }
        "#;

        let mut row = DataRow {
            values: vec![Some(BytesMut::from(json_data.as_bytes()))],
        };

        row = anonymizer.on_data_row(row).await.unwrap();
        let val = std::str::from_utf8(row.values[0].as_ref().unwrap()).unwrap();

        // Parse result to verify
        let v: serde_json::Value = serde_json::from_str(val).unwrap();

        let email = v["user"]["email"].as_str().unwrap();
        let cc = v["payment"]["cc"].as_str().unwrap();
        let tag_email = v["tags"][0].as_str().unwrap();
        let tag_normal = v["tags"][1].as_str().unwrap();

        assert_ne!(email, "test@example.com");
        assert!(email.contains("@")); // Still an email

        assert_ne!(cc, "4532-1234-5678-9012");

        assert_ne!(tag_email, "valid@email.com");
        assert!(tag_email.contains("@"));

        assert_eq!(tag_normal, "not-pii");
    }

    #[tokio::test]
    async fn test_array_masking() {
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
        let mut anonymizer = Anonymizer::new(state, 1);

        // Postgres array format: {val1,val2}
        let array_data = r#"{"test@example.com","normal_val","1234-5678-9012-3456"}"#;

        let mut row = DataRow {
            values: vec![Some(BytesMut::from(array_data.as_bytes()))],
        };

        row = anonymizer.on_data_row(row).await.unwrap();
        let val = std::str::from_utf8(row.values[0].as_ref().unwrap()).unwrap();

        // Should be masked
        assert!(val.starts_with('{'));
        assert!(val.ends_with('}'));

        // Split by comma to check elements
        let content = &val[1..val.len() - 1];
        let parts: Vec<&str> = content.split(',').collect();

        assert_eq!(parts.len(), 3);

        let email = parts[0];
        let normal = parts[1];
        let cc = parts[2];

        assert_ne!(email, "\"test@example.com\"");
        assert!(email.contains("@"));

        assert_eq!(normal, "\"normal_val\""); // Should be unchanged and still quoted

        assert_ne!(cc, "\"1234-5678-9012-3456\"");
    }

    #[tokio::test]
    async fn test_deterministic_masking() {
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
        let mut anonymizer = Anonymizer::new(state, 1);

        let email = "test@example.com";

        // Process same email twice
        let mut row1 = DataRow {
            values: vec![Some(BytesMut::from(email.as_bytes()))],
        };
        let mut row2 = DataRow {
            values: vec![Some(BytesMut::from(email.as_bytes()))],
        };

        row1 = anonymizer.on_data_row(row1).await.unwrap();
        row2 = anonymizer.on_data_row(row2).await.unwrap();

        let val1 = std::str::from_utf8(row1.values[0].as_ref().unwrap()).unwrap();
        let val2 = std::str::from_utf8(row2.values[0].as_ref().unwrap()).unwrap();

        // Same input should produce same output (deterministic)
        assert_eq!(val1, val2, "Same input should produce same masked output");
        assert_ne!(val1, email, "Output should be different from input");
    }

    #[tokio::test]
    async fn test_masking_can_be_disabled() {
        let config = AppConfig {
            masking_enabled: false, // Disabled
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
        let mut anonymizer = Anonymizer::new(state, 1);

        let email = "test@example.com";
        let mut row = DataRow {
            values: vec![Some(BytesMut::from(email.as_bytes()))],
        };

        row = anonymizer.on_data_row(row).await.unwrap();
        let val = std::str::from_utf8(row.values[0].as_ref().unwrap()).unwrap();

        // Should NOT be masked when disabled
        assert_eq!(
            val, email,
            "Data should not be masked when masking is disabled"
        );
    }

    #[tokio::test]
    async fn test_null_values_handled() {
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
        let mut anonymizer = Anonymizer::new(state, 1);

        let mut row = DataRow {
            values: vec![None, Some(BytesMut::from("data".as_bytes())), None],
        };

        row = anonymizer.on_data_row(row).await.unwrap();

        assert!(row.values[0].is_none(), "NULL should remain NULL");
        assert!(row.values[1].is_some(), "Non-NULL should remain Some");
        assert!(row.values[2].is_none(), "NULL should remain NULL");
    }
}
