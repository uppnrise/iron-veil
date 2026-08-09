use crate::metrics;
use crate::protocol::mysql::{ColumnDefinition, ResultRow};
use crate::protocol::postgres::{DataRow, RowDescription};
use crate::scanner::{PiiScanner, PiiType};
use anyhow::Result;
use bytes::BytesMut;
use fake::Fake;
use fake::faker::address::en::StreetName;
use fake::faker::creditcard::en::CreditCardNumber;
use fake::faker::internet::en::SafeEmail;
use fake::faker::lorem::en::Sentence;
use fake::faker::name::en::{FirstName, LastName};
use fake::faker::phone_number::en::PhoneNumber;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Sentinel written when an explicit strategy fails to apply (e.g. a `json`
/// rule over a value that is not valid JSON). Fail closed: never forward the
/// original bytes of a column an operator explicitly marked as sensitive.
const MASK_FAILED_SENTINEL: &[u8] = b"MASKED";

fn generate_fake_data(strategy: &str, seed: u64) -> String {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    match strategy {
        "email" => SafeEmail().fake_with_rng(&mut rng),
        "phone" => PhoneNumber().fake_with_rng(&mut rng),
        "address" => {
            let street: String = StreetName().fake_with_rng(&mut rng);
            format!("{} {}", 100 + seed % 9900, street)
        }
        "name" => {
            let first: String = FirstName().fake_with_rng(&mut rng);
            let last: String = LastName().fake_with_rng(&mut rng);
            format!("{} {}", first, last)
        }
        "text" => Sentence(3..8).fake_with_rng(&mut rng),
        "credit_card" => CreditCardNumber().fake_with_rng(&mut rng),
        "ssn" => format!("XXX-XX-{:04}", (seed % 10000)),
        "ip" => format!("203.0.113.{}", seed % 256),
        "dob" => {
            // TEST-NET-style stand-in date range, deterministic per value
            format!(
                "19{:02}-{:02}-{:02}",
                seed % 100,
                1 + seed % 12,
                1 + seed % 28
            )
        }
        "passport" => format!("X{:08}", seed % 100_000_000),
        _ => "MASKED".to_string(),
    }
}

/// Keyed deterministic seed: same plaintext -> same pseudonym under the same
/// deployment key, but the mapping is not computable without the key.
fn masking_seed(key: &[u8; 32], value: &[u8]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(value);
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("sha256 output >= 8 bytes"))
}

fn hash_value(key: &[u8; 32], value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(value);
    format!("sha256:{:x}", hasher.finalize())
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

/// Runtime view of config::HeuristicsConfig, resolved once per row.
struct HeuristicSettings {
    enabled: bool,
    allowed: HashSet<PiiType>,
}

impl HeuristicSettings {
    fn from_config(config: Option<&crate::config::HeuristicsConfig>) -> Self {
        let resolved = config.cloned().unwrap_or_default();
        Self {
            enabled: resolved.enabled,
            allowed: resolved
                .types
                .iter()
                .filter_map(|t| PiiType::from_config_name(t))
                .collect(),
        }
    }
}

struct MaskContext<'a> {
    scanner: &'a PiiScanner,
    heuristics: &'a HeuristicSettings,
    key: [u8; 32],
}

fn mask_json_recursively(val: &mut serde_json::Value, ctx: &MaskContext) -> bool {
    let mut changed = false;
    match val {
        serde_json::Value::String(s) => {
            if let Some(pii_type) = ctx.scanner.scan_allowed(s, &ctx.heuristics.allowed) {
                let strategy = pii_type_to_strategy(pii_type);
                let seed = masking_seed(&ctx.key, s.as_bytes());
                *s = generate_fake_data(strategy, seed);
                changed = true;
            } else if let Some(masked) =
                ctx.scanner
                    .mask_text_spans(s, &ctx.heuristics.allowed, |pii_type, span| {
                        generate_fake_data(
                            pii_type_to_strategy(pii_type),
                            masking_seed(&ctx.key, span.as_bytes()),
                        )
                    })
            {
                *s = masked;
                changed = true;
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                changed |= mask_json_recursively(v, ctx);
            }
        }
        serde_json::Value::Object(map) => {
            for (_, v) in map {
                changed |= mask_json_recursively(v, ctx);
            }
        }
        _ => {}
    }
    changed
}

fn mask_postgres_array(raw: &str, ctx: &MaskContext) -> Option<String> {
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

        if let Some(pii_type) = ctx
            .scanner
            .scan_allowed(&clean_val, &ctx.heuristics.allowed)
        {
            let strategy = pii_type_to_strategy(pii_type);
            let seed = masking_seed(&ctx.key, clean_val.as_bytes());
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

/// Outcome of masking a single cell: which strategies fired (for stats) and a
/// log record. The record intentionally carries no pre-masking bytes — only
/// the column, the strategy, the original length and the masked preview.
struct CellChange {
    strategies: Vec<String>,
    log: serde_json::Value,
}

fn preview(value: &str) -> String {
    if value.len() > 50 {
        let mut end = 50;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &value[..end])
    } else {
        value.to_string()
    }
}

/// Shared per-cell masking logic for both the PostgreSQL and MySQL paths.
fn mask_cell(
    val: &mut BytesMut,
    column_idx: usize,
    column_name: Option<&str>,
    explicit_strategy: Option<&str>,
    ctx: &MaskContext,
) -> Option<CellChange> {
    let original_len = val.len();

    let change_record = |strategy: &str, masked_preview: String| {
        json!({
            "column_idx": column_idx,
            "column_name": column_name,
            "strategy": strategy,
            "original_len": original_len,
            "masked": masked_preview,
        })
    };

    // Explicit `json` strategy: mask inside the document, fail closed on error.
    if let Some("json") = explicit_strategy {
        let parsed = std::str::from_utf8(val)
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
        match parsed {
            Some(mut json_val) => {
                let changed = mask_json_recursively(&mut json_val, ctx);
                match serde_json::to_string(&json_val) {
                    Ok(new_json) => {
                        if changed && new_json.as_bytes() != &val[..] {
                            val.clear();
                            val.extend_from_slice(new_json.as_bytes());
                            return Some(CellChange {
                                strategies: vec!["json".to_string()],
                                log: change_record("json", "(JSON Masked)".to_string()),
                            });
                        }
                        return None;
                    }
                    Err(e) => {
                        metrics::record_masking_error();
                        tracing::warn!(column_idx, error = %e, "json re-serialization failed; masking whole value");
                    }
                }
            }
            None => {
                metrics::record_masking_error();
                tracing::warn!(
                    column_idx,
                    "value under explicit json rule is not valid JSON; masking whole value"
                );
            }
        }
        // Fail closed: the operator marked this column sensitive.
        val.clear();
        val.extend_from_slice(MASK_FAILED_SENTINEL);
        return Some(CellChange {
            strategies: vec!["json".to_string()],
            log: change_record("json (failed closed)", "MASKED".to_string()),
        });
    }

    // Other explicit strategies.
    if let Some(strat) = explicit_strategy {
        let fake_val = if strat == "hash" {
            hash_value(&ctx.key, &val[..])
        } else {
            generate_fake_data(strat, masking_seed(&ctx.key, &val[..]))
        };
        val.clear();
        val.extend_from_slice(fake_val.as_bytes());
        return Some(CellChange {
            strategies: vec![strat.to_string()],
            log: change_record(strat, preview(&fake_val)),
        });
    }

    // Heuristic path.
    if !ctx.heuristics.enabled {
        return None;
    }
    let Ok(s) = std::str::from_utf8(val) else {
        return None;
    };

    // JSON / PostgreSQL-array heuristic first if it looks structured.
    let trimmed = s.trim();
    if (trimmed.starts_with('{') && trimmed.ends_with('}'))
        || (trimmed.starts_with('[') && trimmed.ends_with(']'))
    {
        match serde_json::from_str::<serde_json::Value>(s) {
            Ok(mut json_val) => {
                if mask_json_recursively(&mut json_val, ctx)
                    && let Ok(new_json) = serde_json::to_string(&json_val)
                    && new_json.as_bytes() != &val[..]
                {
                    val.clear();
                    val.extend_from_slice(new_json.as_bytes());
                    return Some(CellChange {
                        strategies: vec!["json".to_string()],
                        log: change_record("json (heuristic)", "(JSON Masked)".to_string()),
                    });
                }
                return None;
            }
            Err(_) => {
                // Not valid JSON, maybe Postgres Array?
                if trimmed.starts_with('{')
                    && trimmed.ends_with('}')
                    && let Some(masked_array) = mask_postgres_array(s, ctx)
                {
                    let log = change_record("array (heuristic)", preview(&masked_array));
                    val.clear();
                    val.extend_from_slice(masked_array.as_bytes());
                    return Some(CellChange {
                        strategies: vec!["other".to_string()],
                        log,
                    });
                }
            }
        }
    }

    // Whole-value detection.
    if let Some(pii_type) = ctx.scanner.scan_allowed(s, &ctx.heuristics.allowed) {
        let strat = pii_type_to_strategy(pii_type);
        let fake_val = generate_fake_data(strat, masking_seed(&ctx.key, val));
        val.clear();
        val.extend_from_slice(fake_val.as_bytes());
        return Some(CellChange {
            strategies: vec![strat.to_string()],
            log: change_record(strat, preview(&fake_val)),
        });
    }

    // Embedded spans in free text (email/phone only).
    let mut span_strategies = Vec::new();
    if let Some(masked) =
        ctx.scanner
            .mask_text_spans(s, &ctx.heuristics.allowed, |pii_type, span| {
                let strat = pii_type_to_strategy(pii_type);
                span_strategies.push(strat.to_string());
                generate_fake_data(strat, masking_seed(&ctx.key, span.as_bytes()))
            })
    {
        let log = change_record("span (heuristic)", preview(&masked));
        val.clear();
        val.extend_from_slice(masked.as_bytes());
        return Some(CellChange {
            strategies: span_strategies,
            log,
        });
    }

    None
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
    scanner: &'static PiiScanner,
    target_cols: Vec<(usize, String)>,
    column_labels: Vec<String>,
    table_names_by_oid: HashMap<u32, HashSet<String>>,
    column_names_by_oid: HashMap<(u32, u16), String>,
    connection_id: usize,
}

impl Anonymizer {
    pub fn new(state: AppState, connection_id: usize) -> Self {
        Self {
            state,
            scanner: PiiScanner::shared(),
            target_cols: Vec::new(),
            column_labels: Vec::new(),
            table_names_by_oid: HashMap::new(),
            column_names_by_oid: HashMap::new(),
            connection_id,
        }
    }

    /// Drop the per-result-set column map. Called when the client issues a new
    /// Query/Parse/Bind so a stale index->strategy map from a previous
    /// statement can never mask the wrong columns.
    pub fn reset_columns(&mut self) {
        self.target_cols.clear();
        self.column_labels.clear();
    }

    pub fn register_postgres_table_oid(&mut self, oid: u32, schema: &str, table: &str) {
        if oid == 0 {
            return;
        }

        let aliases = self.table_names_by_oid.entry(oid).or_default();
        aliases.insert(normalize_identifier(table));
        aliases.insert(normalize_identifier(&format!("{}.{}", schema, table)));
    }

    /// Register a source column name so rules can match provenance
    /// (table_oid + attnum) instead of just the result-set label.
    pub fn register_postgres_column(&mut self, oid: u32, attnum: i16, column: &str) {
        if oid == 0 || attnum <= 0 {
            return;
        }
        self.column_names_by_oid
            .insert((oid, attnum as u16), normalize_identifier(column));
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
        self.reset_columns();

        let config = self.state.config.read().await;
        for (i, field) in msg.fields.iter().enumerate() {
            let label = normalize_identifier(std::str::from_utf8(&field.name).unwrap_or_default());
            // True provenance when the bootstrap resolved it; aliases can't
            // hide a protected source column from a rule then.
            let source_column = if field.table_oid != 0 && field.column_index > 0 {
                self.column_names_by_oid
                    .get(&(field.table_oid, field.column_index))
                    .cloned()
            } else {
                None
            };
            self.column_labels.push(label.clone());

            for rule in &config.rules {
                // Check if rule applies to this column.
                let table_match = match rule.table.as_deref() {
                    None => true,
                    Some(rule_table) => {
                        self.postgres_rule_matches_table(field.table_oid, rule_table)
                    }
                };

                let rule_column = normalize_identifier(&rule.column);
                let column_match =
                    rule_column == label || source_column.as_deref() == Some(&*rule_column);
                if table_match && column_match {
                    self.target_cols.push((i, rule.strategy.clone()));
                    break; // Apply first matching rule
                }
            }
        }
    }

    async fn on_data_row(&mut self, mut msg: DataRow) -> Result<DataRow> {
        let (heuristics, key) = {
            let config = self.state.config.read().await;
            if !config.masking_enabled {
                return Ok(msg);
            }
            (
                HeuristicSettings::from_config(config.heuristics.as_ref()),
                self.state.masking_key(),
            )
        };
        let ctx = MaskContext {
            scanner: self.scanner,
            heuristics: &heuristics,
            key,
        };

        let mut changes_log = Vec::new();
        let mut strategies_used: Vec<String> = Vec::new();

        for (i, val_opt) in msg.values.iter_mut().enumerate() {
            if let Some(val) = val_opt {
                let explicit_strategy = self
                    .target_cols
                    .iter()
                    .find(|(col_idx, _)| *col_idx == i)
                    .map(|(_, strategy)| strategy.as_str());

                if let Some(change) = mask_cell(
                    val,
                    i,
                    self.column_labels.get(i).map(|s| s.as_str()),
                    explicit_strategy,
                    &ctx,
                ) {
                    strategies_used.extend(change.strategies);
                    changes_log.push(change.log);
                }
            }
        }

        if !strategies_used.is_empty() {
            let refs: Vec<&str> = strategies_used.iter().map(|s| s.as_str()).collect();
            self.state.record_masking_batch(&refs).await;
        }

        if !changes_log.is_empty() {
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
    scanner: &'static PiiScanner,
    target_cols: Vec<(usize, String)>,
    column_names: Vec<String>,
    connection_id: usize,
}

impl MySqlAnonymizer {
    pub fn new(state: AppState, connection_id: usize) -> Self {
        Self {
            state,
            scanner: PiiScanner::shared(),
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
        let label = normalize_identifier(&String::from_utf8_lossy(&col.name));
        // org_name/org_table are the true provenance; the plain name/table are
        // the (aliasable) result-set labels. Match rules against both so
        // `SELECT email AS x` cannot bypass an email rule.
        let source_column = normalize_identifier(&String::from_utf8_lossy(&col.org_name));
        let label_table = normalize_identifier(&String::from_utf8_lossy(&col.table));
        let source_table = normalize_identifier(&String::from_utf8_lossy(&col.org_table));

        let col_idx = self.column_names.len();
        self.column_names.push(label.clone());

        let config = self.state.config.read().await;
        for rule in &config.rules {
            let table_match = rule.table.as_ref().is_none_or(|t| {
                let rule_table = normalize_identifier(t);
                rule_table == label_table
                    || (!source_table.is_empty() && rule_table == source_table)
            });

            let rule_column = normalize_identifier(&rule.column);
            let column_match =
                rule_column == label || (!source_column.is_empty() && rule_column == source_column);

            if table_match && column_match {
                self.target_cols.push((col_idx, rule.strategy.clone()));
                tracing::debug!(column = %label, strategy = %rule.strategy, "MySQL column matched rule");
                break;
            }
        }
    }

    async fn on_result_row(&mut self, mut row: ResultRow) -> Result<ResultRow> {
        let (heuristics, key) = {
            let config = self.state.config.read().await;
            if !config.masking_enabled {
                return Ok(row);
            }
            (
                HeuristicSettings::from_config(config.heuristics.as_ref()),
                self.state.masking_key(),
            )
        };
        let ctx = MaskContext {
            scanner: self.scanner,
            heuristics: &heuristics,
            key,
        };

        let mut changes_log = Vec::new();
        let mut strategies_used: Vec<String> = Vec::new();

        for (i, val_opt) in row.values.iter_mut().enumerate() {
            if let Some(val) = val_opt {
                let explicit_strategy = self
                    .target_cols
                    .iter()
                    .find(|(col_idx, _)| *col_idx == i)
                    .map(|(_, strategy)| strategy.as_str());

                if let Some(change) = mask_cell(
                    val,
                    i,
                    self.column_names.get(i).map(|s| s.as_str()),
                    explicit_strategy,
                    &ctx,
                ) {
                    strategies_used.extend(change.strategies);
                    changes_log.push(change.log);
                }
            }
        }

        if !strategies_used.is_empty() {
            let refs: Vec<&str> = strategies_used.iter().map(|s| s.as_str()).collect();
            self.state.record_masking_batch(&refs).await;
        }

        if !changes_log.is_empty() {
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
    use crate::config::{AppConfig, HeuristicsConfig, MaskingRule};
    use crate::protocol::postgres::{FieldDescription, RowDescription};
    use crate::state::AppState;
    use bytes::BytesMut;

    fn all_heuristics() -> Option<HeuristicsConfig> {
        Some(HeuristicsConfig {
            enabled: true,
            types: crate::config::KNOWN_HEURISTIC_TYPES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        })
    }

    fn mysql_column(name: &str, org_name: &str, table: &str, org_table: &str) -> ColumnDefinition {
        ColumnDefinition {
            sequence_id: 1,
            catalog: bytes::Bytes::from_static(b"def"),
            schema: bytes::Bytes::from_static(b"testdb"),
            table: bytes::Bytes::copy_from_slice(table.as_bytes()),
            org_table: bytes::Bytes::copy_from_slice(org_table.as_bytes()),
            name: bytes::Bytes::copy_from_slice(name.as_bytes()),
            org_name: bytes::Bytes::copy_from_slice(org_name.as_bytes()),
            character_set: 33,
            column_length: 255,
            column_type: 253,
            flags: 0,
            decimals: 0,
            raw: bytes::Bytes::new(),
        }
    }

    #[tokio::test]
    async fn test_heuristic_detection() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
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
    async fn test_ambiguous_heuristics_are_opt_in() {
        // Default heuristics must NOT rewrite dates, IPs or bare numbers —
        // that silently corrupts legitimate query results (audit B9/B10).
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let mut anonymizer = Anonymizer::new(state, 1);

        let date = "2026-01-15";
        let ip = "192.168.1.1";
        let order_no = "1234567890123456";
        let mut row = DataRow {
            values: vec![
                Some(BytesMut::from(date.as_bytes())),
                Some(BytesMut::from(ip.as_bytes())),
                Some(BytesMut::from(order_no.as_bytes())),
            ],
        };

        row = anonymizer.on_data_row(row).await.unwrap();

        assert_eq!(row.values[0].as_ref().unwrap(), date.as_bytes());
        assert_eq!(row.values[1].as_ref().unwrap(), ip.as_bytes());
        assert_eq!(row.values[2].as_ref().unwrap(), order_no.as_bytes());
    }

    #[tokio::test]
    async fn test_opted_in_heuristics_apply() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            heuristics: all_heuristics(),
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let mut anonymizer = Anonymizer::new(state, 1);

        let ip = "192.168.1.1";
        let mut row = DataRow {
            values: vec![Some(BytesMut::from(ip.as_bytes()))],
        };
        row = anonymizer.on_data_row(row).await.unwrap();
        assert_ne!(
            row.values[0].as_ref().unwrap(),
            ip.as_bytes(),
            "opted-in ip heuristic should mask dotted quads"
        );
    }

    #[tokio::test]
    async fn test_heuristics_can_be_disabled() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            heuristics: Some(HeuristicsConfig {
                enabled: false,
                types: vec![],
            }),
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let mut anonymizer = Anonymizer::new(state, 1);

        let email = "test@example.com";
        let mut row = DataRow {
            values: vec![Some(BytesMut::from(email.as_bytes()))],
        };
        row = anonymizer.on_data_row(row).await.unwrap();
        assert_eq!(row.values[0].as_ref().unwrap(), email.as_bytes());
    }

    #[tokio::test]
    async fn test_free_text_email_span_masked() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let mut anonymizer = Anonymizer::new(state, 1);

        let note = "customer john.doe@company.org asked for a refund";
        let mut row = DataRow {
            values: vec![Some(BytesMut::from(note.as_bytes()))],
        };
        row = anonymizer.on_data_row(row).await.unwrap();
        let val = std::str::from_utf8(row.values[0].as_ref().unwrap()).unwrap();
        assert!(!val.contains("john.doe@company.org"));
        assert!(val.starts_with("customer "));
        assert!(val.ends_with(" asked for a refund"));
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
            ..Default::default()
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

        // Should look like an address, not an email
        assert!(
            !val0.contains("@"),
            "Should be masked as address, not email"
        );
    }

    #[tokio::test]
    async fn test_postgres_rule_matches_source_column_behind_alias() {
        let mut anonymizer = {
            let config = AppConfig {
                masking_enabled: true,
                rules: vec![MaskingRule {
                    table: None,
                    column: "email".to_string(),
                    strategy: "hash".to_string(),
                }],
                ..Default::default()
            };
            let state = AppState::new_for_test(config, "proxy.yaml".to_string());
            Anonymizer::new(state, 1)
        };
        anonymizer.register_postgres_table_oid(500, "public", "users");
        anonymizer.register_postgres_column(500, 3, "email");

        // `SELECT email AS contact FROM users` — label differs, provenance matches
        let desc = RowDescription {
            fields: vec![FieldDescription {
                name: bytes::Bytes::from_static(b"contact"),
                table_oid: 500,
                column_index: 3,
                type_oid: 0,
                type_len: 0,
                type_modifier: 0,
                format_code: 0,
            }],
        };
        anonymizer.on_row_description(&desc).await;

        let mut row = DataRow {
            values: vec![Some(BytesMut::from("real@example.com".as_bytes()))],
        };
        row = anonymizer.on_data_row(row).await.unwrap();
        let val = std::str::from_utf8(row.values[0].as_ref().unwrap()).unwrap();
        assert!(
            val.starts_with("sha256:"),
            "aliased column must still match the rule via provenance, got {val}"
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
    async fn test_hash_strategy_is_keyed() {
        // The same plaintext must hash differently under different keys, so
        // pseudonyms cannot be confirmed or brute-forced without the secret.
        let mk_state = |secret: &str| {
            AppState::new_for_test(
                AppConfig {
                    masking_enabled: true,
                    masking_secret: Some(secret.to_string()),
                    rules: vec![MaskingRule {
                        table: None,
                        column: "c".to_string(),
                        strategy: "hash".to_string(),
                    }],
                    ..Default::default()
                },
                "proxy.yaml".to_string(),
            )
        };

        let mask_with = |state: AppState| async move {
            let mut anonymizer = Anonymizer::new(state, 1);
            let desc = RowDescription {
                fields: vec![FieldDescription {
                    name: bytes::Bytes::from_static(b"c"),
                    table_oid: 0,
                    column_index: 0,
                    type_oid: 0,
                    type_len: 0,
                    type_modifier: 0,
                    format_code: 0,
                }],
            };
            anonymizer.on_row_description(&desc).await;
            let row = DataRow {
                values: vec![Some(BytesMut::from("alice@corp.com".as_bytes()))],
            };
            let row = anonymizer.on_data_row(row).await.unwrap();
            std::str::from_utf8(row.values[0].as_ref().unwrap())
                .unwrap()
                .to_string()
        };

        let a = mask_with(mk_state("secret-a")).await;
        let b = mask_with(mk_state("secret-b")).await;
        let a2 = mask_with(mk_state("secret-a")).await;

        assert_ne!(a, b, "different keys must produce different hashes");
        assert_eq!(a, a2, "same key must stay deterministic");
        // And neither equals the unkeyed digest of the plaintext.
        let unkeyed = format!("sha256:{:x}", Sha256::digest(b"alice@corp.com"));
        assert_ne!(a, unkeyed);
        assert_ne!(b, unkeyed);
    }

    #[tokio::test]
    async fn test_json_strategy_fails_closed_on_invalid_json() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![MaskingRule {
                table: None,
                column: "payload".to_string(),
                strategy: "json".to_string(),
            }],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let mut anonymizer = Anonymizer::new(state, 1);

        let desc = RowDescription {
            fields: vec![FieldDescription {
                name: bytes::Bytes::from_static(b"payload"),
                table_oid: 0,
                column_index: 0,
                type_oid: 0,
                type_len: 0,
                type_modifier: 0,
                format_code: 0,
            }],
        };
        anonymizer.on_row_description(&desc).await;

        let original = "not-json: secret@example.com";
        let mut row = DataRow {
            values: vec![Some(BytesMut::from(original.as_bytes()))],
        };
        row = anonymizer.on_data_row(row).await.unwrap();
        assert_eq!(
            row.values[0].as_ref().unwrap(),
            MASK_FAILED_SENTINEL,
            "invalid JSON under an explicit json rule must not be forwarded"
        );
    }

    #[tokio::test]
    async fn test_json_masking() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            heuristics: all_heuristics(),
            ..Default::default()
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
                "cc": "4532-0151-1283-0366"
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

        assert_ne!(cc, "4532-0151-1283-0366");

        assert_ne!(tag_email, "valid@email.com");
        assert!(tag_email.contains("@"));

        assert_eq!(tag_normal, "not-pii");
    }

    #[tokio::test]
    async fn test_array_masking() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            heuristics: all_heuristics(),
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let mut anonymizer = Anonymizer::new(state, 1);

        // Postgres array format: {val1,val2}
        let array_data = r#"{"test@example.com","normal_val","4532-0151-1283-0366"}"#;

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

        assert_ne!(cc, "\"4532-0151-1283-0366\"");
    }

    #[tokio::test]
    async fn test_deterministic_masking() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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

    #[tokio::test]
    async fn test_masking_log_never_contains_original_value() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let mut anonymizer = Anonymizer::new(state.clone(), 1);

        let email = "super.secret@example.com";
        let row = DataRow {
            values: vec![Some(BytesMut::from(email.as_bytes()))],
        };
        anonymizer.on_data_row(row).await.unwrap();

        let logs = state.logs.read().await;
        let serialized = serde_json::to_string(&*logs).unwrap();
        assert!(
            !serialized.contains(email),
            "log ring must not retain pre-masking values"
        );
    }

    // ------------------------------------------------------------------
    // MySQL anonymizer
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_mysql_rule_matching_is_case_insensitive() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![MaskingRule {
                table: Some("Users".to_string()),
                column: "EMAIL".to_string(),
                strategy: "hash".to_string(),
            }],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let mut anonymizer = MySqlAnonymizer::new(state, 1);

        anonymizer
            .on_column_definition(&mysql_column("email", "email", "users", "users"))
            .await;

        let mut row = ResultRow {
            values: vec![Some(BytesMut::from("x@example.com".as_bytes()))],
            sequence_id: 1,
        };
        row = anonymizer.on_result_row(row).await.unwrap();
        let val = std::str::from_utf8(row.values[0].as_ref().unwrap()).unwrap();
        assert!(
            val.starts_with("sha256:"),
            "mixed-case rule must match lower-case wire identifiers, got {val}"
        );
    }

    #[tokio::test]
    async fn test_mysql_rule_matches_org_name_behind_alias() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![MaskingRule {
                table: Some("users".to_string()),
                column: "email".to_string(),
                strategy: "hash".to_string(),
            }],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let mut anonymizer = MySqlAnonymizer::new(state, 1);

        // `SELECT email AS x FROM users u` — label and label-table are aliases
        anonymizer
            .on_column_definition(&mysql_column("x", "email", "u", "users"))
            .await;

        let mut row = ResultRow {
            values: vec![Some(BytesMut::from("x@example.com".as_bytes()))],
            sequence_id: 1,
        };
        row = anonymizer.on_result_row(row).await.unwrap();
        let val = std::str::from_utf8(row.values[0].as_ref().unwrap()).unwrap();
        assert!(
            val.starts_with("sha256:"),
            "aliased MySQL column must match rule via org_name/org_table, got {val}"
        );
    }

    #[tokio::test]
    async fn test_mysql_heuristic_masks_json_document() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let mut anonymizer = MySqlAnonymizer::new(state, 1);

        let json_data = r#"{"contact":"leak@example.com"}"#;
        let mut row = ResultRow {
            values: vec![Some(BytesMut::from(json_data.as_bytes()))],
            sequence_id: 1,
        };
        row = anonymizer.on_result_row(row).await.unwrap();
        let val = std::str::from_utf8(row.values[0].as_ref().unwrap()).unwrap();
        assert!(
            !val.contains("leak@example.com"),
            "MySQL heuristic path must mask JSON documents too, got {val}"
        );
    }

    #[tokio::test]
    async fn test_mysql_masking_disabled_passthrough() {
        let config = AppConfig {
            masking_enabled: false,
            rules: vec![],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let mut anonymizer = MySqlAnonymizer::new(state, 1);

        let email = "test@example.com";
        let mut row = ResultRow {
            values: vec![Some(BytesMut::from(email.as_bytes()))],
            sequence_id: 1,
        };
        row = anonymizer.on_result_row(row).await.unwrap();
        assert_eq!(row.values[0].as_ref().unwrap(), email.as_bytes());
    }
}
