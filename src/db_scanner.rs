//! Database Scanner Module
//!
//! Provides real database introspection capabilities for PII detection.
//! Queries `information_schema` for column metadata and samples actual data.

use crate::scanner::{PiiScanner, PiiType};
use crate::state::DbProtocol;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tokio_postgres::{Client, NoTls};
use tracing::{debug, info, instrument, warn};

/// Error types for database scanning operations
#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Database connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Query execution failed: {0}")]
    QueryFailed(String),
    #[error("Unsupported database protocol: {0:?}")]
    UnsupportedProtocol(DbProtocol),
    #[error("Authentication required: please provide database credentials")]
    AuthRequired,
}

/// Configuration for database scanning
#[derive(Debug, Clone, Deserialize)]
pub struct ScanConfig {
    /// Database username
    pub username: String,
    /// Database password
    pub password: String,
    /// Database name to scan
    pub database: String,
    /// Maximum number of rows to sample per table (default: 100)
    #[serde(default = "default_sample_size")]
    pub sample_size: usize,
    /// Schema to scan (default: "public" for Postgres)
    #[serde(default = "default_schema")]
    pub schema: String,
    /// Tables to exclude from scanning
    #[serde(default)]
    pub exclude_tables: Vec<String>,
    /// Minimum confidence threshold (0.0 - 1.0)
    #[serde(default = "default_confidence_threshold")]
    pub confidence_threshold: f64,
}

fn default_sample_size() -> usize {
    100
}

fn default_schema() -> String {
    "public".to_string()
}

fn default_confidence_threshold() -> f64 {
    0.5
}

/// Represents column metadata from information_schema
#[derive(Debug, Clone, Serialize)]
pub struct ColumnInfo {
    pub table_name: String,
    pub column_name: String,
    pub data_type: String,
    pub is_nullable: bool,
    pub character_maximum_length: Option<i32>,
}

/// Represents a PII finding in the database
#[derive(Debug, Clone, Serialize)]
pub struct PiiFinding {
    pub table: String,
    pub column: String,
    pub pii_type: String,
    pub confidence: f64,
    pub sample: Option<String>,
    pub row_count: usize,
    pub match_count: usize,
    pub data_type: String,
}

/// Represents the complete scan result
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub status: String,
    pub tables_scanned: usize,
    pub columns_scanned: usize,
    pub findings: Vec<PiiFinding>,
    pub schema: String,
    pub database: String,
    pub scan_duration_ms: u64,
}

/// Represents schema information
#[derive(Debug, Clone, Serialize)]
pub struct SchemaInfo {
    pub database: String,
    pub schema: String,
    pub tables: Vec<TableInfo>,
}

/// Represents table information
#[derive(Debug, Clone, Serialize)]
pub struct TableInfo {
    pub name: String,
    pub columns: Vec<ColumnInfo>,
    pub row_count: Option<i64>,
}

/// Database scanner for PII detection
pub struct DbScanner {
    host: String,
    port: u16,
    protocol: DbProtocol,
    pii_scanner: PiiScanner,
}

impl DbScanner {
    /// Create a new database scanner
    pub fn new(host: String, port: u16, protocol: DbProtocol) -> Self {
        Self {
            host,
            port,
            protocol,
            pii_scanner: PiiScanner::new(),
        }
    }

    /// Scan the database for PII
    #[instrument(skip(self, config), fields(host = %self.host, port = %self.port, db = %config.database))]
    pub async fn scan(&self, config: &ScanConfig) -> Result<ScanResult, ScanError> {
        let start = std::time::Instant::now();

        match self.protocol {
            DbProtocol::Postgres => self.scan_postgres(config, start).await,
            DbProtocol::MySql => {
                // MySQL support coming in future
                Err(ScanError::UnsupportedProtocol(DbProtocol::MySql))
            }
        }
    }

    /// Get schema information from the database
    #[instrument(skip(self, config), fields(host = %self.host, port = %self.port, db = %config.database))]
    pub async fn get_schema(&self, config: &ScanConfig) -> Result<SchemaInfo, ScanError> {
        match self.protocol {
            DbProtocol::Postgres => self.get_postgres_schema(config).await,
            DbProtocol::MySql => Err(ScanError::UnsupportedProtocol(DbProtocol::MySql)),
        }
    }

    /// Scan PostgreSQL database for PII
    async fn scan_postgres(
        &self,
        config: &ScanConfig,
        start: std::time::Instant,
    ) -> Result<ScanResult, ScanError> {
        let client = self.connect_postgres(config).await?;

        // Get all columns from information_schema
        let columns = self.get_postgres_columns(&client, &config.schema).await?;
        info!(
            "Found {} columns in schema '{}'",
            columns.len(),
            config.schema
        );

        // Group columns by table
        let mut tables: HashMap<String, Vec<ColumnInfo>> = HashMap::new();
        for col in &columns {
            tables
                .entry(col.table_name.clone())
                .or_default()
                .push(col.clone());
        }

        // Filter out excluded tables
        let tables: HashMap<String, Vec<ColumnInfo>> = tables
            .into_iter()
            .filter(|(name, _)| !config.exclude_tables.contains(name))
            .collect();

        info!(
            "Scanning {} tables (excluding {:?})",
            tables.len(),
            config.exclude_tables
        );

        let mut findings = Vec::new();
        let mut columns_scanned = 0;

        for (table_name, table_columns) in &tables {
            // Sample data from this table
            let sample_data = self
                .sample_postgres_table(&client, &config.schema, table_name, config.sample_size)
                .await?;

            for col in table_columns {
                columns_scanned += 1;

                // Skip non-string columns (unlikely to contain PII patterns)
                if !self.is_scannable_type(&col.data_type) {
                    debug!(
                        "Skipping column {}.{} (type: {})",
                        table_name, col.column_name, col.data_type
                    );
                    continue;
                }

                // Check column name heuristics first
                let name_pii_type = self.check_column_name_heuristics(&col.column_name);

                // Sample column values and scan for PII
                let (match_count, detected_type, sample_value) =
                    self.scan_column_values(&sample_data, &col.column_name);

                let row_count = sample_data.len();
                let confidence = if row_count > 0 {
                    match_count as f64 / row_count as f64
                } else {
                    0.0
                };

                // Combine column name heuristics with data scanning
                let (final_type, final_confidence) = if let Some(name_type) = name_pii_type {
                    // Boost confidence if column name suggests PII
                    if let Some(data_type) = detected_type {
                        if name_type == data_type {
                            // Both agree - high confidence
                            (Some(data_type), (confidence + 0.3).min(1.0))
                        } else {
                            // Conflict - trust data over name but lower confidence
                            (Some(data_type), confidence * 0.8)
                        }
                    } else if confidence < config.confidence_threshold {
                        // Name suggests PII but no data matches - medium confidence
                        (Some(name_type), 0.6)
                    } else {
                        (detected_type, confidence)
                    }
                } else {
                    (detected_type, confidence)
                };

                if let Some(pii_type) = final_type {
                    if final_confidence >= config.confidence_threshold {
                        findings.push(PiiFinding {
                            table: table_name.clone(),
                            column: col.column_name.clone(),
                            pii_type: format!("{:?}", pii_type),
                            confidence: (final_confidence * 100.0).round() / 100.0,
                            sample: sample_value.map(|s| self.mask_sample(&s)),
                            row_count,
                            match_count,
                            data_type: col.data_type.clone(),
                        });
                    }
                }
            }
        }

        let duration = start.elapsed();

        Ok(ScanResult {
            status: "completed".to_string(),
            tables_scanned: tables.len(),
            columns_scanned,
            findings,
            schema: config.schema.clone(),
            database: config.database.clone(),
            scan_duration_ms: duration.as_millis() as u64,
        })
    }

    /// Connect to PostgreSQL database
    async fn connect_postgres(&self, config: &ScanConfig) -> Result<Client, ScanError> {
        let conn_str = format!(
            "host={} port={} user={} password={} dbname={} sslmode=prefer connect_timeout=10",
            self.host, self.port, config.username, config.password, config.database
        );

        debug!("Connecting to PostgreSQL: host={}, port={}, db={}", self.host, self.port, config.database);
        
        let (client, connection) = tokio_postgres::connect(&conn_str, NoTls)
            .await
            .map_err(|e| {
                warn!("PostgreSQL connection failed: {}", e);
                ScanError::ConnectionFailed(format!("{}", e))
            })?;

        // Spawn connection handler
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                warn!("PostgreSQL connection error: {}", e);
            }
        });

        info!(
            "Connected to PostgreSQL at {}:{}/{}",
            self.host, self.port, config.database
        );
        Ok(client)
    }

    /// Get column information from PostgreSQL information_schema
    async fn get_postgres_columns(
        &self,
        client: &Client,
        schema: &str,
    ) -> Result<Vec<ColumnInfo>, ScanError> {
        let query = r#"
            SELECT 
                table_name,
                column_name,
                data_type,
                is_nullable,
                character_maximum_length
            FROM information_schema.columns
            WHERE table_schema = $1
            AND table_name NOT LIKE 'pg_%'
            AND table_name NOT LIKE 'sql_%'
            ORDER BY table_name, ordinal_position
        "#;

        let rows = client
            .query(query, &[&schema])
            .await
            .map_err(|e| ScanError::QueryFailed(e.to_string()))?;

        let columns = rows
            .iter()
            .map(|row| ColumnInfo {
                table_name: row.get("table_name"),
                column_name: row.get("column_name"),
                data_type: row.get("data_type"),
                is_nullable: row.get::<_, String>("is_nullable") == "YES",
                character_maximum_length: row.get("character_maximum_length"),
            })
            .collect();

        Ok(columns)
    }

    /// Get PostgreSQL schema information
    async fn get_postgres_schema(&self, config: &ScanConfig) -> Result<SchemaInfo, ScanError> {
        let client = self.connect_postgres(config).await?;
        let columns = self.get_postgres_columns(&client, &config.schema).await?;

        // Group by table
        let mut table_map: HashMap<String, Vec<ColumnInfo>> = HashMap::new();
        for col in columns {
            table_map
                .entry(col.table_name.clone())
                .or_default()
                .push(col);
        }

        // Get row counts for each table
        let mut tables = Vec::new();
        for (table_name, cols) in table_map {
            if config.exclude_tables.contains(&table_name) {
                continue;
            }

            let row_count = self
                .get_table_row_count(&client, &config.schema, &table_name)
                .await
                .ok();

            tables.push(TableInfo {
                name: table_name,
                columns: cols,
                row_count,
            });
        }

        // Sort tables by name
        tables.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(SchemaInfo {
            database: config.database.clone(),
            schema: config.schema.clone(),
            tables,
        })
    }

    /// Get row count for a table
    async fn get_table_row_count(
        &self,
        client: &Client,
        schema: &str,
        table: &str,
    ) -> Result<i64, ScanError> {
        // Use pg_stat_user_tables for approximate count (faster than COUNT(*))
        let query = r#"
            SELECT n_live_tup::bigint as count
            FROM pg_stat_user_tables
            WHERE schemaname = $1 AND relname = $2
        "#;

        let rows = client
            .query(query, &[&schema, &table])
            .await
            .map_err(|e| ScanError::QueryFailed(e.to_string()))?;

        if let Some(row) = rows.first() {
            Ok(row.get("count"))
        } else {
            Ok(0)
        }
    }

    /// Sample data from a PostgreSQL table
    async fn sample_postgres_table(
        &self,
        client: &Client,
        schema: &str,
        table: &str,
        limit: usize,
    ) -> Result<Vec<HashMap<String, Option<String>>>, ScanError> {
        // Use TABLESAMPLE for large tables, or LIMIT for smaller ones
        let query = format!(
            r#"SELECT * FROM "{}"."{}" LIMIT {}"#,
            schema, table, limit
        );

        let rows = client
            .query(&query, &[])
            .await
            .map_err(|e| ScanError::QueryFailed(format!("Failed to sample {}.{}: {}", schema, table, e)))?;

        let result: Vec<HashMap<String, Option<String>>> = rows
            .iter()
            .map(|row| {
                let mut map = HashMap::new();
                for (idx, col) in row.columns().iter().enumerate() {
                    // Try to get value as string
                    let value: Option<String> = match col.type_().name() {
                        "int2" | "int4" | "int8" | "float4" | "float8" | "numeric" => {
                            // Handle numeric types
                            row.try_get::<_, Option<i64>>(idx)
                                .ok()
                                .flatten()
                                .map(|v| v.to_string())
                                .or_else(|| {
                                    row.try_get::<_, Option<f64>>(idx)
                                        .ok()
                                        .flatten()
                                        .map(|v| v.to_string())
                                })
                        }
                        "bool" => row
                            .try_get::<_, Option<bool>>(idx)
                            .ok()
                            .flatten()
                            .map(|v| v.to_string()),
                        _ => {
                            // Try as string (covers varchar, text, char, etc.)
                            row.try_get::<_, Option<String>>(idx).ok().flatten()
                        }
                    };
                    map.insert(col.name().to_string(), value);
                }
                map
            })
            .collect();

        debug!("Sampled {} rows from {}.{}", result.len(), schema, table);
        Ok(result)
    }

    /// Check if a data type is scannable for PII
    fn is_scannable_type(&self, data_type: &str) -> bool {
        matches!(
            data_type.to_lowercase().as_str(),
            "character varying"
                | "varchar"
                | "text"
                | "character"
                | "char"
                | "name"
                | "citext"
                | "bpchar"
        )
    }

    /// Check column name for PII heuristics
    fn check_column_name_heuristics(&self, column_name: &str) -> Option<PiiType> {
        let name_lower = column_name.to_lowercase();

        // Email patterns
        if name_lower.contains("email")
            || name_lower.contains("e_mail")
            || name_lower == "mail"
        {
            return Some(PiiType::Email);
        }

        // Phone patterns
        if name_lower.contains("phone")
            || name_lower.contains("mobile")
            || name_lower.contains("cell")
            || name_lower.contains("tel")
            || name_lower == "fax"
        {
            return Some(PiiType::Phone);
        }

        // SSN patterns
        if name_lower.contains("ssn")
            || name_lower.contains("social_security")
            || name_lower.contains("socialsecurity")
            || name_lower == "sin" // Canadian Social Insurance Number
            || name_lower == "national_id"
        {
            return Some(PiiType::Ssn);
        }

        // Credit card patterns
        if name_lower.contains("credit_card")
            || name_lower.contains("creditcard")
            || name_lower.contains("card_number")
            || name_lower.contains("cardnumber")
            || name_lower == "cc_num"
            || name_lower == "pan" // Primary Account Number
        {
            return Some(PiiType::CreditCard);
        }

        // IP address patterns
        if name_lower.contains("ip_address")
            || name_lower.contains("ipaddress")
            || name_lower == "ip"
            || name_lower == "client_ip"
            || name_lower == "remote_addr"
        {
            return Some(PiiType::IpAddress);
        }

        // Date of birth patterns
        if name_lower.contains("birth")
            || name_lower == "dob"
            || name_lower == "birthdate"
            || name_lower == "date_of_birth"
        {
            return Some(PiiType::DateOfBirth);
        }

        // Passport patterns
        if name_lower.contains("passport") {
            return Some(PiiType::Passport);
        }

        None
    }

    /// Scan column values for PII patterns
    fn scan_column_values(
        &self,
        sample_data: &[HashMap<String, Option<String>>],
        column_name: &str,
    ) -> (usize, Option<PiiType>, Option<String>) {
        let mut match_count = 0;
        let mut detected_type: Option<PiiType> = None;
        let mut sample_value: Option<String> = None;
        let mut type_counts: HashMap<PiiType, usize> = HashMap::new();

        for row in sample_data {
            if let Some(Some(value)) = row.get(column_name) {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    continue;
                }

                if let Some(pii_type) = self.pii_scanner.scan(trimmed) {
                    match_count += 1;
                    *type_counts.entry(pii_type.clone()).or_insert(0) += 1;

                    if sample_value.is_none() {
                        sample_value = Some(value.clone());
                    }
                }
            }
        }

        // Determine the most common PII type detected
        if let Some((most_common_type, _)) = type_counts.into_iter().max_by_key(|(_, count)| *count)
        {
            detected_type = Some(most_common_type);
        }

        (match_count, detected_type, sample_value)
    }

    /// Mask a sample value for display (don't expose full PII)
    fn mask_sample(&self, value: &str) -> String {
        let len = value.len();
        if len <= 4 {
            "*".repeat(len)
        } else if len <= 8 {
            format!("{}***{}", &value[..2], &value[len - 2..])
        } else {
            format!("{}***{}", &value[..3], &value[len - 3..])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_column_name_heuristics() {
        let scanner = DbScanner::new("localhost".to_string(), 5432, DbProtocol::Postgres);

        assert_eq!(
            scanner.check_column_name_heuristics("email"),
            Some(PiiType::Email)
        );
        assert_eq!(
            scanner.check_column_name_heuristics("user_email"),
            Some(PiiType::Email)
        );
        assert_eq!(
            scanner.check_column_name_heuristics("phone_number"),
            Some(PiiType::Phone)
        );
        assert_eq!(
            scanner.check_column_name_heuristics("mobile"),
            Some(PiiType::Phone)
        );
        assert_eq!(
            scanner.check_column_name_heuristics("ssn"),
            Some(PiiType::Ssn)
        );
        assert_eq!(
            scanner.check_column_name_heuristics("credit_card_number"),
            Some(PiiType::CreditCard)
        );
        assert_eq!(
            scanner.check_column_name_heuristics("cc_num"),
            Some(PiiType::CreditCard)
        );
        assert_eq!(
            scanner.check_column_name_heuristics("ip_address"),
            Some(PiiType::IpAddress)
        );
        assert_eq!(
            scanner.check_column_name_heuristics("dob"),
            Some(PiiType::DateOfBirth)
        );
        assert_eq!(
            scanner.check_column_name_heuristics("passport_number"),
            Some(PiiType::Passport)
        );
        assert_eq!(
            scanner.check_column_name_heuristics("username"),
            None
        );
        assert_eq!(
            scanner.check_column_name_heuristics("created_at"),
            None
        );
    }

    #[test]
    fn test_is_scannable_type() {
        let scanner = DbScanner::new("localhost".to_string(), 5432, DbProtocol::Postgres);

        assert!(scanner.is_scannable_type("character varying"));
        assert!(scanner.is_scannable_type("varchar"));
        assert!(scanner.is_scannable_type("text"));
        assert!(scanner.is_scannable_type("character"));
        assert!(!scanner.is_scannable_type("integer"));
        assert!(!scanner.is_scannable_type("boolean"));
        assert!(!scanner.is_scannable_type("timestamp"));
    }

    #[test]
    fn test_mask_sample() {
        let scanner = DbScanner::new("localhost".to_string(), 5432, DbProtocol::Postgres);

        assert_eq!(scanner.mask_sample("abc"), "***");
        assert_eq!(scanner.mask_sample("abcd"), "****");
        assert_eq!(scanner.mask_sample("abcdefgh"), "ab***gh");
        assert_eq!(scanner.mask_sample("test@example.com"), "tes***com");
        assert_eq!(scanner.mask_sample("123-45-6789"), "123***789");
    }
}
