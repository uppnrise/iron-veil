use crate::protocol::postgres::{DataRow, RowDescription};
use crate::config::AppConfig;
use crate::scanner::{PiiScanner, PiiType};
use anyhow::Result;
use fake::faker::internet::en::SafeEmail;
use fake::faker::phone_number::en::PhoneNumber;
use fake::faker::address::en::CityName;
use fake::faker::creditcard::en::CreditCardNumber;
use fake::Fake;
use std::sync::Arc;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

fn generate_fake_data(strategy: &str, seed: u64) -> String {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    match strategy {
        "email" => SafeEmail().fake_with_rng(&mut rng),
        "phone" => PhoneNumber().fake_with_rng(&mut rng),
        "address" => CityName().fake_with_rng(&mut rng),
        "credit_card" => CreditCardNumber().fake_with_rng(&mut rng),
        _ => "MASKED".to_string(),
    }
}

fn mask_json_recursively(val: &mut serde_json::Value, scanner: &PiiScanner) {
    match val {
        serde_json::Value::String(s) => {
            if let Some(pii_type) = scanner.scan(s) {
                let strategy = match pii_type {
                    PiiType::Email => "email",
                    PiiType::CreditCard => "credit_card",
                };
                
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

pub trait PacketInterceptor {
    fn on_row_description(&mut self, msg: &RowDescription);
    fn on_data_row(&mut self, msg: DataRow) -> Result<DataRow>;
}

pub struct Anonymizer {
    config: Arc<AppConfig>,
    scanner: PiiScanner,
    // Map of column index to masking strategy
    target_cols: Vec<(usize, String)>,
}

impl Anonymizer {
    pub fn new(config: Arc<AppConfig>) -> Self {
        Self {
            config,
            scanner: PiiScanner::new(),
            target_cols: Vec::new(),
        }
    }
}

impl PacketInterceptor for Anonymizer {
    fn on_row_description(&mut self, msg: &RowDescription) {
        self.target_cols.clear();
        
        for (i, field) in msg.fields.iter().enumerate() {
            for rule in &self.config.rules {
                // Check if rule applies to this column
                let table_match = rule.table.as_ref().is_none_or(|_t| {
                    // TODO: In a real app, we'd need to resolve table OID to name.
                    // For now, we assume the rule matches if table is None (global)
                    // or if we could somehow know the table name (which we don't easily from RowDescription alone without a cache).
                    // So for MVP, we'll ignore table name matching in RowDescription and just match on column name.
                    // A proper implementation would query pg_class to map OID -> Name.
                    true 
                });

                if table_match && rule.column == field.name {
                    self.target_cols.push((i, rule.strategy.clone()));
                    break; // Apply first matching rule
                }
            }
        }
    }

    fn on_data_row(&mut self, mut msg: DataRow) -> Result<DataRow> {
        for (i, val_opt) in msg.values.iter_mut().enumerate() {
            if let Some(val) = val_opt {
                // 1. Check for explicit rule
                let explicit_strategy = self.target_cols.iter()
                    .find(|(col_idx, _)| *col_idx == i)
                    .map(|(_, strategy)| strategy.as_str());

                // Handle explicit JSON strategy
                if let Some("json") = explicit_strategy {
                     if let Ok(s) = std::str::from_utf8(val) {
                        if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(s) {
                            mask_json_recursively(&mut json_val, &self.scanner);
                            let new_json = serde_json::to_string(&json_val)?;
                            val.clear();
                            val.extend_from_slice(new_json.as_bytes());
                            continue;
                        }
                     }
                }

                let strategy = if let Some(s) = explicit_strategy {
                    Some(s)
                } else {
                    // 2. Heuristic scan
                    if let Ok(s) = std::str::from_utf8(val) {
                        // Try JSON heuristic first if it looks like JSON
                        let trimmed = s.trim();
                        if (trimmed.starts_with('{') && trimmed.ends_with('}')) || 
                           (trimmed.starts_with('[') && trimmed.ends_with(']')) {
                            if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(s) {
                                mask_json_recursively(&mut json_val, &self.scanner);
                                if let Ok(new_json) = serde_json::to_string(&json_val) {
                                    val.clear();
                                    val.extend_from_slice(new_json.as_bytes());
                                    continue;
                                }
                            }
                        }

                        match self.scanner.scan(s) {
                            Some(PiiType::Email) => Some("email"),
                            Some(PiiType::CreditCard) => Some("credit_card"),
                            None => None,
                        }
                    } else {
                        None
                    }
                };

                if let Some(strat) = strategy {
                    // Create a deterministic seed from the original value
                    let mut hasher = DefaultHasher::new();
                    val.hash(&mut hasher);
                    let seed = hasher.finish();
                    
                    let fake_val = generate_fake_data(strat, seed);
                    
                    val.clear();
                    val.extend_from_slice(fake_val.as_bytes());
                }
            }
        }
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, MaskingRule};
    use crate::protocol::postgres::{FieldDescription, RowDescription};
    use bytes::BytesMut;

    #[test]
    fn test_heuristic_detection() {
        let config = Arc::new(AppConfig { rules: vec![] });
        let mut anonymizer = Anonymizer::new(config);

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
        row = anonymizer.on_data_row(row).unwrap();

        // Check results
        let val0 = std::str::from_utf8(row.values[0].as_ref().unwrap()).unwrap();
        let val1 = std::str::from_utf8(row.values[1].as_ref().unwrap()).unwrap();

        assert_ne!(val0, email, "Email should be masked");
        assert!(val0.contains("@"), "Masked value should still be an email");
        assert_eq!(val1, other, "Non-PII data should be unchanged");
    }
    
    #[test]
    fn test_explicit_rule_overrides_heuristic() {
         let config = Arc::new(AppConfig { 
             rules: vec![
                 MaskingRule {
                     table: None,
                     column: "email_col".to_string(),
                     strategy: "address".to_string(), // Intentionally wrong strategy to prove override
                 }
             ] 
         });
        let mut anonymizer = Anonymizer::new(config);
        
        let desc = RowDescription {
            fields: vec![
                FieldDescription {
                    name: "email_col".to_string(),
                    table_oid: 0,
                    column_index: 0,
                    type_oid: 0,
                    type_len: 0,
                    type_modifier: 0,
                    format_code: 0,
                }
            ]
        };
        
        anonymizer.on_row_description(&desc);

        let email = "test@example.com";
        let mut row = DataRow {
            values: vec![
                Some(BytesMut::from(email.as_bytes())),
            ],
        };

        row = anonymizer.on_data_row(row).unwrap();
        let val0 = std::str::from_utf8(row.values[0].as_ref().unwrap()).unwrap();
        
        // Should look like a city, not an email
        assert!(!val0.contains("@"), "Should be masked as address, not email");
    }

    #[test]
    fn test_json_masking() {
        let config = Arc::new(AppConfig { rules: vec![] });
        let mut anonymizer = Anonymizer::new(config);

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
            values: vec![
                Some(BytesMut::from(json_data.as_bytes())),
            ],
        };

        row = anonymizer.on_data_row(row).unwrap();
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
}
