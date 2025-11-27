use crate::protocol::postgres::{DataRow, RowDescription};
use crate::config::AppConfig;
use anyhow::Result;
use fake::faker::internet::en::SafeEmail;
use fake::faker::phone_number::en::PhoneNumber;
use fake::faker::address::en::CityName;
use fake::Fake;
use std::sync::Arc;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

pub trait PacketInterceptor {
    fn on_row_description(&mut self, msg: &RowDescription);
    fn on_data_row(&mut self, msg: DataRow) -> Result<DataRow>;
}

pub struct Anonymizer {
    config: Arc<AppConfig>,
    // Map of column index to masking strategy
    target_cols: Vec<(usize, String)>,
}

impl Anonymizer {
    pub fn new(config: Arc<AppConfig>) -> Self {
        Self {
            config,
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
                let table_match = rule.table.as_ref().map_or(true, |_t| {
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
        if self.target_cols.is_empty() {
            return Ok(msg);
        }

        for (idx, strategy) in &self.target_cols {
            if *idx < msg.values.len() {
                if let Some(val) = &mut msg.values[*idx] {
                    // Create a deterministic seed from the original value
                    let mut hasher = DefaultHasher::new();
                    val.hash(&mut hasher);
                    let seed = hasher.finish();
                    
                    // Create a seeded RNG
                    let mut rng = ChaCha8Rng::seed_from_u64(seed);

                    let fake_val: String = match strategy.as_str() {
                        "email" => SafeEmail().fake_with_rng(&mut rng),
                        "phone" => PhoneNumber().fake_with_rng(&mut rng),
                        "address" => CityName().fake_with_rng(&mut rng),
                        _ => "MASKED".to_string(),
                    };
                    
                    val.clear();
                    val.extend_from_slice(fake_val.as_bytes());
                }
            }
        }
        Ok(msg)
    }
}
