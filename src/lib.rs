//! Iron Veil — a PII-masking database proxy.
//!
//! The binary in `main.rs` is a thin driver over these modules. They are
//! exposed as a library so integration tests can exercise the real codecs,
//! scanner and interceptors instead of reimplementing them (the previous
//! integration suite asserted against inline copies that had already drifted
//! from production behaviour).

pub mod api;
pub mod audit;
pub mod config;
pub mod db_scanner;
pub mod interceptor;
pub mod metrics;
pub mod protocol;
pub mod scanner;
pub mod state;
pub mod telemetry;
