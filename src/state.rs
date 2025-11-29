use std::sync::{Arc, atomic::AtomicUsize};
use tokio::sync::RwLock;
use crate::config::AppConfig;
use std::collections::VecDeque;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub connection_id: usize,
    pub event_type: String,
    pub content: String,
    pub details: Option<serde_json::Value>,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RwLock<AppConfig>>,
    pub active_connections: Arc<AtomicUsize>,
    pub logs: Arc<RwLock<VecDeque<LogEntry>>>,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            active_connections: Arc::new(AtomicUsize::new(0)),
            logs: Arc::new(RwLock::new(VecDeque::with_capacity(100))),
        }
    }

    pub async fn add_log(&self, entry: LogEntry) {
        let mut logs = self.logs.write().await;
        if logs.len() >= 100 {
            logs.pop_back();
        }
        logs.push_front(entry);
    }
}
