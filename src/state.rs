use crate::config::AppConfig;
use chrono::{DateTime, Utc};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, atomic::{AtomicUsize, AtomicBool, Ordering}};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub connection_id: usize,
    pub event_type: String,
    pub content: String,
    pub details: Option<serde_json::Value>,
}

/// Upstream health status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub healthy: bool,
    pub last_check: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub latency_ms: Option<u64>,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self {
            healthy: true, // Assume healthy until proven otherwise
            last_check: None,
            last_error: None,
            consecutive_failures: 0,
            consecutive_successes: 0,
            latency_ms: None,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RwLock<AppConfig>>,
    pub config_path: Arc<String>,
    pub active_connections: Arc<AtomicUsize>,
    pub logs: Arc<RwLock<VecDeque<LogEntry>>>,
    pub upstream_healthy: Arc<AtomicBool>,
    pub health_status: Arc<RwLock<HealthStatus>>,
    pub metrics_handle: Option<Arc<PrometheusHandle>>,
}

impl AppState {
    pub fn new(config: AppConfig, config_path: String) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            config_path: Arc::new(config_path),
            active_connections: Arc::new(AtomicUsize::new(0)),
            logs: Arc::new(RwLock::new(VecDeque::with_capacity(100))),
            upstream_healthy: Arc::new(AtomicBool::new(true)),
            health_status: Arc::new(RwLock::new(HealthStatus::default())),
            metrics_handle: None,
        }
    }
    
    pub fn with_metrics(mut self, handle: PrometheusHandle) -> Self {
        self.metrics_handle = Some(Arc::new(handle));
        self
    }
    
    /// Save current config to the config file
    pub async fn save_config(&self) -> Result<(), std::io::Error> {
        let config = self.config.read().await;
        let yaml = serde_yaml::to_string(&*config)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&*self.config_path, yaml)
    }

    pub async fn add_log(&self, entry: LogEntry) {
        let mut logs = self.logs.write().await;
        if logs.len() >= 100 {
            logs.pop_back();
        }
        logs.push_front(entry);
    }
    
    /// Check if upstream is healthy (fast atomic check)
    pub fn is_upstream_healthy(&self) -> bool {
        self.upstream_healthy.load(Ordering::Relaxed)
    }
    
    /// Update upstream health status
    pub async fn update_health_status(&self, healthy: bool, latency_ms: Option<u64>, error: Option<String>) {
        let mut status = self.health_status.write().await;
        
        status.last_check = Some(Utc::now());
        status.latency_ms = latency_ms;
        
        if healthy {
            status.consecutive_successes += 1;
            status.consecutive_failures = 0;
            status.last_error = None;
        } else {
            status.consecutive_failures += 1;
            status.consecutive_successes = 0;
            status.last_error = error;
        }
        
        // Read config thresholds
        let config = self.config.read().await;
        let health_config = config.health_check.as_ref();
        let unhealthy_threshold = health_config.map(|h| h.unhealthy_threshold).unwrap_or(3);
        let healthy_threshold = health_config.map(|h| h.healthy_threshold).unwrap_or(1);
        drop(config);
        
        // Update healthy status based on thresholds
        if status.consecutive_failures >= unhealthy_threshold {
            status.healthy = false;
            self.upstream_healthy.store(false, Ordering::Relaxed);
        } else if status.consecutive_successes >= healthy_threshold {
            status.healthy = true;
            self.upstream_healthy.store(true, Ordering::Relaxed);
        }
    }
}
