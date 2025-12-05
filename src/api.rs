use crate::config::MaskingRule;
use crate::state::AppState;
use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

/// Middleware to validate API key for protected endpoints
async fn api_key_auth(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let config = state.config.read().await;
    
    // Check if API key authentication is enabled
    let required_key = config
        .api
        .as_ref()
        .and_then(|api| api.api_key.as_ref());
    
    match required_key {
        Some(expected_key) => {
            // API key is required - validate header
            let provided_key = request
                .headers()
                .get("X-API-Key")
                .and_then(|v| v.to_str().ok());
            
            match provided_key {
                Some(key) if key == expected_key => {
                    drop(config); // Release lock before calling next
                    next.run(request).await
                }
                Some(_) => {
                    (StatusCode::UNAUTHORIZED, Json(json!({
                        "error": "Invalid API key"
                    }))).into_response()
                }
                None => {
                    (StatusCode::UNAUTHORIZED, Json(json!({
                        "error": "Missing X-API-Key header"
                    }))).into_response()
                }
            }
        }
        None => {
            // No API key configured - allow all requests
            drop(config);
            next.run(request).await
        }
    }
}

pub async fn start_api_server(port: u16, state: AppState) -> anyhow::Result<()> {
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/health", get(health_check));
    
    // Protected routes (require API key if configured)
    let protected_routes = Router::new()
        .route("/rules", get(get_rules).post(add_rule))
        .route("/config", get(get_config).post(update_config))
        .route("/scan", post(scan_database))
        .route("/connections", get(get_connections))
        .route("/schema", get(get_schema))
        .route("/logs", get(get_logs))
        .layer(middleware::from_fn_with_state(state.clone(), api_key_auth));
    
    // Combine routes
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Management API listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind API server to {}: {}", addr, e))?;
    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow::anyhow!("API server error: {}", e))?;
    Ok(())
}

async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "ironveil",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn get_rules(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.read().await;
    Json(json!(*config))
}

async fn add_rule(State(state): State<AppState>, Json(rule): Json<MaskingRule>) -> Json<Value> {
    let mut config = state.config.write().await;
    config.rules.push(rule);
    Json(json!({ "status": "success", "rules_count": config.rules.len() }))
}

async fn get_config(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.read().await;
    Json(json!({
        "masking_enabled": config.masking_enabled,
        "rules_count": config.rules.len()
    }))
}

async fn update_config(State(state): State<AppState>, Json(payload): Json<Value>) -> Json<Value> {
    let mut config = state.config.write().await;
    if let Some(enabled) = payload.get("masking_enabled").and_then(|v| v.as_bool()) {
        config.masking_enabled = enabled;
    }
    Json(json!({ "status": "success", "masking_enabled": config.masking_enabled }))
}

async fn scan_database() -> Json<Value> {
    // Mocked scan results for Phase 3.3
    // In a real implementation, this would query the upstream DB and sample data.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await; // Simulate work

    Json(json!({
        "status": "completed",
        "findings": [
            {
                "table": "users",
                "column": "email",
                "type": "Email",
                "confidence": 0.99,
                "sample": "jdoe@example.com"
            },
            {
                "table": "users",
                "column": "phone_number",
                "type": "Phone",
                "confidence": 0.95,
                "sample": "+1-555-0123"
            },
            {
                "table": "orders",
                "column": "shipping_address",
                "type": "Address",
                "confidence": 0.85,
                "sample": "123 Main St, Springfield"
            },
            {
                "table": "customers",
                "column": "cc_num",
                "type": "CreditCard",
                "confidence": 0.98,
                "sample": "4532-xxxx-xxxx-1234"
            }
        ]
    }))
}

async fn get_connections(State(state): State<AppState>) -> Json<Value> {
    let count = state.active_connections.load(Ordering::Relaxed);
    Json(json!({
        "active_connections": count
    }))
}

async fn get_schema() -> Json<Value> {
    Json(json!({
        "tables": [],
        "note": "Schema discovery requires upstream connection. Coming in Phase 3.4"
    }))
}

async fn get_logs(State(state): State<AppState>) -> Json<Value> {
    let logs = state.logs.read().await;
    Json(json!({
        "logs": *logs
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiConfig, AppConfig};

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await;
        let json = response.0;

        assert_eq!(json["status"], "ok");
        assert_eq!(json["service"], "ironveil");
        assert!(json["version"].is_string());
    }

    #[tokio::test]
    async fn test_api_key_config_parsing() {
        // Test that API key is correctly parsed from config
        let config = AppConfig {
            api: Some(ApiConfig {
                api_key: Some("my-secret-key".to_string()),
            }),
            ..Default::default()
        };
        let state = AppState::new(config);
        let config_guard = state.config.read().await;
        
        let required_key = config_guard
            .api
            .as_ref()
            .and_then(|api| api.api_key.as_ref());
        
        assert_eq!(required_key, Some(&"my-secret-key".to_string()));
    }

    #[tokio::test]
    async fn test_api_key_none_when_not_configured() {
        // Test that no API key means None
        let config = AppConfig::default();
        let state = AppState::new(config);
        let config_guard = state.config.read().await;
        
        let required_key = config_guard
            .api
            .as_ref()
            .and_then(|api| api.api_key.as_ref());
        
        assert_eq!(required_key, None);
    }

    #[tokio::test]
    async fn test_get_config() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![MaskingRule {
                table: Some("users".to_string()),
                column: "email".to_string(),
                strategy: "email".to_string(),
            }],
            tls: None,
            upstream_tls: false,
            telemetry: None, api: None,
        };
        let state = AppState::new(config);

        let response = get_config(State(state)).await;
        let json = response.0;

        assert_eq!(json["masking_enabled"], true);
        assert_eq!(json["rules_count"], 1);
    }

    #[tokio::test]
    async fn test_update_config() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            tls: None,
            upstream_tls: false,
            telemetry: None, api: None,
        };
        let state = AppState::new(config);

        let payload = json!({ "masking_enabled": false });
        let response = update_config(State(state.clone()), Json(payload)).await;
        let json = response.0;

        assert_eq!(json["status"], "success");
        assert_eq!(json["masking_enabled"], false);

        // Verify state was actually updated
        let config = state.config.read().await;
        assert!(!config.masking_enabled);
    }

    #[tokio::test]
    async fn test_add_rule() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            tls: None,
            upstream_tls: false,
            telemetry: None, api: None,
        };
        let state = AppState::new(config);

        let new_rule = MaskingRule {
            table: Some("users".to_string()),
            column: "phone".to_string(),
            strategy: "phone".to_string(),
        };

        let response = add_rule(State(state.clone()), Json(new_rule)).await;
        let json = response.0;

        assert_eq!(json["status"], "success");
        assert_eq!(json["rules_count"], 1);

        // Verify rule was added
        let config = state.config.read().await;
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].column, "phone");
    }

    #[tokio::test]
    async fn test_get_rules() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![MaskingRule {
                table: None,
                column: "email".to_string(),
                strategy: "email".to_string(),
            }],
            tls: None,
            upstream_tls: false,
            telemetry: None, api: None,
        };
        let state = AppState::new(config);

        let response = get_rules(State(state)).await;
        let json = response.0;

        assert!(json["rules"].is_array());
        assert_eq!(json["rules"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_get_connections() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            tls: None,
            upstream_tls: false,
            telemetry: None, api: None,
        };
        let state = AppState::new(config);

        // Simulate some connections
        state.active_connections.fetch_add(3, Ordering::Relaxed);

        let response = get_connections(State(state)).await;
        let json = response.0;

        assert_eq!(json["active_connections"], 3);
    }

    #[tokio::test]
    async fn test_scan_database_returns_findings() {
        let response = scan_database().await;
        let json = response.0;

        assert_eq!(json["status"], "completed");
        assert!(json["findings"].is_array());

        let findings = json["findings"].as_array().unwrap();
        assert!(!findings.is_empty());

        // Check structure of first finding
        assert!(findings[0]["table"].is_string());
        assert!(findings[0]["column"].is_string());
        assert!(findings[0]["type"].is_string());
        assert!(findings[0]["confidence"].is_number());
    }
}
