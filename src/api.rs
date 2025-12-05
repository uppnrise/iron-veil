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
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    /// Subject (user identifier)
    sub: String,
    /// Expiration time (Unix timestamp)
    exp: usize,
    /// Issued at (Unix timestamp)
    #[serde(default)]
    iat: usize,
}

/// Validates a JWT token and returns the claims if valid
fn validate_jwt(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    
    let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}

/// Middleware to validate API key or JWT for protected endpoints
async fn api_auth(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let config = state.config.read().await;
    
    let api_config = config.api.as_ref();
    let api_key = api_config.and_then(|c| c.api_key.as_ref());
    let jwt_secret = api_config.and_then(|c| c.jwt_secret.as_ref());
    
    // If neither API key nor JWT is configured, allow all requests
    if api_key.is_none() && jwt_secret.is_none() {
        drop(config);
        return next.run(request).await;
    }
    
    // Try API key authentication first
    if let Some(expected_key) = api_key {
        if let Some(provided_key) = request
            .headers()
            .get("X-API-Key")
            .and_then(|v| v.to_str().ok())
        {
            if provided_key == expected_key {
                drop(config);
                return next.run(request).await;
            } else {
                return (StatusCode::UNAUTHORIZED, Json(json!({
                    "error": "Invalid API key"
                }))).into_response();
            }
        }
    }
    
    // Try JWT authentication
    if let Some(secret) = jwt_secret {
        if let Some(auth_header) = request
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
        {
            if let Some(token) = auth_header.strip_prefix("Bearer ") {
                match validate_jwt(token, secret) {
                    Ok(_claims) => {
                        drop(config);
                        return next.run(request).await;
                    }
                    Err(e) => {
                        tracing::debug!("JWT validation failed: {}", e);
                        return (StatusCode::UNAUTHORIZED, Json(json!({
                            "error": "Invalid or expired JWT token"
                        }))).into_response();
                    }
                }
            }
        }
    }
    
    // No valid authentication provided
    let auth_methods: Vec<&str> = [
        api_key.map(|_| "X-API-Key header"),
        jwt_secret.map(|_| "Authorization: Bearer <token>"),
    ]
    .into_iter()
    .flatten()
    .collect();
    
    (StatusCode::UNAUTHORIZED, Json(json!({
        "error": "Authentication required",
        "methods": auth_methods
    }))).into_response()
}

pub async fn start_api_server(port: u16, state: AppState) -> anyhow::Result<()> {
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/metrics", get(get_metrics));
    
    // Protected routes (require API key or JWT if configured)
    let protected_routes = Router::new()
        .route("/rules", get(get_rules).post(add_rule))
        .route("/config", get(get_config).post(update_config))
        .route("/scan", post(scan_database))
        .route("/connections", get(get_connections))
        .route("/schema", get(get_schema))
        .route("/logs", get(get_logs))
        .layer(middleware::from_fn_with_state(state.clone(), api_auth));
    
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

async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    let health_status = state.health_status.read().await;
    let active_connections = state.active_connections.load(Ordering::Relaxed);
    
    let response = json!({
        "status": if health_status.healthy { "ok" } else { "degraded" },
        "service": "ironveil",
        "version": env!("CARGO_PKG_VERSION"),
        "upstream": {
            "healthy": health_status.healthy,
            "last_check": health_status.last_check,
            "last_error": health_status.last_error,
            "latency_ms": health_status.latency_ms,
            "consecutive_failures": health_status.consecutive_failures,
            "consecutive_successes": health_status.consecutive_successes
        },
        "connections": {
            "active": active_connections
        }
    });
    
    if health_status.healthy {
        (StatusCode::OK, Json(response))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(response))
    }
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

/// Prometheus metrics endpoint
async fn get_metrics(State(state): State<AppState>) -> impl IntoResponse {
    match &state.metrics_handle {
        Some(handle) => {
            let metrics = handle.render();
            (
                StatusCode::OK,
                [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
                metrics,
            )
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            [("content-type", "text/plain; charset=utf-8")],
            "Metrics not enabled".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiConfig, AppConfig};
    use axum::extract::State;

    #[tokio::test]
    async fn test_health_check() {
        let config = AppConfig::default();
        let state = AppState::new(config);
        let response = health_check(State(state)).await;
        let (status, json) = response.into_response().into_parts();

        // For default state (healthy), we should get 200 OK
        assert_eq!(status.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_api_key_config_parsing() {
        // Test that API key is correctly parsed from config
        let config = AppConfig {
            api: Some(ApiConfig {
                api_key: Some("my-secret-key".to_string()),
                jwt_secret: None,
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
    async fn test_jwt_validation_valid_token() {
        use jsonwebtoken::{encode, EncodingKey, Header};
        
        let secret = "test-jwt-secret";
        let claims = Claims {
            sub: "test-user".to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            iat: chrono::Utc::now().timestamp() as usize,
        };
        
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        ).unwrap();
        
        let result = validate_jwt(&token, secret);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().sub, "test-user");
    }

    #[tokio::test]
    async fn test_jwt_validation_expired_token() {
        use jsonwebtoken::{encode, EncodingKey, Header};
        
        let secret = "test-jwt-secret";
        let claims = Claims {
            sub: "test-user".to_string(),
            exp: (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp() as usize,
            iat: (chrono::Utc::now() - chrono::Duration::hours(2)).timestamp() as usize,
        };
        
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        ).unwrap();
        
        let result = validate_jwt(&token, secret);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_jwt_validation_wrong_secret() {
        use jsonwebtoken::{encode, EncodingKey, Header};
        
        let claims = Claims {
            sub: "test-user".to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            iat: chrono::Utc::now().timestamp() as usize,
        };
        
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"correct-secret"),
        ).unwrap();
        
        let result = validate_jwt(&token, "wrong-secret");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_jwt_config_parsing() {
        let config = AppConfig {
            api: Some(ApiConfig {
                api_key: None,
                jwt_secret: Some("my-jwt-secret".to_string()),
            }),
            ..Default::default()
        };
        let state = AppState::new(config);
        let config_guard = state.config.read().await;
        
        let jwt_secret = config_guard
            .api
            .as_ref()
            .and_then(|api| api.jwt_secret.as_ref());
        
        assert_eq!(jwt_secret, Some(&"my-jwt-secret".to_string()));
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
            telemetry: None, api: None, limits: None,
            health_check: None,
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
            telemetry: None, api: None, limits: None,
            health_check: None,
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
            telemetry: None, api: None, limits: None,
            health_check: None,
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
            telemetry: None, api: None, limits: None,
            health_check: None,
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
            telemetry: None, api: None, limits: None,
            health_check: None,
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
