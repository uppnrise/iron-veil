use axum::{
    extract::State,
    routing::{get, post},
    Router,
    Json,
};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tower_http::cors::CorsLayer;
use crate::state::AppState;
use crate::config::MaskingRule;
use std::sync::atomic::Ordering;

pub async fn start_api_server(port: u16, state: AppState) {
    // Define the routes
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/rules", get(get_rules).post(add_rule))
        .route("/scan", post(scan_database))
        .route("/connections", get(get_connections))
        .route("/schema", get(get_schema))
        .route("/logs", get(get_logs))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Management API listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "db-proxy",
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
