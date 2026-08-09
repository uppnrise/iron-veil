use crate::audit::{AuditEventType, AuditLogger, AuditOutcome, AuthMethod};
use crate::config::MaskingRule;
use crate::db_scanner::{DbScanner, ScanConfig, ScanError};
use crate::state::{AppState, DbProtocol};
use axum::extract::ConnectInfo;
use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

/// Compare secrets without a short-circuiting byte comparison: hashing both
/// sides to fixed-length digests removes the length and prefix timing oracle.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use sha2::{Digest, Sha256};
    Sha256::digest(a) == Sha256::digest(b)
}

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
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let config = state.config.read().await;
    let endpoint = request.uri().path().to_string();
    let method = request.method().to_string();
    let client_ip = client_addr.ip().to_string();

    let api_config = config.api.as_ref();
    let api_key = api_config.and_then(|c| c.api_key.as_ref());
    let jwt_secret = api_config.and_then(|c| c.jwt_secret.as_ref());

    // With no credentials configured the server only ever binds loopback
    // (start_api_server refuses anything else), so allow local requests.
    if api_key.is_none() && jwt_secret.is_none() {
        drop(config);
        return next.run(request).await;
    }

    // Try API key authentication first
    if let Some(expected_key) = api_key
        && let Some(provided_key) = request
            .headers()
            .get("X-API-Key")
            .and_then(|v| v.to_str().ok())
    {
        if constant_time_eq(provided_key.as_bytes(), expected_key.as_bytes()) {
            drop(config);
            // Log successful API key auth
            state
                .audit_logger
                .log(
                    AuditLogger::auth_success(AuthMethod::ApiKey, None)
                        .with_client_ip(&client_ip)
                        .with_endpoint(&endpoint)
                        .with_method(&method),
                )
                .await;
            return next.run(request).await;
        } else {
            drop(config);
            // Log failed API key auth
            state
                .audit_logger
                .log(
                    AuditLogger::auth_failure(AuthMethod::ApiKey, "Invalid API key")
                        .with_client_ip(&client_ip)
                        .with_endpoint(&endpoint)
                        .with_method(&method),
                )
                .await;
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Invalid API key"
                })),
            )
                .into_response();
        }
    }

    // Try JWT authentication
    if let Some(secret) = jwt_secret
        && let Some(auth_header) = request
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
        && let Some(token) = auth_header.strip_prefix("Bearer ")
    {
        match validate_jwt(token, secret) {
            Ok(claims) => {
                drop(config);
                // Log successful JWT auth
                state
                    .audit_logger
                    .log(
                        AuditLogger::auth_success(AuthMethod::Jwt, Some(claims.sub))
                            .with_client_ip(&client_ip)
                            .with_endpoint(&endpoint)
                            .with_method(&method),
                    )
                    .await;
                return next.run(request).await;
            }
            Err(e) => {
                tracing::debug!("JWT validation failed: {}", e);
                drop(config);
                // Log failed JWT auth
                state
                    .audit_logger
                    .log(
                        AuditLogger::auth_failure(
                            AuthMethod::Jwt,
                            format!("JWT validation failed: {}", e),
                        )
                        .with_client_ip(&client_ip)
                        .with_endpoint(&endpoint)
                        .with_method(&method),
                    )
                    .await;
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "Invalid or expired JWT token"
                    })),
                )
                    .into_response();
            }
        }
    }

    drop(config);
    // Log denied access (no credentials)
    state
        .audit_logger
        .log(
            AuditLogger::auth_denied()
                .with_client_ip(&client_ip)
                .with_endpoint(&endpoint)
                .with_method(&method),
        )
        .await;

    // No valid authentication provided
    let config = state.config.read().await;
    let api_config = config.api.as_ref();
    let api_key = api_config.and_then(|c| c.api_key.as_ref());
    let jwt_secret = api_config.and_then(|c| c.jwt_secret.as_ref());
    let auth_methods: Vec<&str> = [
        api_key.map(|_| "X-API-Key header"),
        jwt_secret.map(|_| "Authorization: Bearer <token>"),
    ]
    .into_iter()
    .flatten()
    .collect();

    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": "Authentication required",
            "methods": auth_methods
        })),
    )
        .into_response()
}

/// The authenticated half of the management API. Extracted so tests can drive
/// the real router (and therefore the real auth middleware) rather than
/// calling handlers directly and bypassing authorization entirely.
fn protected_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/rules", get(get_rules).post(add_rule))
        .route("/rules/delete", post(delete_rule))
        .route("/rules/export", get(export_rules))
        .route("/rules/import", post(import_rules))
        .route("/config", get(get_config).post(update_config))
        .route("/config/reload", post(reload_config))
        .route("/scan", post(scan_database))
        .route("/connections", get(get_connections))
        .route("/stats", get(get_stats))
        .route("/schema", post(get_schema))
        .route("/logs", get(get_logs))
        .route("/audit", get(get_audit_logs))
        .layer(middleware::from_fn_with_state(state, api_auth))
}

pub async fn start_api_server(bind: IpAddr, port: u16, state: AppState) -> anyhow::Result<()> {
    let (has_credentials, cors_origins) = {
        let config = state.config.read().await;
        let api = config.api.as_ref();
        (
            api.map(|a| a.api_key.is_some() || a.jwt_secret.is_some())
                .unwrap_or(false),
            api.and_then(|a| a.cors_origins.clone()).unwrap_or_else(|| {
                vec![
                    "http://localhost:3000".to_string(),
                    "http://127.0.0.1:3000".to_string(),
                ]
            }),
        )
    };

    // Fail closed: the management API is a global masking kill-switch. It may
    // only be reachable beyond loopback when credentials are configured.
    if !bind.is_loopback() && !has_credentials {
        anyhow::bail!(
            "refusing to bind the management API to non-loopback address {} without \
             api.api_key or api.jwt_secret configured",
            bind
        );
    }
    if !has_credentials {
        tracing::warn!(
            "management API has no api_key/jwt_secret configured; it is unauthenticated \
             and restricted to loopback ({bind})"
        );
    }

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/metrics", get(get_metrics));

    // Protected routes (require API key or JWT if configured)
    let protected_routes = protected_router(state.clone());

    // Explicit CORS allow-list: a permissive layer let any web page a
    // browser on the network visits drive the management API cross-origin.
    let allowed_origins: Vec<axum::http::HeaderValue> =
        cors_origins.iter().filter_map(|o| o.parse().ok()).collect();
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origins))
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderName::from_static("x-api-key"),
        ]);

    // Combine routes
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::new(bind, port);
    tracing::info!("Management API listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind API server to {}: {}", addr, e))?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("API server error: {}", e))?;
    Ok(())
}

async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    let checks_enabled = {
        let config = state.config.read().await;
        config
            .health_check
            .as_ref()
            .map(|h| h.enabled)
            .unwrap_or(true)
    };
    let health_status = state.health_status.read().await;
    let active_connections = state.active_connections.load(Ordering::Relaxed);
    let protocol = match state.db_protocol {
        DbProtocol::Postgres => "postgres",
        DbProtocol::MySql => "mysql",
    };

    // "unknown" when checks are off, "starting" until the first probe lands.
    // Upstream host/port and raw error text are deliberately not exposed on
    // this public route (topology / credential-probing oracle).
    let (status, code) = if !checks_enabled {
        ("unknown", StatusCode::OK)
    } else if health_status.last_check.is_none() {
        ("starting", StatusCode::SERVICE_UNAVAILABLE)
    } else if health_status.healthy {
        ("ok", StatusCode::OK)
    } else {
        ("degraded", StatusCode::SERVICE_UNAVAILABLE)
    };

    let response = json!({
        "status": status,
        "service": "ironveil",
        "version": env!("CARGO_PKG_VERSION"),
        "upstream": {
            "protocol": protocol,
            "healthy": health_status.healthy,
            "last_check": health_status.last_check,
            "latency_ms": health_status.latency_ms,
            "consecutive_failures": health_status.consecutive_failures,
            "consecutive_successes": health_status.consecutive_successes
        },
        "connections": {
            "active": active_connections
        }
    });

    (code, Json(response))
}

async fn get_rules(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.read().await;
    Json(json!({
        "rules": config.rules
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleMutationOutcome {
    Added,
    Updated,
    Unchanged,
}

impl RuleMutationOutcome {
    fn as_str(self) -> &'static str {
        match self {
            RuleMutationOutcome::Added => "added",
            RuleMutationOutcome::Updated => "updated",
            RuleMutationOutcome::Unchanged => "unchanged",
        }
    }
}

fn normalized_rule_key(rule: &MaskingRule) -> (Option<String>, String) {
    let table = rule.table.as_ref().map(|t| t.trim().to_ascii_lowercase());
    let column = rule.column.trim().to_ascii_lowercase();
    (table, column)
}

fn dedupe_rules(rules: &mut Vec<MaskingRule>) -> usize {
    let original_len = rules.len();
    let mut seen = HashSet::new();
    rules.retain(|rule| seen.insert(normalized_rule_key(rule)));
    original_len - rules.len()
}

fn upsert_rule(rules: &mut Vec<MaskingRule>, incoming: MaskingRule) -> RuleMutationOutcome {
    let incoming_key = normalized_rule_key(&incoming);
    if let Some(existing) = rules
        .iter_mut()
        .find(|rule| normalized_rule_key(rule) == incoming_key)
    {
        if existing.strategy == incoming.strategy {
            RuleMutationOutcome::Unchanged
        } else {
            existing.strategy = incoming.strategy;
            RuleMutationOutcome::Updated
        }
    } else {
        rules.push(incoming);
        RuleMutationOutcome::Added
    }
}

/// Lowercase/trim rule identifiers at ingest so matching is consistent with
/// the wire-side normalization on both protocols.
fn normalize_rule(rule: &mut MaskingRule) {
    rule.column = rule.column.trim().to_ascii_lowercase();
    rule.table = rule
        .table
        .as_ref()
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty());
}

fn invalid_strategy_response(strategy: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "status": "error",
            "error": format!(
                "unknown masking strategy '{}' (known: {})",
                strategy,
                crate::config::KNOWN_STRATEGIES.join(", ")
            )
        })),
    )
}

async fn add_rule(
    State(state): State<AppState>,
    Json(mut rule): Json<MaskingRule>,
) -> impl IntoResponse {
    if !crate::config::KNOWN_STRATEGIES.contains(&rule.strategy.as_str()) {
        return invalid_strategy_response(&rule.strategy);
    }
    normalize_rule(&mut rule);

    // Mutate a clone and only swap it in after persistence succeeds, so a
    // failed write can never leave live state diverged from disk.
    let mut new_config = state.config.read().await.clone();
    let rule_json = serde_json::to_value(&rule).unwrap_or_default();
    let deduplicated_existing = dedupe_rules(&mut new_config.rules);
    let result = upsert_rule(&mut new_config.rules, rule);
    let rules_count = new_config.rules.len();

    if let Err(e) = state.commit_config(new_config).await {
        tracing::error!("Failed to save config: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "error": format!("Failed to persist rule: {}", e),
            })),
        );
    }

    // Log audit event
    state
        .audit_logger
        .log(AuditLogger::rule_added(json!({
            "rule": rule_json,
            "result": result.as_str(),
            "deduplicated_existing": deduplicated_existing
        })))
        .await;

    (
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "result": result.as_str(),
            "rules_count": rules_count,
            "deduplicated_existing": deduplicated_existing
        })),
    )
}

/// Delete rule request payload. Rules are identified by (table, column) —
/// positional indexes were racy: a concurrent mutation reordered the list and
/// the confirmed delete removed a different masking rule.
#[derive(Debug, Deserialize, Serialize)]
struct DeleteRuleRequest {
    /// Column name of the rule to delete
    column: String,
    /// Optionally scope to a table name
    table: Option<String>,
}

async fn delete_rule(
    State(state): State<AppState>,
    Json(req): Json<DeleteRuleRequest>,
) -> impl IntoResponse {
    let delete_details = serde_json::to_value(&req).unwrap_or_default();
    let column = req.column.trim().to_ascii_lowercase();
    let table = req.table.as_ref().map(|t| t.trim().to_ascii_lowercase());

    let mut new_config = state.config.read().await.clone();
    let original_len = new_config.rules.len();
    new_config.rules.retain(|rule| {
        let (rule_table, rule_column) = normalized_rule_key(rule);
        if rule_column != column {
            return true;
        }
        match &table {
            Some(table) => rule_table.as_ref() != Some(table),
            None => false,
        }
    });

    let deleted_count = original_len - new_config.rules.len();
    let rules_count = new_config.rules.len();
    if deleted_count == 0 {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "status": "error",
                "error": "No rule matched the given table/column"
            })),
        );
    }

    if let Err(e) = state.commit_config(new_config).await {
        tracing::error!("Failed to save config: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "error": format!("Failed to persist changes: {}", e)
            })),
        );
    }

    // Log audit event
    state
        .audit_logger
        .log(AuditLogger::rule_deleted(json!({
            "request": delete_details,
            "deleted_count": deleted_count
        })))
        .await;

    (
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "deleted": deleted_count,
            "rules_count": rules_count
        })),
    )
}

/// Export rules as JSON
async fn export_rules(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.config.read().await;
    let rules_json =
        serde_json::to_string_pretty(&config.rules).unwrap_or_else(|_| "[]".to_string());

    (
        StatusCode::OK,
        [
            ("content-type", "application/json"),
            (
                "content-disposition",
                "attachment; filename=\"ironveil-rules.json\"",
            ),
        ],
        rules_json,
    )
}

/// Import rules from JSON
async fn import_rules(
    State(state): State<AppState>,
    Json(rules): Json<Vec<MaskingRule>>,
) -> impl IntoResponse {
    if let Some(bad) = rules
        .iter()
        .find(|r| !crate::config::KNOWN_STRATEGIES.contains(&r.strategy.as_str()))
    {
        return invalid_strategy_response(&bad.strategy);
    }

    let mut new_config = state.config.read().await.clone();
    let imported_count = rules.len();
    let deduplicated_existing = dedupe_rules(&mut new_config.rules);
    let mut added = 0usize;
    let mut updated = 0usize;
    let mut unchanged = 0usize;
    for mut rule in rules {
        normalize_rule(&mut rule);
        match upsert_rule(&mut new_config.rules, rule) {
            RuleMutationOutcome::Added => added += 1,
            RuleMutationOutcome::Updated => updated += 1,
            RuleMutationOutcome::Unchanged => unchanged += 1,
        }
    }
    let total_count = new_config.rules.len();

    if let Err(e) = state.commit_config(new_config).await {
        tracing::error!("Failed to save config: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "error": format!("Failed to persist imported rules: {}", e)
            })),
        );
    }

    // Log audit event
    state
        .audit_logger
        .log(AuditLogger::rules_imported(imported_count))
        .await;

    (
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "imported": imported_count,
            "rules_count": total_count,
            "added": added,
            "updated": updated,
            "unchanged": unchanged,
            "deduplicated_existing": deduplicated_existing
        })),
    )
}

async fn get_config(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.read().await;
    Json(json!({
        "masking_enabled": config.masking_enabled,
        "rules_count": config.rules.len()
    }))
}

async fn update_config(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    let mut new_config = state.config.read().await.clone();
    let mut changes = serde_json::Map::new();

    if let Some(enabled) = payload.get("masking_enabled").and_then(|v| v.as_bool()) {
        let old_value = new_config.masking_enabled;
        new_config.masking_enabled = enabled;
        changes.insert(
            "masking_enabled".to_string(),
            json!({
                "old": old_value,
                "new": enabled
            }),
        );
    }

    // Persist first; only report (and audit) a change that actually took.
    if !changes.is_empty() {
        if let Err(e) = state.commit_config(new_config).await {
            tracing::error!("Failed to persist config: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "status": "error",
                    "error": format!("Failed to persist config: {}", e)
                })),
            );
        }

        state
            .audit_logger
            .log(AuditLogger::config_change(Value::Object(changes)))
            .await;
    }

    let config = state.config.read().await;
    (
        StatusCode::OK,
        Json(json!({ "status": "success", "masking_enabled": config.masking_enabled })),
    )
}

/// Reload configuration from disk
async fn reload_config(State(state): State<AppState>) -> impl IntoResponse {
    match state.reload_config().await {
        Ok(rules_count) => {
            // Log audit event
            state
                .audit_logger
                .log(AuditLogger::config_reload(rules_count))
                .await;
            (
                StatusCode::OK,
                Json(json!({
                    "status": "success",
                    "message": "Configuration reloaded successfully",
                    "rules_count": rules_count
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "error": e
            })),
        ),
    }
}

/// Upper bound on a scan/schema request before it is cancelled: an unbounded
/// scan pins both the axum task and the upstream database.
const SCAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

async fn scan_database(
    State(state): State<AppState>,
    Json(config): Json<ScanConfig>,
) -> impl IntoResponse {
    let scanner = DbScanner::new(
        state.upstream_host.to_string(),
        state.upstream_port,
        state.db_protocol,
    );

    let result = match tokio::time::timeout(SCAN_TIMEOUT, scanner.scan(&config)).await {
        Ok(result) => result,
        Err(_) => {
            return (
                StatusCode::GATEWAY_TIMEOUT,
                Json(json!({
                    "status": "error",
                    "error": "scan timed out",
                    "code": "scan_timeout"
                })),
            );
        }
    };

    match result {
        Ok(result) => {
            // Log audit event
            state
                .audit_logger
                .log(AuditLogger::database_scan(
                    &config.database,
                    result.findings.len(),
                ))
                .await;
            (StatusCode::OK, Json(json!(result)))
        }
        Err(e) => scan_error_response(e),
    }
}

async fn get_connections(State(state): State<AppState>) -> Json<Value> {
    let count = state.active_connections.load(Ordering::Relaxed);
    Json(json!({
        "active_connections": count
    }))
}

/// Get application statistics (queries, masking, connections)
async fn get_stats(State(state): State<AppState>) -> Json<Value> {
    let stats = state.get_stats().await;
    let history = state.get_connection_history().await;
    let active_connections = state.active_connections.load(Ordering::Relaxed);

    Json(json!({
        "active_connections": active_connections,
        "total_connections": stats.total_connections,
        "masking": {
            "email": stats.masking.email,
            "phone": stats.masking.phone,
            "address": stats.masking.address,
            "credit_card": stats.masking.credit_card,
            "ssn": stats.masking.ssn,
            "ip": stats.masking.ip,
            "dob": stats.masking.dob,
            "passport": stats.masking.passport,
            "hash": stats.masking.hash,
            "json": stats.masking.json,
            "other": stats.masking.other,
            "total": stats.masking.total()
        },
        "queries": {
            "total": stats.queries.total_queries,
            "select": stats.queries.select_count,
            "insert": stats.queries.insert_count,
            "update": stats.queries.update_count,
            "delete": stats.queries.delete_count,
            "other": stats.queries.other_count
        },
        "history": history.iter().map(|p| json!({
            "timestamp": p.timestamp.to_rfc3339(),
            "active_connections": p.active_connections,
            "total_queries": p.total_queries,
            "total_masked": p.total_masked
        })).collect::<Vec<_>>()
    }))
}

async fn get_schema(
    State(state): State<AppState>,
    Json(config): Json<ScanConfig>,
) -> impl IntoResponse {
    let scanner = DbScanner::new(
        state.upstream_host.to_string(),
        state.upstream_port,
        state.db_protocol,
    );

    let result = match tokio::time::timeout(SCAN_TIMEOUT, scanner.get_schema(&config)).await {
        Ok(result) => result,
        Err(_) => {
            return (
                StatusCode::GATEWAY_TIMEOUT,
                Json(json!({
                    "status": "error",
                    "error": "schema query timed out",
                    "code": "scan_timeout"
                })),
            );
        }
    };

    match result {
        Ok(schema) => {
            // Log audit event
            state
                .audit_logger
                .log(AuditLogger::schema_query(
                    &config.database,
                    schema.tables.len(),
                ))
                .await;
            (StatusCode::OK, Json(json!(schema)))
        }
        Err(e) => scan_error_response(e),
    }
}

fn scan_error_response(error: ScanError) -> (StatusCode, Json<Value>) {
    match error {
        ScanError::UnsupportedProtocol(protocol) => (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({
                "status": "error",
                "error": format!("Unsupported database protocol: {:?}", protocol),
                "code": "unsupported_protocol"
            })),
        ),
        ScanError::AuthRequired => (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "status": "error",
                "error": "Authentication required: please provide database credentials",
                "code": "auth_required"
            })),
        ),
        // Raw driver errors carry SQLSTATE, role and database names — a
        // credential-probing oracle. Log the detail; return a stable code.
        ScanError::ConnectionFailed(message) => {
            tracing::warn!(error = %message, "database scan connection failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "status": "error",
                    "error": "could not connect to the upstream database (see server logs)",
                    "code": "connection_failed"
                })),
            )
        }
        ScanError::QueryFailed(message) => {
            tracing::warn!(error = %message, "database scan query failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "status": "error",
                    "error": "scan query failed (see server logs)",
                    "code": "query_failed"
                })),
            )
        }
    }
}

async fn get_logs(State(state): State<AppState>) -> Json<Value> {
    let logs = state.logs.read().await;
    Json(json!({
        "logs": *logs
    }))
}

/// Query parameters for audit log retrieval
#[derive(Debug, Deserialize)]
struct AuditQuery {
    /// Maximum number of entries to return
    limit: Option<usize>,
    /// Filter by event type
    event_type: Option<String>,
    /// Filter by outcome
    outcome: Option<String>,
}

/// Get audit logs with optional filtering
async fn get_audit_logs(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<AuditQuery>,
) -> Json<Value> {
    let limit = query.limit.unwrap_or(100);

    let entries = if let Some(event_type) = query.event_type {
        // Parse event type
        let event = match event_type.as_str() {
            "auth_attempt" => Some(AuditEventType::AuthAttempt),
            "config_change" => Some(AuditEventType::ConfigChange),
            "rule_added" => Some(AuditEventType::RuleAdded),
            "rule_deleted" => Some(AuditEventType::RuleDeleted),
            "rules_imported" => Some(AuditEventType::RulesImported),
            "config_reload" => Some(AuditEventType::ConfigReload),
            "database_scan" => Some(AuditEventType::DatabaseScan),
            "schema_query" => Some(AuditEventType::SchemaQuery),
            _ => None,
        };
        if let Some(e) = event {
            state.audit_logger.get_entries_by_type(e, Some(limit)).await
        } else {
            state.audit_logger.get_entries(Some(limit)).await
        }
    } else if let Some(outcome) = query.outcome {
        // Parse outcome
        let out = match outcome.as_str() {
            "success" => Some(AuditOutcome::Success),
            "failure" => Some(AuditOutcome::Failure),
            "denied" => Some(AuditOutcome::Denied),
            _ => None,
        };
        if let Some(o) = out {
            state
                .audit_logger
                .get_entries_by_outcome(o, Some(limit))
                .await
        } else {
            state.audit_logger.get_entries(Some(limit)).await
        }
    } else {
        state.audit_logger.get_entries(Some(limit)).await
    };

    Json(json!({
        "count": entries.len(),
        "entries": entries
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
    use crate::state::DbProtocol;
    use axum::body::to_bytes;
    use axum::extract::State;
    use tempfile::{NamedTempFile, tempdir};

    #[tokio::test]
    async fn test_health_check() {
        let config = AppConfig::default();
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let response = health_check(State(state)).await;
        let (status, _json) = response.into_response().into_parts();

        // Health is unknown until the first successful probe: readiness
        // gates must not pass against an unprobed upstream.
        assert_eq!(status.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_health_check_ok_after_successful_probe() {
        let config = AppConfig::default();
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        state.update_health_status(true, Some(3), None).await;

        let response = health_check(State(state)).await;
        let (status, _json) = response.into_response().into_parts();
        assert_eq!(status.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_includes_upstream_runtime_info() {
        let config = AppConfig::default();
        let state = AppState::new(
            config,
            "proxy.yaml".to_string(),
            "db.internal".to_string(),
            6432,
            DbProtocol::MySql,
        );

        state.update_health_status(true, Some(3), None).await;
        let response = health_check(State(state)).await.into_response();
        let (parts, body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::OK);

        let bytes = to_bytes(body, usize::MAX).await.unwrap();
        let payload: Value = serde_json::from_slice(&bytes).unwrap();

        // Topology (host/port) is deliberately absent from the public route
        assert!(payload["upstream"].get("host").is_none());
        assert!(payload["upstream"].get("port").is_none());
        assert_eq!(payload["upstream"]["protocol"], "mysql");
        assert_eq!(payload["upstream"]["healthy"], true);
    }

    #[tokio::test]
    async fn test_api_key_config_parsing() {
        // Test that API key is correctly parsed from config
        let config = AppConfig {
            api: Some(ApiConfig {
                api_key: Some("my-secret-key".to_string()),
                jwt_secret: None,
                bind: None,
                cors_origins: None,
            }),
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
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
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let config_guard = state.config.read().await;

        let required_key = config_guard
            .api
            .as_ref()
            .and_then(|api| api.api_key.as_ref());

        assert_eq!(required_key, None);
    }

    #[tokio::test]
    async fn test_jwt_validation_valid_token() {
        use jsonwebtoken::{EncodingKey, Header, encode};

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
        )
        .unwrap();

        let result = validate_jwt(&token, secret);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().sub, "test-user");
    }

    #[tokio::test]
    async fn test_jwt_validation_expired_token() {
        use jsonwebtoken::{EncodingKey, Header, encode};

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
        )
        .unwrap();

        let result = validate_jwt(&token, secret);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_jwt_validation_wrong_secret() {
        use jsonwebtoken::{EncodingKey, Header, encode};

        let claims = Claims {
            sub: "test-user".to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            iat: chrono::Utc::now().timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"correct-secret"),
        )
        .unwrap();

        let result = validate_jwt(&token, "wrong-secret");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_jwt_config_parsing() {
        let config = AppConfig {
            api: Some(ApiConfig {
                api_key: None,
                jwt_secret: Some("my-jwt-secret".to_string()),
                bind: None,
                cors_origins: None,
            }),
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
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
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());

        let response = get_config(State(state)).await;
        let json = response.0;

        assert_eq!(json["masking_enabled"], true);
        assert_eq!(json["rules_count"], 1);
    }

    #[tokio::test]
    async fn test_update_config() {
        let temp_file = NamedTempFile::new().unwrap();
        let config_path = temp_file.path().to_string_lossy().to_string();
        std::fs::write(
            &config_path,
            "masking_enabled: true\nupstream_tls: false\nrules: []\n",
        )
        .unwrap();

        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, config_path);

        let payload = json!({ "masking_enabled": false });
        let response = update_config(State(state.clone()), Json(payload))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify state was actually updated
        let config = state.config.read().await;
        assert!(!config.masking_enabled);
    }

    #[tokio::test]
    async fn test_add_rule() {
        let temp_file = NamedTempFile::new().unwrap();
        let config_path = temp_file.path().to_string_lossy().to_string();
        std::fs::write(
            &config_path,
            "masking_enabled: true\nupstream_tls: false\nrules: []\n",
        )
        .unwrap();

        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, config_path);

        let new_rule = MaskingRule {
            table: Some("users".to_string()),
            column: "phone".to_string(),
            strategy: "phone".to_string(),
        };

        // Call add_rule and verify rule was added to state
        let _ = add_rule(State(state.clone()), Json(new_rule)).await;

        // Verify rule was added
        let config = state.config.read().await;
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].column, "phone");
    }

    #[tokio::test]
    async fn test_add_rule_upserts_existing_rule_for_same_table_and_column() {
        let temp_file = NamedTempFile::new().unwrap();
        let config_path = temp_file.path().to_string_lossy().to_string();
        std::fs::write(&config_path, "masking_enabled: true\nrules: []\n").unwrap();

        let config = AppConfig {
            masking_enabled: true,
            rules: vec![MaskingRule {
                table: Some("users".to_string()),
                column: "email".to_string(),
                strategy: "email".to_string(),
            }],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, config_path);

        let updated_rule = MaskingRule {
            table: Some("Users".to_string()),
            column: "EMAIL".to_string(),
            strategy: "hash".to_string(),
        };

        let response = add_rule(State(state.clone()), Json(updated_rule))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let config = state.config.read().await;
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].strategy, "hash");
    }

    #[tokio::test]
    async fn test_import_rules_deduplicates_existing_and_imported_rules() {
        let temp_file = NamedTempFile::new().unwrap();
        let config_path = temp_file.path().to_string_lossy().to_string();
        std::fs::write(&config_path, "masking_enabled: true\nrules: []\n").unwrap();

        let config = AppConfig {
            masking_enabled: true,
            rules: vec![
                MaskingRule {
                    table: Some("users".to_string()),
                    column: "email".to_string(),
                    strategy: "email".to_string(),
                },
                MaskingRule {
                    table: Some("users".to_string()),
                    column: "email".to_string(),
                    strategy: "phone".to_string(),
                },
                MaskingRule {
                    table: Some("users".to_string()),
                    column: "phone".to_string(),
                    strategy: "phone".to_string(),
                },
            ],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, config_path);

        let imported = vec![
            MaskingRule {
                table: Some("users".to_string()),
                column: "email".to_string(),
                strategy: "hash".to_string(),
            },
            MaskingRule {
                table: Some("users".to_string()),
                column: "email".to_string(),
                strategy: "hash".to_string(),
            },
            MaskingRule {
                table: Some("users".to_string()),
                column: "PHONE".to_string(),
                strategy: "phone".to_string(),
            },
            MaskingRule {
                table: None,
                column: "address".to_string(),
                strategy: "address".to_string(),
            },
        ];

        let response = import_rules(State(state.clone()), Json(imported))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let config = state.config.read().await;
        assert_eq!(config.rules.len(), 3);
        assert!(
            config
                .rules
                .iter()
                .any(|r| r.table.as_deref() == Some("users")
                    && r.column == "email"
                    && r.strategy == "hash")
        );
        assert!(
            config
                .rules
                .iter()
                .any(|r| r.table.as_deref() == Some("users")
                    && r.column == "phone"
                    && r.strategy == "phone")
        );
        assert!(
            config
                .rules
                .iter()
                .any(|r| r.table.is_none() && r.column == "address" && r.strategy == "address")
        );
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
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());

        let response = get_rules(State(state)).await;
        let json = response.0;

        assert!(json["rules"].is_array());
        assert_eq!(json["rules"].as_array().unwrap().len(), 1);
        assert!(
            json.get("masking_enabled").is_none(),
            "GET /rules should return rules only, not full config"
        );
    }

    #[tokio::test]
    async fn test_delete_rule_by_column_and_table_only_deletes_matching_rule() {
        let temp_file = NamedTempFile::new().unwrap();
        let config_path = temp_file.path().to_string_lossy().to_string();
        std::fs::write(&config_path, "masking_enabled: true\nrules: []\n").unwrap();

        let config = AppConfig {
            masking_enabled: true,
            rules: vec![
                MaskingRule {
                    table: Some("users".to_string()),
                    column: "email".to_string(),
                    strategy: "email".to_string(),
                },
                MaskingRule {
                    table: Some("accounts".to_string()),
                    column: "email".to_string(),
                    strategy: "email".to_string(),
                },
                MaskingRule {
                    table: Some("users".to_string()),
                    column: "phone".to_string(),
                    strategy: "phone".to_string(),
                },
            ],
            ..Default::default()
        };

        let state = AppState::new_for_test(config, config_path);
        let request = DeleteRuleRequest {
            column: "email".to_string(),
            table: Some("users".to_string()),
        };

        let _ = delete_rule(State(state.clone()), Json(request)).await;

        let config = state.config.read().await;
        assert_eq!(config.rules.len(), 2);
        assert!(
            !config
                .rules
                .iter()
                .any(|r| r.table.as_deref() == Some("users") && r.column == "email")
        );
        assert!(
            config
                .rules
                .iter()
                .any(|r| r.table.as_deref() == Some("accounts") && r.column == "email")
        );
    }

    #[tokio::test]
    async fn test_update_config_persists_to_disk() {
        let temp_file = NamedTempFile::new().unwrap();
        let config_path = temp_file.path().to_string_lossy().to_string();
        std::fs::write(
            &config_path,
            "masking_enabled: true\nupstream_tls: false\nrules: []\n",
        )
        .unwrap();

        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, config_path.clone());

        let payload = json!({ "masking_enabled": false });
        let _ = update_config(State(state), Json(payload)).await;

        let persisted = AppConfig::load(&config_path).unwrap();
        assert!(!persisted.masking_enabled);
    }

    #[tokio::test]
    async fn test_update_config_returns_500_when_persist_fails() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
        };
        let dir = tempdir().unwrap();
        let config_path = dir.path().to_string_lossy().to_string();
        let state = AppState::new_for_test(config, config_path);

        let payload = json!({ "masking_enabled": false });
        let response = update_config(State(state), Json(payload))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_get_connections() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());

        // Simulate some connections
        state.active_connections.fetch_add(3, Ordering::Relaxed);

        let response = get_connections(State(state)).await;
        let json = response.0;

        assert_eq!(json["active_connections"], 3);
    }

    #[tokio::test]
    async fn test_scan_database_returns_not_implemented_for_unsupported_protocol() {
        let config = AppConfig::default();
        let state = AppState::new(
            config,
            "proxy.yaml".to_string(),
            "localhost".to_string(),
            3306,
            DbProtocol::MySql,
        );

        let request = ScanConfig {
            username: "user".to_string(),
            password: "pass".to_string(),
            database: "db".to_string(),
            sample_size: 10,
            schema: "public".to_string(),
            exclude_tables: vec![],
            confidence_threshold: 0.5,
        };

        let response = scan_database(State(state), Json(request))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn test_get_schema_returns_not_implemented_for_unsupported_protocol() {
        let config = AppConfig::default();
        let state = AppState::new(
            config,
            "proxy.yaml".to_string(),
            "localhost".to_string(),
            3306,
            DbProtocol::MySql,
        );

        let request = ScanConfig {
            username: "user".to_string(),
            password: "pass".to_string(),
            database: "db".to_string(),
            sample_size: 10,
            schema: "public".to_string(),
            exclude_tables: vec![],
            confidence_threshold: 0.5,
        };

        let response = get_schema(State(state), Json(request))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn test_scan_database_returns_unauthorized_for_missing_credentials() {
        let config = AppConfig::default();
        let state = AppState::new(
            config,
            "proxy.yaml".to_string(),
            "localhost".to_string(),
            5432,
            DbProtocol::Postgres,
        );

        let request = ScanConfig {
            username: "".to_string(),
            password: "".to_string(),
            database: "db".to_string(),
            sample_size: 10,
            schema: "public".to_string(),
            exclude_tables: vec![],
            confidence_threshold: 0.5,
        };

        let response = scan_database(State(state), Json(request))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_get_schema_returns_unauthorized_for_missing_credentials() {
        let config = AppConfig::default();
        let state = AppState::new(
            config,
            "proxy.yaml".to_string(),
            "localhost".to_string(),
            5432,
            DbProtocol::Postgres,
        );

        let request = ScanConfig {
            username: "".to_string(),
            password: "".to_string(),
            database: "db".to_string(),
            sample_size: 10,
            schema: "public".to_string(),
            exclude_tables: vec![],
            confidence_threshold: 0.5,
        };

        let response = get_schema(State(state), Json(request))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ------------------------------------------------------------------
    // api_auth middleware. These drive the real protected router through
    // tower::ServiceExt::oneshot; calling handlers directly (as the rest of
    // this module does) bypasses authorization entirely, which is why the
    // highest-consequence path in the product had no coverage.
    // ------------------------------------------------------------------

    fn auth_test_state(api: Option<ApiConfig>) -> AppState {
        AppState::new_for_test(
            AppConfig {
                api,
                ..Default::default()
            },
            "proxy.yaml".to_string(),
        )
    }

    async fn auth_request(state: AppState, headers: Vec<(&str, String)>) -> StatusCode {
        use tower::ServiceExt;

        let app = protected_router(state.clone()).with_state(state);
        let mut builder = Request::builder().uri("/rules").method("GET");
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let mut request = builder.body(Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50000))));

        app.oneshot(request).await.unwrap().status()
    }

    fn jwt_for(secret: &str, expires_in_secs: i64) -> String {
        use jsonwebtoken::{EncodingKey, Header, encode};
        let now = chrono::Utc::now().timestamp();
        let claims = Claims {
            sub: "tester".to_string(),
            exp: (now + expires_in_secs) as usize,
            iat: now as usize,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_api_auth_rejects_missing_credentials() {
        let state = auth_test_state(Some(ApiConfig {
            api_key: Some("secret".to_string()),
            jwt_secret: None,
            bind: None,
            cors_origins: None,
        }));
        assert_eq!(
            auth_request(state, vec![]).await,
            StatusCode::UNAUTHORIZED,
            "a configured API must reject unauthenticated requests"
        );
    }

    #[tokio::test]
    async fn test_api_auth_rejects_wrong_api_key() {
        let state = auth_test_state(Some(ApiConfig {
            api_key: Some("secret".to_string()),
            jwt_secret: None,
            bind: None,
            cors_origins: None,
        }));
        assert_eq!(
            auth_request(state, vec![("X-API-Key", "wrong".to_string())]).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn test_api_auth_accepts_correct_api_key() {
        let state = auth_test_state(Some(ApiConfig {
            api_key: Some("secret".to_string()),
            jwt_secret: None,
            bind: None,
            cors_origins: None,
        }));
        assert_eq!(
            auth_request(state, vec![("X-API-Key", "secret".to_string())]).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn test_api_auth_rejects_bearer_when_only_api_key_configured() {
        let state = auth_test_state(Some(ApiConfig {
            api_key: Some("secret".to_string()),
            jwt_secret: None,
            bind: None,
            cors_origins: None,
        }));
        assert_eq!(
            auth_request(
                state,
                vec![("Authorization", "Bearer anything".to_string())]
            )
            .await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn test_api_auth_accepts_valid_jwt_and_rejects_expired() {
        let state = auth_test_state(Some(ApiConfig {
            api_key: None,
            jwt_secret: Some("jwt-secret".to_string()),
            bind: None,
            cors_origins: None,
        }));

        let valid = jwt_for("jwt-secret", 3600);
        assert_eq!(
            auth_request(
                state.clone(),
                vec![("Authorization", format!("Bearer {valid}"))]
            )
            .await,
            StatusCode::OK
        );

        let expired = jwt_for("jwt-secret", -3600);
        assert_eq!(
            auth_request(state, vec![("Authorization", format!("Bearer {expired}"))]).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn test_api_auth_allows_when_no_credentials_configured() {
        // Locks in the intended behaviour of the no-credentials branch. It is
        // only reachable because start_api_server refuses to bind anything but
        // loopback in that configuration (see the test below).
        let state = auth_test_state(None);
        assert_eq!(auth_request(state, vec![]).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_start_api_server_refuses_public_bind_without_credentials() {
        let state = auth_test_state(None);
        let result = start_api_server(IpAddr::from([0, 0, 0, 0]), 0, state).await;
        let err = result.expect_err("binding 0.0.0.0 without credentials must fail");
        assert!(
            err.to_string().contains("non-loopback"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_add_rule_rejects_unknown_strategy() {
        let (status, _) = invalid_strategy_response("emial");
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
