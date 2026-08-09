use anyhow::Result;
use clap::{Parser, ValueEnum};
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, info, info_span, warn};

use iron_veil::{api, config, interceptor, metrics, protocol, state, telemetry};

use crate::config::AppConfig;
use crate::interceptor::{Anonymizer, MySqlAnonymizer, MySqlPacketInterceptor, PacketInterceptor};
use crate::protocol::mysql::{MySqlCodec, MySqlMessage};
use crate::protocol::postgres::{DataRow, PgMessage, PostgresCodec, QueryMessage};
use crate::state::{AppState, DbProtocol as StateDbProtocol, LogEntry};
use bytes::{BufMut, Bytes};
use chrono::Utc;
use futures::{SinkExt, StreamExt};
use rustls_platform_verifier::Verifier;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::crypto::aws_lc_rs::default_provider;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ServerConfig, pki_types::CertificateDer, pki_types::PrivateKeyDer};
use tokio_util::codec::Framed;

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum DbProtocol {
    #[default]
    Postgres,
    Mysql,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 6543)]
    port: u16,

    /// Upstream database host
    #[arg(long, default_value = "127.0.0.1")]
    upstream_host: String,

    /// Upstream database port
    #[arg(long, default_value_t = 5432)]
    upstream_port: u16,

    /// Path to configuration file
    #[arg(long, default_value = "proxy.yaml")]
    config: String,

    /// Address the proxy listener binds to
    #[arg(long, default_value = "0.0.0.0")]
    bind: std::net::IpAddr,

    /// Management API port
    #[arg(long, default_value_t = 3001)]
    api_port: u16,

    /// Address the management API binds to (overrides api.bind from the
    /// config file; defaults to 127.0.0.1). Binding a non-loopback address
    /// requires api.api_key or api.jwt_secret.
    #[arg(long)]
    api_bind: Option<std::net::IpAddr>,

    /// Database protocol to proxy
    #[arg(long, value_enum, default_value_t = DbProtocol::Postgres)]
    protocol: DbProtocol,

    /// Graceful shutdown timeout in seconds
    #[arg(long, default_value_t = 30)]
    shutdown_timeout: u64,
}

/// Waits for a shutdown signal (SIGTERM, SIGINT, or Ctrl+C)
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("Received Ctrl+C, initiating shutdown..."),
        _ = terminate => info!("Received SIGTERM, initiating shutdown..."),
    }
}

/// Background task that periodically checks upstream database connectivity
async fn run_health_check_task(
    state: AppState,
    upstream_host: String,
    upstream_port: u16,
    config: Option<crate::config::HealthCheckConfig>,
) {
    let config = config.unwrap_or_default();
    let interval = Duration::from_secs(config.interval_secs);
    let timeout = Duration::from_secs(config.timeout_secs);

    info!(
        "Starting upstream health check task (interval: {}s, timeout: {}s)",
        config.interval_secs, config.timeout_secs
    );

    loop {
        let start = Instant::now();

        // Try to connect to upstream
        let connect_result = tokio::time::timeout(
            timeout,
            tokio::net::TcpStream::connect(format!("{}:{}", upstream_host, upstream_port)),
        )
        .await;

        let latency = start.elapsed().as_millis() as u64;

        match connect_result {
            Ok(Ok(_stream)) => {
                // Connection successful
                state.update_health_status(true, Some(latency), None).await;
                metrics::record_health_check(true, Some(latency));
                tracing::debug!(
                    "Health check passed: upstream {}:{} ({}ms)",
                    upstream_host,
                    upstream_port,
                    latency
                );
            }
            Ok(Err(e)) => {
                // Connection failed
                let error = format!("Connection failed: {}", e);
                state
                    .update_health_status(false, None, Some(error.clone()))
                    .await;
                metrics::record_health_check(false, None);
                warn!(
                    "Health check failed: upstream {}:{} - {}",
                    upstream_host, upstream_port, error
                );
            }
            Err(_) => {
                // Timeout
                let error = format!("Connection timeout after {}s", config.timeout_secs);
                state
                    .update_health_status(false, None, Some(error.clone()))
                    .await;
                metrics::record_health_check(false, None);
                metrics::record_upstream_timeout();
                warn!(
                    "Health check timeout: upstream {}:{} - {}",
                    upstream_host, upstream_port, error
                );
            }
        }

        tokio::time::sleep(interval).await;
    }
}

fn update_upstream_pool_metrics(pool: &Semaphore, max_size: usize) {
    let active = max_size.saturating_sub(pool.available_permits());
    metrics::set_upstream_pool_state(active, max_size);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpstreamPoolAcquireError {
    Closed,
    Timeout,
}

#[derive(Clone)]
struct UpstreamSlotManager {
    pool: Arc<Semaphore>,
    size: usize,
}

impl UpstreamSlotManager {
    fn new(size: usize) -> Self {
        let pool = Arc::new(Semaphore::new(size));
        update_upstream_pool_metrics(&pool, size);
        Self { pool, size }
    }

    #[cfg(test)]
    fn available_slots(&self) -> usize {
        self.pool.available_permits()
    }

    async fn acquire(
        &self,
        timeout: Duration,
    ) -> std::result::Result<UpstreamSlotLease, UpstreamPoolAcquireError> {
        match tokio::time::timeout(timeout, self.pool.clone().acquire_owned()).await {
            Ok(Ok(permit)) => {
                update_upstream_pool_metrics(&self.pool, self.size);
                Ok(UpstreamSlotLease {
                    pool: self.pool.clone(),
                    size: self.size,
                    permit: Some(permit),
                })
            }
            Ok(Err(_)) => Err(UpstreamPoolAcquireError::Closed),
            Err(_) => Err(UpstreamPoolAcquireError::Timeout),
        }
    }
}

struct UpstreamSlotLease {
    pool: Arc<Semaphore>,
    size: usize,
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for UpstreamSlotLease {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            drop(permit);
            update_upstream_pool_metrics(&self.pool, self.size);
        }
    }
}

/// Replace SQL string-literal contents with '?' before logging: query text in
/// INSERT/WHERE clauses routinely carries the exact PII this proxy exists to
/// suppress, and the log ring is re-served by GET /logs.
fn redact_sql_literals(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            out.push_str("'?'");
            let mut escaped = false;
            while let Some(n) = chars.next() {
                if escaped {
                    escaped = false;
                    continue;
                }
                match n {
                    '\\' => escaped = true,
                    '\'' => {
                        // '' is an escaped quote inside the literal
                        if chars.peek() == Some(&'\'') {
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn resolve_timeout_limits(
    limits: Option<&crate::config::LimitsConfig>,
) -> (Duration, Duration, Duration) {
    (
        Duration::from_secs(limits.map_or(30, |l| l.connect_timeout_secs)),
        Duration::from_secs(limits.map_or(300, |l| l.idle_timeout_secs)),
        Duration::from_secs(limits.map_or(5, |l| l.upstream_pool_wait_timeout_secs)),
    )
}

async fn connect_upstream_with_timeout(
    upstream_host: &str,
    upstream_port: u16,
    connect_timeout: Duration,
) -> Result<tokio::net::TcpStream> {
    match tokio::time::timeout(
        connect_timeout,
        tokio::net::TcpStream::connect(format!("{upstream_host}:{upstream_port}")),
    )
    .await
    {
        Ok(Ok(socket)) => Ok(socket),
        Ok(Err(err)) => Err(err.into()),
        Err(_) => {
            metrics::record_upstream_timeout();
            Err(anyhow::anyhow!(
                "Upstream connection timeout after {:?}",
                connect_timeout
            ))
        }
    }
}

fn build_postgres_fatal_error_packet(sqlstate: &str, message: &str) -> Vec<u8> {
    fn push_field(payload: &mut Vec<u8>, key: u8, value: &str) {
        payload.push(key);
        payload.extend_from_slice(value.as_bytes());
        payload.push(0);
    }

    let mut payload = Vec::new();
    push_field(&mut payload, b'S', "FATAL");
    push_field(&mut payload, b'V', "FATAL");
    push_field(&mut payload, b'C', sqlstate);
    push_field(&mut payload, b'M', message);
    payload.push(0);

    let mut packet = Vec::with_capacity(1 + 4 + payload.len());
    packet.push(b'E');
    packet.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    packet.extend_from_slice(&payload);
    packet
}

/// Build a FATAL ErrorResponse as a codec-level RegularMessage (for use on an
/// already-framed connection, e.g. during graceful shutdown).
fn build_postgres_fatal_regular_message(
    sqlstate: &str,
    message: &str,
) -> crate::protocol::postgres::RegularMessage {
    let mut payload = bytes::BytesMut::new();
    for (key, value) in [
        (b'S', "FATAL"),
        (b'V', "FATAL"),
        (b'C', sqlstate),
        (b'M', message),
    ] {
        payload.put_u8(key);
        payload.put_slice(value.as_bytes());
        payload.put_u8(0);
    }
    payload.put_u8(0);
    crate::protocol::postgres::RegularMessage {
        message_type: b'E',
        payload,
    }
}

fn build_mysql_err_packet(error_code: u16, sql_state: &str, message: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + 2 + 1 + 5 + message.len());
    payload.push(0xFF);
    payload.extend_from_slice(&error_code.to_le_bytes());
    payload.push(b'#');

    let mut state = *b"HY000";
    let provided = sql_state.as_bytes();
    if provided.len() == 5 {
        state.copy_from_slice(provided);
    }
    payload.extend_from_slice(&state);
    payload.extend_from_slice(message.as_bytes());

    let len = payload.len();
    let mut packet = Vec::with_capacity(4 + len);
    packet.push((len & 0xFF) as u8);
    packet.push(((len >> 8) & 0xFF) as u8);
    packet.push(((len >> 16) & 0xFF) as u8);
    packet.push(0); // sequence id
    packet.extend_from_slice(&payload);
    packet
}

async fn send_postgres_fatal_error_response<S>(
    client_socket: &mut S,
    sqlstate: &str,
    message: &str,
) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let packet = build_postgres_fatal_error_packet(sqlstate, message);
    client_socket.write_all(&packet).await?;
    client_socket.flush().await?;
    Ok(())
}

async fn send_mysql_err_response<S>(
    client_socket: &mut S,
    error_code: u16,
    sql_state: &str,
    message: &str,
) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let packet = build_mysql_err_packet(error_code, sql_state, message);
    client_socket.write_all(&packet).await?;
    client_socket.flush().await?;
    Ok(())
}

/// Background task that watches the config file for changes and reloads.
/// The notify callback feeds a tokio channel: blocking recv on a std channel
/// parked a runtime worker thread for seconds at a time.
async fn run_config_watcher(state: AppState, config_path: String) {
    use std::path::Path;

    let path = Path::new(&config_path);
    let parent = path.parent().unwrap_or(Path::new("."));

    // Create a channel to receive events
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    // Create a watcher with debounce
    let mut watcher: RecommendedWatcher = match Watcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        NotifyConfig::default().with_poll_interval(Duration::from_secs(2)),
    ) {
        Ok(w) => w,
        Err(e) => {
            warn!(
                "Failed to create config file watcher: {}. Hot reload disabled.",
                e
            );
            return;
        }
    };

    // Watch the config file's parent directory
    if let Err(e) = watcher.watch(parent, RecursiveMode::NonRecursive) {
        warn!(
            "Failed to watch config directory: {}. Hot reload disabled.",
            e
        );
        return;
    }

    info!("Config file watcher started for {}", config_path);

    let filename = path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("proxy.yaml");
    let mut last_reload = Instant::now();
    let debounce_duration = Duration::from_secs(1);

    while let Some(event) = rx.recv().await {
        // Check if this event is for our config file
        let is_config_file = event.paths.iter().any(|p| {
            p.file_name()
                .and_then(|f| f.to_str())
                .map(|f| f == filename)
                .unwrap_or(false)
        });

        if is_config_file && last_reload.elapsed() > debounce_duration {
            info!("Config file changed, reloading...");
            match state.reload_config().await {
                Ok(rules_count) => {
                    info!("Configuration reloaded: {} rules", rules_count);
                }
                Err(e) => {
                    warn!("Failed to reload configuration: {}", e);
                }
            }
            last_reload = Instant::now();
        }
    }
    warn!("Config watcher channel disconnected, stopping watcher");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Load configuration
    let config = AppConfig::load(&args.config)?;

    // Initialize telemetry (must be done before any tracing calls)
    let _telemetry_guard = telemetry::init_telemetry(config.telemetry.as_ref())?;

    info!(
        "Loaded {} masking rules from {}",
        config.rules.len(),
        args.config
    );

    // Initialize Prometheus metrics
    let metrics_handle = metrics::init_metrics();
    info!("Prometheus metrics initialized");

    // Load TLS config if enabled
    let tls_acceptor = if let Some(tls_config) = &config.tls {
        if tls_config.enabled {
            info!("TLS enabled. Loading certs from {}", tls_config.cert_path);
            let certs = load_certs(&tls_config.cert_path)?;
            let key = load_keys(&tls_config.key_path)?;
            let config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)?;
            Some(TlsAcceptor::from(Arc::new(config)))
        } else {
            info!("TLS disabled in config.");
            None
        }
    } else {
        info!("TLS not configured.");
        None
    };

    // Initialize shared state
    let db_protocol = match args.protocol {
        DbProtocol::Postgres => StateDbProtocol::Postgres,
        DbProtocol::Mysql => StateDbProtocol::MySql,
    };
    let state = AppState::new(
        config.clone(),
        args.config.clone(),
        args.upstream_host.clone(),
        args.upstream_port,
        db_protocol,
    )
    .with_metrics(metrics_handle);

    // Start Management API in a separate task
    let api_port = args.api_port;
    let api_bind = match args.api_bind {
        Some(addr) => addr,
        None => match config.api.as_ref().and_then(|a| a.bind.as_deref()) {
            Some(bind) => bind
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid api.bind '{}': {}", bind, e))?,
            None => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        },
    };
    let api_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = api::start_api_server(api_bind, api_port, api_state).await {
            // The API carries /health, /metrics and the masking control
            // plane; running blind without it is worse than restarting.
            tracing::error!("management API server failed: {}", e);
            std::process::exit(1);
        }
    });

    // Start upstream health check task
    let health_check_enabled = config
        .health_check
        .as_ref()
        .map(|h| h.enabled)
        .unwrap_or(true);

    if health_check_enabled {
        let health_state = state.clone();
        let health_host = args.upstream_host.clone();
        let health_port = args.upstream_port;
        let health_config = config.health_check.clone();
        tokio::spawn(async move {
            run_health_check_task(health_state, health_host, health_port, health_config).await;
        });
    }

    // Start config file watcher for hot reload
    let watch_state = state.clone();
    let config_path = args.config.clone();
    tokio::spawn(async move {
        run_config_watcher(watch_state, config_path).await;
    });

    // Start stats history recorder (every 5 seconds)
    let stats_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            stats_state.record_history_snapshot().await;
        }
    });

    info!("Starting DB Proxy on {}:{}", args.bind, args.port);
    info!(
        "Forwarding to upstream at {}:{}",
        args.upstream_host, args.upstream_port
    );
    info!("Protocol: {:?}", args.protocol);

    // Loud rail: this proxy exists to protect PII, and with both TLS legs off
    // it crosses the network in cleartext on both hops.
    let client_tls_on = config.tls.as_ref().map(|t| t.enabled).unwrap_or(false);
    if config.masking_enabled && !client_tls_on && !config.upstream_tls {
        warn!(
            "masking is enabled but both tls.enabled and upstream_tls are false: \
             client and upstream traffic are cleartext. Acceptable only on a trusted network."
        );
    }

    // Build the upstream TLS client config once: it loads the OS trust store,
    // which is too expensive (and too panic-prone) for the per-connection path.
    let upstream_tls_config = if config.upstream_tls {
        Some(Arc::new(create_upstream_tls_config()?))
    } else {
        None
    };

    let listener = tokio::net::TcpListener::bind((args.bind, args.port)).await?;
    let protocol = args.protocol;

    // Create cancellation token for graceful shutdown
    let cancel_token = CancellationToken::new();
    let shutdown_timeout = args.shutdown_timeout;

    // Connection limiting
    let max_connections = config.limits.as_ref().and_then(|l| l.max_connections);
    let connection_semaphore = max_connections.map(|max| {
        info!("Connection limit set to {}", max);
        Arc::new(Semaphore::new(max))
    });

    // Upstream pool guardrails
    let upstream_pool = config
        .limits
        .as_ref()
        .and_then(|l| l.upstream_pool_size)
        .map(|size| {
            info!("Upstream pool size set to {}", size);
            UpstreamSlotManager::new(size)
        });

    // Rate limiting state
    let rate_limit = config
        .limits
        .as_ref()
        .and_then(|l| l.connections_per_second);
    if let Some(rate) = rate_limit {
        info!("Rate limit set to {} connections/second", rate);
    }
    let mut rate_limit_tokens: u32 = rate_limit.unwrap_or(0);
    let mut last_refill = Instant::now();

    // Accept connections until shutdown signal
    loop {
        tokio::select! {
            // Wait for new connection
            accept_result = listener.accept() => {
                let (client_socket, client_addr) = match accept_result {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        // accept() returns transient errors (EMFILE/ENFILE on
                        // fd exhaustion, ECONNABORTED, ENOBUFS); none of them
                        // justify taking the whole proxy down.
                        warn!("accept() failed: {}", e);
                        metrics::record_connection_rejected("accept_error");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

                // Rate limiting check
                if let Some(max_rate) = rate_limit {
                    // Refill tokens based on elapsed time
                    let elapsed = last_refill.elapsed();
                    if elapsed >= Duration::from_secs(1) {
                        rate_limit_tokens = max_rate;
                        last_refill = Instant::now();
                    }

                    if rate_limit_tokens == 0 {
                        warn!("Rate limit exceeded, rejecting connection from {}", client_addr);
                        metrics::record_connection_rejected("rate_limit");
                        drop(client_socket);
                        continue;
                    }
                    rate_limit_tokens = rate_limit_tokens.saturating_sub(1);
                }

                // Connection limit check
                let permit = if let Some(ref sem) = connection_semaphore {
                    match sem.clone().try_acquire_owned() {
                        Ok(permit) => Some(permit),
                        Err(_) => {
                            warn!("Connection limit reached, rejecting connection from {}", client_addr);
                            metrics::record_connection_rejected("max_connections");
                            drop(client_socket);
                            continue;
                        }
                    }
                } else {
                    None
                };

                info!("Accepted connection from {}", client_addr);

                let upstream_host = args.upstream_host.clone();
                let upstream_port = args.upstream_port;
                let state = state.clone();
                let tls_acceptor = tls_acceptor.clone();
                let upstream_pool = upstream_pool.clone();
                let upstream_tls_config = upstream_tls_config.clone();
                let conn_cancel = cancel_token.child_token();

                tokio::spawn(async move {
                    // Hold the permit for the duration of the connection
                    let _inbound_permit = permit;
                    let mut client_socket = client_socket;

                    let span = info_span!(
                        "connection",
                        client.addr = %client_addr,
                        upstream.host = %upstream_host,
                        upstream.port = %upstream_port,
                        protocol = ?protocol
                    );

                    async {
                        let mut _upstream_pool_lease = None;
                        if matches!(protocol, DbProtocol::Mysql)
                            && let Some(pool) = upstream_pool.clone()
                        {
                            let wait_timeout = {
                                let config = state.config.read().await;
                                let (_, _, pool_wait_timeout) =
                                    resolve_timeout_limits(config.limits.as_ref());
                                pool_wait_timeout
                            };
                            let wait_started = Instant::now();
                            match pool.acquire(wait_timeout).await {
                                Ok(lease) => {
                                    metrics::record_upstream_pool_wait(
                                        wait_started.elapsed().as_secs_f64(),
                                    );
                                    _upstream_pool_lease = Some(lease);
                                }
                                Err(UpstreamPoolAcquireError::Closed) => {
                                    warn!(
                                        "Upstream pool closed while acquiring slot for {}",
                                        client_addr
                                    );
                                    metrics::record_connection_rejected("upstream_pool_closed");
                                    let _ = send_mysql_err_response(
                                        &mut client_socket,
                                        1040,
                                        "08004",
                                        "upstream pool unavailable",
                                    )
                                    .await;
                                    return;
                                }
                                Err(UpstreamPoolAcquireError::Timeout) => {
                                    warn!(
                                        "Timed out waiting for upstream pool slot after {:?} for {}",
                                        wait_timeout, client_addr
                                    );
                                    metrics::record_upstream_pool_acquire_timeout();
                                    metrics::record_connection_rejected(
                                        "upstream_pool_wait_timeout",
                                    );
                                    let message = format!(
                                        "upstream pool is at capacity; timed out after {}s waiting for an available slot",
                                        wait_timeout.as_secs()
                                    );
                                    let _ = send_mysql_err_response(
                                        &mut client_socket,
                                        1040,
                                        "08004",
                                        &message,
                                    )
                                    .await;
                                    return;
                                }
                            }
                        }

                        state.active_connections.fetch_add(1, Ordering::Relaxed);
                        metrics::record_connection_opened();
                        state.record_connection().await;
                        let result = match protocol {
                            DbProtocol::Postgres => {
                                process_postgres_connection(
                                    client_socket,
                                    upstream_host,
                                    upstream_port,
                                    state.clone(),
                                    tls_acceptor,
                                    upstream_pool.clone(),
                                    upstream_tls_config,
                                    conn_cancel,
                                )
                                .await
                            }
                            DbProtocol::Mysql => {
                                process_mysql_connection(
                                    client_socket,
                                    upstream_host,
                                    upstream_port,
                                    state.clone(),
                                    tls_acceptor,
                                    upstream_tls_config,
                                    conn_cancel,
                                )
                                .await
                            }
                        };
                        state.active_connections.fetch_sub(1, Ordering::Relaxed);
                        metrics::record_connection_closed();

                        if let Err(e) = result {
                            tracing::error!(error = %e, "Connection error");
                        }
                    }
                    .instrument(span)
                    .await
                });
            }

            // Wait for shutdown signal
            _ = shutdown_signal() => {
                info!("Shutdown signal received, stopping accept loop...");
                break;
            }
        }
    }

    // Graceful shutdown: wait for active connections to drain
    info!(
        "Waiting for {} active connections to close (timeout: {}s)...",
        state.active_connections.load(Ordering::Relaxed),
        shutdown_timeout
    );

    // Signal all connections to shutdown
    cancel_token.cancel();

    // Wait for connections to drain with timeout
    let drain_start = std::time::Instant::now();
    let timeout_duration = std::time::Duration::from_secs(shutdown_timeout);

    while state.active_connections.load(Ordering::Relaxed) > 0 {
        if drain_start.elapsed() >= timeout_duration {
            warn!(
                "Shutdown timeout reached, {} connections still active",
                state.active_connections.load(Ordering::Relaxed)
            );
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    info!("Shutdown complete.");
    Ok(())
}

// ============================================================================
// PostgreSQL Connection Handling
// ============================================================================

/// Deadline for the pre-protocol phase (startup peek, SSLRequest, TLS
/// handshake): unauthenticated peers must not be able to pin a task and an fd
/// by connecting and sending nothing.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(15);

#[allow(clippy::too_many_arguments)]
async fn process_postgres_connection(
    mut client_socket: tokio::net::TcpStream,
    upstream_host: String,
    upstream_port: u16,
    state: AppState,
    tls_acceptor: Option<TlsAcceptor>,
    upstream_pool: Option<UpstreamSlotManager>,
    upstream_tls_config: Option<Arc<ClientConfig>>,
    cancel: CancellationToken,
) -> Result<()> {
    // Buffer the whole 8-byte prelude before routing. `peek` returns whatever
    // is in the socket buffer at first readability, so a segmented client
    // write used to skip the TLS-aware branch entirely and get an
    // unconditional 'N' from the codec path — silently cleartext against a
    // proxy the operator had configured for TLS.
    let mut buffer = [0u8; 8];
    let n = tokio::time::timeout(HANDSHAKE_DEADLINE, async {
        loop {
            let n = client_socket.peek(&mut buffer).await?;
            if n >= 8 || n == 0 {
                return Ok::<usize, std::io::Error>(n);
            }
            // Nothing else to wait on but more data arriving.
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("client handshake timed out"))??;
    if n >= 8 {
        let len = u32::from_be_bytes(
            buffer[0..4]
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid startup message length"))?,
        );
        let code = u32::from_be_bytes(
            buffer[4..8]
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid startup message code"))?,
        );

        if len == 8 && code == 80877103 {
            // It is an SSLRequest
            let mut trash = [0u8; 8];
            client_socket.read_exact(&mut trash).await?;

            if let Some(acceptor) = tls_acceptor {
                info!("Received SSLRequest, accepting...");
                client_socket.write_all(b"S").await?;

                let tls_stream =
                    tokio::time::timeout(HANDSHAKE_DEADLINE, acceptor.accept(client_socket))
                        .await
                        .map_err(|_| anyhow::anyhow!("client TLS handshake timed out"))??;
                return handle_postgres_protocol(
                    tls_stream,
                    upstream_host,
                    upstream_port,
                    state,
                    upstream_pool,
                    upstream_tls_config,
                    cancel,
                )
                .await;
            } else {
                info!("Received SSLRequest, denying (TLS not configured)...");
                client_socket.write_all(b"N").await?;
            }
        }
    }

    handle_postgres_protocol(
        client_socket,
        upstream_host,
        upstream_port,
        state,
        upstream_pool,
        upstream_tls_config,
        cancel,
    )
    .await
}

/// Creates a TLS ClientConfig that uses the OS native certificate verifier.
pub fn create_upstream_tls_config() -> Result<ClientConfig> {
    // Initialize the platform-specific verifier
    let provider = Arc::new(default_provider());
    let verifier = Arc::new(
        Verifier::new(provider)
            .map_err(|e| anyhow::anyhow!("failed to create platform TLS verifier: {}", e))?,
    );

    Ok(ClientConfig::builder()
        // .dangerous() is required because we are overriding the default
        // WebPki verifier with a custom one (the platform verifier).
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

async fn handle_postgres_protocol<S>(
    client_socket: S,
    upstream_host: String,
    upstream_port: u16,
    state: AppState,
    upstream_pool: Option<UpstreamSlotManager>,
    upstream_tls_config: Option<Arc<ClientConfig>>,
    cancel: CancellationToken,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut client_socket = client_socket;

    // Get timeout configuration
    let (connect_timeout, idle_timeout, pool_wait_timeout) = {
        let config = state.config.read().await;
        resolve_timeout_limits(config.limits.as_ref())
    };

    let mut _upstream_pool_lease = None;
    if let Some(pool) = upstream_pool {
        let wait_started = Instant::now();
        match pool.acquire(pool_wait_timeout).await {
            Ok(lease) => {
                metrics::record_upstream_pool_wait(wait_started.elapsed().as_secs_f64());
                _upstream_pool_lease = Some(lease);
            }
            Err(UpstreamPoolAcquireError::Closed) => {
                metrics::record_connection_rejected("upstream_pool_closed");
                let _ = send_postgres_fatal_error_response(
                    &mut client_socket,
                    "08006",
                    "upstream pool unavailable",
                )
                .await;
                return Ok(());
            }
            Err(UpstreamPoolAcquireError::Timeout) => {
                metrics::record_upstream_pool_acquire_timeout();
                metrics::record_connection_rejected("upstream_pool_wait_timeout");
                let message = format!(
                    "upstream pool is at capacity; timed out after {}s waiting for an available slot",
                    pool_wait_timeout.as_secs()
                );
                let _ =
                    send_postgres_fatal_error_response(&mut client_socket, "53300", &message).await;
                return Ok(());
            }
        }
    }

    // Create upstream connection with timeout
    let mut upstream_socket =
        connect_upstream_with_timeout(&upstream_host, upstream_port, connect_timeout).await?;

    // Check if upstream TLS is enabled
    let upstream_tls_enabled = {
        let config = state.config.read().await;
        config.upstream_tls
    };

    if upstream_tls_enabled {
        info!(
            "Upstream TLS enabled. Attempting handshake with {}:{}",
            upstream_host, upstream_port
        );

        // 1. Send SSLRequest to upstream
        let mut ssl_request = bytes::BytesMut::with_capacity(8);
        ssl_request.put_u32(8); // Length
        ssl_request.put_u32(80877103); // SSLRequest code
        upstream_socket.write_all(&ssl_request).await?;

        // 2. Read response (1 byte)
        let mut response = [0u8; 1];
        upstream_socket.read_exact(&mut response).await?;

        if response[0] == b'S' {
            info!("Upstream accepted SSLRequest. Upgrading connection...");

            // 3. Upgrade to TLS
            let client_config = match upstream_tls_config {
                Some(config) => config,
                None => Arc::new(create_upstream_tls_config()?),
            };
            let connector = TlsConnector::from(client_config);

            let domain = ServerName::try_from(upstream_host.as_str())
                .map_err(|_| anyhow::anyhow!("Invalid DNS name for upstream host"))?
                .to_owned();

            let upstream_tls_stream = connector.connect(domain, upstream_socket).await?;

            // 4. Continue with TLS stream
            let result = handle_postgres_protocol_inner(
                client_socket,
                upstream_tls_stream,
                state,
                idle_timeout,
                cancel,
            )
            .await;
            return result;
        } else {
            // upstream_tls: true means required. Silently downgrading to
            // cleartext turned a one-byte response (or an on-path rewrite)
            // into credentials and unmasked data crossing the wire in plain.
            let _ = send_postgres_fatal_error_response(
                &mut client_socket,
                "08006",
                "upstream refused TLS but upstream_tls is required",
            )
            .await;
            anyhow::bail!("upstream denied SSLRequest while upstream_tls is enabled");
        }
    }

    // Cleartext connection
    handle_postgres_protocol_inner(client_socket, upstream_socket, state, idle_timeout, cancel)
        .await
}

async fn handle_postgres_protocol_inner<S, U>(
    client_socket: S,
    upstream_socket: U,
    state: AppState,
    idle_timeout: Duration,
    cancel: CancellationToken,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut client_framed = Framed::new(client_socket, PostgresCodec::new());
    let mut upstream_framed = Framed::new(upstream_socket, PostgresCodec::new_upstream());

    let connection_id = rand::random::<u64>() as usize;
    let mut interceptor = Anonymizer::new(state.clone(), connection_id);
    let mut postgres_oid_bootstrap_done = false;
    // Start of the in-flight query, for the round-trip latency histogram.
    let mut query_started_at: Option<Instant> = None;

    loop {
        tokio::select! {
            // Client -> Upstream
            msg = client_framed.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        match msg {
                            PgMessage::SSLRequest => {
                                info!("Received SSLRequest, denying...");
                                // Deny SSL, force cleartext
                                client_framed.get_mut().write_all(b"N").await?;
                            }
                            PgMessage::Query(ref q) => {
                                let query_str = String::from_utf8_lossy(&q.query).to_string();
                                let id = format!("{:x}", rand::random::<u128>());
                                state.add_log(LogEntry {
                                    id,
                                    timestamp: Utc::now(),
                                    connection_id,
                                    event_type: "Query".to_string(),
                                    content: redact_sql_literals(&query_str),
                                    details: None,
                                }).await;

                                // Record query type stats
                                let query_type = query_str
                                    .split_whitespace()
                                    .next()
                                    .unwrap_or("OTHER")
                                    .to_uppercase();
                                state.record_query(&query_type).await;
                                query_started_at = Some(Instant::now());

                                // Drop any stale index->strategy map from a previous
                                // statement before its result set arrives.
                                interceptor.reset_columns();

                                upstream_framed.send(msg).await?;
                            }
                            PgMessage::Parse(ref p) => {
                                let query_str = String::from_utf8_lossy(&p.query).to_string();
                                let id = format!("{:x}", rand::random::<u128>());
                                state.add_log(LogEntry {
                                    id,
                                    timestamp: Utc::now(),
                                    connection_id,
                                    event_type: "Parse".to_string(),
                                    content: redact_sql_literals(&query_str),
                                    details: None,
                                }).await;

                                // Record query type stats for prepared statements
                                let query_type = query_str
                                    .split_whitespace()
                                    .next()
                                    .unwrap_or("OTHER")
                                    .to_uppercase();
                                state.record_query(&query_type).await;
                                query_started_at = Some(Instant::now());

                                interceptor.reset_columns();

                                upstream_framed.send(msg).await?;
                            }
                            _ => {
                                // Forward other messages (Startup, Query, etc.)
                                upstream_framed.send(msg).await?;
                            }
                        }
                    }
                    Some(Err(e)) => return Err(e),
                    None => return Ok(()), // Client disconnected
                }
            }
            // Upstream -> Client
            msg = upstream_framed.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        match msg {
                            PgMessage::Regular(regular)
                                if regular.message_type == b'Z' && !postgres_oid_bootstrap_done =>
                            {
                                client_framed.send(PgMessage::Regular(regular)).await?;

                                let needs_bootstrap = {
                                    let config = state.config.read().await;
                                    !config.rules.is_empty()
                                };
                                if !needs_bootstrap {
                                    postgres_oid_bootstrap_done = true;
                                } else {
                                    match bootstrap_postgres_table_oid_map(&mut upstream_framed, &mut interceptor).await {
                                        Ok(loaded) => {
                                            // Mark done only on success so a transient failure
                                            // retries at the next ReadyForQuery instead of
                                            // leaving table-scoped rules silently inert.
                                            postgres_oid_bootstrap_done = true;
                                            info!("Loaded {} PostgreSQL table/column mappings for rule matching", loaded);
                                        }
                                        Err(err) => {
                                            warn!("Failed to bootstrap PostgreSQL OID mappings (will retry): {}", err);
                                        }
                                    }
                                }
                            }
                            PgMessage::RowDescription(rd) => {
                                interceptor.on_row_description(&rd).await;
                                client_framed.send(PgMessage::RowDescription(rd)).await?;
                            }
                            PgMessage::DataRow(dr) => {
                                let new_dr = interceptor.on_data_row(dr).await?;
                                client_framed.send(PgMessage::DataRow(new_dr)).await?;
                            }
                            other => {
                                // ReadyForQuery ends the query round trip.
                                if let PgMessage::Regular(ref regular) = other
                                    && regular.message_type == b'Z'
                                    && let Some(started) = query_started_at.take()
                                {
                                    state.record_query_latency(started);
                                }
                                // COPY TO STDOUT bypasses the DataRow interceptor entirely.
                                // Make the unmasked path visible instead of silent.
                                if let PgMessage::Regular(ref regular) = other
                                    && regular.message_type == b'H'
                                {
                                    warn!(
                                        "PostgreSQL COPY-out response forwarded without masking: \
                                         COPY data does not pass through the row interceptor"
                                    );
                                    metrics::record_copy_passthrough();
                                }
                                client_framed.send(other).await?;
                            }
                        }
                    }
                    Some(Err(e)) => return Err(e),
                    None => return Ok(()), // Upstream disconnected
                }
            }
            // Graceful shutdown
            _ = cancel.cancelled() => {
                info!("Shutdown requested; closing PostgreSQL connection");
                let _ = client_framed.send(PgMessage::Regular(build_postgres_fatal_regular_message(
                    "57P01",
                    "proxy is shutting down",
                ))).await;
                return Ok(());
            }
            // Idle timeout
            _ = tokio::time::sleep(idle_timeout) => {
                info!("Connection idle timeout after {:?}", idle_timeout);
                metrics::record_idle_timeout();
                return Ok(());
            }
        }
    }
}

fn decode_postgres_data_row_text_value(row: &DataRow, index: usize) -> Option<String> {
    row.values
        .get(index)
        .and_then(|v| v.as_ref())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(|value| value.trim().to_string())
}

async fn bootstrap_postgres_table_oid_map<U>(
    upstream_framed: &mut Framed<U, PostgresCodec>,
    interceptor: &mut Anonymizer,
) -> Result<usize>
where
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Read all regular tables, partitions, views and foreign tables that appear in result sets,
    // including their column names/attnums so rules can match true provenance
    // (table_oid + column_index) rather than the aliasable result-set label.
    const OID_LOOKUP_QUERY: &str = "
        SELECT c.oid::text, n.nspname, c.relname, a.attnum::text, a.attname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_attribute a
          ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
        WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
    ";

    upstream_framed
        .send(PgMessage::Query(QueryMessage {
            query: Bytes::copy_from_slice(OID_LOOKUP_QUERY.as_bytes()),
        }))
        .await?;

    let mut loaded = 0usize;

    loop {
        match upstream_framed.next().await {
            Some(Ok(PgMessage::DataRow(row))) => {
                let oid = decode_postgres_data_row_text_value(&row, 0)
                    .and_then(|raw| raw.parse::<u32>().ok());
                let schema = decode_postgres_data_row_text_value(&row, 1);
                let table = decode_postgres_data_row_text_value(&row, 2);
                let attnum = decode_postgres_data_row_text_value(&row, 3)
                    .and_then(|raw| raw.parse::<i16>().ok());
                let column = decode_postgres_data_row_text_value(&row, 4);

                if let (Some(oid), Some(schema), Some(table)) = (oid, schema, table) {
                    interceptor.register_postgres_table_oid(oid, &schema, &table);
                    if let (Some(attnum), Some(column)) = (attnum, column) {
                        interceptor.register_postgres_column(oid, attnum, &column);
                    }
                    loaded += 1;
                }
            }
            Some(Ok(PgMessage::Regular(msg))) if msg.message_type == b'Z' => break,
            Some(Ok(_)) => {}
            Some(Err(err)) => return Err(err),
            None => {
                return Err(anyhow::anyhow!(
                    "Upstream disconnected during OID map bootstrap"
                ));
            }
        }
    }

    Ok(loaded)
}

// ============================================================================
// MySQL Connection Handling
// ============================================================================

/// Any stream the proxy can run a protocol over. Boxing keeps the plain and
/// TLS-wrapped variants of both legs from multiplying into a type explosion.
trait ProxyStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> ProxyStream for T {}
type BoxedStream = Box<dyn ProxyStream + 'static>;

/// A stream with bytes already read into a buffer put back in front of it.
/// Framed may have buffered the client's TLS ClientHello together with the
/// SSLRequest packet; those bytes must survive the switch to a TLS stream.
struct PrefixedStream<S> {
    prefix: bytes::BytesMut,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: bytes::BytesMut, inner: S) -> Self {
        Self { prefix, inner }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let n = this.prefix.len().min(buf.remaining());
            buf.put_slice(&this.prefix.split_to(n));
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

async fn process_mysql_connection(
    client_socket: tokio::net::TcpStream,
    upstream_host: String,
    upstream_port: u16,
    state: AppState,
    tls_acceptor: Option<TlsAcceptor>,
    upstream_tls_config: Option<Arc<ClientConfig>>,
    cancel: CancellationToken,
) -> Result<()> {
    // Get timeout configuration
    let (connect_timeout, idle_timeout) = {
        let config = state.config.read().await;
        let (connect_timeout, idle_timeout, _) = resolve_timeout_limits(config.limits.as_ref());
        (connect_timeout, idle_timeout)
    };

    // Connect to upstream MySQL server with timeout
    let upstream_socket =
        connect_upstream_with_timeout(&upstream_host, upstream_port, connect_timeout).await?;

    handle_mysql_protocol(
        Box::new(client_socket),
        Box::new(upstream_socket),
        upstream_host,
        state,
        idle_timeout,
        tls_acceptor,
        upstream_tls_config,
        cancel,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_mysql_protocol(
    client_socket: BoxedStream,
    upstream_socket: BoxedStream,
    upstream_host: String,
    state: AppState,
    idle_timeout: Duration,
    tls_acceptor: Option<TlsAcceptor>,
    upstream_tls_config: Option<Arc<ClientConfig>>,
    cancel: CancellationToken,
) -> Result<()> {
    let upstream_tls_required = {
        let config = state.config.read().await;
        config.upstream_tls
    };

    let mut client_framed = Framed::new(client_socket, MySqlCodec::new_server());
    let mut upstream_framed = Framed::new(upstream_socket, MySqlCodec::new_client());

    let connection_id = rand::random::<u64>() as usize;
    let mut interceptor = MySqlAnonymizer::new(state.clone(), connection_id);
    // Start of the in-flight query, for the round-trip latency histogram.
    let mut query_started_at: Option<Instant> = None;

    // Phase 1: Forward handshake from upstream to client
    let handshake = match upstream_framed.next().await {
        Some(Ok(MySqlMessage::Handshake(h))) => {
            info!(server_version = %h.server_version, "Received MySQL handshake from upstream");
            // Advertise to the client only what this proxy can actually serve:
            // CLIENT_SSL only when a TLS acceptor is configured (otherwise a
            // TLS-preferring client attempts an upgrade nothing answers), and
            // never CLIENT_COMPRESS (the codec cannot frame a compressed
            // stream, so masking would be bypassed).
            let mut client_handshake = h.clone();
            client_handshake.capability_flags &= !crate::protocol::mysql::CLIENT_COMPRESS;
            if tls_acceptor.is_some() {
                client_handshake.capability_flags |= crate::protocol::mysql::CLIENT_SSL;
            } else {
                client_handshake.capability_flags &= !crate::protocol::mysql::CLIENT_SSL;
            }
            client_framed
                .send(MySqlMessage::Handshake(client_handshake))
                .await?;
            h
        }
        Some(Ok(other)) => {
            tracing::warn!("Expected handshake, got {:?}", other);
            return Err(anyhow::anyhow!("Protocol error: expected handshake"));
        }
        Some(Err(e)) => return Err(e),
        None => return Ok(()),
    };

    // Update codec capability flags
    client_framed
        .codec_mut()
        .set_capability_flags(handshake.capability_flags);
    upstream_framed
        .codec_mut()
        .set_capability_flags(handshake.capability_flags);

    // Phase 2: client handshake response, upgrading to TLS if the client asks
    let mut client_response = match tokio::time::timeout(HANDSHAKE_DEADLINE, client_framed.next())
        .await
        .map_err(|_| anyhow::anyhow!("client handshake response timed out"))?
    {
        Some(Ok(MySqlMessage::HandshakeResponse(r))) => r,
        Some(Ok(other)) => {
            tracing::warn!("Expected handshake response, got {:?}", other);
            return Err(anyhow::anyhow!(
                "Protocol error: expected handshake response"
            ));
        }
        Some(Err(e)) => return Err(e),
        None => return Ok(()),
    };

    if client_response.is_ssl_request() {
        let Some(acceptor) = tls_acceptor else {
            anyhow::bail!("client requested TLS but no TLS acceptor is configured");
        };
        let negotiated_caps = client_response.capability_flags;

        // Re-wrap the client socket, carrying over anything Framed had already
        // buffered past the SSLRequest packet.
        let parts = client_framed.into_parts();
        let prefixed = PrefixedStream::new(parts.read_buf, parts.io);
        let tls_stream = tokio::time::timeout(HANDSHAKE_DEADLINE, acceptor.accept(prefixed))
            .await
            .map_err(|_| anyhow::anyhow!("client TLS handshake timed out"))??;
        info!("MySQL client connection upgraded to TLS");

        client_framed = Framed::new(
            Box::new(tls_stream) as BoxedStream,
            MySqlCodec::new_server_awaiting_handshake_response(negotiated_caps),
        );

        client_response = match tokio::time::timeout(HANDSHAKE_DEADLINE, client_framed.next())
            .await
            .map_err(|_| anyhow::anyhow!("client handshake response timed out after TLS"))?
        {
            Some(Ok(MySqlMessage::HandshakeResponse(r))) => r,
            Some(Ok(other)) => {
                anyhow::bail!("expected handshake response after TLS, got {:?}", other);
            }
            Some(Err(e)) => return Err(e),
            None => return Ok(()),
        };
    }

    info!(username = %client_response.username, database = ?client_response.database,
          "Received client handshake response");

    // Upstream TLS leg. MySQL 8.4's default caching_sha2_password sends the
    // password in cleartext during full auth and the server rejects that on an
    // insecure connection, so a TLS-terminating proxy must re-originate TLS
    // upstream for a non-cached credential to authenticate at all.
    if upstream_tls_required {
        if handshake.capability_flags & crate::protocol::mysql::CLIENT_SSL == 0 {
            anyhow::bail!("upstream_tls is enabled but the upstream does not offer CLIENT_SSL");
        }
        let ssl_request = crate::protocol::mysql::build_ssl_request(
            client_response.capability_flags,
            client_response.max_packet_size,
            client_response.character_set,
        );
        upstream_framed
            .send(MySqlMessage::Generic(ssl_request))
            .await?;

        let parts = upstream_framed.into_parts();
        if !parts.read_buf.is_empty() {
            anyhow::bail!("upstream sent data before the TLS handshake");
        }
        let client_config = match upstream_tls_config {
            Some(config) => config,
            None => Arc::new(create_upstream_tls_config()?),
        };
        let connector = TlsConnector::from(client_config);
        let domain = ServerName::try_from(upstream_host.as_str())
            .map_err(|_| anyhow::anyhow!("Invalid DNS name for upstream host"))?
            .to_owned();
        let tls_stream = connector.connect(domain, parts.io).await?;
        info!("MySQL upstream connection upgraded to TLS");

        upstream_framed = Framed::new(
            Box::new(tls_stream) as BoxedStream,
            MySqlCodec::new_client_awaiting_auth(client_response.capability_flags),
        );
    } else if client_response.capability_flags & crate::protocol::mysql::CLIENT_SSL != 0 {
        warn!(
            "client connected over TLS but upstream_tls is false: caching_sha2_password \
             full authentication will fail for credentials the server has not cached"
        );
    }

    // Update capability flags based on what the client actually negotiated
    client_framed
        .codec_mut()
        .set_capability_flags(client_response.capability_flags);
    upstream_framed
        .codec_mut()
        .set_capability_flags(client_response.capability_flags);
    upstream_framed
        .send(MySqlMessage::HandshakeResponse(client_response))
        .await?;

    // Phase 3: relay the authentication exchange verbatim until it resolves.
    // caching_sha2_password needs several round trips (auth switch, fast-auth
    // result, public-key request, full auth); handling only one packet left
    // every non-cached credential unable to connect.
    let mut auth_rounds = 0;
    loop {
        auth_rounds += 1;
        if auth_rounds > 20 {
            anyhow::bail!("MySQL authentication exceeded 20 round trips");
        }

        match tokio::time::timeout(HANDSHAKE_DEADLINE, upstream_framed.next())
            .await
            .map_err(|_| anyhow::anyhow!("upstream auth response timed out"))?
        {
            Some(Ok(msg @ MySqlMessage::Ok(_))) => {
                info!("MySQL authentication successful");
                client_framed.send(msg).await?;
                break;
            }
            Some(Ok(MySqlMessage::Err(e))) => {
                tracing::warn!(error_code = e.error_code, "MySQL authentication failed");
                client_framed.send(MySqlMessage::Err(e)).await?;
                return Ok(());
            }
            Some(Ok(other)) => {
                // Intermediate auth packet (AuthMoreData / AuthSwitchRequest).
                // Forward to the client, but only wait for a client reply when
                // the protocol actually requires one. caching_sha2_password
                // fast-auth success (0x01 0x03) is followed immediately by OK
                // with no client bytes — waiting hangs every successful MySQL 8
                // login through the proxy.
                let expects_reply = match &other {
                    MySqlMessage::Generic(g) => {
                        crate::protocol::mysql::auth_packet_expects_client_reply(&g.payload)
                    }
                    // Parsed OK/ERR are handled above; anything else during auth
                    // is treated as needing a client reply.
                    _ => true,
                };
                client_framed.send(other).await?;
                if expects_reply {
                    match tokio::time::timeout(HANDSHAKE_DEADLINE, client_framed.next())
                        .await
                        .map_err(|_| anyhow::anyhow!("client auth response timed out"))?
                    {
                        Some(Ok(reply)) => upstream_framed.send(reply).await?,
                        Some(Err(e)) => return Err(e),
                        None => return Ok(()),
                    }
                }
            }
            Some(Err(e)) => return Err(e),
            None => return Ok(()),
        }
    }

    // Authentication is done; both codecs resume the command phase.
    client_framed.codec_mut().set_command_state();
    upstream_framed.codec_mut().set_command_state();

    // Phase 4: Command phase - bidirectional proxy with interception
    loop {
        tokio::select! {
            // Client -> Upstream
            msg = client_framed.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        match &msg {
                            MySqlMessage::Query(q) => {
                                let query_str = String::from_utf8_lossy(&q.query).to_string();
                                let id = format!("{:x}", rand::random::<u128>());
                                state.add_log(LogEntry {
                                    id,
                                    timestamp: Utc::now(),
                                    connection_id,
                                    event_type: "MySqlQuery".to_string(),
                                    content: redact_sql_literals(&query_str),
                                    details: None,
                                }).await;

                                // Record query type stats
                                let query_type = query_str
                                    .split_whitespace()
                                    .next()
                                    .unwrap_or("OTHER")
                                    .to_uppercase();
                                state.record_query(&query_type).await;
                                query_started_at = Some(Instant::now());

                                // Reset interceptor and response codec for the
                                // new result set — a desynced response stream
                                // must not survive past the next command.
                                interceptor.reset_columns();
                                upstream_framed.codec_mut().set_command_state();
                            }
                            MySqlMessage::Generic(g) => {
                                // COM_STMT_PREPARE / COM_STMT_EXECUTE / COM_STMT_FETCH: the
                                // binary protocol is unsupported — its result rows would
                                // bypass masking entirely. Reject visibly with ER_UNSUPPORTED_PS
                                // (most connectors fall back to client-side statements) instead
                                // of forwarding a stream the codec would misparse.
                                if let Some(cmd @ (0x16 | 0x17 | 0x1c)) = g.payload.first() {
                                    tracing::warn!(
                                        command = format!("0x{cmd:02x}"),
                                        "rejecting MySQL binary-protocol command; \
                                         iron-veil masks the text protocol only"
                                    );
                                    metrics::record_binary_protocol_rejected();
                                    let err = crate::protocol::mysql::ErrPacket::proxy_error(
                                        1,
                                        1295, // ER_UNSUPPORTED_PS
                                        b"HY000",
                                        "iron-veil: server-side prepared statements (binary \
                                         protocol) are not supported; use the text protocol",
                                    );
                                    client_framed.send(MySqlMessage::Err(err)).await?;
                                    continue;
                                }
                                upstream_framed.codec_mut().set_command_state();
                            }
                            _ => {}
                        }
                        upstream_framed.send(msg).await?;
                    }
                    Some(Err(e)) => return Err(e),
                    None => return Ok(()),
                }
            }
            // Upstream -> Client
            msg = upstream_framed.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        // A result-set terminator, OK or ERR ends the round trip.
                        if matches!(
                            msg,
                            MySqlMessage::Ok(_) | MySqlMessage::Err(_) | MySqlMessage::Generic(_)
                        ) && let Some(started) = query_started_at.take()
                        {
                            state.record_query_latency(started);
                        }

                        let msg_to_send = match msg {
                            MySqlMessage::ColumnDefinition(ref col) => {
                                interceptor.on_column_definition(col).await;
                                msg
                            }
                            MySqlMessage::ResultRow(row) => {
                                let new_row = interceptor.on_result_row(row).await?;
                                MySqlMessage::ResultRow(new_row)
                            }
                            MySqlMessage::Eof(_) => {
                                // EOF after columns means we're about to get rows
                                // EOF after rows means result set is done
                                msg
                            }
                            _ => msg,
                        };
                        client_framed.send(msg_to_send).await?;
                    }
                    Some(Err(e)) => return Err(e),
                    None => return Ok(()),
                }
            }
            // Graceful shutdown
            _ = cancel.cancelled() => {
                info!("Shutdown requested; closing MySQL connection");
                let err = crate::protocol::mysql::ErrPacket::proxy_error(
                    0,
                    1053, // ER_SERVER_SHUTDOWN
                    b"08S01",
                    "proxy is shutting down",
                );
                let _ = client_framed.send(MySqlMessage::Err(err)).await;
                return Ok(());
            }
            // Idle timeout
            _ = tokio::time::sleep(idle_timeout) => {
                info!("MySQL connection idle timeout after {:?}", idle_timeout);
                metrics::record_idle_timeout();
                return Ok(());
            }
        }
    }
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certfile = File::open(path)?;
    let mut reader = BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn load_keys(path: &str) -> Result<PrivateKeyDer<'static>> {
    let keyfile = File::open(path)?;
    let mut reader = BufReader::new(keyfile);
    let key = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("No private key found"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::{
        UpstreamPoolAcquireError, UpstreamSlotManager, build_mysql_err_packet,
        build_postgres_fatal_error_packet, resolve_timeout_limits,
    };
    use crate::config::LimitsConfig;
    use std::time::Duration;

    #[test]
    fn test_build_postgres_fatal_error_packet_format() {
        let packet = build_postgres_fatal_error_packet("53300", "pool timeout");

        assert_eq!(packet[0], b'E');
        let length = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]) as usize;
        assert_eq!(length, packet.len() - 1);

        let payload = &packet[5..];
        assert_eq!(payload[0], b'S');
        assert!(payload.ends_with(&[0]));
        assert!(payload.windows("FATAL\0".len()).any(|w| w == b"FATAL\0"));
        assert!(payload.windows("53300\0".len()).any(|w| w == b"53300\0"));
        assert!(
            payload
                .windows("pool timeout\0".len())
                .any(|w| w == b"pool timeout\0")
        );
    }

    #[test]
    fn test_build_mysql_err_packet_format() {
        let packet = build_mysql_err_packet(1040, "08004", "upstream pool timeout");

        // Packet header: 3-byte payload length + 1-byte sequence
        let payload_len =
            (packet[0] as usize) | ((packet[1] as usize) << 8) | ((packet[2] as usize) << 16);
        assert_eq!(payload_len, packet.len() - 4);
        assert_eq!(packet[3], 0);

        let payload = &packet[4..];
        assert_eq!(payload[0], 0xFF);
        assert_eq!(u16::from_le_bytes([payload[1], payload[2]]), 1040);
        assert_eq!(payload[3], b'#');
        assert_eq!(&payload[4..9], b"08004");
        assert_eq!(&payload[9..], b"upstream pool timeout");
    }

    #[test]
    fn test_resolve_timeout_limits_defaults() {
        let (connect, idle, pool_wait) = resolve_timeout_limits(None);
        assert_eq!(connect, Duration::from_secs(30));
        assert_eq!(idle, Duration::from_secs(300));
        assert_eq!(pool_wait, Duration::from_secs(5));
    }

    #[test]
    fn test_resolve_timeout_limits_from_config() {
        let limits = LimitsConfig {
            max_connections: None,
            connections_per_second: None,
            connect_timeout_secs: 12,
            idle_timeout_secs: 34,
            upstream_pool_size: Some(10),
            upstream_pool_wait_timeout_secs: 7,
        };
        let (connect, idle, pool_wait) = resolve_timeout_limits(Some(&limits));
        assert_eq!(connect, Duration::from_secs(12));
        assert_eq!(idle, Duration::from_secs(34));
        assert_eq!(pool_wait, Duration::from_secs(7));
    }

    #[tokio::test]
    async fn test_upstream_slot_manager_acquire_and_release() {
        let manager = UpstreamSlotManager::new(1);
        assert_eq!(manager.available_slots(), 1);

        let lease = manager
            .acquire(Duration::from_millis(20))
            .await
            .expect("first acquire should succeed");
        assert_eq!(manager.available_slots(), 0);

        drop(lease);
        assert_eq!(manager.available_slots(), 1);
    }

    #[tokio::test]
    async fn test_upstream_slot_manager_acquire_times_out_when_full() {
        let manager = UpstreamSlotManager::new(1);
        let _lease = manager
            .acquire(Duration::from_millis(20))
            .await
            .expect("first acquire should succeed");

        let result = manager.acquire(Duration::from_millis(20)).await;
        assert!(matches!(result, Err(UpstreamPoolAcquireError::Timeout)));
    }
}
