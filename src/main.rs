use anyhow::Result;
use clap::{Parser, ValueEnum};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, info, info_span, warn};

mod api;
mod config;
mod interceptor;
mod protocol;
mod scanner;
mod state;
mod telemetry;

use crate::config::AppConfig;
use crate::interceptor::{Anonymizer, MySqlAnonymizer, MySqlPacketInterceptor, PacketInterceptor};
use crate::protocol::mysql::{MySqlCodec, MySqlMessage};
use crate::protocol::postgres::{PgMessage, PostgresCodec};
use crate::state::{AppState, LogEntry};
use bytes::BufMut;
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

    /// Management API port
    #[arg(long, default_value_t = 3001)]
    api_port: u16,

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
    let state = AppState::new(config.clone());

    // Start Management API in a separate task
    let api_port = args.api_port;
    let api_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = api::start_api_server(api_port, api_state).await {
            tracing::error!("API server error: {}", e);
        }
    });

    info!("Starting DB Proxy on port {}", args.port);
    info!(
        "Forwarding to upstream at {}:{}",
        args.upstream_host, args.upstream_port
    );
    info!("Protocol: {:?}", args.protocol);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", args.port)).await?;
    let protocol = args.protocol;

    // Create cancellation token for graceful shutdown
    let cancel_token = CancellationToken::new();
    let shutdown_timeout = args.shutdown_timeout;

    // Connection limiting
    let max_connections = config
        .limits
        .as_ref()
        .and_then(|l| l.max_connections);
    let connection_semaphore = max_connections.map(|max| {
        info!("Connection limit set to {}", max);
        Arc::new(Semaphore::new(max))
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
                let (client_socket, client_addr) = accept_result?;
                
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

                tokio::spawn(async move {
                    // Hold the permit for the duration of the connection
                    let _permit = permit;
                    
                    let span = info_span!(
                        "connection",
                        client.addr = %client_addr,
                        upstream.host = %upstream_host,
                        upstream.port = %upstream_port,
                        protocol = ?protocol
                    );

                    async {
                        state.active_connections.fetch_add(1, Ordering::Relaxed);
                        let result = match protocol {
                            DbProtocol::Postgres => {
                                process_postgres_connection(
                                    client_socket,
                                    upstream_host,
                                    upstream_port,
                                    state.clone(),
                                    tls_acceptor,
                                )
                                .await
                            }
                            DbProtocol::Mysql => {
                                process_mysql_connection(
                                    client_socket,
                                    upstream_host,
                                    upstream_port,
                                    state.clone(),
                                )
                                .await
                            }
                        };
                        state.active_connections.fetch_sub(1, Ordering::Relaxed);

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
    info!("Waiting for {} active connections to close (timeout: {}s)...", 
          state.active_connections.load(Ordering::Relaxed), shutdown_timeout);
    
    // Signal all connections to shutdown
    cancel_token.cancel();

    // Wait for connections to drain with timeout
    let drain_start = std::time::Instant::now();
    let timeout_duration = std::time::Duration::from_secs(shutdown_timeout);
    
    while state.active_connections.load(Ordering::Relaxed) > 0 {
        if drain_start.elapsed() >= timeout_duration {
            warn!("Shutdown timeout reached, {} connections still active", 
                  state.active_connections.load(Ordering::Relaxed));
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

async fn process_postgres_connection(
    mut client_socket: tokio::net::TcpStream,
    upstream_host: String,
    upstream_port: u16,
    state: AppState,
    tls_acceptor: Option<TlsAcceptor>,
) -> Result<()> {
    let mut buffer = [0u8; 8];
    let n = client_socket.peek(&mut buffer).await?;
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

                let tls_stream = acceptor.accept(client_socket).await?;
                return handle_postgres_protocol(tls_stream, upstream_host, upstream_port, state)
                    .await;
            } else {
                info!("Received SSLRequest, denying (TLS not configured)...");
                client_socket.write_all(b"N").await?;
            }
        }
    }

    handle_postgres_protocol(client_socket, upstream_host, upstream_port, state).await
}

/// Creates a TLS ClientConfig that uses the OS native certificate verifier.
pub fn create_upstream_tls_config() -> ClientConfig {
    // Initialize the platform-specific verifier
    let provider = Arc::new(default_provider());
    let verifier = Arc::new(Verifier::new(provider).expect("Failed to create platform verifier"));

    ClientConfig::builder()
        // .dangerous() is required because we are overriding the default
        // WebPki verifier with a custom one (the platform verifier).
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

async fn handle_postgres_protocol<S>(
    client_socket: S,
    upstream_host: String,
    upstream_port: u16,
    state: AppState,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Create upstream connection
    let mut upstream_socket =
        tokio::net::TcpStream::connect(format!("{}:{}", upstream_host, upstream_port)).await?;

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
            let client_config = Arc::new(create_upstream_tls_config());
            let connector = TlsConnector::from(client_config);

            let domain = ServerName::try_from(upstream_host.as_str())
                .map_err(|_| anyhow::anyhow!("Invalid DNS name for upstream host"))?
                .to_owned();

            let upstream_tls_stream = connector.connect(domain, upstream_socket).await?;

            // 4. Continue with TLS stream
            return handle_postgres_protocol_inner(client_socket, upstream_tls_stream, state).await;
        } else {
            tracing::warn!(
                "Upstream denied SSLRequest. Falling back to cleartext (or aborting if strict)."
            );
            // For now, we fall back to cleartext as per standard behavior, but you might want to enforce it.
        }
    }

    // Cleartext connection
    handle_postgres_protocol_inner(client_socket, upstream_socket, state).await
}

async fn handle_postgres_protocol_inner<S, U>(
    client_socket: S,
    upstream_socket: U,
    state: AppState,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut client_framed = Framed::new(client_socket, PostgresCodec::new());
    let mut upstream_framed = Framed::new(upstream_socket, PostgresCodec::new_upstream());

    let connection_id = rand::random::<u64>() as usize;
    let mut interceptor = Anonymizer::new(state.clone(), connection_id);

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
                                let id = format!("{:x}", rand::random::<u128>());
                                state.add_log(LogEntry {
                                    id,
                                    timestamp: Utc::now(),
                                    connection_id,
                                    event_type: "Query".to_string(),
                                    content: String::from_utf8_lossy(&q.query).to_string(),
                                    details: None,
                                }).await;
                                upstream_framed.send(msg).await?;
                            }
                            PgMessage::Parse(ref p) => {
                                let id = format!("{:x}", rand::random::<u128>());
                                state.add_log(LogEntry {
                                    id,
                                    timestamp: Utc::now(),
                                    connection_id,
                                    event_type: "Parse".to_string(),
                                    content: String::from_utf8_lossy(&p.query).to_string(),
                                    details: None,
                                }).await;
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
                        let msg_to_send = match msg {
                            PgMessage::RowDescription(ref rd) => {
                                interceptor.on_row_description(rd).await;
                                PgMessage::RowDescription(rd.clone())
                            }
                            PgMessage::DataRow(dr) => {
                                let new_dr = interceptor.on_data_row(dr).await?;
                                PgMessage::DataRow(new_dr)
                            }
                            _ => msg,
                        };
                        client_framed.send(msg_to_send).await?;
                    }
                    Some(Err(e)) => return Err(e),
                    None => return Ok(()), // Upstream disconnected
                }
            }
        }
    }
}

// ============================================================================
// MySQL Connection Handling
// ============================================================================

async fn process_mysql_connection(
    client_socket: tokio::net::TcpStream,
    upstream_host: String,
    upstream_port: u16,
    state: AppState,
) -> Result<()> {
    // Connect to upstream MySQL server
    let upstream_socket =
        tokio::net::TcpStream::connect(format!("{}:{}", upstream_host, upstream_port)).await?;

    handle_mysql_protocol(client_socket, upstream_socket, state).await
}

async fn handle_mysql_protocol<S, U>(
    client_socket: S,
    upstream_socket: U,
    state: AppState,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut client_framed = Framed::new(client_socket, MySqlCodec::new_server());
    let mut upstream_framed = Framed::new(upstream_socket, MySqlCodec::new_client());

    let connection_id = rand::random::<u64>() as usize;
    let mut interceptor = MySqlAnonymizer::new(state.clone(), connection_id);

    // Phase 1: Forward handshake from upstream to client
    let handshake = match upstream_framed.next().await {
        Some(Ok(MySqlMessage::Handshake(h))) => {
            info!(server_version = %h.server_version, "Received MySQL handshake from upstream");
            // Forward the handshake to the client
            client_framed
                .send(MySqlMessage::Handshake(h.clone()))
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

    // Phase 2: Forward client handshake response to upstream
    match client_framed.next().await {
        Some(Ok(MySqlMessage::HandshakeResponse(r))) => {
            info!(username = %r.username, database = ?r.database, "Received client handshake response");
            // Update capability flags based on what client actually supports
            client_framed
                .codec_mut()
                .set_capability_flags(r.capability_flags);
            upstream_framed
                .codec_mut()
                .set_capability_flags(r.capability_flags);
            upstream_framed
                .send(MySqlMessage::HandshakeResponse(r))
                .await?;
        }
        Some(Ok(other)) => {
            tracing::warn!("Expected handshake response, got {:?}", other);
            return Err(anyhow::anyhow!(
                "Protocol error: expected handshake response"
            ));
        }
        Some(Err(e)) => return Err(e),
        None => return Ok(()),
    }

    // Phase 3: Forward auth result
    match upstream_framed.next().await {
        Some(Ok(msg @ MySqlMessage::Ok(_))) => {
            info!("MySQL authentication successful");
            client_framed.send(msg).await?;
        }
        Some(Ok(MySqlMessage::Err(e))) => {
            tracing::warn!(error_code = e.error_code, "MySQL authentication failed");
            client_framed.send(MySqlMessage::Err(e)).await?;
            return Ok(());
        }
        Some(Ok(other)) => {
            // Could be auth switch request or other auth packets - forward as-is
            client_framed.send(other).await?;
        }
        Some(Err(e)) => return Err(e),
        None => return Ok(()),
    }

    // Phase 4: Command phase - bidirectional proxy with interception
    loop {
        tokio::select! {
            // Client -> Upstream
            msg = client_framed.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        if let MySqlMessage::Query(q) = &msg {
                            let id = format!("{:x}", rand::random::<u128>());
                            state.add_log(LogEntry {
                                id,
                                timestamp: Utc::now(),
                                connection_id,
                                event_type: "MySqlQuery".to_string(),
                                content: String::from_utf8_lossy(&q.query).to_string(),
                                details: None,
                            }).await;
                            // Reset interceptor for new result set
                            interceptor.reset_columns();
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
