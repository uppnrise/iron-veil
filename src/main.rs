use anyhow::Result;
use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod protocol;
mod interceptor;
mod config;
mod scanner;
mod api;
mod state;

use futures::{SinkExt, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio_util::codec::Framed;
use crate::protocol::postgres::{PostgresCodec, PgMessage};
use crate::interceptor::{PacketInterceptor, Anonymizer};
use crate::config::AppConfig;
use crate::state::{AppState, LogEntry};
use chrono::Utc;
use std::sync::atomic::Ordering;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{ServerConfig, pki_types::CertificateDer, pki_types::PrivateKeyDer};
use std::sync::Arc;
use std::fs::File;
use std::io::BufReader;
use tokio::io::AsyncReadExt;
use tokio_rustls::rustls::ClientConfig;
use rustls_platform_verifier::Verifier;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use bytes::BufMut;
use tokio_rustls::rustls::crypto::aws_lc_rs::default_provider;

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
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    let args = Args::parse();

    // Load configuration
    let config = AppConfig::load(&args.config)?;
    info!("Loaded {} masking rules from {}", config.rules.len(), args.config);

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
        api::start_api_server(api_port, api_state).await;
    });

    info!("Starting DB Proxy on port {}", args.port);
    info!("Forwarding to upstream at {}:{}", args.upstream_host, args.upstream_port);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", args.port)).await?;

    loop {
        let (client_socket, client_addr) = listener.accept().await?;
        info!("Accepted connection from {}", client_addr);

        let upstream_host = args.upstream_host.clone();
        let upstream_port = args.upstream_port;
        let state = state.clone();
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            state.active_connections.fetch_add(1, Ordering::Relaxed);
            let result = process_connection(client_socket, upstream_host, upstream_port, state.clone(), tls_acceptor).await;
            state.active_connections.fetch_sub(1, Ordering::Relaxed);

            if let Err(e) = result {
                tracing::error!("Connection error: {}", e);
            }
        });
    }
}

async fn process_connection(
    mut client_socket: tokio::net::TcpStream,
    upstream_host: String,
    upstream_port: u16,
    state: AppState,
    tls_acceptor: Option<TlsAcceptor>,
) -> Result<()> {
    let mut buffer = [0u8; 8];
    let n = client_socket.peek(&mut buffer).await?;
    if n >= 8 {
        let len = u32::from_be_bytes(buffer[0..4].try_into().unwrap());
        let code = u32::from_be_bytes(buffer[4..8].try_into().unwrap());
        
        if len == 8 && code == 80877103 {
            // It is an SSLRequest
            let mut trash = [0u8; 8];
            client_socket.read_exact(&mut trash).await?;
            
            if let Some(acceptor) = tls_acceptor {
                info!("Received SSLRequest, accepting...");
                client_socket.write_all(b"S").await?;
                
                let tls_stream = acceptor.accept(client_socket).await?;
                return handle_protocol(tls_stream, upstream_host, upstream_port, state).await;
            } else {
                info!("Received SSLRequest, denying (TLS not configured)...");
                client_socket.write_all(b"N").await?;
            }
        }
    }
    
    handle_protocol(client_socket, upstream_host, upstream_port, state).await
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

async fn handle_protocol<S>(
    client_socket: S, 
    upstream_host: String, 
    upstream_port: u16, 
    state: AppState,
) -> Result<()> 
where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static
{
    // Create upstream connection
    let mut upstream_socket = tokio::net::TcpStream::connect(format!("{}:{}", upstream_host, upstream_port)).await?;
    
    // Check if upstream TLS is enabled
    let upstream_tls_enabled = {
        let config = state.config.read().await;
        config.upstream_tls
    };

    if upstream_tls_enabled {
        info!("Upstream TLS enabled. Attempting handshake with {}:{}", upstream_host, upstream_port);
        
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
            return handle_protocol_inner(client_socket, upstream_tls_stream, state).await;
        } else {
            tracing::warn!("Upstream denied SSLRequest. Falling back to cleartext (or aborting if strict).");
            // For now, we fall back to cleartext as per standard behavior, but you might want to enforce it.
        }
    }

    // Cleartext connection
    handle_protocol_inner(client_socket, upstream_socket, state).await
}

async fn handle_protocol_inner<S, U>(client_socket: S, upstream_socket: U, state: AppState) -> Result<()> 
where 
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static
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

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certfile = File::open(path)?;
    let mut reader = BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn load_keys(path: &str) -> Result<PrivateKeyDer<'static>> {
    let keyfile = File::open(path)?;
    let mut reader = BufReader::new(keyfile);
    let key = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("No private key found"))?;
    Ok(key)
}
