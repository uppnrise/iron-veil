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

    // Use the config from state which is already wrapped in Arc<RwLock>
    let config = state.config.clone();

    loop {
        let (client_socket, client_addr) = listener.accept().await?;
        info!("Accepted connection from {}", client_addr);

        let upstream_host = args.upstream_host.clone();
        let upstream_port = args.upstream_port;
        let state = state.clone();

        tokio::spawn(async move {
            state.active_connections.fetch_add(1, Ordering::Relaxed);
            let result = process_connection(client_socket, upstream_host, upstream_port, state.clone()).await;
            state.active_connections.fetch_sub(1, Ordering::Relaxed);

            if let Err(e) = result {
                tracing::error!("Connection error: {}", e);
            }
        });
    }
}

async fn process_connection(client_socket: tokio::net::TcpStream, upstream_host: String, upstream_port: u16, state: AppState) -> Result<()> {
    let upstream_socket = tokio::net::TcpStream::connect(format!("{}:{}", upstream_host, upstream_port)).await?;
    
    let mut client_framed = Framed::new(client_socket, PostgresCodec::new());
    let mut upstream_framed = Framed::new(upstream_socket, PostgresCodec::new_upstream());
    
    let connection_id = rand::random::<usize>();
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
                                    content: q.query.clone(),
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
                                    content: p.query.clone(),
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
