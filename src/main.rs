use anyhow::Result;
use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod protocol;
mod interceptor;

use futures::{SinkExt, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio_util::codec::Framed;
use crate::protocol::postgres::{PostgresCodec, PgMessage};
use crate::interceptor::{PacketInterceptor, Anonymizer};

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

    info!("Starting DB Proxy on port {}", args.port);
    info!("Forwarding to upstream at {}:{}", args.upstream_host, args.upstream_port);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", args.port)).await?;

    loop {
        let (client_socket, client_addr) = listener.accept().await?;
        info!("Accepted connection from {}", client_addr);

        let upstream_host = args.upstream_host.clone();
        let upstream_port = args.upstream_port;

        tokio::spawn(async move {
            if let Err(e) = process_connection(client_socket, upstream_host, upstream_port).await {
                tracing::error!("Connection error: {}", e);
            }
        });
    }
}

async fn process_connection(client_socket: tokio::net::TcpStream, upstream_host: String, upstream_port: u16) -> Result<()> {
    let upstream_socket = tokio::net::TcpStream::connect(format!("{}:{}", upstream_host, upstream_port)).await?;
    
    let mut client_framed = Framed::new(client_socket, PostgresCodec::new());
    let mut upstream_framed = Framed::new(upstream_socket, PostgresCodec::new_upstream());
    let mut interceptor = Anonymizer::new();

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
                                interceptor.on_row_description(rd);
                                PgMessage::RowDescription(rd.clone())
                            }
                            PgMessage::DataRow(dr) => {
                                let new_dr = interceptor.on_data_row(dr)?;
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
