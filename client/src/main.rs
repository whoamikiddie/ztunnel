use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{error, info, warn};

mod tunnel;
mod proxy;

#[derive(Parser)]
#[command(name = "ztunnel")]
#[command(author = "ZTunnel Team")]
#[command(version = "0.1.0")]
#[command(about = "Secure tunnel to expose local services", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Relay server URL
    #[arg(short, long, default_value = "ws://localhost:8080/tunnel")]
    relay: String,
    
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Expose HTTP service
    Http {
        /// Local port to expose
        port: u16,
        
        /// Custom subdomain
        #[arg(short, long)]
        subdomain: Option<String>,
    },
    /// Expose TCP service
    Tcp {
        /// Local port to expose
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();
    }

    match cli.command {
        Commands::Http { port, subdomain } => {
            run_http_tunnel(&cli.relay, port, subdomain).await?;
        }
        Commands::Tcp { port } => {
            run_tcp_tunnel(&cli.relay, port).await?;
        }
    }

    Ok(())
}

/// Run HTTP tunnel
async fn run_http_tunnel(relay_url: &str, local_port: u16, subdomain: Option<String>) -> Result<()> {
    info!("Connecting to relay: {}", relay_url);
    
    let (ws_stream, _) = connect_async(relay_url)
        .await
        .context("Failed to connect to relay server")?;
    
    let (mut write, mut read) = ws_stream.split();
    
    // Send registration
    let registration = serde_json::json!({
        "subdomain": subdomain,
        "type": "http",
        "local_port": local_port,
    });
    
    write.send(Message::Text(registration.to_string().into())).await?;
    info!("Sent registration request");
    
    // Wait for confirmation
    if let Some(Ok(Message::Text(text))) = read.next().await {
        let response: serde_json::Value = serde_json::from_str(&text)?;
        
        if response.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
            let url = response.get("url").and_then(|v| v.as_str()).unwrap_or("unknown");
            println!("\n╔══════════════════════════════════════════════════════════════╗");
            println!("║  🚀 ZTunnel Active                                           ║");
            println!("╠══════════════════════════════════════════════════════════════╣");
            println!("║  Public URL: {:<47} ║", url);
            println!("║  Local:      http://localhost:{:<34} ║", local_port);
            println!("╚══════════════════════════════════════════════════════════════╝\n");
            println!("Press Ctrl+C to stop the tunnel\n");
        } else {
            let err = response.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
            error!("Registration failed: {}", err);
            return Err(anyhow::anyhow!("Registration failed: {}", err));
        }
    }
    
    // Main tunnel loop
    loop {
        tokio::select! {
            msg = read.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        // Parse and forward HTTP request to local server
                        if let Err(e) = handle_tunnel_request(&data, local_port, &mut write).await {
                            warn!("Error handling request: {}", e);
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        write.send(Message::Pong(data)).await?;
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        info!("Connection closed");
                        break;
                    }
                    Some(Err(e)) => {
                        error!("WebSocket error: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Shutting down...");
                write.send(Message::Close(None)).await?;
                break;
            }
        }
    }
    
    Ok(())
}

/// Handle incoming tunnel request and forward to local server
async fn handle_tunnel_request<S>(
    data: &[u8],
    local_port: u16,
    write: &mut S,
) -> Result<()>
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    // Parse tunnel request
    let request: tunnel::TunnelRequest = serde_json::from_slice(data)?;
    
    info!("Proxying {} {} to localhost:{}", request.method, request.path, local_port);
    
    // Connect to local server
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", local_port)).await?;
    
    // Build HTTP request
    let mut http_request = format!(
        "{} {} HTTP/1.1\r\nHost: localhost:{}\r\n",
        request.method, request.path, local_port
    );
    
    for (key, value) in &request.headers {
        http_request.push_str(&format!("{}: {}\r\n", key, value));
    }
    http_request.push_str("\r\n");
    
    stream.write_all(http_request.as_bytes()).await?;
    
    if let Some(body) = &request.body {
        stream.write_all(body).await?;
    }
    
    // Read response
    let mut response_buf = vec![0u8; 65536];
    let n = stream.read(&mut response_buf).await?;
    response_buf.truncate(n);
    
    // Parse response (simplified)
    let response = tunnel::TunnelResponse {
        id: request.id,
        status: 200, // Would parse from actual response
        headers: vec![],
        body: Some(response_buf),
    };
    
    let response_data = serde_json::to_vec(&response)?;
    write.send(Message::Binary(response_data.into())).await
        .map_err(|e| anyhow::anyhow!("Failed to send response: {}", e))?;
    
    Ok(())
}

/// Run TCP tunnel
async fn run_tcp_tunnel(relay_url: &str, local_port: u16) -> Result<()> {
    info!("TCP tunnel mode for port {}", local_port);
    
    let (ws_stream, _) = connect_async(relay_url)
        .await
        .context("Failed to connect to relay server")?;
    
    let (mut write, mut read) = ws_stream.split();
    
    // Send registration
    let registration = serde_json::json!({
        "type": "tcp",
        "local_port": local_port,
    });
    
    write.send(Message::Text(registration.to_string().into())).await?;
    
    // Wait for confirmation and get assigned port
    if let Some(Ok(Message::Text(text))) = read.next().await {
        let response: serde_json::Value = serde_json::from_str(&text)?;
        
        if response.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
            let url = response.get("url").and_then(|v| v.as_str()).unwrap_or("unknown");
            println!("\n╔══════════════════════════════════════════════════════════════╗");
            println!("║  🚀 ZTunnel TCP Active                                       ║");
            println!("╠══════════════════════════════════════════════════════════════╣");
            println!("║  Public:     {:<47} ║", url);
            println!("║  Local:      localhost:{:<38} ║", local_port);
            println!("╚══════════════════════════════════════════════════════════════╝\n");
        }
    }
    
    // TCP forwarding loop
    loop {
        tokio::select! {
            msg = read.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        // Forward raw TCP data to local port
                        if let Ok(mut stream) = tokio::net::TcpStream::connect(
                            format!("127.0.0.1:{}", local_port)
                        ).await {
                            let _ = stream.write_all(&data).await;
                            
                            let mut response = vec![0u8; 65536];
                            if let Ok(n) = stream.read(&mut response).await {
                                response.truncate(n);
                                let _ = write.send(Message::Binary(response.into())).await;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        break;
                    }
                    _ => {}
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Shutting down...");
                break;
            }
        }
    }
    
    Ok(())
}
