use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{error, info, warn};

mod tunnel;
mod proxy;
mod inspector;
mod config;
mod multi;

use inspector::{InspectorEntry, InspectorState};

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

        /// Disable inspector dashboard
        #[arg(long)]
        no_inspect: bool,

        /// Inspector dashboard port
        #[arg(long, default_value = "4040")]
        inspect_port: u16,
    },
    /// Expose TCP service
    Tcp {
        /// Local port to expose
        port: u16,
    },
    /// Start tunnels from config file (ztunnel.yml)
    Start {
        /// Path to config file (default: auto-detect)
        #[arg(short, long)]
        config: Option<String>,
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
        Commands::Http { port, subdomain, no_inspect, inspect_port } => {
            run_http_tunnel(&cli.relay, port, subdomain, !no_inspect, inspect_port).await?;
        }
        Commands::Tcp { port } => {
            run_tcp_tunnel(&cli.relay, port).await?;
        }
        Commands::Start { config: config_path } => {
            run_multi_tunnel(config_path).await?;
        }
    }

    Ok(())
}

/// Run multi-tunnel mode from config file
async fn run_multi_tunnel(config_path: Option<String>) -> Result<()> {
    let path = if let Some(p) = config_path {
        std::path::PathBuf::from(p)
    } else {
        config::ZTunnelConfig::find_config()
            .ok_or_else(|| anyhow::anyhow!("No config file found. Create ztunnel.yml or specify --config"))?
    };

    let cfg = config::ZTunnelConfig::load(&path)?;
    info!("Loaded config from {}", path.display());

    // Setup inspector
    let (replay_tx, mut replay_rx) = mpsc::channel::<String>(32);
    let (entry_tx, mut entry_rx) = mpsc::channel::<InspectorEntry>(256);
    let inspector = InspectorState::new(replay_tx);

    // Start inspector server if enabled
    if cfg.inspector.enabled {
        let insp = inspector.clone();
        let port = cfg.inspector.port;
        tokio::spawn(async move {
            inspector::start_inspector(insp, port).await;
        });
    }

    // Pipe entries from tunnels to inspector
    let insp2 = inspector.clone();
    tokio::spawn(async move {
        while let Some(entry) = entry_rx.recv().await {
            insp2.record(entry).await;
        }
    });

    // Handle replay requests
    let cfg_clone = cfg.clone();
    let entry_tx_clone = entry_tx.clone();
    tokio::spawn(async move {
        while let Some(id) = replay_rx.recv().await {
            info!("Replaying request: {}", id);
            let insp = InspectorState::new(tokio::sync::mpsc::channel(1).0);
            if let Some(entry) = insp.get_entry(&id).await {
                info!("Found entry for replay: {} {}", entry.method, entry.path);
            }
        }
    });

    let mut manager = multi::TunnelManager::new(cfg, inspector, entry_tx);
    manager.start_all().await?;

    println!("\n  Inspector: http://localhost:{}\n", cfg_clone.inspector.port);
    println!("Press Ctrl+C to stop all tunnels\n");

    manager.wait_for_shutdown().await;
    Ok(())
}

/// Run HTTP tunnel with optional inspector
async fn run_http_tunnel(
    relay_url: &str,
    local_port: u16,
    subdomain: Option<String>,
    inspect: bool,
    inspect_port: u16,
) -> Result<()> {
    // Setup inspector
    let (replay_tx, mut replay_rx) = mpsc::channel::<String>(32);
    let inspector = InspectorState::new(replay_tx);

    if inspect {
        let insp = inspector.clone();
        tokio::spawn(async move {
            inspector::start_inspector(insp, inspect_port).await;
        });
    }

    // Handle replay requests
    let insp_for_replay = inspector.clone();
    let relay_for_replay = relay_url.to_string();
    tokio::spawn(async move {
        while let Some(id) = replay_rx.recv().await {
            info!("Replay request: {}", id);
            if let Some(entry) = insp_for_replay.get_entry(&id).await {
                // Re-execute the request against local server
                let _ = replay_local_request(&entry, local_port).await;
            }
        }
    });

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
            if inspect {
                println!("║  Inspector:  http://localhost:{:<34} ║", inspect_port);
            }
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
                        let start = std::time::Instant::now();
                        if let Err(e) = handle_tunnel_request_with_inspector(
                            &data, local_port, &mut write, &inspector, start
                        ).await {
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

/// Handle tunnel request with inspector recording
async fn handle_tunnel_request_with_inspector<S>(
    data: &[u8],
    local_port: u16,
    write: &mut S,
    inspector: &InspectorState,
    start: std::time::Instant,
) -> Result<()>
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let request: tunnel::TunnelRequest = serde_json::from_slice(data)?;
    info!("Proxying {} {} to localhost:{}", request.method, request.path, local_port);
    
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", local_port)).await?;
    
    let mut http_request = format!(
        "{} {} HTTP/1.1\r\nHost: localhost:{}\r\n",
        request.method, request.path, local_port
    );
    for (key, value) in &request.headers {
        http_request.push_str(&format!("{}: {}\r\n", key, value));
    }
    if let Some(body) = &request.body {
        http_request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    http_request.push_str("\r\n");
    
    stream.write_all(http_request.as_bytes()).await?;
    if let Some(body) = &request.body {
        stream.write_all(body).await?;
    }
    
    // Read response
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut header_end = None;
    
    for _ in 0..64 {
        let n = stream.read(&mut tmp).await?;
        if n == 0 { break; }
        buf.extend_from_slice(&tmp[..n]);
        if header_end.is_none() {
            if let Some(pos) = find_header_end(&buf) {
                header_end = Some(pos);
                break;
            }
        }
    }
    
    let (status, headers, body) = if let Some(hend) = header_end {
        let header_bytes = &buf[..hend];
        let mut lines = header_bytes.split(|b| *b == b'\r' || *b == b'\n').filter(|l| !l.is_empty());
        let status_line = lines.next().unwrap_or(&[]);
        let status = parse_status_code(status_line).unwrap_or(200);
        let mut headers_vec: Vec<(String, String)> = Vec::new();
        let mut content_len: Option<usize> = None;
        
        for line in lines {
            if let Some((k, v)) = split_header_kv(line) {
                if k.eq_ignore_ascii_case("content-length") {
                    if let Ok(cl) = v.trim().parse::<usize>() {
                        content_len = Some(cl);
                    }
                }
                headers_vec.push((k.to_string(), v.to_string()));
            }
        }
        
        let mut body = buf[hend + 4..].to_vec();
        if let Some(cl) = content_len {
            while body.len() < cl {
                let n = stream.read(&mut tmp).await?;
                if n == 0 { break; }
                body.extend_from_slice(&tmp[..n]);
            }
            if body.len() > cl {
                body.truncate(cl);
            }
        }
        (status, headers_vec, body)
    } else {
        (200, Vec::new(), buf)
    };
    
    let latency_ms = start.elapsed().as_millis() as u64;
    let body_size = body.len();
    
    // Send tunnel response
    let response = tunnel::TunnelResponse {
        id: request.id.clone(),
        status,
        headers: headers.clone(),
        body: Some(body.clone()),
    };
    let response_data = serde_json::to_vec(&response)?;
    write
        .send(Message::Binary(response_data.into()))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to send response: {}", e))?;
    
    // Record in inspector
    let entry = InspectorEntry {
        id: request.id,
        timestamp: chrono::Utc::now().to_rfc3339(),
        method: request.method,
        path: request.path,
        status,
        latency_ms,
        req_headers: request.headers,
        req_body: request.body.map(|b| String::from_utf8_lossy(&b).to_string()),
        res_headers: headers,
        res_body: Some(String::from_utf8_lossy(&body).to_string()),
        res_body_size: body_size,
    };
    inspector.record(entry).await;
    
    Ok(())
}

/// Replay a request against the local server
async fn replay_local_request(entry: &InspectorEntry, local_port: u16) -> Result<()> {
    use tokio::io::{AsyncWriteExt, AsyncReadExt};

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", local_port)).await?;

    let mut http_request = format!(
        "{} {} HTTP/1.1\r\nHost: localhost:{}\r\n",
        entry.method, entry.path, local_port
    );
    for (key, value) in &entry.req_headers {
        http_request.push_str(&format!("{}: {}\r\n", key, value));
    }
    http_request.push_str("\r\n");

    stream.write_all(http_request.as_bytes()).await?;
    if let Some(body) = &entry.req_body {
        stream.write_all(body.as_bytes()).await?;
    }

    let mut response = vec![0u8; 65536];
    let n = stream.read(&mut response).await?;
    info!("Replay response: {} bytes", n);

    Ok(())
}

// Helper functions (pub(crate) for use in multi.rs)
pub(crate) fn find_header_end(buf: &[u8]) -> Option<usize> {
    let pat = b"\r\n\r\n";
    buf.windows(4).position(|w| w == pat)
}

pub(crate) fn parse_status_code(line: &[u8]) -> Option<u16> {
    let s = std::str::from_utf8(line).ok()?;
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() >= 2 {
        parts[1].parse::<u16>().ok()
    } else {
        None
    }
}

pub(crate) fn split_header_kv(line: &[u8]) -> Option<(&str, &str)> {
    let s = std::str::from_utf8(line).ok()?;
    let mut iter = s.splitn(2, ':');
    let k = iter.next()?.trim();
    let v = iter.next()?.trim();
    Some((k, v))
}

/// Run TCP tunnel
async fn run_tcp_tunnel(relay_url: &str, local_port: u16) -> Result<()> {
    info!("TCP tunnel mode for port {}", local_port);
    
    let (ws_stream, _) = connect_async(relay_url)
        .await
        .context("Failed to connect to relay server")?;
    
    let (mut write, mut read) = ws_stream.split();
    
    let registration = serde_json::json!({
        "type": "tcp",
        "local_port": local_port,
    });
    
    write.send(Message::Text(registration.to_string().into())).await?;
    
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
    
    loop {
        tokio::select! {
            msg = read.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
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
