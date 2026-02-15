//! Multi-tunnel manager
//!
//! Spawns and manages multiple tunnel connections from a single
//! configuration file, with shared inspector and graceful shutdown.

use crate::config::{TunnelConfig, ZTunnelConfig};
use crate::inspector::{InspectorEntry, InspectorState};
use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{error, info, warn};

/// Manages multiple tunnel connections
pub struct TunnelManager {
    config: ZTunnelConfig,
    inspector: InspectorState,
    inspector_tx: mpsc::Sender<InspectorEntry>,
    handles: Vec<JoinHandle<()>>,
}

impl TunnelManager {
    pub fn new(config: ZTunnelConfig, inspector: InspectorState, inspector_tx: mpsc::Sender<InspectorEntry>) -> Self {
        Self {
            config,
            inspector,
            inspector_tx,
            handles: Vec::new(),
        }
    }

    /// Start all tunnels defined in the configuration
    pub async fn start_all(&mut self) -> Result<()> {
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║  🚀 ZTunnel Multi-Tunnel Mode                                ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║  Starting {} tunnel(s)...                                     ║", self.config.tunnels.len());
        println!("╚══════════════════════════════════════════════════════════════╝\n");

        for tunnel_conf in &self.config.tunnels {
            let relay = self.config.relay.clone();
            let conf = tunnel_conf.clone();
            let inspector_tx = self.inspector_tx.clone();

            let handle = tokio::spawn(async move {
                loop {
                    match run_single_tunnel(&relay, &conf, inspector_tx.clone()).await {
                        Ok(_) => {
                            info!("Tunnel '{}' closed gracefully", conf.name);
                            break;
                        }
                        Err(e) => {
                            error!("Tunnel '{}' error: {}. Reconnecting in 5s...", conf.name, e);
                            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                        }
                    }
                }
            });

            self.handles.push(handle);
        }

        Ok(())
    }

    /// Wait for all tunnels to complete or Ctrl+C
    pub async fn wait_for_shutdown(self) {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutting down all tunnels...");
        for handle in self.handles {
            handle.abort();
        }
        println!("\n✓ All tunnels stopped.");
    }
}

/// Run a single tunnel connection
async fn run_single_tunnel(
    relay_url: &str,
    conf: &TunnelConfig,
    inspector_tx: mpsc::Sender<InspectorEntry>,
) -> Result<()> {
    info!("Connecting tunnel '{}' ({}) to {}", conf.name, conf.proto, relay_url);

    let (ws_stream, _) = connect_async(relay_url).await?;
    let (mut write, mut read) = ws_stream.split();

    // Send registration with IP filter info
    let registration = serde_json::json!({
        "subdomain": conf.subdomain,
        "type": conf.proto,
        "local_port": conf.local_port,
        "name": conf.name,
        "ip_filter": {
            "allow": conf.ip_filter.as_ref().map(|f| &f.allow).unwrap_or(&vec![]),
            "deny": conf.ip_filter.as_ref().map(|f| &f.deny).unwrap_or(&vec![]),
        }
    });

    write.send(Message::Text(registration.to_string().into())).await?;

    // Wait for confirmation
    if let Some(Ok(Message::Text(text))) = read.next().await {
        let response: serde_json::Value = serde_json::from_str(&text)?;
        if response.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
            let url = response.get("url").and_then(|v| v.as_str()).unwrap_or("unknown");
            println!("  ✓ {} ({}) → {} ↔ localhost:{}",
                conf.name, conf.proto.to_uppercase(), url, conf.local_port);
        } else {
            let err = response.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown");
            anyhow::bail!("Registration failed for '{}': {}", conf.name, err);
        }
    }

    // Main loop
    loop {
        tokio::select! {
            msg = read.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        let start = std::time::Instant::now();
                        match conf.proto.as_str() {
                            "http" => {
                                if let Err(e) = handle_http_request(
                                    &data, conf.local_port, &conf.local_host,
                                    &mut write, &inspector_tx, start
                                ).await {
                                    warn!("[{}] Error: {}", conf.name, e);
                                }
                            }
                            "tcp" => {
                                if let Err(e) = handle_tcp_data(
                                    &data, conf.local_port, &conf.local_host, &mut write
                                ).await {
                                    warn!("[{}] TCP error: {}", conf.name, e);
                                }
                            }
                            _ => {}
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        write.send(Message::Pong(data)).await?;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(e)) => {
                        error!("[{}] WebSocket error: {}", conf.name, e);
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

/// Handle an HTTP tunnel request with inspector integration
async fn handle_http_request<S>(
    data: &[u8],
    local_port: u16,
    local_host: &str,
    write: &mut S,
    inspector_tx: &mpsc::Sender<InspectorEntry>,
    start: std::time::Instant,
) -> Result<()>
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    use crate::tunnel::{TunnelRequest, TunnelResponse};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let request: TunnelRequest = serde_json::from_slice(data)?;
    info!("Proxying {} {} to {}:{}", request.method, request.path, local_host, local_port);

    let mut stream = tokio::net::TcpStream::connect(format!("{}:{}", local_host, local_port)).await?;

    // Build HTTP request
    let mut http_request = format!(
        "{} {} HTTP/1.1\r\nHost: {}:{}\r\n",
        request.method, request.path, local_host, local_port
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

    // Read and parse response
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut header_end = None;

    for _ in 0..64 {
        let n = stream.read(&mut tmp).await?;
        if n == 0 { break; }
        buf.extend_from_slice(&tmp[..n]);
        if header_end.is_none() {
            if let Some(pos) = crate::find_header_end(&buf) {
                header_end = Some(pos);
                break;
            }
        }
    }

    let (status, headers, body) = if let Some(hend) = header_end {
        let header_bytes = &buf[..hend];
        let mut lines = header_bytes.split(|b| *b == b'\r' || *b == b'\n').filter(|l| !l.is_empty());
        let status_line = lines.next().unwrap_or(&[]);
        let status = crate::parse_status_code(status_line).unwrap_or(200);
        let mut headers_vec: Vec<(String, String)> = Vec::new();
        let mut content_len: Option<usize> = None;

        for line in lines {
            if let Some((k, v)) = crate::split_header_kv(line) {
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

    // Send response back through tunnel
    let response = TunnelResponse {
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
    let _ = inspector_tx.send(entry).await;

    Ok(())
}

/// Handle raw TCP data
async fn handle_tcp_data<S>(
    data: &[u8],
    local_port: u16,
    local_host: &str,
    write: &mut S,
) -> Result<()>
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(format!("{}:{}", local_host, local_port)).await?;
    stream.write_all(data).await?;

    let mut response = vec![0u8; 65536];
    let n = stream.read(&mut response).await?;
    response.truncate(n);

    write
        .send(Message::Binary(response.into()))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to send: {}", e))?;

    Ok(())
}
