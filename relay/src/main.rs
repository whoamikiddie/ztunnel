use anyhow::Result;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::{StatusCode, header::HOST, Request},
    body::Body,
    response::IntoResponse,
    routing::{get, any},
    Router,
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};
use futures_util::{SinkExt, StreamExt};

mod tunnel;
mod router;

use tunnel::Tunnel;

#[derive(Clone)]
pub struct AppState {
    tunnels: Arc<RwLock<HashMap<String, Tunnel>>>,
    domain: String,
}

impl AppState {
    pub fn new(domain: String) -> Self {
        Self {
            tunnels: Arc::new(RwLock::new(HashMap::new())),
            domain,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("ztunnel_relay=info")
        .init();

    let domain = std::env::var("ZTUNNEL_DOMAIN").unwrap_or_else(|_| "connectus.net.in".to_string());
    let port: u16 = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string()).parse().unwrap_or(8080);

    let state = AppState::new(domain.clone());

    let app = Router::new()
        .route("/tunnel", get(ws_handler))
        .route("/health", get(|| async { "OK" }))
        .route("/{*path}", any(proxy_handler))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("ZTunnel Relay on {} (domain: {})", addr, domain);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: AppState) {
    let subdomain = if let Some(Ok(Message::Text(text))) = socket.recv().await {
        serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v.get("subdomain")?.as_str().map(String::from))
            .unwrap_or_else(gen_subdomain)
    } else {
        gen_subdomain()
    };

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
    let tunnel = Tunnel::new(subdomain.clone(), tx);
    
    state.tunnels.write().await.insert(subdomain.clone(), tunnel);

    let url = format!("https://{}.{}", subdomain, state.domain);
    let resp = serde_json::json!({"success": true, "subdomain": &subdomain, "url": &url});
    
    if socket.send(Message::Text(resp.to_string().into())).await.is_err() {
        state.tunnels.write().await.remove(&subdomain);
        return;
    }
    
    info!("Tunnel active: {}", url);

    let (mut sender, mut receiver) = socket.split();

    loop {
        tokio::select! {
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Ping(d))) => { let _ = sender.send(Message::Pong(d)).await; }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
            Some(data) = rx.recv() => {
                if sender.send(Message::Binary(data.into())).await.is_err() { break; }
            }
        }
    }

    state.tunnels.write().await.remove(&subdomain);
    info!("Tunnel {} closed", subdomain);
}

async fn proxy_handler(
    State(state): State<AppState>,
    req: Request<Body>,
) -> impl IntoResponse {
    let host = req.headers().get(HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    let subdomain = host.split('.').next().unwrap_or("");
    let path = req.uri().path();
    
    let tunnels = state.tunnels.read().await;
    if let Some(_t) = tunnels.get(subdomain) {
        info!("Proxy {} → {}", subdomain, path);
        (StatusCode::OK, format!("Tunnel {} path {}", subdomain, path))
    } else {
        warn!("No tunnel: {}", subdomain);
        (StatusCode::NOT_FOUND, "Tunnel not found".to_string())
    }
}

fn gen_subdomain() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!("t{:x}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() % 0xFFFFFF)
}
