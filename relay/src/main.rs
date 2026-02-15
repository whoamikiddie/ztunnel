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
use tokio::sync::{mpsc, RwLock, oneshot};
use tracing::{info, warn};
use futures_util::{SinkExt, StreamExt};
use hyper::Response;
use hyper::header::{HeaderName, HeaderValue};
use tokio::time::{timeout, Duration};

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
        .fallback(any(proxy_handler))
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
    
    state.tunnels.write().await.insert(subdomain.clone(), tunnel.clone());

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
                    Some(Ok(Message::Binary(data))) => {
                        if let Ok(resp) = serde_json::from_slice::<tunnel::TunnelResponse>(&data) {
                            if let Some((_id, tx)) = tunnel.pending_requests.remove(&resp.id) {
                                let _ = tx.send(resp);
                            }
                        }
                    }
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
    let subdomain = host.split('.').next().unwrap_or("").to_string();
    let path = req.uri().path().to_string();
    let method = req.method().to_string();
    let headers: Vec<(String, String)> = req.headers().iter().filter_map(|(k, v)| {
        v.to_str().ok().map(|val| (k.as_str().to_string(), val.to_string()))
    }).collect();

    // Read request body BEFORE dropping the request
    let body_bytes = match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
        Ok(b) if !b.is_empty() => Some(b.to_vec()),
        _ => None,
    };

    // Clone tunnel and DROP the lock immediately to avoid holding across awaits
    let tunnel = {
        let tunnels = state.tunnels.read().await;
        match tunnels.get(&subdomain) {
            Some(t) => t.clone(),
            None => {
                warn!("No tunnel: {}", subdomain);
                return (StatusCode::NOT_FOUND, "Tunnel not found".to_string()).into_response();
            }
        }
    }; // RwLock released here

    let id = gen_request_id();
    let tr = tunnel::TunnelRequest {
        id: id.clone(),
        method,
        path,
        headers,
        body: body_bytes,
    };
    let data = match serde_json::to_vec(&tr) {
        Ok(d) => d,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Serialization error").into_response();
        }
    };
    let (tx, rx) = oneshot::channel::<tunnel::TunnelResponse>();
    tunnel.pending_requests.insert(id.clone(), tx);
    if tunnel.send(data).await.is_err() {
        tunnel.pending_requests.remove(&id);
        return (StatusCode::BAD_GATEWAY, "Upstream send failed").into_response();
    }
    match timeout(Duration::from_secs(30), rx).await {
        Ok(Ok(resp)) => {
            let mut builder = Response::builder()
                .status(StatusCode::from_u16(resp.status).unwrap_or(StatusCode::OK));
            if let Some(headers_mut) = builder.headers_mut() {
                for (k, v) in resp.headers {
                    if let (Ok(hn), Ok(hv)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&v)) {
                        headers_mut.insert(hn, hv);
                    }
                }
            }
            let body = resp.body.unwrap_or_default();
            match builder.body(Body::from(body)) {
                Ok(r) => r.into_response(),
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Response build error").into_response()
            }
        }
        Ok(Err(_)) => {
            tunnel.pending_requests.remove(&id);
            (StatusCode::BAD_GATEWAY, "Upstream closed").into_response()
        }
        Err(_) => {
            tunnel.pending_requests.remove(&id);
            (StatusCode::GATEWAY_TIMEOUT, "Timeout").into_response()
        }
    }
}

fn gen_subdomain() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!("t{:x}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() % 0xFFFFFF)
}

fn gen_request_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("r{:x}", ts)
}
