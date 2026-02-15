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
use tokio::time::{timeout, Duration, Instant};

mod tunnel;
mod router;
mod ip_filter;
mod circuit_breaker;
mod metrics;
mod tls;
mod log_export;
mod headers;
mod policy;
mod acme;

use tunnel::Tunnel;
use metrics::Metrics;
use log_export::{LogExporter, LogExportConfig, LogEntry};

#[derive(Clone)]
pub struct AppState {
    tunnels: Arc<RwLock<HashMap<String, Tunnel>>>,
    domain: String,
    metrics: Metrics,
    log_exporter: LogExporter,
}

impl AppState {
    pub fn new(domain: String) -> Self {
        let log_config = LogExportConfig::default();
        Self {
            tunnels: Arc::new(RwLock::new(HashMap::new())),
            domain,
            metrics: Metrics::new(),
            log_exporter: LogExporter::new(log_config),
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
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .fallback(any(proxy_handler))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("ZTunnel Relay on {} (domain: {})", addr, domain);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Health check endpoint
async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let tunnels = state.tunnels.read().await;
    let count = tunnels.len();
    drop(tunnels);
    axum::Json(serde_json::json!({
        "status": "ok",
        "active_tunnels": count,
    }))
}

/// Prometheus metrics endpoint
async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let body = state.metrics.to_prometheus().await;
    (StatusCode::OK, [("content-type", "text/plain")], body)
}

/// WebSocket upgrade handler
async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

/// Handle a new WebSocket connection (tunnel registration)
async fn handle_socket(mut socket: WebSocket, state: AppState) {
    // Parse registration message
    let (subdomain, ip_filter_conf) = if let Some(Ok(Message::Text(text))) = socket.recv().await {
        let v = serde_json::from_str::<serde_json::Value>(&text).unwrap_or_default();
        
        let sub = v.get("subdomain")
            .and_then(|s| s.as_str())
            .map(String::from)
            .unwrap_or_else(gen_subdomain);
        
        // Parse IP filter from registration
        let ip_f = if let Some(ip_cfg) = v.get("ip_filter") {
            let allow: Vec<String> = ip_cfg.get("allow")
                .and_then(|a| serde_json::from_value(a.clone()).ok())
                .unwrap_or_default();
            let deny: Vec<String> = ip_cfg.get("deny")
                .and_then(|a| serde_json::from_value(a.clone()).ok())
                .unwrap_or_default();
            ip_filter::IpFilter::from_strings(&allow, &deny)
        } else {
            ip_filter::IpFilter::default()
        };

        (sub, ip_f)
    } else {
        (gen_subdomain(), ip_filter::IpFilter::default())
    };

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
    let cb = circuit_breaker::CircuitBreaker::new(circuit_breaker::CircuitBreakerConfig::default());

    // ─── Subdomain conflict resolution ───
    let final_subdomain = {
        let tunnels = state.tunnels.read().await;
        if tunnels.contains_key(&subdomain) {
            // Subdomain taken → append random suffix
            let suffix = gen_subdomain_short();
            let alt = format!("{}-{}", subdomain, suffix);
            warn!("Subdomain '{}' taken, assigning '{}'", subdomain, alt);
            alt
        } else {
            subdomain.clone()
        }
    };

    let tunnel = Tunnel::new(final_subdomain.clone(), tx, ip_filter_conf, cb.clone());
    
    state.tunnels.write().await.insert(final_subdomain.clone(), tunnel.clone());
    state.metrics.tunnel_opened();

    let url = format!("https://{}.{}", final_subdomain, state.domain);
    let was_reassigned = final_subdomain != subdomain;
    let resp = serde_json::json!({
        "success": true,
        "subdomain": &final_subdomain,
        "url": &url,
        "reassigned": was_reassigned,
    });
    
    if socket.send(Message::Text(resp.to_string().into())).await.is_err() {
        state.tunnels.write().await.remove(&final_subdomain);
        state.metrics.tunnel_closed();
        return;
    }
    
    if was_reassigned {
        info!("Tunnel active: {} (requested '{}', was taken)", url, subdomain);
    } else {
        info!("Tunnel active: {}", url);
    }

    // Drain any queued requests from circuit breaker
    let queued = cb.drain_queue().await;
    for data in queued {
        if socket.send(Message::Binary(data.into())).await.is_err() {
            break;
        }
    }

    let (mut sender, mut receiver) = socket.split();

    // Ping/pong keepalive
    let keepalive_interval = Duration::from_secs(30);
    let mut ping_timer = tokio::time::interval(keepalive_interval);

    loop {
        tokio::select! {
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Ping(d))) => { let _ = sender.send(Message::Pong(d)).await; }
                    Some(Ok(Message::Binary(data))) => {
                        if let Ok(resp) = serde_json::from_slice::<tunnel::TunnelResponse>(&data) {
                            tunnel.circuit_breaker.record_success().await;
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
                if sender.send(Message::Binary(data.into())).await.is_err() {
                    tunnel.circuit_breaker.record_failure().await;
                    break;
                }
            }
            _ = ping_timer.tick() => {
                if sender.send(Message::Ping(vec![].into())).await.is_err() {
                    break;
                }
            }
        }
    }

    state.tunnels.write().await.remove(&subdomain);
    state.metrics.tunnel_closed();
    info!("Tunnel {} closed", subdomain);
}

/// Main proxy handler with IP filtering, metrics, and circuit breaker
async fn proxy_handler(
    State(state): State<AppState>,
    req: Request<Body>,
) -> impl IntoResponse {
    let start = Instant::now();
    
    let host = req.headers().get(HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    let subdomain = host.split('.').next().unwrap_or("").to_string();
    let path = req.uri().path().to_string();
    let method = req.method().to_string();
    let headers: Vec<(String, String)> = req.headers().iter().filter_map(|(k, v)| {
        v.to_str().ok().map(|val| (k.as_str().to_string(), val.to_string()))
    }).collect();

    // Read request body
    let body_bytes = match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
        Ok(b) if !b.is_empty() => Some(b.to_vec()),
        _ => None,
    };

    let bytes_in = body_bytes.as_ref().map(|b| b.len() as u64).unwrap_or(0);

    // Get tunnel (clone + drop lock)
    let tunnel = {
        let tunnels = state.tunnels.read().await;
        match tunnels.get(&subdomain) {
            Some(t) => t.clone(),
            None => {
                warn!("No tunnel: {}", subdomain);
                return (StatusCode::NOT_FOUND, "Tunnel not found".to_string()).into_response();
            }
        }
    };

    // IP filtering
    if !tunnel.ip_filter.is_empty() {
        if let Some(client_ip) = ip_filter::extract_client_ip(&headers, None) {
            if !tunnel.ip_filter.is_allowed(client_ip) {
                warn!("IP {} blocked for tunnel {}", client_ip, subdomain);
                state.metrics.record_request(&subdomain, 403, start.elapsed().as_micros() as u64, bytes_in, 0).await;
                return (StatusCode::FORBIDDEN, "Access denied".to_string()).into_response();
            }
        }
    }

    let id = gen_request_id();
    let tr = tunnel::TunnelRequest {
        id: id.clone(),
        method: method.clone(),
        path: path.clone(),
        headers: headers.clone(),
        body: body_bytes,
    };
    let data = match serde_json::to_vec(&tr) {
        Ok(d) => d,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Serialization error").into_response();
        }
    };

    // Circuit breaker check
    let data = match tunnel.circuit_breaker.try_send(data).await {
        Ok(d) => d,
        Err(()) => {
            let latency = start.elapsed().as_micros() as u64;
            state.metrics.record_request(&subdomain, 503, latency, bytes_in, 0).await;
            return (StatusCode::SERVICE_UNAVAILABLE, "Service temporarily unavailable (queued)").into_response();
        }
    };

    let (tx, rx) = oneshot::channel::<tunnel::TunnelResponse>();
    tunnel.pending_requests.insert(id.clone(), tx);
    
    if tunnel.send(data).await.is_err() {
        tunnel.pending_requests.remove(&id);
        tunnel.circuit_breaker.record_failure().await;
        let latency = start.elapsed().as_micros() as u64;
        state.metrics.record_request(&subdomain, 502, latency, bytes_in, 0).await;
        return (StatusCode::BAD_GATEWAY, "Upstream send failed").into_response();
    }

    match timeout(Duration::from_secs(30), rx).await {
        Ok(Ok(resp)) => {
            let status_code = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::OK);
            let mut builder = Response::builder().status(status_code);
            if let Some(headers_mut) = builder.headers_mut() {
                for (k, v) in &resp.headers {
                    if let (Ok(hn), Ok(hv)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
                        headers_mut.insert(hn, hv);
                    }
                }
            }
            let body = resp.body.unwrap_or_default();
            let bytes_out = body.len() as u64;
            let latency = start.elapsed().as_micros() as u64;

            // Record metrics
            state.metrics.record_request(&subdomain, resp.status, latency, bytes_in, bytes_out).await;

            // Export log
            let user_agent = headers.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
                .map(|(_, v)| v.clone());
            let client_ip = ip_filter::extract_client_ip(&headers, None)
                .map(|ip| ip.to_string());

            let log_entry = LogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                level: if resp.status >= 500 { "ERROR" } else { "INFO" }.to_string(),
                subdomain: subdomain.clone(),
                method,
                path,
                status: resp.status,
                latency_us: latency,
                bytes_in,
                bytes_out,
                client_ip,
                user_agent,
            };
            state.log_exporter.log(&log_entry).await;

            match builder.body(Body::from(body)) {
                Ok(r) => r.into_response(),
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Response build error").into_response()
            }
        }
        Ok(Err(_)) => {
            tunnel.pending_requests.remove(&id);
            tunnel.circuit_breaker.record_failure().await;
            let latency = start.elapsed().as_micros() as u64;
            state.metrics.record_request(&subdomain, 502, latency, bytes_in, 0).await;
            (StatusCode::BAD_GATEWAY, "Upstream closed").into_response()
        }
        Err(_) => {
            tunnel.pending_requests.remove(&id);
            tunnel.circuit_breaker.record_failure().await;
            let latency = start.elapsed().as_micros() as u64;
            state.metrics.record_request(&subdomain, 504, latency, bytes_in, 0).await;
            (StatusCode::GATEWAY_TIMEOUT, "Timeout").into_response()
        }
    }
}

fn gen_subdomain() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!("t{:x}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() % 0xFFFFFF)
}

fn gen_subdomain_short() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!("{:x}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() % 0xFFF)
}

fn gen_request_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("r{:x}", ts)
}
