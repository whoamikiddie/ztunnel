//! Request Inspector Dashboard
//!
//! Provides a local web UI showing real-time request/response logs
//! with replay capability via Server-Sent Events (SSE).

use axum::{
    extract::State as AxumState,
    http::StatusCode,
    response::{Html, IntoResponse, Sse},
    routing::{get, post},
    Router,
};
use axum::response::sse::{Event, KeepAlive};
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use tracing::{info, warn};

/// Max entries kept in the ring buffer
const MAX_ENTRIES: usize = 500;

/// An inspector entry representing a single request/response pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectorEntry {
    pub id: String,
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub latency_ms: u64,
    pub req_headers: Vec<(String, String)>,
    pub req_body: Option<String>,
    pub res_headers: Vec<(String, String)>,
    pub res_body: Option<String>,
    pub res_body_size: usize,
}

/// Shared inspector state
#[derive(Clone)]
pub struct InspectorState {
    /// Ring buffer of recent entries
    entries: Arc<Mutex<VecDeque<InspectorEntry>>>,
    /// Broadcast channel for SSE
    tx: broadcast::Sender<InspectorEntry>,
    /// Replay callback: sends a request ID to replay
    replay_tx: tokio::sync::mpsc::Sender<String>,
}

impl InspectorState {
    pub fn new(replay_tx: tokio::sync::mpsc::Sender<String>) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            entries: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_ENTRIES))),
            tx,
            replay_tx,
        }
    }

    /// Record a new request/response pair
    pub async fn record(&self, entry: InspectorEntry) {
        {
            let mut entries = self.entries.lock().await;
            if entries.len() >= MAX_ENTRIES {
                entries.pop_back();
            }
            entries.push_front(entry.clone());
        }
        // Broadcast to all SSE listeners (ignore if no receivers)
        let _ = self.tx.send(entry);
    }

    /// Get an entry by ID for replay
    pub async fn get_entry(&self, id: &str) -> Option<InspectorEntry> {
        let entries = self.entries.lock().await;
        entries.iter().find(|e| e.id == id).cloned()
    }
}

/// Start the inspector HTTP server on the given port
pub async fn start_inspector(state: InspectorState, port: u16) {
    let app = Router::new()
        .route("/", get(dashboard_handler))
        .route("/events", get(sse_handler))
        .route("/replay/{id}", post(replay_handler))
        .route("/api/entries", get(entries_handler))
        .with_state(state);

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    info!("Inspector dashboard: http://localhost:{}", port);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!("Failed to start inspector on port {}: {}", port, e);
            return;
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        warn!("Inspector server error: {}", e);
    }
}

/// Serve the embedded HTML dashboard
async fn dashboard_handler() -> impl IntoResponse {
    Html(include_str!("../assets/inspector.html"))
}

/// SSE endpoint for real-time request streaming
async fn sse_handler(
    AxumState(state): AxumState<InspectorState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = state.tx.subscribe();

    let stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(entry) => {
                    if let Ok(json) = serde_json::to_string(&entry) {
                        yield Ok(Event::default().data(json));
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("SSE client lagged, skipped {} events", n);
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Replay a previously recorded request
async fn replay_handler(
    AxumState(state): AxumState<InspectorState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    if let Some(_entry) = state.get_entry(&id).await {
        match state.replay_tx.send(id).await {
            Ok(_) => (StatusCode::OK, "Replaying request"),
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Replay channel closed"),
        }
    } else {
        (StatusCode::NOT_FOUND, "Request not found")
    }
}

/// Get all stored entries as JSON
async fn entries_handler(
    AxumState(state): AxumState<InspectorState>,
) -> impl IntoResponse {
    let entries = state.entries.lock().await;
    let vec: Vec<InspectorEntry> = entries.iter().cloned().collect();
    axum::Json(vec)
}
