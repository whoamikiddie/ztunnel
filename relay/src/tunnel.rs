//! Tunnel management for ZTunnel Relay

use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use dashmap::DashMap;

/// Unique tunnel identifier
pub type TunnelId = String;

/// Represents an active tunnel connection
#[derive(Clone)]
pub struct Tunnel {
    /// Subdomain for this tunnel
    pub subdomain: String,
    /// Channel to send data to the tunnel client
    pub tx: mpsc::Sender<Vec<u8>>,
    /// Tunnel metadata
    pub created_at: std::time::Instant,
    /// Pending request correlation map
    pub pending_requests: Arc<DashMap<String, oneshot::Sender<TunnelResponse>>>,
}

impl Tunnel {
    pub fn new(subdomain: String, tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            subdomain,
            tx,
            created_at: std::time::Instant::now(),
            pending_requests: Arc::new(DashMap::new()),
        }
    }

    /// Send data to the tunnel client
    pub async fn send(&self, data: Vec<u8>) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.tx.send(data).await
    }
}

/// Tunnel request/response for HTTP proxying
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TunnelRequest {
    pub id: String,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TunnelResponse {
    pub id: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}
