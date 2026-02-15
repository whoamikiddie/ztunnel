//! Tunnel management for ZTunnel Relay
//!
//! Extended with IP filtering, circuit breaker, and load balancing support.

use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use dashmap::DashMap;

use crate::ip_filter::IpFilter;
use crate::circuit_breaker::CircuitBreaker;

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
    /// IP access control
    pub ip_filter: IpFilter,
    /// Circuit breaker for this tunnel
    pub circuit_breaker: CircuitBreaker,
    /// Load balanced clients (for future multi-client support)
    pub lb_clients: Arc<tokio::sync::RwLock<Vec<mpsc::Sender<Vec<u8>>>>>,
    /// Round-robin counter for load balancing
    pub lb_counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl Tunnel {
    pub fn new(
        subdomain: String,
        tx: mpsc::Sender<Vec<u8>>,
        ip_filter: IpFilter,
        circuit_breaker: CircuitBreaker,
    ) -> Self {
        Self {
            subdomain,
            tx: tx.clone(),
            created_at: std::time::Instant::now(),
            pending_requests: Arc::new(DashMap::new()),
            ip_filter,
            circuit_breaker,
            lb_clients: Arc::new(tokio::sync::RwLock::new(vec![tx])),
            lb_counter: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Send data to a tunnel client (with load balancing)
    pub async fn send(&self, data: Vec<u8>) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        let clients = self.lb_clients.read().await;
        
        if clients.len() <= 1 {
            // Single client, use primary
            return self.tx.send(data).await;
        }

        // Round-robin across connected clients
        let idx = self.lb_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % clients.len();
        clients[idx].send(data).await
    }

    /// Add a load-balanced client
    pub async fn add_lb_client(&self, tx: mpsc::Sender<Vec<u8>>) {
        let mut clients = self.lb_clients.write().await;
        clients.push(tx);
    }

    /// Remove disconnected clients
    pub async fn cleanup_lb_clients(&self) {
        let mut clients = self.lb_clients.write().await;
        clients.retain(|tx| !tx.is_closed());
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
