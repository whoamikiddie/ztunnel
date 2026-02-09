//! Tunnel types for client-server communication

use serde::{Deserialize, Serialize};

/// Request forwarded through tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelRequest {
    pub id: String,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

/// Response from local server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelResponse {
    pub id: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}
