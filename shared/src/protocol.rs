//! Binary protocol types for ZTunnel communication.

use serde::{Deserialize, Serialize};

/// Maximum message size (16 MB)
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Message types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    /// Handshake initiation
    ClientHello = 0x01,
    /// Handshake response
    ServerHello = 0x02,
    /// Encrypted data frame
    Data = 0x10,
    /// Tunnel request
    TunnelRequest = 0x20,
    /// Tunnel response
    TunnelResponse = 0x21,
    /// Heartbeat ping
    Ping = 0x30,
    /// Heartbeat pong
    Pong = 0x31,
    /// Close connection
    Close = 0xFF,
}

/// Handshake message for key exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub version: u8,
    pub ephemeral_pubkey: [u8; 32],
    pub nonce: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    pub version: u8,
    pub ephemeral_pubkey: [u8; 32],
    pub nonce: [u8; 32],
}

/// Tunnel request from client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelRequest {
    pub subdomain: Option<String>,
    pub tunnel_type: TunnelType,
    pub local_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelType {
    Http,
    Tcp,
}

/// Tunnel response from relay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelResponse {
    pub success: bool,
    pub tunnel_id: String,
    pub public_url: String,
    pub error: Option<String>,
}

/// Encrypted data frame
#[derive(Debug, Clone)]
pub struct DataFrame {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
}
