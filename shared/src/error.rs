//! Error types for ZTunnel.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Tunnel error: {0}")]
    Tunnel(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Authentication failed")]
    AuthFailed,

    #[error("Invalid message")]
    InvalidMessage,

    #[error("Timeout")]
    Timeout,
}
