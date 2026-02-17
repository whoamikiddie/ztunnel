//! ZTunnel Shared Library
//! 
//! Common types, protocols, and FFI bindings for libzcrypto.

pub mod protocol;
pub mod crypto;
pub mod error;
pub mod throttle;

pub use error::{Error, Result};
