//! TLS Termination and Passthrough
//!
//! Supports two modes per tunnel:
//! - Terminate: Relay handles TLS, forwards plain HTTP to client
//! - Passthrough: SNI-based routing, encrypted traffic forwarded directly

use tracing::info;

/// TLS mode for a tunnel
#[derive(Debug, Clone, PartialEq)]
pub enum TlsMode {
    /// Relay terminates TLS (default for HTTP tunnels)
    Terminate,
    /// Pass encrypted traffic directly to client (TCP tunnels)
    Passthrough,
    /// No TLS
    None,
}

impl TlsMode {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "terminate" => TlsMode::Terminate,
            "passthrough" | "pass" => TlsMode::Passthrough,
            _ => TlsMode::None,
        }
    }
}

/// Extract SNI (Server Name Indication) from a TLS ClientHello
///
/// This is used in passthrough mode to route encrypted connections
/// based on the requested hostname without decrypting the traffic.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    // TLS record header: content_type(1) + version(2) + length(2)
    if data.len() < 5 {
        return None;
    }

    // Check for TLS handshake (content type 0x16)
    if data[0] != 0x16 {
        return None;
    }

    // Handshake message header: type(1) + length(3)
    let pos = 5;
    if data.len() < pos + 4 {
        return None;
    }

    // Check for ClientHello (type 0x01)
    if data[pos] != 0x01 {
        return None;
    }

    // Skip: handshake header(4) + version(2) + random(32)
    let pos = pos + 4 + 2 + 32;
    if data.len() < pos + 1 {
        return None;
    }

    // Skip session ID
    let session_id_len = data[pos] as usize;
    let pos = pos + 1 + session_id_len;
    if data.len() < pos + 2 {
        return None;
    }

    // Skip cipher suites
    let cipher_suites_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
    let pos = pos + 2 + cipher_suites_len;
    if data.len() < pos + 1 {
        return None;
    }

    // Skip compression methods
    let compression_len = data[pos] as usize;
    let pos = pos + 1 + compression_len;
    if data.len() < pos + 2 {
        return None;
    }

    // Extensions length
    let extensions_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
    let mut pos = pos + 2;
    let end = pos + extensions_len;

    // Parse extensions to find SNI (type 0x0000)
    while pos + 4 <= end && pos + 4 <= data.len() {
        let ext_type = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
        let ext_len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension
            if pos + 2 > data.len() {
                return None;
            }
            let _sni_list_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
            let pos = pos + 2;

            if pos + 3 > data.len() {
                return None;
            }
            let _name_type = data[pos]; // 0 = hostname
            let name_len = ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
            let pos = pos + 3;

            if pos + name_len > data.len() {
                return None;
            }

            return std::str::from_utf8(&data[pos..pos + name_len])
                .ok()
                .map(String::from);
        }

        pos += ext_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_mode_parse() {
        assert_eq!(TlsMode::from_str("terminate"), TlsMode::Terminate);
        assert_eq!(TlsMode::from_str("passthrough"), TlsMode::Passthrough);
        assert_eq!(TlsMode::from_str("pass"), TlsMode::Passthrough);
        assert_eq!(TlsMode::from_str("none"), TlsMode::None);
        assert_eq!(TlsMode::from_str(""), TlsMode::None);
    }
}
