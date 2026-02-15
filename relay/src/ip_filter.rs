//! IP Filtering Middleware
//!
//! Axum middleware layer that checks incoming requests against
//! per-tunnel allow/deny CIDR rules.

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

/// IP filter configuration for a tunnel
#[derive(Debug, Clone, Default)]
pub struct IpFilter {
    /// Allowed CIDR ranges (empty = allow all)
    pub allow: Vec<CidrRange>,
    /// Denied CIDR ranges
    pub deny: Vec<CidrRange>,
}

/// A parsed CIDR range
#[derive(Debug, Clone)]
pub struct CidrRange {
    pub network: u32,
    pub mask: u32,
    pub raw: String,
}

impl CidrRange {
    /// Parse a CIDR string like "192.168.1.0/24"
    pub fn parse(cidr: &str) -> Option<Self> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return None;
        }

        let ip: Ipv4Addr = parts[0].parse().ok()?;
        let prefix_len: u32 = parts[1].parse().ok()?;

        if prefix_len > 32 {
            return None;
        }

        let ip_u32 = u32::from(ip);
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };

        Some(CidrRange {
            network: ip_u32 & mask,
            mask,
            raw: cidr.to_string(),
        })
    }

    /// Check if an IP address is within this CIDR range
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let ip_u32 = u32::from(v4);
                (ip_u32 & self.mask) == self.network
            }
            IpAddr::V6(_) => false, // IPv6 not supported yet
        }
    }
}

impl IpFilter {
    /// Create an IP filter from string lists
    pub fn from_strings(allow: &[String], deny: &[String]) -> Self {
        Self {
            allow: allow.iter().filter_map(|s| CidrRange::parse(s)).collect(),
            deny: deny.iter().filter_map(|s| CidrRange::parse(s)).collect(),
        }
    }

    /// Check if an IP is allowed through this filter
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        // Check deny list first
        for cidr in &self.deny {
            if cidr.contains(ip) {
                return false;
            }
        }

        // If allow list is empty, allow all (that aren't denied)
        if self.allow.is_empty() {
            return true;
        }

        // Check allow list
        for cidr in &self.allow {
            if cidr.contains(ip) {
                return true;
            }
        }

        false
    }

    /// Returns true if this filter has no rules (allows everything)
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }
}

/// Extract client IP from request headers or socket address
pub fn extract_client_ip(
    headers: &[(String, String)],
    peer_addr: Option<std::net::SocketAddr>,
) -> Option<IpAddr> {
    // Check X-Forwarded-For header first
    for (key, value) in headers {
        if key.eq_ignore_ascii_case("x-forwarded-for") {
            // Take the first IP in the chain
            if let Some(ip_str) = value.split(',').next() {
                if let Ok(ip) = IpAddr::from_str(ip_str.trim()) {
                    return Some(ip);
                }
            }
        }
    }

    // Check X-Real-IP
    for (key, value) in headers {
        if key.eq_ignore_ascii_case("x-real-ip") {
            if let Ok(ip) = IpAddr::from_str(value.trim()) {
                return Some(ip);
            }
        }
    }

    // Fall back to peer address
    peer_addr.map(|addr| addr.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_parse() {
        let cidr = CidrRange::parse("192.168.1.0/24").unwrap();
        assert!(cidr.contains("192.168.1.100".parse().unwrap()));
        assert!(!cidr.contains("192.168.2.1".parse().unwrap()));
        assert!(cidr.contains("192.168.1.0".parse().unwrap()));
        assert!(cidr.contains("192.168.1.255".parse().unwrap()));
    }

    #[test]
    fn test_ip_filter() {
        let filter = IpFilter::from_strings(
            &["192.168.1.0/24".to_string()],
            &["192.168.1.100/32".to_string()],
        );

        assert!(filter.is_allowed("192.168.1.50".parse().unwrap()));
        assert!(!filter.is_allowed("192.168.1.100".parse().unwrap())); // denied
        assert!(!filter.is_allowed("10.0.0.1".parse().unwrap())); // not in allow
    }

    #[test]
    fn test_empty_filter() {
        let filter = IpFilter::from_strings(&[], &[]);
        assert!(filter.is_allowed("1.2.3.4".parse().unwrap()));
        assert!(filter.is_empty());
    }
}
