//! Configuration file parser for ZTunnel
//!
//! Supports ztunnel.yml with multi-tunnel definitions,
//! IP filtering, and auth token configuration.

use serde::{Deserialize, Serialize};
use std::path::Path;
use anyhow::{Context, Result};

/// Root configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZTunnelConfig {
    /// Relay server URL
    #[serde(default = "default_relay")]
    pub relay: String,

    /// Optional authentication token
    pub auth_token: Option<String>,

    /// Inspector settings
    #[serde(default)]
    pub inspector: InspectorConfig,

    /// Tunnel definitions
    #[serde(default)]
    pub tunnels: Vec<TunnelConfig>,

    /// Global IP filter rules
    #[serde(default)]
    pub ip_filter: IpFilterConfig,
}

/// Single tunnel definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Human-readable name
    pub name: String,

    /// Protocol: http, tcp, or udp
    #[serde(default = "default_proto")]
    pub proto: String,

    /// Local port to forward traffic to
    pub local_port: u16,

    /// Optional custom subdomain (HTTP only)
    pub subdomain: Option<String>,

    /// Enable inspector for this tunnel
    #[serde(default = "default_true")]
    pub inspect: bool,

    /// Per-tunnel IP filter override
    pub ip_filter: Option<IpFilterConfig>,

    /// Bandwidth throttle in bytes/sec (0 = unlimited)
    #[serde(default)]
    pub throttle_bps: u64,

    /// Local hostname to forward to (default: 127.0.0.1)
    #[serde(default = "default_host")]
    pub local_host: String,
}

/// Inspector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectorConfig {
    /// Enable the inspector dashboard
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Port for the inspector UI
    #[serde(default = "default_inspect_port")]
    pub port: u16,
}

impl Default for InspectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 4040,
        }
    }
}

/// IP filtering configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpFilterConfig {
    /// Allowed CIDR ranges (empty = allow all)
    #[serde(default)]
    pub allow: Vec<String>,

    /// Denied CIDR ranges
    #[serde(default)]
    pub deny: Vec<String>,
}

fn default_relay() -> String {
    "ws://localhost:8080/tunnel".to_string()
}

fn default_proto() -> String {
    "http".to_string()
}

fn default_true() -> bool {
    true
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_inspect_port() -> u16 {
    4040
}

impl ZTunnelConfig {
    /// Load configuration from a YAML file
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        
        let config: ZTunnelConfig = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
        
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration
    fn validate(&self) -> Result<()> {
        if self.tunnels.is_empty() {
            anyhow::bail!("No tunnels defined in configuration");
        }

        for tunnel in &self.tunnels {
            if tunnel.name.is_empty() {
                anyhow::bail!("Tunnel name cannot be empty");
            }
            match tunnel.proto.as_str() {
                "http" | "tcp" | "udp" => {}
                other => anyhow::bail!("Invalid protocol '{}' for tunnel '{}'", other, tunnel.name),
            }
            if tunnel.local_port == 0 {
                anyhow::bail!("Invalid port 0 for tunnel '{}'", tunnel.name);
            }
        }

        Ok(())
    }

    /// Search for config file in standard locations
    pub fn find_config() -> Option<std::path::PathBuf> {
        let candidates = [
            "ztunnel.yml",
            "ztunnel.yaml",
            ".ztunnel.yml",
            ".ztunnel.yaml",
        ];

        // Check current directory
        for name in &candidates {
            let path = std::path::PathBuf::from(name);
            if path.exists() {
                return Some(path);
            }
        }

        // Check home directory
        if let Some(home) = dirs::home_dir() {
            for name in &candidates {
                let path = home.join(name);
                if path.exists() {
                    return Some(path);
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let yaml = r#"
relay: wss://ztunnel.example.com/tunnel
auth_token: "test-token"
tunnels:
  - name: api
    proto: http
    local_port: 3000
    subdomain: my-api
    inspect: true
  - name: db
    proto: tcp
    local_port: 5432
ip_filter:
  allow: ["192.168.1.0/24"]
  deny: ["10.0.0.0/8"]
"#;
        let config: ZTunnelConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.tunnels.len(), 2);
        assert_eq!(config.tunnels[0].name, "api");
        assert_eq!(config.tunnels[0].proto, "http");
        assert_eq!(config.tunnels[1].proto, "tcp");
        assert_eq!(config.ip_filter.allow.len(), 1);
    }
}
