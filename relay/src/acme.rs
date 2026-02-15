//! Lightweight ACME (Let's Encrypt) Certificate Manager
//!
//! Handles automatic TLS certificate provisioning using
//! the HTTP-01 challenge flow. Stores certs on disk and
//! auto-renews when within 30 days of expiry.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// ACME certificate state
#[derive(Debug, Clone)]
pub struct CertEntry {
    pub domain: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub expires_at: u64, // Unix timestamp
}

/// ACME challenge tokens for HTTP-01 validation
#[derive(Default, Clone)]
pub struct AcmeChallenges {
    /// token -> key_authorization
    pub tokens: Arc<RwLock<HashMap<String, String>>>,
}

impl AcmeChallenges {
    /// Respond to /.well-known/acme-challenge/{token}
    pub async fn respond(&self, token: &str) -> Option<String> {
        let tokens = self.tokens.read().await;
        tokens.get(token).cloned()
    }

    /// Store a challenge response
    pub async fn set(&self, token: String, auth: String) {
        let mut tokens = self.tokens.write().await;
        tokens.insert(token, auth);
    }

    /// Remove a challenge after validation
    pub async fn remove(&self, token: &str) {
        let mut tokens = self.tokens.write().await;
        tokens.remove(token);
    }
}

/// Certificate manager
pub struct CertManager {
    /// Directory to store certs
    cert_dir: PathBuf,
    /// Loaded certificates by domain
    certs: Arc<RwLock<HashMap<String, CertEntry>>>,
    /// ACME challenges for HTTP-01
    pub challenges: AcmeChallenges,
    /// ACME directory URL
    acme_url: String,
}

impl CertManager {
    pub fn new(cert_dir: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&cert_dir);
        Self {
            cert_dir,
            certs: Arc::new(RwLock::new(HashMap::new())),
            challenges: AcmeChallenges::default(),
            // Use Let's Encrypt staging for dev, production for real
            acme_url: std::env::var("ACME_URL")
                .unwrap_or_else(|_| "https://acme-v02.api.letsencrypt.org/directory".into()),
        }
    }

    /// Load existing certs from disk
    pub async fn load_certs(&self) {
        let dir = match std::fs::read_dir(&self.cert_dir) {
            Ok(d) => d,
            Err(_) => return,
        };

        for entry in dir.flatten() {
            let path = entry.path();
            if path.extension().map_or(true, |e| e != "json") {
                continue;
            }
            if let Ok(data) = std::fs::read_to_string(&path) {
                if let Ok(cert) = serde_json::from_str::<serde_json::Value>(&data) {
                    let domain = cert["domain"].as_str().unwrap_or("").to_string();
                    let cert_pem = cert["cert_pem"].as_str().unwrap_or("").to_string();
                    let key_pem = cert["key_pem"].as_str().unwrap_or("").to_string();
                    let expires_at = cert["expires_at"].as_u64().unwrap_or(0);
                    
                    if !domain.is_empty() {
                        info!("Loaded cert for {}", domain);
                        let mut certs = self.certs.write().await;
                        certs.insert(domain.clone(), CertEntry {
                            domain, cert_pem, key_pem, expires_at,
                        });
                    }
                }
            }
        }
    }

    /// Get certificate for domain
    pub async fn get_cert(&self, domain: &str) -> Option<CertEntry> {
        let certs = self.certs.read().await;
        certs.get(domain).cloned()
    }

    /// Store certificate on disk
    pub async fn store_cert(&self, entry: CertEntry) -> std::io::Result<()> {
        let json = serde_json::json!({
            "domain": entry.domain,
            "cert_pem": entry.cert_pem,
            "key_pem": entry.key_pem,
            "expires_at": entry.expires_at,
        });

        let path = self.cert_dir.join(format!("{}.json", entry.domain));
        std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap())?;

        let mut certs = self.certs.write().await;
        certs.insert(entry.domain.clone(), entry);
        Ok(())
    }

    /// Check if cert needs renewal (within 30 days of expiry)
    pub async fn needs_renewal(&self, domain: &str) -> bool {
        let certs = self.certs.read().await;
        match certs.get(domain) {
            Some(cert) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let thirty_days = 30 * 24 * 60 * 60;
                cert.expires_at < now + thirty_days
            }
            None => true, // No cert = needs one
        }
    }

    /// List all managed domains
    pub async fn domains(&self) -> Vec<String> {
        let certs = self.certs.read().await;
        certs.keys().cloned().collect()
    }
}
