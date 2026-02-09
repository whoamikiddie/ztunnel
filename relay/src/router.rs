//! Subdomain routing for ZTunnel Relay

use std::collections::HashMap;
use tokio::sync::RwLock;

/// Router for mapping subdomains to tunnels
pub struct SubdomainRouter {
    routes: RwLock<HashMap<String, String>>,
}

impl SubdomainRouter {
    pub fn new() -> Self {
        Self {
            routes: RwLock::new(HashMap::new()),
        }
    }

    pub async fn add_route(&self, subdomain: String, tunnel_id: String) {
        let mut routes = self.routes.write().await;
        routes.insert(subdomain, tunnel_id);
    }

    pub async fn remove_route(&self, subdomain: &str) {
        let mut routes = self.routes.write().await;
        routes.remove(subdomain);
    }

    pub async fn get_tunnel_id(&self, subdomain: &str) -> Option<String> {
        let routes = self.routes.read().await;
        routes.get(subdomain).cloned()
    }

    pub async fn is_available(&self, subdomain: &str) -> bool {
        let routes = self.routes.read().await;
        !routes.contains_key(subdomain)
    }
}

impl Default for SubdomainRouter {
    fn default() -> Self {
        Self::new()
    }
}
