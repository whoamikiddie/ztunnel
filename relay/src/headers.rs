//! Request/Response Header Rewriting
//!
//! Lightweight middleware to inject standard proxy headers
//! and apply custom add/remove/replace rules.

use std::collections::HashMap;

/// Header rewrite rule
#[derive(Debug, Clone)]
pub enum HeaderRule {
    /// Add header (won't overwrite existing)
    Add(String, String),
    /// Set header (overwrites existing)
    Set(String, String),
    /// Remove header by name
    Remove(String),
}

/// Header rewriter configuration
#[derive(Debug, Clone)]
pub struct HeaderRewriter {
    /// Auto-inject standard proxy headers
    pub inject_proxy_headers: bool,
    /// Auto-inject CORS headers for dev
    pub inject_cors: bool,
    /// Custom rules applied in order
    pub rules: Vec<HeaderRule>,
}

impl Default for HeaderRewriter {
    fn default() -> Self {
        Self {
            inject_proxy_headers: true,
            inject_cors: false,
            rules: Vec::new(),
        }
    }
}

impl HeaderRewriter {
    /// Rewrite request headers before forwarding to local service
    pub fn rewrite_request(
        &self,
        headers: &mut Vec<(String, String)>,
        client_ip: Option<&str>,
        host: &str,
    ) {
        if self.inject_proxy_headers {
            if let Some(ip) = client_ip {
                upsert(headers, "X-Forwarded-For", ip);
            }
            upsert(headers, "X-Forwarded-Proto", "https");
            upsert(headers, "X-Forwarded-Host", host);
            upsert(headers, "X-Real-IP", client_ip.unwrap_or("unknown"));
        }

        self.apply_rules(headers);
    }

    /// Rewrite response headers before sending back to client
    pub fn rewrite_response(&self, headers: &mut Vec<(String, String)>) {
        if self.inject_cors {
            upsert(headers, "Access-Control-Allow-Origin", "*");
            upsert(headers, "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS");
            upsert(headers, "Access-Control-Allow-Headers", "Content-Type, Authorization");
            upsert(headers, "Access-Control-Max-Age", "86400");
        }

        self.apply_rules(headers);
    }

    fn apply_rules(&self, headers: &mut Vec<(String, String)>) {
        for rule in &self.rules {
            match rule {
                HeaderRule::Add(k, v) => {
                    if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case(k)) {
                        headers.push((k.clone(), v.clone()));
                    }
                }
                HeaderRule::Set(k, v) => {
                    upsert(headers, k, v);
                }
                HeaderRule::Remove(k) => {
                    headers.retain(|(name, _)| !name.eq_ignore_ascii_case(k));
                }
            }
        }
    }
}

/// Insert or update a header
fn upsert(headers: &mut Vec<(String, String)>, key: &str, value: &str) {
    if let Some(h) = headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(key)) {
        h.1 = value.to_string();
    } else {
        headers.push((key.to_string(), value.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_headers() {
        let rw = HeaderRewriter::default();
        let mut h = vec![("Host".into(), "example.com".into())];
        rw.rewrite_request(&mut h, Some("1.2.3.4"), "myapp.example.com");
        assert!(h.iter().any(|(k, v)| k == "X-Forwarded-For" && v == "1.2.3.4"));
        assert!(h.iter().any(|(k, v)| k == "X-Forwarded-Proto" && v == "https"));
    }

    #[test]
    fn test_cors_injection() {
        let rw = HeaderRewriter { inject_cors: true, ..Default::default() };
        let mut h = vec![];
        rw.rewrite_response(&mut h);
        assert!(h.iter().any(|(k, _)| k == "Access-Control-Allow-Origin"));
    }

    #[test]
    fn test_custom_rules() {
        let rw = HeaderRewriter {
            inject_proxy_headers: false,
            inject_cors: false,
            rules: vec![
                HeaderRule::Set("X-Custom".into(), "hello".into()),
                HeaderRule::Remove("Cookie".into()),
            ],
        };
        let mut h = vec![("Cookie".into(), "secret".into())];
        rw.rewrite_request(&mut h, None, "");
        assert!(!h.iter().any(|(k, _)| k == "Cookie"));
        assert!(h.iter().any(|(k, v)| k == "X-Custom" && v == "hello"));
    }
}
