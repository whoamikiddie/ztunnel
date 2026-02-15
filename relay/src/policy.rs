//! Traffic Policy Rules Engine
//!
//! Lightweight rule matching for blocking, redirecting,
//! rate-limiting, or requiring auth per path/method.

/// Action to take when a rule matches
#[derive(Debug, Clone)]
pub enum PolicyAction {
    /// Allow request (default)
    Allow,
    /// Block with status code
    Block(u16),
    /// Redirect to URL
    Redirect(String),
    /// Require basic auth
    RequireAuth,
    /// Rate limit (requests per minute)
    RateLimit(u32),
    /// Add response header
    AddHeader(String, String),
}

/// A single traffic policy rule
#[derive(Debug, Clone)]
pub struct PolicyRule {
    /// Path glob pattern (e.g., "/admin/*", "/api/v1/**")
    pub path_pattern: String,
    /// Optional method filter (None = all methods)
    pub method: Option<String>,
    /// Action to take
    pub action: PolicyAction,
}

/// Policy engine that evaluates rules in order
#[derive(Debug, Clone, Default)]
pub struct PolicyEngine {
    pub rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// Evaluate request against rules. Returns first matching action.
    pub fn evaluate(&self, path: &str, method: &str) -> PolicyAction {
        for rule in &self.rules {
            // Check method filter
            if let Some(ref m) = rule.method {
                if !m.eq_ignore_ascii_case(method) {
                    continue;
                }
            }

            // Check path pattern
            if matches_glob(&rule.path_pattern, path) {
                return rule.action.clone();
            }
        }

        PolicyAction::Allow
    }
}

/// Simple glob matcher supporting * (single segment) and ** (any depth)
fn matches_glob(pattern: &str, path: &str) -> bool {
    // Exact match
    if pattern == path {
        return true;
    }

    // "**" matches everything
    if pattern == "**" || pattern == "/**" {
        return true;
    }

    let pat_parts: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let path_parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    matches_parts(&pat_parts, &path_parts)
}

fn matches_parts(pattern: &[&str], path: &[&str]) -> bool {
    if pattern.is_empty() {
        return path.is_empty();
    }

    if pattern[0] == "**" {
        // ** matches zero or more path segments
        for i in 0..=path.len() {
            if matches_parts(&pattern[1..], &path[i..]) {
                return true;
            }
        }
        return false;
    }

    if path.is_empty() {
        return false;
    }

    // * matches any single segment, otherwise exact match
    let seg_match = pattern[0] == "*" || pattern[0] == path[0];
    if seg_match {
        return matches_parts(&pattern[1..], &path[1..]);
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert!(matches_glob("/api/users", "/api/users"));
        assert!(!matches_glob("/api/users", "/api/posts"));
    }

    #[test]
    fn test_wildcard() {
        assert!(matches_glob("/api/*", "/api/users"));
        assert!(!matches_glob("/api/*", "/api/users/123"));
    }

    #[test]
    fn test_double_wildcard() {
        assert!(matches_glob("/admin/**", "/admin/settings"));
        assert!(matches_glob("/admin/**", "/admin/users/123/edit"));
    }

    #[test]
    fn test_policy_engine() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            path_pattern: "/admin/**".into(),
            method: None,
            action: PolicyAction::Block(403),
        });
        engine.add_rule(PolicyRule {
            path_pattern: "/api/**".into(),
            method: Some("DELETE".into()),
            action: PolicyAction::RequireAuth,
        });

        assert!(matches!(engine.evaluate("/admin/settings", "GET"), PolicyAction::Block(403)));
        assert!(matches!(engine.evaluate("/api/users", "DELETE"), PolicyAction::RequireAuth));
        assert!(matches!(engine.evaluate("/api/users", "GET"), PolicyAction::Allow));
        assert!(matches!(engine.evaluate("/public", "GET"), PolicyAction::Allow));
    }
}
