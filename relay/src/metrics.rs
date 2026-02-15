//! Metrics Collection for ZTunnel Relay
//!
//! Provides atomic counters, latency histograms, and a
//! Prometheus-compatible /metrics endpoint.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Relay-wide metrics
#[derive(Clone)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
}

struct MetricsInner {
    /// Total requests processed
    total_requests: AtomicU64,
    /// Active tunnel count
    active_tunnels: AtomicU64,
    /// Status code counts
    status_2xx: AtomicU64,
    status_3xx: AtomicU64,
    status_4xx: AtomicU64,
    status_5xx: AtomicU64,
    /// Total bytes in/out
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    /// Latency tracking
    latencies: Mutex<LatencyHistogram>,
    /// Per-subdomain metrics
    subdomain_metrics: Mutex<std::collections::HashMap<String, SubdomainMetrics>>,
}

/// Latency histogram for percentile calculation
struct LatencyHistogram {
    /// Recent latencies (ring buffer, microseconds)
    values: Vec<u64>,
    /// Write position
    pos: usize,
    /// Total count
    count: u64,
    /// Sum for average
    sum: u64,
}

impl LatencyHistogram {
    fn new(capacity: usize) -> Self {
        Self {
            values: vec![0; capacity],
            pos: 0,
            count: 0,
            sum: 0,
        }
    }

    fn record(&mut self, latency_us: u64) {
        self.values[self.pos] = latency_us;
        self.pos = (self.pos + 1) % self.values.len();
        self.count += 1;
        self.sum += latency_us;
    }

    fn percentile(&self, p: f64) -> u64 {
        let count = self.count.min(self.values.len() as u64) as usize;
        if count == 0 {
            return 0;
        }

        let mut sorted: Vec<u64> = if self.count < self.values.len() as u64 {
            self.values[..count].to_vec()
        } else {
            self.values.clone()
        };
        sorted.sort_unstable();

        let idx = ((count as f64 * p / 100.0) as usize).min(count - 1);
        sorted[idx]
    }

    fn average(&self) -> u64 {
        if self.count == 0 { 0 } else { self.sum / self.count }
    }
}

/// Per-subdomain metrics
#[derive(Debug, Clone, Default)]
pub struct SubdomainMetrics {
    pub requests: u64,
    pub errors: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(MetricsInner {
                total_requests: AtomicU64::new(0),
                active_tunnels: AtomicU64::new(0),
                status_2xx: AtomicU64::new(0),
                status_3xx: AtomicU64::new(0),
                status_4xx: AtomicU64::new(0),
                status_5xx: AtomicU64::new(0),
                bytes_in: AtomicU64::new(0),
                bytes_out: AtomicU64::new(0),
                latencies: Mutex::new(LatencyHistogram::new(10000)),
                subdomain_metrics: Mutex::new(std::collections::HashMap::new()),
            }),
        }
    }

    /// Record a completed request
    pub async fn record_request(
        &self,
        subdomain: &str,
        status: u16,
        latency_us: u64,
        bytes_in: u64,
        bytes_out: u64,
    ) {
        self.inner.total_requests.fetch_add(1, Ordering::Relaxed);
        self.inner.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.inner.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);

        match status / 100 {
            2 => { self.inner.status_2xx.fetch_add(1, Ordering::Relaxed); }
            3 => { self.inner.status_3xx.fetch_add(1, Ordering::Relaxed); }
            4 => { self.inner.status_4xx.fetch_add(1, Ordering::Relaxed); }
            5 => { self.inner.status_5xx.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        }

        self.inner.latencies.lock().await.record(latency_us);

        // Per-subdomain
        let mut subs = self.inner.subdomain_metrics.lock().await;
        let entry = subs.entry(subdomain.to_string()).or_default();
        entry.requests += 1;
        if status >= 400 {
            entry.errors += 1;
        }
        entry.bytes_in += bytes_in;
        entry.bytes_out += bytes_out;
    }

    /// Increment active tunnel count
    pub fn tunnel_opened(&self) {
        self.inner.active_tunnels.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement active tunnel count
    pub fn tunnel_closed(&self) {
        self.inner.active_tunnels.fetch_sub(1, Ordering::Relaxed);
    }

    /// Generate Prometheus-format metrics text
    pub async fn to_prometheus(&self) -> String {
        let lat = self.inner.latencies.lock().await;
        let p50 = lat.percentile(50.0);
        let p95 = lat.percentile(95.0);
        let p99 = lat.percentile(99.0);
        let avg = lat.average();
        drop(lat);

        format!(
r#"# HELP ztunnel_requests_total Total number of requests processed
# TYPE ztunnel_requests_total counter
ztunnel_requests_total {}

# HELP ztunnel_active_tunnels Number of active tunnel connections
# TYPE ztunnel_active_tunnels gauge
ztunnel_active_tunnels {}

# HELP ztunnel_requests_by_status Requests by HTTP status class
# TYPE ztunnel_requests_by_status counter
ztunnel_requests_by_status{{status="2xx"}} {}
ztunnel_requests_by_status{{status="3xx"}} {}
ztunnel_requests_by_status{{status="4xx"}} {}
ztunnel_requests_by_status{{status="5xx"}} {}

# HELP ztunnel_bytes_total Total bytes transferred
# TYPE ztunnel_bytes_total counter
ztunnel_bytes_total{{direction="in"}} {}
ztunnel_bytes_total{{direction="out"}} {}

# HELP ztunnel_latency_us Request latency in microseconds
# TYPE ztunnel_latency_us summary
ztunnel_latency_us{{quantile="0.5"}} {}
ztunnel_latency_us{{quantile="0.95"}} {}
ztunnel_latency_us{{quantile="0.99"}} {}
ztunnel_latency_us_avg {}
"#,
            self.inner.total_requests.load(Ordering::Relaxed),
            self.inner.active_tunnels.load(Ordering::Relaxed),
            self.inner.status_2xx.load(Ordering::Relaxed),
            self.inner.status_3xx.load(Ordering::Relaxed),
            self.inner.status_4xx.load(Ordering::Relaxed),
            self.inner.status_5xx.load(Ordering::Relaxed),
            self.inner.bytes_in.load(Ordering::Relaxed),
            self.inner.bytes_out.load(Ordering::Relaxed),
            p50, p95, p99, avg,
        )
    }
}
