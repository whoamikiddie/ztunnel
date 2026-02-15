//! Circuit Breaker for Tunnel Connections
//!
//! Automatically queues requests when a client is disconnected
//! and replays them upon reconnection.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};
use tracing::{info, warn};

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CircuitState {
    /// Normal operation — requests flow through
    Closed,
    /// Client disconnect detected — queuing requests
    Open,
    /// Testing if client is back
    HalfOpen,
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Max requests to queue while circuit is open
    pub max_queue_size: usize,
    /// How long to keep the circuit open before testing
    pub open_timeout: Duration,
    /// Max age of queued requests (drop if older)
    pub max_request_age: Duration,
    /// Number of consecutive failures before opening circuit
    pub failure_threshold: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            max_queue_size: 50,
            open_timeout: Duration::from_secs(30),
            max_request_age: Duration::from_secs(60),
            failure_threshold: 3,
        }
    }
}

/// A queued request waiting for the circuit to close
#[derive(Debug, Clone)]
pub struct QueuedRequest {
    pub data: Vec<u8>,
    pub queued_at: Instant,
}

/// Circuit breaker for a single tunnel
pub struct CircuitBreaker {
    state: Arc<Mutex<CircuitState>>,
    queue: Arc<Mutex<VecDeque<QueuedRequest>>>,
    config: CircuitBreakerConfig,
    consecutive_failures: Arc<AtomicU64>,
    last_state_change: Arc<Mutex<Instant>>,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: Arc::new(Mutex::new(CircuitState::Closed)),
            queue: Arc::new(Mutex::new(VecDeque::with_capacity(config.max_queue_size))),
            config,
            consecutive_failures: Arc::new(AtomicU64::new(0)),
            last_state_change: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Get current circuit state
    pub async fn state(&self) -> CircuitState {
        *self.state.lock().await
    }

    /// Record a successful request — reset failure count
    pub async fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::SeqCst);
        let mut state = self.state.lock().await;
        if *state == CircuitState::HalfOpen {
            *state = CircuitState::Closed;
            *self.last_state_change.lock().await = Instant::now();
            info!("Circuit breaker: HalfOpen → Closed");
        }
    }

    /// Record a failed request — potentially open the circuit
    pub async fn record_failure(&self) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
        
        if failures >= self.config.failure_threshold as u64 {
            let mut state = self.state.lock().await;
            if *state == CircuitState::Closed {
                *state = CircuitState::Open;
                *self.last_state_change.lock().await = Instant::now();
                warn!("Circuit breaker: Closed → Open (after {} failures)", failures);
            }
        }
    }

    /// Attempt to send a request through the circuit
    /// Returns Ok(data) if the request should be sent
    /// Returns Err(()) if the request was queued
    pub async fn try_send(&self, data: Vec<u8>) -> Result<Vec<u8>, ()> {
        let mut state = self.state.lock().await;

        match *state {
            CircuitState::Closed => Ok(data),
            CircuitState::HalfOpen => Ok(data), // Let it through as a test
            CircuitState::Open => {
                // Check if it's time to try again
                let last_change = *self.last_state_change.lock().await;
                if last_change.elapsed() >= self.config.open_timeout {
                    *state = CircuitState::HalfOpen;
                    *self.last_state_change.lock().await = Instant::now();
                    info!("Circuit breaker: Open → HalfOpen (testing)");
                    Ok(data)
                } else {
                    // Queue the request
                    let mut queue = self.queue.lock().await;
                    if queue.len() < self.config.max_queue_size {
                        queue.push_back(QueuedRequest {
                            data,
                            queued_at: Instant::now(),
                        });
                        info!("Circuit breaker: Request queued ({}/{})", queue.len(), self.config.max_queue_size);
                    } else {
                        warn!("Circuit breaker: Queue full, dropping request");
                    }
                    Err(())
                }
            }
        }
    }

    /// Drain all valid queued requests (called when client reconnects)
    pub async fn drain_queue(&self) -> Vec<Vec<u8>> {
        let mut queue = self.queue.lock().await;
        let now = Instant::now();
        
        let valid: Vec<Vec<u8>> = queue
            .drain(..)
            .filter(|req| now.duration_since(req.queued_at) < self.config.max_request_age)
            .map(|req| req.data)
            .collect();

        // Reset state
        let mut state = self.state.lock().await;
        *state = CircuitState::Closed;
        self.consecutive_failures.store(0, Ordering::SeqCst);
        *self.last_state_change.lock().await = Instant::now();

        info!("Circuit breaker: Drained {} queued requests", valid.len());
        valid
    }

    /// Get queue size
    pub async fn queue_size(&self) -> usize {
        self.queue.lock().await.len()
    }
}

impl Clone for CircuitBreaker {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            queue: self.queue.clone(),
            config: self.config.clone(),
            consecutive_failures: self.consecutive_failures.clone(),
            last_state_change: self.last_state_change.clone(),
        }
    }
}
