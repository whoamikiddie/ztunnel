//! FFI bindings to libznet throttle (C implementation)

use std::ffi::c_void;

#[repr(C)]
pub struct ZnetThrottle {
    _private: [u8; 0],
}

extern "C" {
    pub fn znet_throttle_create(bytes_per_sec: u64) -> *mut ZnetThrottle;
    pub fn znet_throttle_consume(throttle: *mut ZnetThrottle, bytes: usize) -> i32;
    pub fn znet_throttle_wait(throttle: *mut ZnetThrottle);
    pub fn znet_throttle_get_rate(throttle: *mut ZnetThrottle) -> u64;
    pub fn znet_throttle_set_rate(throttle: *mut ZnetThrottle, bytes_per_sec: u64);
    pub fn znet_throttle_destroy(throttle: *mut ZnetThrottle);
}

/// Safe Rust wrapper for libznet throttle
pub struct BandwidthThrottle {
    inner: *mut ZnetThrottle,
}

impl BandwidthThrottle {
    /// Create a new throttle with the given rate in bytes/sec
    pub fn new(bytes_per_sec: u64) -> Option<Self> {
        let inner = unsafe { znet_throttle_create(bytes_per_sec) };
        if inner.is_null() {
            None
        } else {
            Some(Self { inner })
        }
    }

    /// Consume tokens for the given number of bytes
    /// Returns true if we need to wait
    pub fn consume(&mut self, bytes: usize) -> bool {
        unsafe { znet_throttle_consume(self.inner, bytes) != 0 }
    }

    /// Wait until tokens are available (blocks)
    pub fn wait(&mut self) {
        unsafe { znet_throttle_wait(self.inner) }
    }

    /// Get current rate limit
    pub fn get_rate(&self) -> u64 {
        unsafe { znet_throttle_get_rate(self.inner) }
    }

    /// Update rate limit
    pub fn set_rate(&mut self, bytes_per_sec: u64) {
        unsafe { znet_throttle_set_rate(self.inner, bytes_per_sec) }
    }

    /// Throttle a chunk of data (consume + wait if needed)
    pub fn throttle(&mut self, bytes: usize) {
        if self.consume(bytes) {
            self.wait();
        }
    }
}

impl Drop for BandwidthThrottle {
    fn drop(&mut self) {
        unsafe { znet_throttle_destroy(self.inner) }
    }
}

unsafe impl Send for BandwidthThrottle {}
unsafe impl Sync for BandwidthThrottle {}

/// Parse human-readable bandwidth string (e.g., "3kbps", "1mbps", "500kB/s")
pub fn parse_bandwidth(s: &str) -> Option<u64> {
    let s = s.trim().to_lowercase();
    
    // Extract number and unit
    let (num_str, unit) = if let Some(pos) = s.find(|c: char| !c.is_numeric() && c != '.') {
        (&s[..pos], &s[pos..])
    } else {
        return s.parse::<u64>().ok(); // Plain number = bytes/sec
    };

    let num: f64 = num_str.parse().ok()?;
    
    let multiplier = match unit {
        // Bits per second
        "bps" | "bit/s" => 1.0 / 8.0,
        "kbps" | "kbit/s" => 1_000.0 / 8.0,
        "mbps" | "mbit/s" => 1_000_000.0 / 8.0,
        "gbps" | "gbit/s" => 1_000_000_000.0 / 8.0,
        
        // Bytes per second
        "b/s" => 1.0,
        "kb/s" | "k" => 1_000.0,
        "mb/s" | "m" => 1_000_000.0,
        "gb/s" | "g" => 1_000_000_000.0,
        
        // IEC units (KiB, MiB, etc.)
        "kib/s" | "ki" => 1_024.0,
        "mib/s" | "mi" => 1_048_576.0,
        "gib/s" | "gi" => 1_073_741_824.0,
        
        _ => return None,
    };

    Some((num * multiplier) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bandwidth() {
        assert_eq!(parse_bandwidth("3kbps"), Some(375)); // 3000 bits/sec = 375 bytes/sec
        assert_eq!(parse_bandwidth("1mbps"), Some(125_000));
        assert_eq!(parse_bandwidth("500kb/s"), Some(500_000));
        assert_eq!(parse_bandwidth("10m"), Some(10_000_000));
        assert_eq!(parse_bandwidth("1024"), Some(1024)); // Plain bytes
    }

    #[test]
    fn test_throttle_basic() {
        let mut throttle = BandwidthThrottle::new(1_000_000).unwrap(); // 1 MB/s
        assert_eq!(throttle.get_rate(), 1_000_000);
        
        // Small chunk shouldn't block
        assert!(!throttle.consume(100));
        
        throttle.set_rate(500_000);
        assert_eq!(throttle.get_rate(), 500_000);
    }
}
