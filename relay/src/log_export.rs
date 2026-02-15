//! Structured Log Export
//!
//! JSON structured logging with file rotation and optional
//! webhook export for external logging services.

use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::warn;

/// Log export configuration
#[derive(Debug, Clone)]
pub struct LogExportConfig {
    /// Enable file logging
    pub file_enabled: bool,
    /// Log directory
    pub log_dir: PathBuf,
    /// Max file size before rotation (bytes)
    pub max_file_size: u64,
    /// Max number of rotated files to keep
    pub max_files: usize,
    /// Optional webhook URL for external export
    pub webhook_url: Option<String>,
}

impl Default for LogExportConfig {
    fn default() -> Self {
        Self {
            file_enabled: false,
            log_dir: PathBuf::from("./logs"),
            max_file_size: 100 * 1024 * 1024, // 100MB
            max_files: 10,
            webhook_url: None,
        }
    }
}

/// A structured log entry
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub subdomain: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub latency_us: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
}

/// Log exporter with file rotation
pub struct LogExporter {
    config: LogExportConfig,
    current_file: Arc<Mutex<Option<std::fs::File>>>,
    current_size: Arc<Mutex<u64>>,
    #[cfg(feature = "webhook")]
    http_client: Option<reqwest::Client>,
}

impl LogExporter {
    pub fn new(config: LogExportConfig) -> Self {
        #[cfg(feature = "webhook")]
        let http_client = config.webhook_url.as_ref().map(|_| reqwest::Client::new());
        
        // Ensure log directory exists
        if config.file_enabled {
            let _ = std::fs::create_dir_all(&config.log_dir);
        }

        Self {
            config,
            current_file: Arc::new(Mutex::new(None)),
            current_size: Arc::new(Mutex::new(0)),
            #[cfg(feature = "webhook")]
            http_client,
        }
    }

    /// Write a log entry
    pub async fn log(&self, entry: &LogEntry) {
        if self.config.file_enabled {
            self.write_to_file(entry).await;
        }

        #[cfg(feature = "webhook")]
        if let (Some(url), Some(client)) = (&self.config.webhook_url, &self.http_client) {
            let url = url.clone();
            let client = client.clone();
            let entry = entry.clone();
            tokio::spawn(async move {
                if let Err(e) = client.post(&url).json(&entry).send().await {
                    warn!("Log webhook failed: {}", e);
                }
            });
        }
    }

    /// Write entry to log file with rotation
    async fn write_to_file(&self, entry: &LogEntry) {
        let json = match serde_json::to_string(entry) {
            Ok(j) => j,
            Err(_) => return,
        };
        let line = format!("{}\n", json);
        let line_len = line.len() as u64;

        let mut file_guard = self.current_file.lock().await;
        let mut size_guard = self.current_size.lock().await;

        // Check if rotation needed
        if *size_guard + line_len > self.config.max_file_size || file_guard.is_none() {
            // Close current file
            *file_guard = None;
            *size_guard = 0;

            // Rotate existing files
            self.rotate_files();

            // Open new file
            let path = self.config.log_dir.join("ztunnel.log");
            match std::fs::File::create(&path) {
                Ok(f) => {
                    *file_guard = Some(f);
                }
                Err(e) => {
                    warn!("Failed to create log file: {}", e);
                    return;
                }
            }
        }

        if let Some(ref mut f) = *file_guard {
            if f.write_all(line.as_bytes()).is_ok() {
                *size_guard += line_len;
            }
        }
    }

    /// Rotate log files: ztunnel.log -> ztunnel.1.log -> ztunnel.2.log ...
    fn rotate_files(&self) {
        // Delete oldest if at max
        let oldest = self.config.log_dir.join(format!("ztunnel.{}.log", self.config.max_files));
        let _ = std::fs::remove_file(&oldest);

        // Shift all files up by 1
        for i in (1..self.config.max_files).rev() {
            let from = self.config.log_dir.join(format!("ztunnel.{}.log", i));
            let to = self.config.log_dir.join(format!("ztunnel.{}.log", i + 1));
            let _ = std::fs::rename(&from, &to);
        }

        // Move current to .1
        let current = self.config.log_dir.join("ztunnel.log");
        let first_backup = self.config.log_dir.join("ztunnel.1.log");
        let _ = std::fs::rename(&current, &first_backup);
    }
}

impl Clone for LogExporter {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            current_file: self.current_file.clone(),
            current_size: self.current_size.clone(),
            #[cfg(feature = "webhook")]
            http_client: self.http_client.clone(),
        }
    }
}
