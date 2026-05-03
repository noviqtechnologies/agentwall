//! HMAC-SHA256 append-only audit log (FR-104, NFR-204)

use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

type HmacSha256 = Hmac<Sha256>;

/// Initial prev_hmac for the first entry: 64 hex zeros
pub const ZERO_HMAC: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A single audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: String,
    pub session_id: String,
    pub event: String, // tool_allow | tool_deny | tool_dry_run_deny | log_rotation_seed | dry_run_active
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>, // redacted for DENY
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    pub entry_index: u64,
    pub prev_hmac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
}

/// The audit logger manages the HMAC chain and file writes
pub struct AuditLogger {
    file: Mutex<Option<File>>,
    session_secret: Vec<u8>,
    session_id: String,
    entry_index: Mutex<u64>,
    prev_hmac: Mutex<String>,
    pub log_path: PathBuf,
    max_bytes: u64,
}

/// Error from audit operations
#[derive(Debug)]
pub enum AuditError {
    IoError(std::io::Error),
    SerializationError(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "I/O error: {}", e),
            Self::SerializationError(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

impl AuditLogger {
    /// Create a new audit logger.
    /// session_secret is generated at proxy startup and never written to disk.
    pub fn new(
        log_path: PathBuf,
        session_id: String,
        session_secret: Vec<u8>,
        max_bytes: u64,
    ) -> Result<Self, AuditError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(AuditError::IoError)?;

        Ok(Self {
            file: Mutex::new(Some(file)),
            session_secret,
            session_id,
            entry_index: Mutex::new(0),
            prev_hmac: Mutex::new(ZERO_HMAC.to_string()),
            log_path,
            max_bytes,
        })
    }

    /// Compute HMAC-SHA256 of the canonical JSON of an entry (without the hmac field).
    fn compute_hmac(&self, entry: &AuditEntry) -> String {
        // Canonical JSON: sorted keys via serde_json with sorted maps
        let canonical = serde_json::to_string(entry).expect("audit entry must serialize");

        let mut mac =
            HmacSha256::new_from_slice(&self.session_secret).expect("HMAC key length is valid");
        mac.update(canonical.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Write an audit entry with HMAC chain. Performs fsync before returning.
    /// Returns the completed entry on success.
    pub fn write_entry(
        &self,
        event: &str,
        tool_name: &str,
        params: Option<Value>,
        reason: Option<String>,
        latency_ms: Option<f64>,
    ) -> Result<AuditEntry, AuditError> {
        let mut idx = self.entry_index.lock().unwrap();
        let mut prev = self.prev_hmac.lock().unwrap();

        let mut entry = AuditEntry {
            ts: Utc::now().to_rfc3339(),
            session_id: self.session_id.clone(),
            event: event.to_string(),
            tool_name: Some(tool_name.to_string()),
            params,
            reason,
            latency_ms,
            entry_index: *idx,
            prev_hmac: prev.clone(),
            hmac: None, // computed below
        };

        // Compute HMAC over entry without hmac field
        let hmac_hex = self.compute_hmac(&entry);
        entry.hmac = Some(hmac_hex.clone());

        // Serialize to JSON line
        let line = serde_json::to_string(&entry)
            .map_err(|e| AuditError::SerializationError(e.to_string()))?;

        // Write + fsync (NFR-204: non-negotiable)
        let mut file_opt = self.file.lock().unwrap();
        let mut file = file_opt.take().expect("Audit file handle must be present");
        
        writeln!(file, "{}", line).map_err(AuditError::IoError)?;
        file.flush().map_err(AuditError::IoError)?;
        file.sync_all().map_err(AuditError::IoError)?;

        let mut rotated = false;
        if self.max_bytes > 0 {
            if let Ok(metadata) = file.metadata() {
                if metadata.len() >= self.max_bytes {
                    rotated = true;
                }
            }
        }
        
        let prev_hmac_for_seed = hmac_hex.clone();

        if rotated {
            // Log rotation
            let ts_compact = Utc::now().format("%Y%m%dT%H%M%S%.9f").to_string();
            let rand_suffix: u16 = rand::random();
            let mut backup_path = self.log_path.clone();
            backup_path.set_file_name(format!(
                "{}.{}_{:04x}.bak",
                self.log_path.file_name().unwrap().to_string_lossy(),
                ts_compact,
                rand_suffix
            ));

            // Close current file by dropping it
            drop(file);
            
            // Rename with retry (Windows can be picky about timing)
            let mut rename_result = std::fs::rename(&self.log_path, &backup_path);
            if rename_result.is_err() {
                for _ in 0..10 {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    rename_result = std::fs::rename(&self.log_path, &backup_path);
                    if rename_result.is_ok() { break; }
                }
            }
            rename_result.map_err(AuditError::IoError)?;

            // Open new file
            let new_file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_path)
                .map_err(AuditError::IoError)?;
            
            let mut seed_entry = AuditEntry {
                ts: Utc::now().to_rfc3339(),
                session_id: self.session_id.clone(),
                event: "log_rotation_seed".to_string(),
                tool_name: None,
                params: None,
                reason: None,
                latency_ms: None,
                entry_index: 0,
                prev_hmac: prev_hmac_for_seed,
                hmac: None,
            };
            let seed_hmac = self.compute_hmac(&seed_entry);
            seed_entry.hmac = Some(seed_hmac.clone());
            let seed_line = serde_json::to_string(&seed_entry).unwrap();
            
            let mut new_file_handle = new_file;
            writeln!(new_file_handle, "{}", seed_line).map_err(AuditError::IoError)?;
            new_file_handle.flush().map_err(AuditError::IoError)?;
            new_file_handle.sync_all().map_err(AuditError::IoError)?;

            *file_opt = Some(new_file_handle);
            *prev = seed_hmac;
            *idx = 1;

            crate::logging::log_event(
                crate::logging::Level::Info,
                "log_rotated",
                serde_json::json!({
                    "archived": backup_path.to_string_lossy(),
                    "new_log": self.log_path.to_string_lossy()
                }),
            );
        } else {
            // Put file back
            *file_opt = Some(file);
            *prev = hmac_hex;
            *idx += 1;
        }

        Ok(entry)
    }

    /// Get current entry count
    pub fn entry_count(&self) -> u64 {
        *self.entry_index.lock().unwrap()
    }
}
