//! HMAC-SHA256 append-only audit log (FR-104, NFR-204)

use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

type HmacSha256 = Hmac<Sha256>;

pub const ZERO_HMAC: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: String,
    pub session_id: String,
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub entry_index: u64,
    pub prev_hmac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
}

pub struct AuditLogger {
    sender: mpsc::UnboundedSender<AuditEntry>,
    is_broken: Arc<AtomicBool>,
    entry_count: Arc<AtomicU64>,
    session_id: String,
}

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
    pub fn new(
        log_path: PathBuf,
        session_id: String,
        session_secret: Vec<u8>,
        max_bytes: u64,
    ) -> Result<Self, AuditError> {
        let (tx, mut rx) = mpsc::unbounded_channel::<AuditEntry>();
        let is_broken = Arc::new(AtomicBool::new(false));
        let is_broken_clone = is_broken.clone();
        let entry_count = Arc::new(AtomicU64::new(0));
        let entry_count_clone = entry_count.clone();

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(AuditError::IoError)?;

        std::thread::spawn(move || {
            let mut current_idx = 0u64;
            let mut prev_hmac = ZERO_HMAC.to_string();

            while let Some(mut entry) = rx.blocking_recv() {
                entry.entry_index = current_idx;
                entry.prev_hmac = prev_hmac.clone();

                let canonical = serde_json::to_string(&entry).expect("audit entry must serialize");
                let mut mac = HmacSha256::new_from_slice(&session_secret).expect("HMAC key length is valid");
                mac.update(canonical.as_bytes());
                let hmac_hex = hex::encode(mac.finalize().into_bytes());

                entry.hmac = Some(hmac_hex.clone());

                let line = match serde_json::to_string(&entry) {
                    Ok(l) => l,
                    Err(_) => continue,
                };

                if writeln!(file, "{}", line).is_err() {
                    is_broken_clone.store(true, Ordering::Relaxed);
                    break;
                }
                if file.flush().is_err() {
                    is_broken_clone.store(true, Ordering::Relaxed);
                    break;
                }
                if file.sync_all().is_err() {
                    is_broken_clone.store(true, Ordering::Relaxed);
                    break;
                }

                let mut rotated = false;
                if max_bytes > 0 {
                    if let Ok(metadata) = file.metadata() {
                        if metadata.len() >= max_bytes {
                            rotated = true;
                        }
                    }
                }

                if rotated {
                    let ts_compact = Utc::now().format("%Y%m%dT%H%M%S%.9f").to_string();
                    let rand_suffix: u16 = rand::random();
                    let mut backup_path = log_path.clone();
                    backup_path.set_file_name(format!(
                        "{}.{}_{:04x}.bak",
                        log_path.file_name().unwrap().to_string_lossy(),
                        ts_compact,
                        rand_suffix
                    ));

                    drop(file);

                    let mut rename_result = std::fs::rename(&log_path, &backup_path);
                    if rename_result.is_err() {
                        for _ in 0..10 {
                            std::thread::sleep(std::time::Duration::from_millis(50));
                            rename_result = std::fs::rename(&log_path, &backup_path);
                            if rename_result.is_ok() { break; }
                        }
                    }
                    if rename_result.is_err() {
                        is_broken_clone.store(true, Ordering::Relaxed);
                        break;
                    }

                    match OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&log_path)
                    {
                        Ok(new_file) => {
                            file = new_file;
                            
                            let mut seed_entry = AuditEntry {
                                ts: Utc::now().to_rfc3339(),
                                session_id: entry.session_id.clone(),
                                event: "log_rotation_seed".to_string(),
                                tool_name: None,
                                params: None,
                                reason: None,
                                latency_ms: None,
                                subject: None,
                                entry_index: 0,
                                prev_hmac: hmac_hex,
                                hmac: None,
                            };
                            
                            let seed_canonical = serde_json::to_string(&seed_entry).unwrap();
                            let mut mac = HmacSha256::new_from_slice(&session_secret).expect("HMAC");
                            mac.update(seed_canonical.as_bytes());
                            let seed_hmac = hex::encode(mac.finalize().into_bytes());
                            seed_entry.hmac = Some(seed_hmac.clone());
                            let seed_line = serde_json::to_string(&seed_entry).unwrap();

                            if writeln!(file, "{}", seed_line).is_err() ||
                               file.flush().is_err() ||
                               file.sync_all().is_err() {
                                is_broken_clone.store(true, Ordering::Relaxed);
                                break;
                            }
                            
                            prev_hmac = seed_hmac;
                            current_idx = 1;

                            crate::logging::log_event(
                                crate::logging::Level::Info,
                                "log_rotated",
                                serde_json::json!({
                                    "archived": backup_path.to_string_lossy(),
                                    "new_log": log_path.to_string_lossy()
                                }),
                            );
                        }
                        Err(_) => {
                            is_broken_clone.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                } else {
                    prev_hmac = hmac_hex;
                    current_idx += 1;
                }
                
                entry_count_clone.store(current_idx, Ordering::Relaxed);
            }
        });

        Ok(Self {
            sender: tx,
            is_broken,
            entry_count,
            session_id,
        })
    }

    pub fn write_entry(
        &self,
        event: &str,
        tool_name: &str,
        params: Option<Value>,
        reason: Option<String>,
        latency_ms: Option<f64>,
        subject: Option<String>,
    ) -> Result<(), AuditError> {
        if self.is_broken.load(Ordering::Relaxed) {
            return Err(AuditError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Audit log is broken/disk full",
            )));
        }

        let entry = AuditEntry {
            ts: Utc::now().to_rfc3339(),
            session_id: self.session_id.clone(),
            event: event.to_string(),
            tool_name: Some(tool_name.to_string()),
            params,
            reason,
            latency_ms,
            subject,
            // Filled by background thread:
            entry_index: 0,
            prev_hmac: "".to_string(),
            hmac: None,
        };

        if self.sender.send(entry).is_err() {
            self.is_broken.store(true, Ordering::Relaxed);
            return Err(AuditError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Audit channel closed",
            )));
        }

        Ok(())
    }

    pub fn entry_count(&self) -> u64 {
        self.entry_count.load(Ordering::Relaxed)
    }
}
