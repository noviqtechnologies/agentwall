//! Audit log HMAC chain verification (vexa verify-log)

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{BufRead, BufReader};
use std::path::Path;

use super::logger::{AuditEntry, ZERO_HMAC};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub enum VerifyResult {
    /// Chain is intact
    Valid { entry_count: u64 },
    /// Chain is broken at this entry
    Invalid { entry_index: u64, reason: String },
    /// Error reading or parsing the log
    Error(String),
}

/// Verify the HMAC chain integrity of an audit log.
/// Note: without the session secret, we can only verify chain consistency
/// (each entry's prev_hmac matches the prior entry's hmac).
/// Full HMAC recomputation requires the session secret.
pub fn verify_chain(log_path: &Path) -> VerifyResult {
    let file = match std::fs::File::open(log_path) {
        Ok(f) => f,
        Err(e) => return VerifyResult::Error(format!("Cannot open log file: {}", e)),
    };

    let reader = BufReader::new(file);
    let mut prev_hmac = ZERO_HMAC.to_string();
    let mut count: u64 = 0;

    for (line_num, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                return VerifyResult::Error(format!("Read error at line {}: {}", line_num + 1, e))
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let entry: AuditEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                return VerifyResult::Error(format!(
                    "Malformed JSON at line {}: {}",
                    line_num + 1,
                    e
                ))
            }
        };

        // Handle FR-109 log rotation seed
        if count == 0 && entry.event == "log_rotation_seed" {
            prev_hmac = entry.prev_hmac.clone();
        }

        // Verify entry_index matches expected sequence
        if entry.entry_index != count {
            return VerifyResult::Invalid {
                entry_index: entry.entry_index,
                reason: format!("Expected entry_index {}, got {}", count, entry.entry_index),
            };
        }

        // Verify prev_hmac chain
        if entry.prev_hmac != prev_hmac {
            return VerifyResult::Invalid {
                entry_index: entry.entry_index,
                reason: format!("prev_hmac mismatch at entry {}", entry.entry_index),
            };
        }

        // Update chain
        prev_hmac = entry.hmac.unwrap_or_default();
        count += 1;
    }

    if count == 0 {
        return VerifyResult::Error("Empty log file".to_string());
    }

    VerifyResult::Valid { entry_count: count }
}

/// Verify chain with the session secret (full HMAC recomputation).
/// Used when the secret is available (e.g., during a live session).
pub fn verify_chain_with_secret(log_path: &Path, session_secret: &[u8]) -> VerifyResult {
    let file = match std::fs::File::open(log_path) {
        Ok(f) => f,
        Err(e) => return VerifyResult::Error(format!("Cannot open log file: {}", e)),
    };

    let reader = BufReader::new(file);
    let mut prev_hmac = ZERO_HMAC.to_string();
    let mut count: u64 = 0;

    for (line_num, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                return VerifyResult::Error(format!("Read error at line {}: {}", line_num + 1, e))
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let entry: AuditEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                return VerifyResult::Error(format!(
                    "Malformed JSON at line {}: {}",
                    line_num + 1,
                    e
                ))
            }
        };

        // Handle FR-109 log rotation seed
        if count == 0 && entry.event == "log_rotation_seed" {
            prev_hmac = entry.prev_hmac.clone();
        }

        if entry.entry_index != count {
            return VerifyResult::Invalid {
                entry_index: entry.entry_index,
                reason: format!("Expected entry_index {}, got {}", count, entry.entry_index),
            };
        }

        if entry.prev_hmac != prev_hmac {
            return VerifyResult::Invalid {
                entry_index: entry.entry_index,
                reason: format!("prev_hmac mismatch at entry {}", entry.entry_index),
            };
        }

        // Recompute HMAC
        let stored_hmac = entry.hmac.clone().unwrap_or_default();
        let mut verify_entry = entry;
        verify_entry.hmac = None;
        let canonical = serde_json::to_string(&verify_entry).unwrap();

        let mut mac = HmacSha256::new_from_slice(session_secret).expect("HMAC key length is valid");
        mac.update(canonical.as_bytes());
        let computed = hex::encode(mac.finalize().into_bytes());

        if computed != stored_hmac {
            return VerifyResult::Invalid {
                entry_index: verify_entry.entry_index,
                reason: format!("HMAC mismatch at entry {}", verify_entry.entry_index),
            };
        }

        prev_hmac = stored_hmac;
        count += 1;
    }

    if count == 0 {
        return VerifyResult::Error("Empty log file".to_string());
    }

    VerifyResult::Valid { entry_count: count }
}
