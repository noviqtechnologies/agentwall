//! Audit log HMAC chain verification (`agentwall verify-log`).
//!
//! Two verification modes are available:
//!
//! - **Chain-only** (`verify_chain`): checks that every entry's `prev_hmac`
//!   matches the prior entry's `hmac` and that `entry_index` is monotonically
//!   increasing. No secret required — useful for offline / forensic review.
//!
//! - **Full HMAC** (`verify_chain_with_secret`): additionally recomputes each
//!   entry's HMAC from scratch using the session secret and confirms it matches
//!   the stored value.  Detects any byte-level modification to the payload.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{BufRead, BufReader};
use std::path::Path;

use super::logger::{AuditEntry, ZERO_HMAC};

type HmacSha256 = Hmac<Sha256>;

/// Result of a chain verification run.
#[derive(Debug)]
pub enum VerifyResult {
    /// All entries are intact.
    Valid { entry_count: u64 },
    /// A break in the chain was detected at this entry index.
    Invalid { entry_index: u64, reason: String },
    /// A file-level error prevented verification.
    Error(String),
}

// ─── Helpers ───────────────────────────────────────────────────────────────

/// Parse a JSONL line into an `AuditEntry`, tolerating trailing whitespace.
/// Returns `None` for blank lines; `Err` for unparseable lines.
fn parse_line(line: &str, line_num: usize) -> Result<Option<AuditEntry>, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    // Fast path: strict parse.
    if let Ok(e) = serde_json::from_str::<AuditEntry>(trimmed) {
        return Ok(Some(e));
    }

    // Slow path: streaming parser recovers the first object from a line that
    // has unexpected trailing bytes (e.g. double-written entries during crash).
    let mut stream = serde_json::Deserializer::from_str(trimmed)
        .into_iter::<AuditEntry>();
    if let Some(Ok(e)) = stream.next() {
        return Ok(Some(e));
    }

    Err(format!("malformed JSON at line {}: {}", line_num + 1, trimmed))
}

/// Advance the chain cursor over a `log_rotation_seed` entry.
///
/// A rotation seed carries `prev_hmac` = HMAC of the last entry in the
/// archived file, providing continuity across log rotation boundaries.
fn handle_rotation_seed(entry: &AuditEntry, count: &mut u64, prev_hmac: &mut String) {
    // Reset the per-file sequence counter.
    *count = 0;
    // The seed's own prev_hmac is the bridge from the old file.
    *prev_hmac = entry.prev_hmac.clone();
}

// ─── Public API ────────────────────────────────────────────────────────────

/// Verify the HMAC chain consistency of an audit log without the session secret.
///
/// Checks:
/// - Every `prev_hmac` matches the prior entry's `hmac`.
/// - `entry_index` is monotonically increasing within each file segment.
///
/// **Cannot** detect modification of a single entry where both the payload
/// and the stored `hmac` field are changed — use `verify_chain_with_secret`
/// for that level of assurance.
pub fn verify_chain(log_path: &Path) -> VerifyResult {
    let file = match std::fs::File::open(log_path) {
        Ok(f)  => f,
        Err(e) => return VerifyResult::Error(format!("cannot open log file: {}", e)),
    };

    let reader = BufReader::new(file);
    let mut prev_hmac = ZERO_HMAC.to_string();
    let mut count: u64 = 0;

    for (line_num, raw) in reader.lines().enumerate() {
        let raw = match raw {
            Ok(l)  => l,
            Err(e) => {
                return VerifyResult::Error(
                    format!("read error at line {}: {}", line_num + 1, e)
                );
            }
        };

        let entry = match parse_line(&raw, line_num) {
            Ok(None)     => continue,
            Ok(Some(e))  => e,
            Err(msg)     => return VerifyResult::Error(msg),
        };

        // Rotation seed resets the per-segment index counter.
        if entry.event == "log_rotation_seed" {
            handle_rotation_seed(&entry, &mut count, &mut prev_hmac);
        } else if entry.entry_index == 0 && count == 0 {
            // First entry in a fresh file — initialise prev_hmac sentinel.
            prev_hmac = ZERO_HMAC.to_string();
        }

        if entry.entry_index != count {
            return VerifyResult::Invalid {
                entry_index: entry.entry_index,
                reason:      format!(
                    "expected entry_index {}, got {}",
                    count, entry.entry_index
                ),
            };
        }

        if entry.prev_hmac != prev_hmac {
            return VerifyResult::Invalid {
                entry_index: entry.entry_index,
                reason:      format!("prev_hmac mismatch at entry {}", entry.entry_index),
            };
        }

        prev_hmac = entry.hmac.unwrap_or_default();
        count += 1;
    }

    if count == 0 {
        return VerifyResult::Error("log file contains no audit entries".to_string());
    }

    VerifyResult::Valid { entry_count: count }
}

/// Verify the HMAC chain with full HMAC recomputation using the session secret.
///
/// In addition to the chain-consistency checks performed by `verify_chain`, this
/// function recomputes each entry's HMAC from its canonical JSON and confirms it
/// matches the stored value.  Any single-byte modification to any field — including
/// `ts`, `reason`, `identity_sub`, `policy_hash`, etc. — is detected.
pub fn verify_chain_with_secret(log_path: &Path, session_secret: &[u8]) -> VerifyResult {
    let file = match std::fs::File::open(log_path) {
        Ok(f)  => f,
        Err(e) => return VerifyResult::Error(format!("cannot open log file: {}", e)),
    };

    let reader = BufReader::new(file);
    let mut prev_hmac = ZERO_HMAC.to_string();
    let mut count: u64 = 0;

    for (line_num, raw) in reader.lines().enumerate() {
        let raw = match raw {
            Ok(l)  => l,
            Err(e) => {
                return VerifyResult::Error(
                    format!("read error at line {}: {}", line_num + 1, e)
                );
            }
        };

        let entry = match parse_line(&raw, line_num) {
            Ok(None)     => continue,
            Ok(Some(e))  => e,
            Err(msg)     => return VerifyResult::Error(msg),
        };

        // Rotation seed.
        if entry.event == "log_rotation_seed" {
            handle_rotation_seed(&entry, &mut count, &mut prev_hmac);
        }

        if entry.entry_index != count {
            return VerifyResult::Invalid {
                entry_index: entry.entry_index,
                reason:      format!(
                    "expected entry_index {}, got {}",
                    count, entry.entry_index
                ),
            };
        }

        if entry.prev_hmac != prev_hmac {
            return VerifyResult::Invalid {
                entry_index: entry.entry_index,
                reason:      format!("prev_hmac mismatch at entry {}", entry.entry_index),
            };
        }

        // Recompute HMAC: strip the stored `hmac` field, serialise, compute.
        let stored_hmac = entry.hmac.clone().unwrap_or_default();
        let mut verify_entry = entry.clone();
        verify_entry.hmac = None;

        let canonical = match serde_json::to_string(&verify_entry) {
            Ok(s)  => s,
            Err(e) => {
                return VerifyResult::Error(
                    format!("re-serialisation error at entry {}: {}", count, e)
                );
            }
        };

        let mut mac =
            HmacSha256::new_from_slice(session_secret).expect("HMAC key length is valid");
        mac.update(canonical.as_bytes());
        let computed = hex::encode(mac.finalize().into_bytes());

        if computed != stored_hmac {
            return VerifyResult::Invalid {
                entry_index: verify_entry.entry_index,
                reason:      format!("HMAC mismatch at entry {} — payload has been modified", verify_entry.entry_index),
            };
        }

        prev_hmac = stored_hmac;
        count += 1;
    }

    if count == 0 {
        return VerifyResult::Error("log file contains no audit entries".to_string());
    }

    VerifyResult::Valid { entry_count: count }
}
