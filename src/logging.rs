//! Structured stderr JSON logging — exact event names per PRD §5.4

use chrono::Utc;
use serde_json::json;
use std::io::Write;

/// Log levels matching PRD spec
#[derive(Debug, Clone, Copy)]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }
}

/// Emit a structured JSON log line to stderr.
/// All fields are merged into the top-level object alongside ts, level, event.
pub fn log_event(level: Level, event: &str, fields: serde_json::Value) {
    let mut obj = match fields {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    obj.insert("ts".to_string(), json!(Utc::now().to_rfc3339()));
    obj.insert("level".to_string(), json!(level.as_str()));
    obj.insert("event".to_string(), json!(event));

    // Ensure deterministic key order: ts, level, event first, then rest
    let ordered = json!({
        "ts": obj.remove("ts").unwrap(),
        "level": obj.remove("level").unwrap(),
        "event": obj.remove("event").unwrap(),
    });

    let mut final_obj = match ordered {
        serde_json::Value::Object(map) => map,
        _ => unreachable!(),
    };
    for (k, v) in obj {
        final_obj.insert(k, v);
    }

    let line = serde_json::to_string(&serde_json::Value::Object(final_obj))
        .unwrap_or_else(|_| "{}".to_string());
    let _ = writeln!(std::io::stderr(), "{}", line);
}

// Convenience macros
#[macro_export]
macro_rules! log_info {
    ($event:expr, $($fields:tt)*) => {
        $crate::logging::log_event($crate::logging::Level::Info, $event, serde_json::json!({$($fields)*}))
    };
}

#[macro_export]
macro_rules! log_warn {
    ($event:expr, $($fields:tt)*) => {
        $crate::logging::log_event($crate::logging::Level::Warn, $event, serde_json::json!({$($fields)*}))
    };
}

#[macro_export]
macro_rules! log_error {
    ($event:expr, $($fields:tt)*) => {
        $crate::logging::log_event($crate::logging::Level::Error, $event, serde_json::json!({$($fields)*}))
    };
}
