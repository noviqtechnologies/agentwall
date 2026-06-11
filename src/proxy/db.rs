// src/proxy/db.rs
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

use rusqlite::{params, Connection, Transaction};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Event {
    pub timestamp: String,
    pub tool_name: String,
    pub parameters: String,
    pub response: String,
    pub upstream_endpoint: String,
    pub session_id: String,
    pub latency_ms: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DbStats {
    pub total_events: i64,
    pub unique_tools: i64,
    pub risk_flag_count: i64,
}

// Commands sent to the DB manager thread
enum DbCmd {
    Insert(Event),
    Fetch {
        limit: usize,
        responder: oneshot::Sender<Result<Vec<Event>, String>>,
    },
    /// Fetch all events in chronological order (oldest first) — used by generate-policy (FR-4)
    FetchAll {
        limit: usize,
        responder: oneshot::Sender<Result<Vec<Event>, String>>,
    },
    GetStats {
        responder: oneshot::Sender<Result<DbStats, String>>,
    },
    Prune,
}

/// Handles SQLite interactions on a dedicated thread.
/// The manager is cheap to clone (Arc) and provides async helpers.
#[derive(Clone)]
pub struct DbManager {
    cmd_tx: mpsc::UnboundedSender<DbCmd>,
    // Keep a handle for potential graceful shutdown (not used currently)
    _shutdown: Arc<()>,
}

impl DbManager {
    /// Initialise the manager, opening/creating the DB file under $HOME/.agentwall/events.db.
    /// Spawns a background thread that processes commands.
    pub fn init() -> Self {
        // Resolve path
        let home_dir = dirs::home_dir().expect("Failed to get home directory");
        let db_path = PathBuf::from(&home_dir).join(".agentwall").join("events.db");
        // Ensure directory exists
        if let Some(parent) = db_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).expect("Failed to create .agentwall directory");
            }
        }
        // Open connection (will create file if missing)
        let conn = Connection::open(&db_path).expect("Failed to open SQLite DB");
        // Ensure schema exists
        conn.execute(
            "CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                parameters TEXT NOT NULL,
                response TEXT NOT NULL,
                upstream_endpoint TEXT NOT NULL,
                session_id TEXT NOT NULL,
                latency_ms REAL NOT NULL
            )",
            [],
        )
        .expect("Failed to create events table");

        // Channel for commands
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<DbCmd>();
        // Use Arc to keep connection alive across thread boundaries safely (rusqlite is not Send, so we keep it in the thread)
        let _shutdown = Arc::new(());
        // Spawn background thread
        std::thread::spawn(move || {
            // The thread owns the connection and a possible transaction.
            let conn = conn;
            let mut tx: Option<Transaction> = None;
            loop {
                match cmd_rx.blocking_recv() {
                    Some(cmd) => match cmd {
                        DbCmd::Insert(event) => {
                            // Use existing transaction if present, otherwise direct exec
                            if let Some(ref mut tx) = tx {
                                tx.execute(
                                    "INSERT INTO events (timestamp, tool_name, parameters, response, upstream_endpoint, session_id, latency_ms) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                    params![
                                        event.timestamp,
                                        event.tool_name,
                                        event.parameters,
                                        event.response,
                                        event.upstream_endpoint,
                                        event.session_id,
                                        event.latency_ms,
                                    ],
                                )
                                .ok();
                            } else {
                                conn.execute(
                                    "INSERT INTO events (timestamp, tool_name, parameters, response, upstream_endpoint, session_id, latency_ms) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                    params![
                                        event.timestamp,
                                        event.tool_name,
                                        event.parameters,
                                        event.response,
                                        event.upstream_endpoint,
                                        event.session_id,
                                        event.latency_ms,
                                    ],
                                )
                                .ok();
                            }
                        }
                        DbCmd::Fetch { limit, responder } => {
                            let mut stmt = conn.prepare(
                                "SELECT timestamp, tool_name, parameters, response, upstream_endpoint, session_id, latency_ms FROM events ORDER BY id DESC LIMIT ?",
                            )
                            .expect("Failed to prepare fetch stmt");
                            let rows = stmt
                                .query_map(params![limit as i64], |row| {
                                    Ok(Event {
                                        timestamp: row.get(0)?,
                                        tool_name: row.get(1)?,
                                        parameters: row.get(2)?,
                                        response: row.get(3)?,
                                        upstream_endpoint: row.get(4)?,
                                        session_id: row.get(5)?,
                                        latency_ms: row.get(6)?,
                                    })
                                })
                                .expect("Failed to query events");
                            let mut events = Vec::new();
                            for ev in rows {
                                if let Ok(e) = ev {
                                    events.push(e);
                                }
                            }
                            let _ = responder.send(Ok(events));
                        }
                        DbCmd::FetchAll { limit, responder } => {
                            // Oldest-first ordering for policy generation corpus (FR-4)
                            let mut stmt = conn.prepare(
                                "SELECT timestamp, tool_name, parameters, response, upstream_endpoint, session_id, latency_ms FROM events ORDER BY id ASC LIMIT ?",
                            )
                            .expect("Failed to prepare fetch-all stmt");
                            let rows = stmt
                                .query_map(params![limit as i64], |row| {
                                    Ok(Event {
                                        timestamp: row.get(0)?,
                                        tool_name: row.get(1)?,
                                        parameters: row.get(2)?,
                                        response: row.get(3)?,
                                        upstream_endpoint: row.get(4)?,
                                        session_id: row.get(5)?,
                                        latency_ms: row.get(6)?,
                                    })
                                })
                                .expect("Failed to query all events");
                            let mut events = Vec::new();
                            for ev in rows {
                                if let Ok(e) = ev {
                                    events.push(e);
                                }
                            }
                            let _ = responder.send(Ok(events));
                        }
                        DbCmd::GetStats { responder } => {
                            let total_events: i64 = conn.query_row(
                                "SELECT COUNT(*) FROM events",
                                [],
                                |row| row.get(0),
                            ).unwrap_or(0);
                            
                            let unique_tools: i64 = conn.query_row(
                                "SELECT COUNT(DISTINCT tool_name) FROM events",
                                [],
                                |row| row.get(0),
                            ).unwrap_or(0);

                            let _ = responder.send(Ok(DbStats {
                                total_events,
                                unique_tools,
                                risk_flag_count: 0, // Inferred on client
                            }));
                        }
                        DbCmd::Prune => {
                            // Prune if file size > 500 MiB
                            if let Ok(metadata) = fs::metadata(&db_path) {
                                if metadata.len() > 500 * 1024 * 1024 {
                                    // Delete oldest 1000 rows
                                    conn.execute(
                                        "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id ASC LIMIT 1000)",
                                        [],
                                    )
                                    .ok();
                                }
                            }
                        }
                    },
                    None => break, // channel closed
                }
            }
        });

        Self {
            cmd_tx,
            _shutdown,
        }
    }

    /// Async insert of an event.
    pub async fn insert(&self, event: Event) -> Result<(), String> {
        self.cmd_tx
            .send(DbCmd::Insert(event))
            .map_err(|e| format!("Failed to send insert cmd: {}", e))
    }

    /// Async fetch of recent events in reverse-chronological order (newest first), limited to `limit`.
    pub async fn get_events(&self, limit: usize) -> Result<Vec<Event>, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DbCmd::Fetch { limit, responder: tx })
            .map_err(|e| format!("Failed to send fetch cmd: {}", e))?;
        rx.await.map_err(|e| format!("Fetch response error: {}", e))?
    }

    /// Async fetch of all events in chronological order (oldest first) for policy generation (FR-4).
    /// `limit` is capped at 500 by the `generate-policy` command.
    pub async fn get_all_events(&self, limit: usize) -> Result<Vec<Event>, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DbCmd::FetchAll { limit, responder: tx })
            .map_err(|e| format!("Failed to send fetch-all cmd: {}", e))?;
        rx.await.map_err(|e| format!("FetchAll response error: {}", e))?
    }

    /// Async fetch of aggregate stats.
    pub async fn get_stats(&self) -> Result<DbStats, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DbCmd::GetStats { responder: tx })
            .map_err(|e| format!("Failed to send stats cmd: {}", e))?;
        rx.await.map_err(|e| format!("Stats response error: {}", e))?
    }

    /// Trigger pruning (optional public helper).
    pub fn prune(&self) {
        let _ = self.cmd_tx.send(DbCmd::Prune);
    }
}

// Helper to create a ready‑to‑use manager – mirrors the previous `new` function name.
pub fn init_db_manager() -> DbManager {
    DbManager::init()
}

// The module is deliberately lightweight; higher‑level code should call `insert` and `get_events`.