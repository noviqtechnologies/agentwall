//! FR-304 integration tests — wrap/unwrap lifecycle

use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn fake_config_1_server() -> serde_json::Value {
    serde_json::json!({
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"],
                "env": { "HOME": "/home/alice" }
            }
        }
    })
}

fn fake_config_3_servers() -> serde_json::Value {
    serde_json::json!({
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"],
                "env": { "FOO": "bar" }
            },
            "memory": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-memory"],
                "env": {}
            },
            "custom": {
                "command": "/usr/local/bin/my-mcp-server",
                "args": ["--port", "3100"],
                "env": { "SECRET": "abc" }
            }
        }
    })
}

fn write_config(dir: &std::path::Path, content: &serde_json::Value) -> PathBuf {
    let p = dir.join("claude_desktop_config.json");
    fs::write(&p, serde_json::to_string_pretty(content).unwrap()).unwrap();
    p
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn test_transformer_wrap_then_unwrap_cycle_1_server() {
    use agentwall::wrap::transformer;

    let mut entry = serde_json::json!({
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"],
        "env": { "HOME": "/home/alice" }
    });
    let original = entry.clone();

    transformer::wrap_entry(&mut entry, "/usr/bin/agentwall").unwrap();

    // Wrapped correctly
    assert_eq!(entry["command"], "/usr/bin/agentwall");
    assert_eq!(entry["args"][0], "stdio-proxy");
    assert_eq!(entry["args"][1], "--");
    assert_eq!(entry["args"][2], "npx");

    // Env preserved
    assert_eq!(entry["env"]["HOME"], "/home/alice");

    // Unwrap
    transformer::unwrap_entry(&mut entry).unwrap();

    // Restored exactly
    assert_eq!(entry["command"], original["command"]);
    assert_eq!(entry["args"], original["args"]);
    assert_eq!(entry["env"], original["env"]);
}

#[test]
fn test_wrap_all_servers_wraps_3_servers() {
    use agentwall::wrap::transformer;

    let mut config = fake_config_3_servers();
    let (wrapped, already) = transformer::wrap_all_servers(&mut config, "/bin/agentwall").unwrap();

    assert_eq!(wrapped, 3);
    assert_eq!(already, 0);

    // All servers use agentwall as command
    for (_name, entry) in config["mcpServers"].as_object().unwrap() {
        assert_eq!(entry["command"], "/bin/agentwall");
        assert_eq!(entry["args"][0], "stdio-proxy");
    }
}

#[test]
fn test_wrap_is_idempotent() {
    use agentwall::wrap::transformer;

    let mut config = fake_config_1_server();

    // First wrap
    let (wrapped, already) = transformer::wrap_all_servers(&mut config, "/bin/agentwall").unwrap();
    assert_eq!(wrapped, 1);
    assert_eq!(already, 0);

    // Second wrap attempt: all already wrapped → AlreadyWrapped
    let result = transformer::wrap_all_servers(&mut config, "/bin/agentwall");
    assert!(matches!(result, Err(agentwall::wrap::WrapError::AlreadyWrapped)));
}

#[test]
fn test_env_preserved_through_wrap_cycle() {
    use agentwall::wrap::transformer;

    let mut entry = serde_json::json!({
        "command": "npx",
        "args": [],
        "env": { "SECRET_KEY": "super-secret-123", "PORT": "3000" }
    });

    transformer::wrap_entry(&mut entry, "/bin/agentwall").unwrap();
    assert_eq!(entry["env"]["SECRET_KEY"], "super-secret-123");
    assert_eq!(entry["env"]["PORT"], "3000");

    transformer::unwrap_entry(&mut entry).unwrap();
    assert_eq!(entry["env"]["SECRET_KEY"], "super-secret-123");
    assert_eq!(entry["env"]["PORT"], "3000");
}

#[test]
fn test_backup_and_prune() {
    use agentwall::wrap::backup;

    let dir = tempdir().unwrap();
    let config = write_config(dir.path(), &fake_config_1_server());

    // Create 6 backups manually (simulate time-ordered)
    for i in 0..6usize {
        let ts = format!("20260512-{:06}", i * 1000);
        let bk = dir.path().join(format!("claude_desktop_config.json.agentwall-backup-{}", ts));
        fs::write(&bk, "{}").unwrap();
    }

    backup::prune_backups(dir.path(), 5).unwrap();

    // Count remaining backup files
    let count = fs::read_dir(dir.path()).unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains("agentwall-backup-"))
        .count();
    assert_eq!(count, 5);

    // Original config untouched
    assert!(config.exists());
}

#[test]
fn test_find_latest_backup() {
    use agentwall::wrap::backup;

    let dir = tempdir().unwrap();
    write_config(dir.path(), &fake_config_1_server());

    for ts in &["20260512-100000", "20260512-110000", "20260512-120000"] {
        let bk = dir.path().join(format!("claude_desktop_config.json.agentwall-backup-{}", ts));
        fs::write(&bk, "{}").unwrap();
    }

    let latest = backup::find_latest_backup(dir.path()).unwrap();
    assert!(latest.to_string_lossy().contains("120000"));
}

#[test]
fn test_no_backup_returns_none() {
    use agentwall::wrap::backup;
    let dir = tempdir().unwrap();
    write_config(dir.path(), &fake_config_1_server());
    assert!(backup::find_latest_backup(dir.path()).is_none());
}

#[test]
fn test_wrap_empty_servers_returns_error() {
    use agentwall::wrap::transformer;
    let mut config = serde_json::json!({ "mcpServers": {} });
    let result = transformer::wrap_all_servers(&mut config, "/bin/agentwall");
    assert!(matches!(result, Err(agentwall::wrap::WrapError::NoMcpServers)));
}

#[test]
fn test_unwrap_restores_exact_original() {
    use agentwall::wrap::transformer;

    let original = fake_config_3_servers();
    let mut config = original.clone();

    transformer::wrap_all_servers(&mut config, "/bin/agentwall").unwrap();
    
    // Unwrap all servers
    for (_name, entry) in config["mcpServers"].as_object_mut().unwrap() {
        transformer::unwrap_entry(entry).unwrap();
    }

    // Each server matches original
    for (name, entry) in config["mcpServers"].as_object().unwrap() {
        let orig_entry = &original["mcpServers"][name];
        assert_eq!(entry["command"], orig_entry["command"], "command mismatch for {}", name);
        assert_eq!(entry["args"], orig_entry["args"], "args mismatch for {}", name);
        assert_eq!(entry["env"], orig_entry["env"], "env mismatch for {}", name);
    }
}

#[test]
fn test_absolute_agentwall_path_is_used() {
    use agentwall::wrap::transformer;

    let mut entry = serde_json::json!({ "command": "npx", "args": [] });
    // Simulate an absolute path
    transformer::wrap_entry(&mut entry, "/home/alice/.local/bin/agentwall").unwrap();

    let cmd = entry["command"].as_str().unwrap();
    assert!(cmd.starts_with('/') || cmd.contains(':'), // Unix or Windows absolute path
        "command should be absolute: {}", cmd);
}
