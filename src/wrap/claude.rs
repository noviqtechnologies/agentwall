//! FR-304: Core wrap/unwrap orchestration for Claude Desktop

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use colored::*;

use super::{WrapError, backup, config_path, transformer};

// ─── Public API ────────────────────────────────────────────────────────────

pub struct WrapResult {
    pub config_path: PathBuf,
    pub backup_path: PathBuf,
    pub servers_wrapped: usize,
    pub scan_responses: bool,
}

pub struct UnwrapResult {
    pub config_path: PathBuf,
    pub backup_path: PathBuf,
}

/// Wrap Claude Desktop MCP servers with AgentWall (FR-304).
/// If dry_run is true, prints the diff but makes no writes.
pub fn wrap_claude(dry_run: bool, scan_responses: bool) -> Result<WrapResult, WrapError> {
    // 1. Resolve config path
    let config_path = config_path::claude_config_path()?;

    if !config_path.exists() {
        return Err(WrapError::ConfigNotFound(config_path.display().to_string()));
    }

    // 2. Read & parse config
    let raw = fs::read_to_string(&config_path)
        .map_err(WrapError::Io)?;
    let config: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| WrapError::InvalidJson(e.to_string()))?;

    // 3. Check mcpServers exists
    if config.get("mcpServers").is_none() {
        return Err(WrapError::NoMcpServers);
    }

    // 4. Get absolute agentwall binary path
    let agentwall_bin = std::env::current_exe()
        .map_err(|e| WrapError::NoBinaryPath(e.to_string()))?
        .to_string_lossy()
        .to_string();

    // 5. Check if all servers are already wrapped (idempotency)
    let servers = config["mcpServers"].as_object()
        .ok_or(WrapError::NoMcpServers)?;
    if !servers.is_empty() && servers.values().all(transformer::is_already_wrapped) {
        return Err(WrapError::AlreadyWrapped);
    }

    // 6. Transform (or just preview in dry-run)
    let mut modified = config.clone();
    let (wrapped_count, _) = transformer::wrap_all_servers(&mut modified, &agentwall_bin)?;

    if dry_run {
        print_dry_run_diff(&config, &modified, &config_path, wrapped_count, scan_responses);
        // Return a fake result (backup not created)
        return Ok(WrapResult {
            config_path,
            backup_path: PathBuf::from("<dry-run: no backup created>"),
            servers_wrapped: wrapped_count,
            scan_responses,
        });
    }

    // 7. Create backup before any write
    let backup_path = backup::create_backup(&config_path)?;

    // 8. Prune old backups (keep 5 most recent)
    if let Some(dir) = config_path.parent() {
        let _ = backup::prune_backups(dir, 5);
    }

    // 9. Validate modified JSON is still parseable
    let output_str = serde_json::to_string_pretty(&modified)
        .map_err(|e| WrapError::InvalidJson(e.to_string()))?;
    serde_json::from_str::<serde_json::Value>(&output_str)
        .map_err(|e| {
            // Auto-restore from backup
            let _ = fs::copy(&backup_path, &config_path);
            WrapError::InvalidJson(format!("Transform produced invalid JSON: {}. Restored from backup.", e))
        })?;

    // 10. Atomic write
    atomic_write(&config_path, &output_str)?;

    // 11. Bootstrap ~/.agentwall/config.yaml
    let _ = bootstrap_agentwall_config(scan_responses);

    Ok(WrapResult {
        config_path,
        backup_path,
        servers_wrapped: wrapped_count,
        scan_responses,
    })
}

/// Restore Claude Desktop config from the most recent AgentWall backup (FR-304).
pub fn unwrap_claude(force: bool) -> Result<UnwrapResult, WrapError> {
    let config_path = config_path::claude_config_path()?;

    if !config_path.exists() {
        return Err(WrapError::ConfigNotFound(config_path.display().to_string()));
    }

    let config_dir = config_path.parent().unwrap_or(Path::new("."));

    match backup::find_latest_backup(config_dir) {
        Some(backup_path) => {
            fs::copy(&backup_path, &config_path)?;
            fs::remove_file(&backup_path)?;
            Ok(UnwrapResult { config_path, backup_path })
        }
        None if force => {
            print_force_unwrap_instructions(&config_path);
            Err(WrapError::NoBackupFound)
        }
        None => Err(WrapError::NoBackupFound),
    }
}

// ─── Helpers ───────────────────────────────────────────────────────────────

/// Atomically write content to path via temp file + fsync + rename.
fn atomic_write(path: &Path, content: &str) -> Result<(), WrapError> {
    let tmp_path = path.with_extension("agentwall-tmp");
    {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Create ~/.agentwall/config.yaml on first wrap if it doesn't exist.
fn bootstrap_agentwall_config(scan_responses: bool) -> Result<(), WrapError> {
    let dir = match config_path::agentwall_config_dir() {
        Some(d) => d,
        None => return Ok(()),
    };
    fs::create_dir_all(&dir)?;
    let config_file = dir.join("config.yaml");
    if !config_file.exists() {
        let scan = if scan_responses { "enabled" } else { "disabled" };
        let content = format!(
            "# AgentWall configuration\n\
             # Generated by: agentwall wrap claude\n\
             safe_mode: enabled          # FR-303a: 15 request scanning rules active\n\
             scan_responses: {}    # FR-303b: opt-in with --scan-responses\n\
             log_path: ~/.agentwall/audit.log\n",
            scan
        );
        fs::write(&config_file, content)?;
    }
    Ok(())
}

/// Print a human-readable diff of the wrap changes (dry-run mode).
fn print_dry_run_diff(
    original: &serde_json::Value,
    modified: &serde_json::Value,
    config_path: &Path,
    wrapped_count: usize,
    scan_responses: bool,
) {
    println!("{} {}", "🔍".blue(), "DRY-RUN MODE — no changes will be written".yellow().bold());
    println!("{} Config: {}", "  →".dimmed(), config_path.display().to_string().cyan());
    println!("{} Servers that would be wrapped: {}", "  →".dimmed(), wrapped_count.to_string().green());

    if let (Some(before_servers), Some(after_servers)) = (
        original["mcpServers"].as_object(),
        modified["mcpServers"].as_object(),
    ) {
        for (name, after) in after_servers {
            let before = &before_servers[name];
            println!("\n  {} {}", "Server:".bold(), name.cyan());
            println!("    {} command: {} → {}", "-".red(), before["command"].to_string().red(), after["command"].to_string().green());
            println!("    {} args:    {} → {}", "~".yellow(),
                serde_json::to_string(&before["args"]).unwrap_or_default().red(),
                serde_json::to_string(&after["args"]).unwrap_or_default().green(),
            );
        }
    }

    println!("\n  {} Safe Mode:         {}", "→".dimmed(), "ACTIVE (15 request rules)".green());
    println!("  {} Response scanning: {}",
        "→".dimmed(),
        if scan_responses { "ENABLED".green().to_string() } else { "DISABLED (use --scan-responses to enable)".yellow().to_string() }
    );
    println!("\n{} Run without {} to apply changes.", "ℹ".blue(), "--dry-run".yellow());
}

/// Print manual cleanup instructions when --force is used without a backup.
fn print_force_unwrap_instructions(config_path: &Path) {
    println!("{} No backup found. Manual cleanup instructions:", "⚠".yellow().bold());
    println!("\nEdit {} and restore each mcpServer entry:", config_path.display().to_string().cyan());
    println!("{}", r#"
  // REMOVE this pattern (the agentwall wrapper):
  {
    "command": "/path/to/agentwall",
    "args": ["stdio-proxy", "--", "<original-command>", "<original-args...>"],
    "env": { ... }
  }

  // RESTORE to the original pattern:
  {
    "command": "<original-command>",
    "args": ["<original-args...>"],
    "env": { ... }
  }
"#.yellow());
}

// ─── Print helpers ──────────────────────────────────────────────────────────

/// Print wrap success summary to stdout.
pub fn print_wrap_summary(result: &WrapResult) {
    println!("{} {}", "✔".green().bold(), "AgentWall wrapped Claude Desktop.".green().bold());
    println!("  {} Config:            {}", "→".dimmed(), result.config_path.display().to_string().cyan());
    println!("  {} Backup:            {}", "→".dimmed(), result.backup_path.display().to_string().cyan());
    println!("  {} Servers wrapped:   {}", "→".dimmed(), result.servers_wrapped.to_string().green());
    println!("  {} Safe Mode:         {}", "→".dimmed(), "ACTIVE (15 request rules)".green());
    println!("  {} Response scanning: {}",
        "→".dimmed(),
        if result.scan_responses {
            "ENABLED".green().to_string()
        } else {
            "DISABLED (use --scan-responses to enable)".yellow().to_string()
        }
    );
    println!("\n  {} Restart Claude Desktop to apply changes.", "ℹ".blue());
}

/// Print unwrap success summary to stdout.
pub fn print_unwrap_summary(result: &UnwrapResult) {
    println!("{} {}", "✔".green().bold(), "AgentWall removed from Claude Desktop.".green().bold());
    println!("  {} Config restored:   {}", "→".dimmed(), result.config_path.display().to_string().cyan());
    println!("  {} Backup removed:    {}", "→".dimmed(), result.backup_path.display().to_string().dimmed());
    println!("\n  {} Restart Claude Desktop to apply changes.", "ℹ".blue());
}
