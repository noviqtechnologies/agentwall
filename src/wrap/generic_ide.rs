//! Generic wrap/unwrap orchestration for standard IDEs (Cursor, VS Code, etc.)

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use colored::*;

use super::{WrapError, backup, transformer};
use super::claude::{WrapResult, UnwrapResult};

pub fn wrap_generic(ide_name: &str, config_path: PathBuf, dry_run: bool) -> Result<WrapResult, WrapError> {
    if !config_path.exists() {
        return Err(WrapError::ConfigNotFound(config_path.display().to_string()));
    }

    let raw = fs::read_to_string(&config_path)
        .map_err(WrapError::Io)?;
    let config: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| WrapError::InvalidJson(e.to_string()))?;

    if config.get("mcpServers").is_none() {
        return Err(WrapError::NoMcpServers);
    }

    let agentwall_bin = std::env::current_exe()
        .map_err(|e| WrapError::NoBinaryPath(e.to_string()))?
        .to_string_lossy()
        .to_string();

    let servers = config["mcpServers"].as_object()
        .ok_or(WrapError::NoMcpServers)?;
    if !servers.is_empty() && servers.values().all(transformer::is_already_wrapped) {
        return Err(WrapError::AlreadyWrapped);
    }

    let mut modified = config.clone();
    let (wrapped_count, _) = transformer::wrap_all_servers(&mut modified, &agentwall_bin)?;

    if dry_run {
        println!("{} {}", "🔍".blue(), format!("DRY-RUN MODE — no changes will be written for {}", ide_name).yellow().bold());
        println!("{} Config: {}", "  →".dimmed(), config_path.display().to_string().cyan());
        println!("{} Servers that would be wrapped: {}", "  →".dimmed(), wrapped_count.to_string().green());
        return Ok(WrapResult {
            config_path,
            backup_path: PathBuf::from("<dry-run: no backup created>"),
            servers_wrapped: wrapped_count,
            scan_responses: false,
        });
    }

    let backup_path = backup::create_backup(&config_path)?;

    if let Some(dir) = config_path.parent() {
        let _ = backup::prune_backups(dir, 5);
    }

    let output_str = serde_json::to_string_pretty(&modified)
        .map_err(|e| WrapError::InvalidJson(e.to_string()))?;
    serde_json::from_str::<serde_json::Value>(&output_str)
        .map_err(|e| {
            let _ = fs::copy(&backup_path, &config_path);
            WrapError::InvalidJson(format!("Transform produced invalid JSON: {}. Restored from backup.", e))
        })?;

    atomic_write(&config_path, &output_str)?;

    Ok(WrapResult {
        config_path,
        backup_path,
        servers_wrapped: wrapped_count,
        scan_responses: false,
    })
}

pub fn unwrap_generic(ide_name: &str, config_path: PathBuf, force: bool) -> Result<UnwrapResult, WrapError> {
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
            println!("{} No backup found for {}. Manual cleanup instructions:", "⚠".yellow().bold(), ide_name);
            println!("\nEdit {} and restore each mcpServer entry.", config_path.display().to_string().cyan());
            Err(WrapError::NoBackupFound)
        }
        None => Err(WrapError::NoBackupFound),
    }
}

pub fn print_wrap_summary_generic(ide_name: &str, result: &WrapResult) {
    println!("{} {}", "✔".green().bold(), format!("AgentWall wrapped {}.", ide_name).green().bold());
    println!("  {} Config:            {}", "→".dimmed(), result.config_path.display().to_string().cyan());
    println!("  {} Backup:            {}", "→".dimmed(), result.backup_path.display().to_string().cyan());
    println!("  {} Servers wrapped:   {}", "→".dimmed(), result.servers_wrapped.to_string().green());
    println!("\n  {} Restart {} to apply changes.", "ℹ".blue(), ide_name);
}

pub fn print_unwrap_summary_generic(ide_name: &str, result: &UnwrapResult) {
    println!("{} {}", "✔".green().bold(), format!("AgentWall removed from {}.", ide_name).green().bold());
    println!("  {} Config restored:   {}", "→".dimmed(), result.config_path.display().to_string().cyan());
    println!("  {} Backup removed:    {}", "→".dimmed(), result.backup_path.display().to_string().dimmed());
    println!("\n  {} Restart {} to apply changes.", "ℹ".blue(), ide_name);
}

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
