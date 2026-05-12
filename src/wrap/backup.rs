//! FR-304: Backup creation, rotation, and lookup for Claude Desktop config

use chrono::Local;
use std::path::{Path, PathBuf};
use super::WrapError;

const BACKUP_SUFFIX_PREFIX: &str = "agentwall-backup-";
#[allow(dead_code)]
const MAX_BACKUPS: usize = 5;

/// Create a timestamped backup of the config file in the same directory.
/// Returns the path of the created backup.
pub fn create_backup(config_path: &Path) -> Result<PathBuf, WrapError> {
    let ts = Local::now().format("%Y%m%d-%H%M%S").to_string();
    let file_name = config_path
        .file_name()
        .ok_or_else(|| WrapError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid config path")))?
        .to_string_lossy();

    let backup_name = format!("{}.{}{}", file_name, BACKUP_SUFFIX_PREFIX, ts);
    let backup_path = config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(&backup_name);

    std::fs::copy(config_path, &backup_path)?;
    Ok(backup_path)
}

/// Delete oldest backups, keeping only `max_keep` most recent.
pub fn prune_backups(config_dir: &Path, max_keep: usize) -> Result<(), WrapError> {
    let mut backups = list_backups(config_dir)?;
    // Sort chronologically (filename contains timestamp, so lexicographic == time order)
    backups.sort();
    while backups.len() > max_keep {
        let oldest = backups.remove(0);
        let _ = std::fs::remove_file(&oldest);
    }
    Ok(())
}

/// Find the most recent backup file in the config directory.
pub fn find_latest_backup(config_dir: &Path) -> Option<PathBuf> {
    let mut backups = list_backups(config_dir).unwrap_or_default();
    backups.sort();
    backups.into_iter().last()
}

/// List all agentwall backup files in a directory.
fn list_backups(config_dir: &Path) -> Result<Vec<PathBuf>, WrapError> {
    let entries = std::fs::read_dir(config_dir)?;
    let backups = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.contains(BACKUP_SUFFIX_PREFIX))
                .unwrap_or(false)
        })
        .collect();
    Ok(backups)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;

    fn make_fake_config(dir: &Path) -> PathBuf {
        let p = dir.join("claude_desktop_config.json");
        fs::write(&p, r#"{"mcpServers": {}}"#).unwrap();
        p
    }

    #[test]
    fn test_backup_creates_file_with_timestamp() {
        let dir = tempdir().unwrap();
        let config = make_fake_config(dir.path());
        let backup = create_backup(&config).unwrap();
        assert!(backup.exists());
        assert!(backup.to_string_lossy().contains(BACKUP_SUFFIX_PREFIX));
    }

    #[test]
    fn test_prune_keeps_only_max_backups() {
        let dir = tempdir().unwrap();
        let config = make_fake_config(dir.path());
        // Create 7 backups
        for i in 0..7 {
            let ts = format!("20260512-{:06}", i);
            let bk = dir.path().join(format!("claude_desktop_config.json.{}{}",
                BACKUP_SUFFIX_PREFIX, ts));
            fs::write(&bk, "{}").unwrap();
        }
        prune_backups(dir.path(), MAX_BACKUPS).unwrap();
        let remaining = list_backups(dir.path()).unwrap();
        assert_eq!(remaining.len(), MAX_BACKUPS);
        // config itself should be untouched
        assert!(config.exists());
    }

    #[test]
    fn test_find_latest_backup_returns_most_recent() {
        let dir = tempdir().unwrap();
        make_fake_config(dir.path());
        for ts in &["20260512-100000", "20260512-110000", "20260512-120000"] {
            let bk = dir.path().join(format!("claude_desktop_config.json.{}{}",
                BACKUP_SUFFIX_PREFIX, ts));
            fs::write(&bk, "{}").unwrap();
        }
        let latest = find_latest_backup(dir.path()).unwrap();
        assert!(latest.to_string_lossy().contains("120000"));
    }

    #[test]
    fn test_find_latest_backup_returns_none_when_empty() {
        let dir = tempdir().unwrap();
        make_fake_config(dir.path());
        assert!(find_latest_backup(dir.path()).is_none());
    }
}
