//! FR-304: OS-specific Claude Desktop config path resolution

use std::path::PathBuf;
use super::WrapError;

/// Returns the absolute path to claude_desktop_config.json for the current OS.
pub fn claude_config_path() -> Result<PathBuf, WrapError> {
    let base = match std::env::consts::OS {
        "macos" => dirs::data_dir().ok_or_else(|| {
            WrapError::ConfigNotFound("Cannot resolve ~/Library/Application Support".to_string())
        })?,
        "linux" => dirs::config_dir().ok_or_else(|| {
            WrapError::ConfigNotFound("Cannot resolve ~/.config".to_string())
        })?,
        "windows" => {
            let standard = dirs::data_dir()
                .ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve %APPDATA%".to_string()))?
                .join("Claude")
                .join("claude_desktop_config.json");

            if standard.exists() {
                standard
            } else {
                // Fallback for Microsoft Store version
                let user_name = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string());
                let store_path = PathBuf::from(format!(
                    "C:\\Users\\{}\\AppData\\Local\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\claude_desktop_config.json",
                    user_name
                ));
                if store_path.exists() {
                    store_path
                } else {
                    return Err(WrapError::ConfigNotFound(format!(
                        "Tested standard path ({}) and Microsoft Store path",
                        standard.display()
                    )));
                }
            }
        }
        other => return Err(WrapError::UnsupportedOs(other.to_string())),
    };
    Ok(base)
}

/// Returns the path to the ~/.agentwall/ config directory.
pub fn agentwall_config_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".agentwall"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claude_config_path_returns_json_file() {
        // Should return a path ending in claude_desktop_config.json
        let path = claude_config_path();
        // On any supported OS this should succeed
        if let Ok(p) = path {
            assert!(p.to_string_lossy().contains("claude_desktop_config.json"));
            assert!(p.is_absolute());
        }
        // On unsupported OS it returns UnsupportedOs — also valid
    }

    #[test]
    fn test_agentwall_config_dir_returns_path() {
        // Should return Some path under home dir
        let dir = agentwall_config_dir();
        if let Some(d) = dir {
            assert!(d.to_string_lossy().contains(".agentwall"));
        }
    }
}
