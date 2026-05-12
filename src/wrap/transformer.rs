//! FR-304: JSON transformer — wraps / unwraps mcpServer entries

use serde_json::{json, Value};
use super::WrapError;

const STDIO_PROXY_MARKER: &str = "stdio-proxy";

/// Check whether an mcpServer entry is already wrapped by agentwall.
pub fn is_already_wrapped(entry: &Value) -> bool {
    // Check 1: command field equals agentwall binary path
    // Check 2: first arg is "stdio-proxy"
    let first_arg = entry["args"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str());
    first_arg == Some(STDIO_PROXY_MARKER)
}

/// Wrap a single mcpServer entry in-place.
/// Before: { "command": "npx", "args": [...], "env": {...} }
/// After:  { "command": "/path/agentwall", "args": ["stdio-proxy", "--", "npx", ...], "env": {...} }
pub fn wrap_entry(entry: &mut Value, agentwall_bin: &str) -> Result<(), WrapError> {
    if is_already_wrapped(entry) {
        return Err(WrapError::AlreadyWrapped);
    }

    let command = entry["command"]
        .as_str()
        .ok_or_else(|| WrapError::InvalidJson(
            "mcpServer entry missing 'command' field".to_string()
        ))?
        .to_string();

    let existing_args: Vec<Value> = entry["args"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    // Build: ["stdio-proxy", "--", <original_command>, <original_args...>]
    let mut new_args = vec![
        json!(STDIO_PROXY_MARKER),
        json!("--"),
        json!(command),
    ];
    new_args.extend(existing_args);

    entry["command"] = json!(agentwall_bin);
    entry["args"] = json!(new_args);
    // env, description, and all other fields are preserved automatically

    Ok(())
}

/// Unwrap a single mcpServer entry in-place (reverse of wrap_entry).
/// Returns Err if the entry is not wrapped.
pub fn unwrap_entry(entry: &mut Value) -> Result<(), WrapError> {
    if !is_already_wrapped(entry) {
        // Not wrapped by us — leave as-is
        return Ok(());
    }

    let args = entry["args"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    // args[0] = "stdio-proxy", args[1] = "--", args[2] = original command, args[3..] = original args
    if args.len() < 3 {
        return Err(WrapError::InvalidJson(
            "Wrapped entry has unexpected args format".to_string()
        ));
    }

    let original_command = args[2]
        .as_str()
        .ok_or_else(|| WrapError::InvalidJson("Original command is not a string".to_string()))?
        .to_string();

    let original_args: Vec<Value> = args[3..].to_vec();

    entry["command"] = json!(original_command);
    if original_args.is_empty() {
        entry["args"] = json!([]);
    } else {
        entry["args"] = json!(original_args);
    }

    Ok(())
}

/// Apply wrap_entry to every server in the mcpServers map.
/// Returns (wrapped_count, already_wrapped_count).
pub fn wrap_all_servers(
    config: &mut Value,
    agentwall_bin: &str,
) -> Result<(usize, usize), WrapError> {
    let servers = config["mcpServers"]
        .as_object_mut()
        .ok_or(WrapError::NoMcpServers)?;

    if servers.is_empty() {
        return Err(WrapError::NoMcpServers);
    }

    let mut wrapped = 0;
    let mut already = 0;
    for (_name, entry) in servers.iter_mut() {
        match wrap_entry(entry, agentwall_bin) {
            Ok(()) => wrapped += 1,
            Err(WrapError::AlreadyWrapped) => already += 1,
            Err(e) => return Err(e),
        }
    }

    // If nothing was newly wrapped, all servers were already protected — idempotent rejection
    if wrapped == 0 && already > 0 {
        return Err(WrapError::AlreadyWrapped);
    }

    Ok((wrapped, already))
}

/// Apply unwrap_entry to every server in the mcpServers map.
/// Returns count of servers restored.
pub fn unwrap_all_servers(config: &mut Value) -> Result<usize, WrapError> {
    let servers = config["mcpServers"]
        .as_object_mut()
        .ok_or(WrapError::NoMcpServers)?;

    let mut count = 0;
    for (_name, entry) in servers.iter_mut() {
        unwrap_entry(entry)?;
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn server_no_args() -> Value {
        json!({
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-memory"],
            "env": { "FOO": "bar" }
        })
    }

    fn server_with_args() -> Value {
        json!({
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"],
            "env": { "HOME": "/home/alice" }
        })
    }

    #[test]
    fn test_wrap_single_server_no_args() {
        let mut entry = json!({ "command": "my-mcp", "args": [] });
        wrap_entry(&mut entry, "/usr/bin/agentwall").unwrap();
        assert_eq!(entry["command"], "/usr/bin/agentwall");
        assert_eq!(entry["args"][0], "stdio-proxy");
        assert_eq!(entry["args"][1], "--");
        assert_eq!(entry["args"][2], "my-mcp");
    }

    #[test]
    fn test_wrap_single_server_with_args() {
        let mut entry = server_with_args();
        wrap_entry(&mut entry, "/bin/agentwall").unwrap();
        assert_eq!(entry["command"], "/bin/agentwall");
        assert_eq!(entry["args"][0], "stdio-proxy");
        assert_eq!(entry["args"][1], "--");
        assert_eq!(entry["args"][2], "npx");
        assert_eq!(entry["args"][3], "-y");
        assert_eq!(entry["args"][4], "@modelcontextprotocol/server-filesystem");
        assert_eq!(entry["args"][5], "/workspace");
    }

    #[test]
    fn test_wrap_preserves_env() {
        let mut entry = server_no_args();
        wrap_entry(&mut entry, "/bin/agentwall").unwrap();
        assert_eq!(entry["env"]["FOO"], "bar");
    }

    #[test]
    fn test_wrap_preserves_extra_fields() {
        let mut entry = json!({
            "command": "npx",
            "args": [],
            "env": {},
            "description": "My server",
            "type": "stdio"
        });
        wrap_entry(&mut entry, "/bin/agentwall").unwrap();
        assert_eq!(entry["description"], "My server");
        assert_eq!(entry["type"], "stdio");
    }

    #[test]
    fn test_idempotency_guard_detects_wrapped() {
        let mut entry = server_no_args();
        wrap_entry(&mut entry, "/bin/agentwall").unwrap();
        // Second wrap should return AlreadyWrapped
        let result = wrap_entry(&mut entry, "/bin/agentwall");
        assert!(matches!(result, Err(WrapError::AlreadyWrapped)));
    }

    #[test]
    fn test_is_already_wrapped_false_for_clean_entry() {
        let entry = server_no_args();
        assert!(!is_already_wrapped(&entry));
    }

    #[test]
    fn test_is_already_wrapped_true_for_wrapped_entry() {
        let mut entry = server_no_args();
        wrap_entry(&mut entry, "/bin/agentwall").unwrap();
        assert!(is_already_wrapped(&entry));
    }

    #[test]
    fn test_unwrap_restores_original_command_and_args() {
        let mut entry = server_with_args();
        let original = entry.clone();
        wrap_entry(&mut entry, "/bin/agentwall").unwrap();
        unwrap_entry(&mut entry).unwrap();
        assert_eq!(entry["command"], original["command"]);
        assert_eq!(entry["args"], original["args"]);
        assert_eq!(entry["env"], original["env"]);
    }

    #[test]
    fn test_wrap_multiple_servers() {
        let mut config = json!({
            "mcpServers": {
                "server1": { "command": "npx", "args": ["-y", "s1"] },
                "server2": { "command": "node", "args": ["server.js"] },
                "server3": { "command": "python3", "args": ["-m", "mcp"] }
            }
        });
        let (wrapped, already) = wrap_all_servers(&mut config, "/bin/agentwall").unwrap();
        assert_eq!(wrapped, 3);
        assert_eq!(already, 0);
        // All servers should now have "stdio-proxy" as first arg
        for (_name, entry) in config["mcpServers"].as_object().unwrap() {
            assert_eq!(entry["args"][0], "stdio-proxy");
        }
    }

    #[test]
    fn test_wrap_empty_mcp_servers_returns_error() {
        let mut config = json!({ "mcpServers": {} });
        let result = wrap_all_servers(&mut config, "/bin/agentwall");
        assert!(matches!(result, Err(WrapError::NoMcpServers)));
    }
}
