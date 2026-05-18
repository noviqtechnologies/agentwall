import os
import sys
import json
import shutil
import subprocess

def find_agentwall_bin():
    # Check if the binary is already available in PATH (e.g. installed system-wide)
    if shutil.which("agentwall"):
        return "agentwall"
    
    # Try looking in local build paths
    bin_name = "agentwall.exe" if sys.platform == "win32" else "agentwall"
    
    # Try current directory, parent, and root
    candidates = [
        bin_name,
        os.path.join("..", bin_name),
        os.path.join("..", "..", bin_name),
        os.path.join("target", "release", bin_name),
        os.path.join("..", "target", "release", bin_name),
        os.path.join("..", "..", "target", "release", bin_name),
    ]
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)
            
    return bin_name

def get_claude_config_path():
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            standard = os.path.join(appdata, "Claude", "claude_desktop_config.json")
            # If standard folder exists or appdata is valid
            return standard
        username = os.environ.get("USERNAME", "user")
        return f"C:\\Users\\{username}\\AppData\\Roaming\\Claude\\claude_desktop_config.json"
    elif sys.platform == "darwin":
        return os.path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
    else:
        # Linux
        config_dir = os.environ.get("XDG_CONFIG_HOME")
        if not config_dir:
            config_dir = os.path.join(home, ".config")
        return os.path.join(config_dir, "Claude", "claude_desktop_config.json")

def create_dummy_config(path):
    directory = os.path.dirname(path)
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    dummy_data = {
        "mcpServers": {
            "sqlite-server": {
                "command": "node",
                "args": ["/path/to/sqlite/index.js", "--db", "test.db"]
            }
        }
    }
    with open(path, "w") as f:
        json.dump(dummy_data, f, indent=2)
    print(f"Created dummy Claude config at: {path}")

def run_cmd(args):
    print(f"Running: {' '.join(args)}")
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  [!] Command failed! Exit code: {result.returncode}")
        print(f"  STDOUT: {result.stdout}")
        print(f"  STDERR: {result.stderr}")
        return False, result.stdout, result.stderr
    return True, result.stdout, result.stderr

def verify_is_wrapped(path):
    with open(path, "r") as f:
        data = json.load(f)
    servers = data.get("mcpServers", {})
    for server, cfg in servers.items():
        cmd = cfg.get("command", "")
        args = cfg.get("args", [])
        if "agentwall" in cmd.lower():
            # Wrapped with agentwall command directly
            return True
        if len(args) > 0 and "stdio-proxy" in args:
            # Wrapped via stdio-proxy args
            return True
    return False

def count_backups(directory):
    if not os.path.exists(directory):
        return 0
    count = 0
    for name in os.listdir(directory):
        if name.startswith("claude_desktop_config.json.") and not name.endswith(".agentwall-tmp"):
            count += 1
    return count

def clean_backups(directory):
    if not os.path.exists(directory):
        return
    for name in os.listdir(directory):
        if name.startswith("claude_desktop_config.json."):
            try:
                os.remove(os.path.join(directory, name))
            except Exception:
                pass

def test_wrap_cycle():
    print("=== AgentWall Claude Desktop Wrap/Unwrap Cycle Test ===")
    
    bin_path = find_agentwall_bin()
    print(f"Using AgentWall binary: {bin_path}")
    
    config_path = get_claude_config_path()
    config_dir = os.path.dirname(config_path)
    
    # Backup original config if it exists
    original_exists = os.path.exists(config_path)
    original_backup = config_path + ".orig-bak"
    if original_exists:
        shutil.copy2(config_path, original_backup)
        print(f"Backed up original Claude Desktop config to: {original_backup}")
        
    try:
        # Create fresh dummy config
        create_dummy_config(config_path)
        clean_backups(config_dir)
        
        loops = 5
        success_count = 0
        
        for i in range(1, loops + 1):
            print(f"\n--- Wrap/Unwrap Loop {i}/{loops} ---")
            
            # 1. Test Wrap
            ok, out, err = run_cmd([bin_path, "wrap", "claude", "--scan-responses"])
            if not ok:
                print(f"  [FAIL] Wrap command failed during loop {i}")
                continue
                
            # Verify config is wrapped
            if not verify_is_wrapped(config_path):
                print(f"  [FAIL] Config is not wrapped after wrap command!")
                continue
                
            # Verify backup is created
            backups = count_backups(config_dir)
            print(f"  [PASS] Wrapped successfully. Active backups: {backups}")
            
            # 2. Test Unwrap
            ok, out, err = run_cmd([bin_path, "unwrap", "claude"])
            if not ok:
                print(f"  [FAIL] Unwrap command failed during loop {i}")
                continue
                
            # Verify config is restored
            if verify_is_wrapped(config_path):
                print(f"  [FAIL] Config is still wrapped after unwrap command!")
                continue
                
            # Verify backup is cleaned up
            backups_after = count_backups(config_dir)
            if backups_after >= backups:
                print(f"  [FAIL] Backup files did not decrease after unwrap! Backups remaining: {backups_after}")
                continue
                
            print(f"  [PASS] Unwrapped successfully. Active backups: {backups_after}")
            success_count += 1
            
        print("\n==============================================")
        if success_count == loops:
            print(f"SUCCESS: Completed all {loops} wrap/unwrap loops flawlessly!")
            return True
        else:
            print(f"FAILURE: Only {success_count}/{loops} loops succeeded.")
            return False
            
    finally:
        # Clean up dummy config
        if os.path.exists(config_path):
            os.remove(config_path)
        clean_backups(config_dir)
        
        # Restore original config
        if original_exists:
            shutil.copy2(original_backup, config_path)
            os.remove(original_backup)
            print(f"Restored original Claude Desktop config.")

if __name__ == "__main__":
    success = test_wrap_cycle()
    sys.exit(0 if success else 1)
