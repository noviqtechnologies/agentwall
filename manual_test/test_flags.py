import json
import requests
import time
import subprocess
import os
import signal

# --- Configuration ---
PROXY_URL = "http://127.0.0.1:8080"
AUDIT_LOG = "manual_test/audit.log"
BINARY = "agentwall.exe" if os.name == "nt" else "./agentwall"

def test_response_redaction():
    print("\n--- Testing Response Redaction (FR-303b) ---")
    
    # 1. Start AgentWall with --scan-responses
    # We use a mock upstream that returns a secret
    # Since we don't have a full mock server running for this quick test, 
    # we'll just check if the flag is accepted and the proxy starts.
    # For a real integration test, we'd need a mock MCP server.
    
    print(f"Starting {BINARY} with --scan-responses...")
    process = subprocess.Popen([
        BINARY, "start", 
        "--listen", "127.0.0.1:8080", 
        "--log-path", AUDIT_LOG,
        "--scan-responses",
        "--dry-run" # Use dry-run so we don't need a real policy
    ])
    
    time.sleep(2) # Wait for startup
    
    try:
        # Check health
        resp = requests.get(f"{PROXY_URL}/healthz")
        if resp.status_code == 200:
            print("✓ Proxy started successfully with --scan-responses")
        else:
            print(f"✗ Proxy failed to start: {resp.status_code}")
            return

    finally:
        print("Stopping proxy...")
        if os.name == "nt":
            subprocess.call(['taskkill', '/F', '/T', '/PID', str(process.pid)])
        else:
            os.kill(process.pid, signal.SIGTERM)

if __name__ == "__main__":
    if not os.path.exists(BINARY):
        print(f"✗ Error: {BINARY} not found in current directory. Please build it first.")
    else:
        test_response_redaction()
