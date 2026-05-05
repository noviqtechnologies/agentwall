import os
import json
import requests
import sys

def main():
    # 1. Get the proxy URL from the environment
    proxy_url = os.environ.get("VEXA_PROXY_URL")
    
    if not proxy_url:
        print("ERROR: VEXA_PROXY_URL environment variable is not set.")
        print("Please run: $env:VEXA_PROXY_URL=\"http://127.0.0.1:8080\" (PowerShell)")
        print("        or: export VEXA_PROXY_URL=http://127.0.0.1:8080 (Bash)")
        sys.exit(1)

    print(f"--- Starting Quickstart Agent ---")
    print(f"Targeting Proxy: {proxy_url}")
    print("-" * 30)

    # 2. Define some sample tool calls to simulate an agent's workflow
    # We include some 'safe' ones and one 'dangerous' one to see how dry-run works
    calls = [
        {
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "README.md"}
            },
            "note": "Standard safe read"
        },
        {
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "list_directory",
                "arguments": {"directory": "."}
            },
            "note": "Standard discovery"
        },
        {
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "exec_shell",
                "arguments": {"command": "rm -rf /"}
            },
            "note": "DANGEROUS command (Forwarded because of --dry-run!)"
        },
        {
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": "test.txt", "content": "Vexa was here"}
            },
            "note": "State mutation"
        }
    ]

    # 3. Execute the calls
    for call in calls:
        tool_name = call["params"]["name"]
        note = call["note"]
        print(f"[AGENT] Calling tool: {tool_name}")
        print(f"        Purpose: {note}")
        
        try:
            response = requests.post(
                proxy_url,
                json={
                    "jsonrpc": "2.0",
                    "id": call["id"],
                    "method": call["method"],
                    "params": call["params"]
                },
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                if "error" in result:
                    # This happens in ENFORCEMENT mode if a call is blocked
                    print(f"[PROXY] 🚫 BLOCKED: {result['error']['message']}")
                else:
                    # This happens in DRY-RUN mode or if the call is ALLOWED
                    print(f"[PROXY] ✅ SUCCESS: The call was forwarded to the tool server.")
            else:
                print(f"[HTTP] Error: {response.status_code}")
                
        except Exception as e:
            print(f"[SYSTEM] Failed to connect to proxy: {e}")
            break
        print("-" * 10)
        
    print("-" * 30)
    print("Agent workflow completed.")
    print("\nNext step: Run the report to see which calls 'would have been denied':")
    print("  agentwall report audit.log --format text")

if __name__ == "__main__":
    main()
