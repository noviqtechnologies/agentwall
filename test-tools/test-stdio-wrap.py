import subprocess
import json
import os
import sys
import time

def main():
    # Path to agentwall binary
    vexa_bin = "./target/debug/agentwall.exe" if os.name == "nt" else "./target/debug/agentwall"
    if not os.path.exists(vexa_bin):
        # Try release just in case
        vexa_bin = "./target/release/agentwall.exe" if os.name == "nt" else "./target/release/agentwall"
        if not os.path.exists(vexa_bin):
            print(f"Error: agentwall binary not found in debug or release.")
            sys.exit(1)

    # Command to wrap
    import shlex
    mock_server = f"{shlex.quote(sys.executable)} test-tools/mock-stdio-server.py"
    
    # Start agentwall wrap
    cmd = [vexa_bin, "wrap", "--command", mock_server, "--log-path", "test-stdio.log", "--policy", "test-tools/test-policy.yaml"]
    
    print(f"Starting: {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    # Test call 1: Allowable
    call1 = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "safe_tool",
            "arguments": {"arg1": "val1"}
        }
    }
    
    print(f"Sending call 1: {call1['params']['name']}")
    proc.stdin.write(json.dumps(call1) + "\n")
    proc.stdin.flush()
    
    # Read response 1
    resp1 = proc.stdout.readline()
    if resp1:
        print(f"Received resp 1: {resp1.strip()}")
    else:
        print("No response 1 on stdout.")
        err = proc.stderr.read()
        if err:
            print(f"AgentWall Stderr: {err}")
            
    # Test call 2: Safe Mode Violation (should be blocked)
    call2 = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "~/.ssh/id_rsa"}
        }
    }
    
    print(f"Sending call 2: {call2['params']['name']} with sensitive path")
    proc.stdin.write(json.dumps(call2) + "\n")
    proc.stdin.flush()
    
    # Read response 2
    resp2 = proc.stdout.readline()
    if resp2:
        print(f"Received resp 2: {resp2.strip()}")
    else:
        print("No response 2 on stdout.")
        
    proc.terminate()
    proc.wait()
    print("Test finished.")

if __name__ == "__main__":
    main()
