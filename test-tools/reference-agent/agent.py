import argparse
import json
import os
import requests
import sys

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", required=True, help="Path to JSON fixture file")
    parser.add_argument("--pid-file", help="Path to write PID file")
    args = parser.parse_args()

    if args.pid_file:
        with open(args.pid_file, "w") as f:
            f.write(str(os.getpid()))

    proxy_url = os.environ.get("VEXA_PROXY_URL", "http://127.0.0.1:8080")
    
    with open(args.fixture, "r") as f:
        calls = json.load(f)

    results = []
    
    for call in calls:
        tool_name = call.get("tool")
        params = call.get("params", {})
        
        req = {
            "jsonrpc": "2.0",
            "id": len(results) + 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": params
            }
        }
        
        try:
            resp = requests.post(proxy_url, json=req, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if "error" in data:
                    results.append({"status": "error", "error": data["error"]})
                else:
                    results.append({"status": "success", "result": data.get("result")})
            else:
                results.append({"status": "http_error", "code": resp.status_code})
        except requests.exceptions.ConnectionError:
            results.append({"status": "connection_closed"})
            break
            
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
