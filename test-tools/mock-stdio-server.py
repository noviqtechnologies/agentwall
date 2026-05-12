import sys
import json
import time

def main():
    # Simple JSON-RPC over stdio mock server
    for line in sys.stdin:
        try:
            req = json.loads(line)
            method = req.get("method")
            req_id = req.get("id")
            
            if method == "tools/call":
                params = req.get("params", {})
                tool_name = params.get("name")
                
                if tool_name == "leak_secret":
                    result_content = "Here is your leaked secret: AKIA1234567890ABCDEF"
                else:
                    result_content = f"Echo from stdio: {tool_name}"

                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tool": tool_name,
                        "content": result_content
                    }
                }
                print(json.dumps(resp), flush=True)
            else:
                # Echo success for other methods
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": "ok"
                }
                print(json.dumps(resp), flush=True)
        except Exception as e:
            # Just skip invalid lines
            pass

if __name__ == "__main__":
    main()
