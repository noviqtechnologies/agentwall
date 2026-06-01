#!/usr/bin/env python3
"""
Mock Splunk HEC — FR-203 Developer Stack

Mimics the Splunk HTTP Event Collector endpoint so AgentWall SIEM export can
be tested locally without a real Splunk instance.

Endpoints:
  POST /services/collector/event   → Accept and print audit events
  GET  /health                     → Health check
  GET  /events                     → Return all received events (for assertions)

Usage:
    python3 mock_splunk.py [--port 8088]
"""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

_received_events = []
PORT = 8088


class SplunkHECHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[mock-splunk] {self.address_string()} - {format % args}")

    def send_json(self, data, status=200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.send_json({"status": "ok", "events_received": len(_received_events)})
        elif self.path == "/events":
            self.send_json({"events": _received_events, "count": len(_received_events)})
        else:
            self.send_json({"error": "not_found"}, status=404)

    def do_POST(self):
        if self.path not in ("/services/collector/event", "/services/collector"):
            self.send_json({"text": "Not Found", "code": 4}, status=404)
            return

        # Read body
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length > 0 else b""

        # Validate Splunk HEC auth token (accept any non-empty)
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Splunk "):
            self.send_json({"text": "Token is required", "code": 1}, status=401)
            return

        # Parse — Splunk HEC accepts newline-delimited JSON events
        events = []
        for line in raw.decode("utf-8", errors="replace").strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                events.append({"raw": line})

        for ev in events:
            _received_events.append(ev)
            event_data = ev.get("event", ev)
            print(f"[mock-splunk] EVENT: {json.dumps(event_data, separators=(',', ':'))}")

        self.send_json({"text": "Success", "code": 0})


def main():
    global PORT
    parser = argparse.ArgumentParser(description="Mock Splunk HEC for AgentWall local development")
    parser.add_argument("--port", type=int, default=8088)
    args = parser.parse_args()
    PORT = args.port

    server = HTTPServer(("0.0.0.0", PORT), SplunkHECHandler)
    print(f"[mock-splunk] Listening on http://0.0.0.0:{PORT}")
    print(f"[mock-splunk] HEC endpoint: POST http://0.0.0.0:{PORT}/services/collector/event")
    print(f"[mock-splunk] Events log:   GET  http://0.0.0.0:{PORT}/events")
    print(f"[mock-splunk] Health check: GET  http://0.0.0.0:{PORT}/health")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[mock-splunk] Stopped.")
        print(f"[mock-splunk] Total events received: {len(_received_events)}")


if __name__ == "__main__":
    main()
