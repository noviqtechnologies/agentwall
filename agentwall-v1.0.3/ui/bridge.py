import argparse
import subprocess
import threading
import queue
import time
import json
import os
import urllib.request
import urllib.error
import tempfile
import atexit
import signal
from flask import Flask, request, jsonify, Response, stream_with_context, cli, send_from_directory
from flask_cors import CORS
import logging

def cleanup(signum=None, frame=None):
    global proxy_process
    try:
        with proxy_lock:
            if proxy_process is not None and proxy_process.poll() is None:
                print("\n[INFO] Shutdown signal received. Stopping proxy...")
                proxy_process.terminate()
                try:
                    proxy_process.wait(timeout=2)
                except:
                    proxy_process.kill()
    except:
        pass
    if signum:
        os._exit(0)

# Register for both standard exit and Ctrl+C
atexit.register(cleanup)
signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# Suppress Flask development server banner and logs
cli.show_server_banner = lambda *args: None
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__, static_folder='.')
CORS(app)

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

cfg = {}

proxy_process = None
proxy_lock = threading.Lock()

log_subscribers = []
subscribers_lock = threading.Lock()

def log_tailer_daemon():
    last_size = -1
    
    while True:
        try:
            if not os.path.exists(cfg['log_path']):
                last_size = -1
                time.sleep(1)
                continue
                
            curr_size = os.path.getsize(cfg['log_path'])
            
            # First run: start at current end
            if last_size == -1:
                last_size = curr_size
                time.sleep(0.5)
                continue

            # If file shrunk (rotated), reset
            if curr_size < last_size:
                last_size = 0

            # If file grew, read the new data
            if curr_size > last_size:
                # We open and close quickly to avoid lock conflicts
                with open(cfg['log_path'], 'r', encoding='utf-8', errors='replace') as f:
                    f.seek(last_size)
                    while True:
                        line = f.readline()
                        if not line:
                            break
                        
                        clean_line = line.strip()
                        if clean_line:
                            with subscribers_lock:
                                for sub in log_subscribers:
                                    try:
                                        sub.put_nowait(clean_line)
                                    except:
                                        pass
                last_size = curr_size
            
            time.sleep(0.3)

        except Exception as e:
            # Silent retry
            time.sleep(1)

@app.route('/healthz', methods=['GET'])
def healthz():
    return jsonify({"bridge": "ok"})

@app.route('/proxy/start', methods=['POST'])
def proxy_start():
    global proxy_process
    data = request.json or {}
    policy_path = data.get('policy_path', cfg['policy'])
    listen = data.get('listen', cfg['listen'])
    log_path = data.get('log_path', cfg['log_path'])
    kill_mode = data.get('kill_mode', 'both')
    dry_run = data.get('dry_run', False)
    report_path = data.get('report_path', cfg['report_path'])

    with proxy_lock:
        if proxy_process is not None and proxy_process.poll() is None:
            return jsonify({"error": "Proxy already running"}), 409

        cmd = [
            cfg['vexa_bin'], 'start',
            '--policy', policy_path,
            '--listen', listen,
            '--log-path', log_path,
            '--kill-mode', kill_mode,
            '--report-path', report_path
        ]
        if dry_run:
            cmd.append('--dry-run')

        try:
            proxy_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True
            )
            cfg['current_listen'] = listen # save current listen
            time.sleep(0.5)
            
            # Check if process already exited
            if proxy_process.poll() is not None:
                stderr = proxy_process.stderr.read()
                return jsonify({"error": f"Proxy failed to start: {stderr.strip()}", "stderr": stderr}), 500
                
            # If still running, we should probably close stderr to avoid buffer filling up,
            # or just let it be if we don't expect much output there.
            # But we can't easily "close" it from here without risking the next read.
            # However, vexa should be logging to the file, not stderr.
            
            return jsonify({
                "status": "started", 
                "pid": proxy_process.pid, 
                "listen": listen
            })
            
        except FileNotFoundError:
            return jsonify({"error": f"Binary not found: {cfg['vexa_bin']}"}), 500
        except Exception as e:
            return jsonify({"error": str(e)}), 500

@app.route('/proxy/stop', methods=['POST'])
def proxy_stop():
    global proxy_process
    with proxy_lock:
        if proxy_process is None or proxy_process.poll() is not None:
            return jsonify({"status": "not_running"})
            
        proxy_process.terminate()
        try:
            proxy_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy_process.kill()
            proxy_process.wait()
            
        return jsonify({"status": "stopped"})

@app.route('/proxy/status', methods=['GET'])
def proxy_status():
    with proxy_lock:
        if proxy_process is not None and proxy_process.poll() is None:
            return jsonify({"running": True, "pid": proxy_process.pid})
        return jsonify({"running": False, "pid": None})

@app.route('/proxy/readyz', methods=['GET'])
def proxy_readyz():
    listen = cfg.get('current_listen', cfg['listen'])
    try:
        url = f"http://{listen}/readyz"
        req = urllib.request.Request(url, method='GET')
        with urllib.request.urlopen(req, timeout=1.0) as response:
            if response.status == 200:
                return jsonify({"ready": True})
    except Exception:
        pass
    return jsonify({"ready": False})

@app.route('/check', methods=['POST'])
def check():
    data = request.json or {}
    policy_str = data.get('policy', '')
    fixture = data.get('fixture', [])
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f_policy:
        f_policy.write(policy_str)
        policy_tmp = f_policy.name
        
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f_fixture:
        json.dump(fixture, f_fixture)
        fixture_tmp = f_fixture.name

    try:
        cmd = [cfg['vexa_bin'], 'check', '--policy', policy_tmp, fixture_tmp]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return jsonify({
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr
        })
    except FileNotFoundError:
        return jsonify({"error": f"Binary not found: {cfg['vexa_bin']}"}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out"}), 500
    finally:
        try:
            os.remove(policy_tmp)
            os.remove(fixture_tmp)
        except:
            pass

@app.route('/policy/save', methods=['POST'])
def save_policy():
    data = request.json or {}
    policy_content = data.get('policy')
    if not policy_content:
        return jsonify({"error": "No policy provided"}), 400
    try:
        with open(cfg['policy'], 'w') as f:
            f.write(policy_content)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/verify-log', methods=['POST'])
def verify_log():
    try:
        # Be lenient with JSON parsing
        try:
            data = request.get_json(silent=True) or {}
        except:
            data = {}
            
        log_path = os.path.abspath(data.get('log_path', cfg.get('log_path', 'audit.log')))
        bin_path = os.path.abspath(cfg.get('vexa_bin', 'agentwall.exe'))
        
        print(f"[DEBUG] Verifying log: {log_path} using {bin_path}")
        
        if not os.path.exists(bin_path):
            return jsonify({"error": f"Binary not found at {bin_path}"}), 404

        cmd = [bin_path, "verify-log", log_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        print(f"[DEBUG] Verify exit_code: {proc.returncode}")
        if proc.stdout: print(f"[DEBUG] Verify stdout: {proc.stdout.strip()}")
        if proc.stderr: print(f"[DEBUG] Verify stderr: {proc.stderr.strip()}")
        
        # Handle the "Empty log file" case gracefully for the UI
        if proc.returncode != 0 and "Empty log file" in proc.stderr:
            return jsonify({
                "exit_code": 0,
                "stdout": "Log is empty. Start a session to generate entries.",
                "stderr": "",
                "is_empty": True
            })

        return jsonify({
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr
        })
    except Exception as e:
        print(f"[ERROR] Verification failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/report', methods=['POST'])
def report():
    data = request.json or {}
    log_path = data.get('log_path', cfg['log_path'])
    
    if not os.path.exists(log_path):
        return jsonify({"error": f"Log file not found: {log_path}"}), 404
        
    try:
        cmd = [cfg['vexa_bin'], 'report', log_path, '--format', 'json']
        print(f"[DEBUG] Running report cmd: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        print(f"[DEBUG] Report exit_code: {proc.returncode}, stdout len: {len(proc.stdout)}, stderr: {proc.stderr}")
        
        if proc.returncode != 0:
            return jsonify({"error": f"Vexa report failed (exit {proc.returncode})", "stderr": proc.stderr}), 500
            
        try:
            parsed = json.loads(proc.stdout)
            return jsonify(parsed)
        except json.JSONDecodeError:
            return jsonify({"error": "Vexa report returned invalid JSON", "stdout": proc.stdout}), 500
            
    except FileNotFoundError:
        return jsonify({"error": f"Binary not found: {cfg['vexa_bin']}"}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Report command timed out"}), 500

@app.route('/log/entries', methods=['GET'])
def log_entries():
    limit = int(request.args.get('limit', 500))
    entries = []
    try:
        if not os.path.exists(cfg['log_path']):
            return jsonify({"entries": [], "total": 0})
            
        with open(cfg['log_path'], 'r') as f:
            lines = f.readlines()
            for line in lines[-limit:]:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    entries.append({"raw": line.strip()})
            return jsonify({
                "entries": entries,
                "total": len(lines)
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/log/stream', methods=['GET'])
def log_stream():
    def event_stream():
        q = queue.Queue(maxsize=200)
        with subscribers_lock:
            log_subscribers.append(q)
            
        # Pre-populate with last 10 lines for context
        try:
            if os.path.exists(cfg['log_path']):
                with open(cfg['log_path'], 'r') as f:
                    lines = f.readlines()
                    for line in lines[-10:]:
                        if line.strip():
                            q.put(line.strip())
        except:
            pass

        try:
            while True:
                try:
                    line = q.get(timeout=15)
                    yield f"data: {line}\n\n"
                except queue.Empty:
                    yield ": heartbeat\n\n"
        finally:
            with subscribers_lock:
                if q in log_subscribers:
                    log_subscribers.remove(q)
                    
    response = Response(stream_with_context(event_stream()), content_type='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    return response

@app.route('/proxy/call', methods=['POST'])
def proxy_call():
    data = request.json or {}
    tool = data.get('tool')
    params = data.get('params', {})
    listen = data.get('listen', cfg.get('current_listen', cfg['listen']))
    
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": params
        },
        "id": 1
    }
    
    req = urllib.request.Request(
        f"http://{listen}/", 
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            body = response.read().decode('utf-8')
            return jsonify({
                "status": response.status,
                "body": json.loads(body) if body else None
            })
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8')
        try:
            body_json = json.loads(body)
        except:
            body_json = {"raw": body}
        return jsonify({
            "status": e.code,
            "body": body_json
        })
    except (ConnectionRefusedError, OSError) as e:
        return jsonify({"error": "Proxy not reachable. Is it running?"}), 503

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="VEXA AgentWall Bridge")
    parser.add_argument('--vexa-bin', default='./vexa', help='Path to the vexa binary')
    parser.add_argument('--policy', default='./policy.yaml', help='Default policy file path')
    parser.add_argument('--log-path', default='./audit.log', help='Audit log to tail')
    parser.add_argument('--listen', default='127.0.0.1:8080', help='Proxy listen address')
    parser.add_argument('--report-path', default='./session-report.json', help='Session report output path')
    parser.add_argument('--port', type=int, default=5173, help='Bridge HTTP port')
    
    args = parser.parse_args()
    
    cfg['vexa_bin'] = args.vexa_bin
    cfg['policy'] = os.path.abspath(args.policy)
    cfg['log_path'] = os.path.abspath(args.log_path)
    cfg['listen'] = args.listen
    cfg['report_path'] = os.path.abspath(args.report_path)
    
    print("=" * 60)
    print(" VEXA AGENTWALL - BRIDGE SERVER")
    print(" Status:        RUNNING")
    print(f" Bridge URL:   http://127.0.0.1:{args.port}")
    print(f" Vexa Binary:  {cfg['vexa_bin']}")
    print(f" Policy File:  {cfg['policy']}")
    print("-" * 60)
    print(" Press Ctrl+C to shutdown.")
    print("=" * 60)
    
    t = threading.Thread(target=log_tailer_daemon, daemon=True)
    t.start()
    
    app.run(host='127.0.0.1', port=args.port, threaded=True, debug=False)
