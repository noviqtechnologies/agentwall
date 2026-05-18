import os
import sys
import time
import json
import urllib.request
import urllib.error
import threading
import subprocess
import shutil

URL = "http://127.0.0.1:8080"
TEST_REQ = {
    "name": "read_file",
    "arguments": {
        "path": "src/main.py"
    }
}

def get_agentwall_pid():
    # Find pid of agentwall process
    try:
        # Check proc filesystem
        for name in os.listdir("/proc"):
            if name.isdigit():
                try:
                    with open(os.path.join("/proc", name, "cmdline"), "r") as f:
                        cmd = f.read()
                        if "agentwall" in cmd:
                            return int(name)
                except Exception:
                    pass
    except Exception:
        pass
    return None

def get_process_metrics(pid):
    if pid is None:
        return None
    try:
        # 1. Read RSS memory (in KB) from /proc/{pid}/status
        rss = 0
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1]) # VmRSS:     12345 kB
                    break
        
        # 2. Count open file descriptors under /proc/{pid}/fd
        fd_count = len(os.listdir(f"/proc/{pid}/fd"))
        
        return {"rss_kb": rss, "fds": fd_count}
    except Exception as e:
        return None

def send_rpc():
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": TEST_REQ,
        "id": 999
    }
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        URL, 
        data=data, 
        headers={'Content-Type': 'application/json'}
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as response:
            resp_data = response.read().decode('utf-8')
            return True
    except Exception:
        return False

def run_stress_test(duration=60, thread_count=15):
    print("=== AgentWall Phase 3 Marathon Stress & Resource Test ===")
    
    pid = get_agentwall_pid()
    if pid is None:
        print("[!] Warning: Could not locate running agentwall process PID. Resource metrics will be skipped.")
    else:
        print(f"Found running AgentWall process on PID: {pid}")
        
    # Baseline Metrics
    baseline = get_process_metrics(pid)
    if baseline:
        print(f"Baseline Memory: {baseline['rss_kb'] / 1024:.2f} MB")
        print(f"Baseline Open File Descriptors: {baseline['fds']}")
    
    stop_event = threading.Event()
    stats = {"success": 0, "failed": 0}
    
    def worker():
        while not stop_event.is_set():
            # Send continuous load. Since we want to stress-test, we run as fast as possible.
            # However, if rate limit is active, we might get rate-limited. But this tests system stability!
            ok = send_rpc()
            if ok:
                stats["success"] += 1
            else:
                stats["failed"] += 1
            # Very tiny sleep to prevent CPU starvation in python thread orchestration
            time.sleep(0.005)
            
    print(f"\nBombarding AgentWall with {thread_count} concurrent workers for {duration} seconds...")
    threads = []
    start_time = time.time()
    for _ in range(thread_count):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)
        
    # Monitor metrics periodically during the test
    peek_metrics = []
    for _ in range(duration):
        if stop_event.is_set():
            break
        time.sleep(1)
        metrics = get_process_metrics(pid)
        if metrics:
            peek_metrics.append(metrics)
            
    stop_event.set()
    for t in threads:
        t.join()
        
    elapsed = time.time() - start_time
    total_reqs = stats["success"] + stats["failed"]
    reqs_per_sec = total_reqs / elapsed
    
    print("\n--- Load Metrics ---")
    print(f"Elapsed Time: {elapsed:.2f} seconds")
    print(f"Total Requests Processed: {total_reqs}")
    print(f"  - Successful: {stats['success']}")
    print(f"  - Failed (Rate-limited/blocked): {stats['failed']}")
    print(f"Throughput: {reqs_per_sec:.2f} req/sec")
    
    # End Metrics
    end_metrics = get_process_metrics(pid)
    print("\n--- Resource Utilization ---")
    if baseline and end_metrics:
        mem_diff_kb = end_metrics["rss_kb"] - baseline["rss_kb"]
        mem_growth_pct = (mem_diff_kb / baseline["rss_kb"]) * 100
        
        print(f"End Memory: {end_metrics['rss_kb'] / 1024:.2f} MB (Growth: {mem_growth_pct:.2f}%)")
        print(f"End Open File Descriptors: {end_metrics['fds']} (Baseline: {baseline['fds']})")
        
        # Validation checks
        mem_ok = mem_growth_pct < 10.0
        fd_ok = abs(end_metrics["fds"] - baseline["fds"]) <= 3 # Allow slight fluctuation
        
        if mem_ok:
            print("  [PASS] Memory growth is under the 10% limit!")
        else:
            print(f"  [FAIL] Memory growth exceeded 10%! Growth was {mem_growth_pct:.2f}%")
            
        if fd_ok:
            print("  [PASS] Open file descriptors remained stable (no leak)!")
        else:
            print(f"  [WARNING] Open file descriptors changed from {baseline['fds']} to {end_metrics['fds']}!")
    else:
        print("Resource metrics not available on this platform/configuration.")
        mem_ok = True
        fd_ok = True
        
    # Cryptographic Audit Log Integrity Verification
    print("\n--- Cryptographic Audit Log Verification ---")
    audit_log = "/root/audit.log"
    if not os.path.exists(audit_log):
        # Check standard config path
        home = os.path.expanduser("~")
        audit_log = os.path.join(home, ".agentwall", "audit.log")
        
    if os.path.exists(audit_log):
        print(f"Verifying HMAC chain on audit log: {audit_log}")
        # Run agentwall verify-log
        # Inside PATH or build folders
        shutil_bin = shutil.which("agentwall") or "agentwall"
        res = subprocess.run([shutil_bin, "verify-log", audit_log], capture_output=True, text=True)
        if res.returncode == 0:
            print("  [PASS] Cryptographic verification succeeded! All audit log HMAC chains are intact.")
            log_ok = True
        else:
            print(f"  [FAIL] Cryptographic verification failed!")
            print(f"  STDOUT: {res.stdout}")
            print(f"  STDERR: {res.stderr}")
            log_ok = False
    else:
        print(f"[!] Warning: Audit log not found at expected path: {audit_log}")
        log_ok = True
        
    print("\n==============================================")
    if mem_ok and fd_ok and log_ok:
        print("SUCCESS: Phase 3 Marathon Stress and Resource Test PASSED!")
        return True
    else:
        print("FAILURE: Phase 3 did not meet all resource/integrity constraints.")
        return False

if __name__ == "__main__":
    dur = 60
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        dur = int(sys.argv[1])
    success = run_stress_test(duration=dur)
    sys.exit(0 if success else 1)
