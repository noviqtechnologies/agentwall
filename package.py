import os
import shutil
import subprocess
import zipfile
import platform

def package():
    version = "1.0.3"
    dist_dir = f"agentwall-v{version}"
    
    print(f"[*] Starting packaging for VEXA AgentWall v{version}...")
    
    # 1. Clean up old builds
    if os.path.exists(dist_dir):
        shutil.rmtree(dist_dir)
    
    os.makedirs(f"{dist_dir}/bin", exist_ok=True)
    os.makedirs(f"{dist_dir}/ui", exist_ok=True)
    os.makedirs(f"{dist_dir}/config", exist_ok=True)

    # 2. Build Rust Binary
    print("[*] Building Rust binary in release mode...")
    try:
        subprocess.run(["cargo", "build", "--release"], check=True)
    except Exception as e:
        print(f"[!] Build failed: {e}")
        return

    # 3. Copy Binary
    bin_ext = ".exe" if platform.system() == "Windows" else ""
    bin_name = f"agentwall{bin_ext}"
    shutil.copy(f"target/release/{bin_name}", f"{dist_dir}/bin/{bin_name}")

    # 4. Copy UI and Bridge
    print("[*] Copying UI components...")
    ui_files = ["index.html", "bridge.py"]
    for f in ui_files:
        shutil.copy(f"demo-ui/{f}", f"{dist_dir}/ui/{f}")

    # 5. Create Example Policy
    print("[*] Creating example config...")
    if os.path.exists("demo-ui/policy.yaml"):
        shutil.copy("demo-ui/policy.yaml", f"{dist_dir}/config/policy.yaml.example")

    # 6. Create Start Scripts
    print("[*] Generating cross-platform startup scripts...")
    
    # Windows PowerShell
    ps1_content = f"""# VEXA AgentWall Start Script
Write-Host "Starting VEXA AgentWall Bridge..." -ForegroundColor Cyan
Set-Location -Path ui
python bridge.py --vexa-bin ..\\bin\\{bin_name} --policy ..\\config\\policy.yaml.example
"""
    with open(f"{dist_dir}/start-agentwall.ps1", "w") as f:
        f.write(ps1_content)

    # Linux/macOS Shell
    sh_content = f"""#!/bin/bash
echo "Starting VEXA AgentWall Bridge..."
cd ui
python3 bridge.py --vexa-bin ../bin/agentwall --policy ../config/policy.yaml.example
"""
    with open(f"{dist_dir}/start-agentwall.sh", "w") as f:
        f.write(sh_content)
    os.chmod(f"{dist_dir}/start-agentwall.sh", 0o755)

    # 7. Create ZIP
    print(f"[*] Creating ZIP archive: {dist_dir}.zip")
    shutil.make_archive(dist_dir, 'zip', dist_dir)
    
    print(f"\n[✓] SUCCESS: {dist_dir}.zip is ready!")
    print(f"    You can now distribute this file to users.")

if __name__ == "__main__":
    package()
