# Deployment & Installation

Welcome to the AgentWall installation guide! Whether you are on Windows, macOS, or Linux, this guide will walk you through setting up AgentWall step-by-step so you can start securing your AI agents immediately.

## 🍎 macOS Installation

### Step 1: Open your Terminal
You can find the Terminal app by pressing `Cmd + Space` (Spotlight Search), typing `Terminal`, and pressing `Return`.

### Step 2: Download and Install AgentWall
Copy the following command, paste it into your Terminal window, and press `Return`:

```bash
curl -fsSL https://vexasec.io/install.sh | sh
```
*This script safely downloads the AgentWall application and places it in a hidden folder on your computer (`~/.local/bin`).*

### Step 3: Make AgentWall accessible
To ensure you can run the `agentwall` command from anywhere, you need to add it to your system path. Paste this into your Terminal and press `Return`:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### Step 4: Verify Installation
Type the following and press `Return`. If you see the AgentWall help menu, you are good to go!
```bash
agentwall --help
```

---

## 🐧 Linux Installation

### Step 1: Open your Terminal
Open your preferred terminal emulator (e.g., GNOME Terminal, Konsole, xterm).

### Step 2: Download and Install AgentWall
Paste the following command to download and install the binary:

```bash
curl -fsSL https://vexasec.io/install.sh | sh
```

### Step 3: Make AgentWall accessible
Add the installation directory to your bash profile:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Step 4: Verify Installation
```bash
agentwall --help
```

---

## 🪟 Windows Installation

### Step 1: Open PowerShell
Press the `Windows` key on your keyboard, type `PowerShell`, and click **Windows PowerShell**.

### Step 2: Download AgentWall
Copy and paste the following command into PowerShell and press `Enter`. This downloads the AgentWall ZIP file to your computer.

```powershell
Invoke-WebRequest -Uri "https://github.com/noviqtechnologies/agentwall/releases/latest/download/agentwall-windows-x86_64.zip" -OutFile "agentwall.zip"
```

### Step 3: Extract the Application
Now, let's extract the downloaded file into a dedicated folder. Paste this command and press `Enter`:

```powershell
Expand-Archive -Path "agentwall.zip" -DestinationPath "$env:USERPROFILE\.local" -Force
```

### Step 4: Make AgentWall accessible
Add the AgentWall folder to your active PowerShell session so you can run it easily:

```powershell
$env:PATH += ";$env:USERPROFILE\.local\bin"
```
*(Tip: To make this permanent so you don't have to run this command every time you open PowerShell, search for "Environment Variables" in your Windows Start menu and add `%USERPROFILE%\.local\bin` to your User `PATH` variable).*

### Step 5: Verify Installation
Type the following and press `Enter`:
```powershell
agentwall.exe --help
```

---

## 🐳 Docker Deployment (For Production)

If you are a system administrator deploying AgentWall for a team, you can run the centralized Enforcement Gateway using Docker.

```bash
# Start AgentWall Gateway using Docker
docker run -d \
  --name agentwall \
  -p 8080:8080 \
  -v ./policy.yaml:/etc/agentwall/policy.yaml:ro \
  -v ./audit.log:/var/log/agentwall/audit.log \
  ghcr.io/noviqtechnologies/agentwall:latest \
  start --policy /etc/agentwall/policy.yaml --listen 0.0.0.0:8080
```
