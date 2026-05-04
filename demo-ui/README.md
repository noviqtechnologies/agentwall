# VEXA AgentWall Demo UI

This is a professional, local-first single-page application (SPA) to demonstrate Phase 1 of the VEXA AgentWall security proxy. It connects to the `vexa` CLI tool running on your system to process actual commands and interact with its logic.

## Prerequisites

1. **Python 3.x**: Make sure you have Python installed. You can check by running `python --version` in your terminal.
2. **VEXA CLI Binary**: You need a compiled version of the `vexa` binary. Since you are on Windows, this is usually located in the `target/debug` or `target/release` folder after running `cargo build`.

## Setup & Installation

The bridge server requires a couple of standard Python packages (`flask` and `flask-cors`) to handle HTTP requests from the demo UI to the VEXA binary. 

Open your terminal, navigate to this `demo-ui` folder, and run:

```powershell
pip install flask flask-cors
```

## Running the Demo

### Step 1: Start the Bridge Server

The Python bridge server acts as a middleman between the web browser UI and your local VEXA binary. 

From inside the `demo-ui` folder, run the following command. Note that you need to point `--vexa-bin` to where your compiled `vexa.exe` is located. Assuming it's one folder up in the debug build path, you would run:

```powershell
python bridge.py --vexa-bin ..\target\debug\vexa.exe
```

*(If your binary is somewhere else, just change the path after `--vexa-bin`)*

**Optional configuration flags:**
- `--policy`: Path to the policy YAML file (default: `./policy.yaml`)
- `--log-path`: Path where the audit log will be written/tailed (default: `./audit.log`)
- `--port`: The port the bridge server runs on (default: `5173`)

### Step 2: Open the Web UI

Once the bridge server is running and says "VEXA AgentWall Bridge Server", you can start the UI. 

Simply double-click the `index.html` file in your File Explorer to open it in your default web browser.

## How to Use the Demo

The UI is divided into 4 main sections that you can navigate through the sidebar:

- **Policy Editor ([P])**: A pre-loaded testing policy where you can simulate and validate rules. Click "Run vexa check" to simulate pre-flight validation against built-in sample tool calls.
- **Session Monitor ([S])**: Click "Start Proxy" to run the local proxy. You can watch live log streams and manually simulate JSON-RPC tool calls to see how the proxy allows or denies them in real-time based on your policy.
- **Audit Log ([A])**: A historical view of all tool calls made during your session. You can click "Run vexa verify-log" to verify the log's cryptographic integrity.
- **Session Report ([R])**: Generates a high-level summary of the session using the `vexa report` command, displaying allowed vs. denied calls and other useful proxy statistics. You can view this formatted nicely or as raw JSON.
