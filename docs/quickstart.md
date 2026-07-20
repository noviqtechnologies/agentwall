# Quickstart Guide

This guide will walk you through a real-world scenario: **Securing Claude Desktop so it can only run specific commands on your computer.**

By default, when you give an AI Agent access to your filesystem or terminal (via the Model Context Protocol), it has full control. In this guide, we will use AgentWall to observe what Claude Desktop does, and then lock it down using a security policy.

---

## Step 1: Start the AgentWall Proxy

First, we need to start AgentWall in **developer mode**. In this mode, AgentWall acts as a "shadow proxy"—it watches the traffic between Claude Desktop and your computer but doesn't block anything yet. 

Open a terminal (or PowerShell on Windows) and run:

```bash
agentwall dev
```

*AgentWall is now running and listening on `http://127.0.0.1:8080`.*

---

## Step 2: Connect Claude Desktop to AgentWall

Now we need to tell Claude Desktop to route its tool requests through AgentWall instead of directly to your computer.

Open a **new, separate terminal window** and run our automatic integration command:

```bash
agentwall wrap claude
```
*(This command automatically updates Claude Desktop's `claude_desktop_config.json` file so that its MCP traffic routes through the proxy you just started.)*

---

## Step 3: Run a Real-World Scenario

1. Open **Claude Desktop** on your computer.
2. Ask Claude to do something harmless on your system. For example, type:
   > *"Claude, can you run the `whoami` command in my terminal and tell me my username? Also, can you read the contents of a text file on my Desktop?"*

Claude will use its tools to execute the command and read the file. Meanwhile, in your first terminal window, you will see AgentWall logging these actions!

---

## Step 4: Generate a Security Policy

Now that AgentWall has seen what tools Claude needs to use, we can generate a security policy (a firewall rule) that *only* allows those specific actions and blocks everything else.

In your second terminal window, run:

```bash
agentwall generate-policy --decay-window 30d
```

This creates an `agentwall-policy.yaml` file in your current folder. If you open this file, you will see something like this:

```yaml
version: "2"
default_action: deny

tools:
  - name: exec_shell
    action: allow
    parameters:
      - name: command
        type: string
        required: true
        # The policy noticed Claude ran "whoami" and automatically allowed it
        enum:
         - "whoami"

  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
```

---

## Step 5: Enforce the Policy

Right now, you are running `agentwall dev` (observation mode). Let's switch to **enforcement mode** to actually block bad behavior.

1. Go to your first terminal (where `agentwall dev` is running) and press `Ctrl + C` to stop it.
2. Start the gateway in enforcement mode using the policy we just generated:

```bash
agentwall start --policy agentwall-policy.yaml --listen 127.0.0.1:8080
```

### Test the Firewall

Go back to Claude Desktop and ask it to do something malicious or unexpected:
> *"Claude, can you run the `rm -rf /` command?"* or *"Claude, can you read my `.env` file?"*

AgentWall will immediately intercept and **block** the request because it doesn't match the strict allowlist in your `agentwall-policy.yaml` file. You have successfully secured your AI Agent!

---

## Step 6: Clean Up (Optional)

If you ever want to remove AgentWall from Claude Desktop and return to normal, simply run:

```bash
agentwall unwrap claude
```
