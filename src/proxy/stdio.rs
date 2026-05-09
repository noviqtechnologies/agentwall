//! Stdio bridge proxy for local MCP servers (FR-302)

use futures::{SinkExt, StreamExt};
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::Command;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::kill::KillMode;
use crate::proxy::codec::JsonRpcCodec;
use crate::proxy::handler::{evaluate_jsonrpc, ProxyAction, ProxyState};

pub async fn run_stdio_bridge(
    state: Arc<ProxyState>,
    mut command: Command,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Configure stdio for the child process
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::inherit());

    let mut child = command.spawn()?;

    let child_stdin = child.stdin.take().expect("Failed to open stdin");
    let child_stdout = child.stdout.take().expect("Failed to open stdout");

    // We use FramedRead/Write to parse JSON objects from the streams
    let mut upstream_reader = FramedRead::new(child_stdout, JsonRpcCodec);
    let mut upstream_writer = FramedWrite::new(child_stdin, JsonRpcCodec);

    // Also wrap our own stdin/stdout to communicate with the local agent
    let agent_stdin = tokio::io::stdin();
    let agent_stdout = tokio::io::stdout();

    let mut agent_reader = FramedRead::new(agent_stdin, JsonRpcCodec);
    let mut agent_writer = FramedWrite::new(agent_stdout, JsonRpcCodec);

    loop {
        tokio::select! {
            // Read from Agent (client)
            msg = agent_reader.next() => {
                match msg {
                    Some(Ok(json)) => {
                        let action = evaluate_jsonrpc(&state, &json, None).await;
                        match action {
                            ProxyAction::Forward => {
                                if let Err(e) = upstream_writer.send(json).await {
                                    eprintln!("Error sending to upstream: {}", e);
                                    break;
                                }
                            }
                            ProxyAction::Respond(resp) => {
                                if let Err(e) = agent_writer.send(resp).await {
                                    eprintln!("Error sending to agent: {}", e);
                                    break;
                                }
                            }
                            ProxyAction::KillAndRespond(resp) => {
                                let _ = agent_writer.send(resp).await;
                                if state.kill_mode == KillMode::Process || state.kill_mode == KillMode::Both {
                                    eprintln!("Violation: Killing process and exiting.");
                                    let _ = child.kill().await;
                                    break;
                                }
                            }
                        }
                    }
                    Some(Err(e)) => {
                        eprintln!("Error reading from agent: {}", e);
                        break;
                    }
                    None => {
                        eprintln!("Agent EOF: Closing session.");
                        break;
                    }
                }
            }

            // Read from Upstream (MCP Server)
            msg = upstream_reader.next() => {
                match msg {
                    Some(Ok(json)) => {
                        // Transparently forward upstream responses to the agent
                        // In the future, we could evaluate server-to-client notifications here
                        if let Err(e) = agent_writer.send(json).await {
                            eprintln!("Error sending to agent: {}", e);
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        eprintln!("Error reading from upstream: {}", e);
                        break;
                    }
                    None => {
                        eprintln!("Upstream EOF: Server process likely exited.");
                        break;
                    }
                }
            }

            // Subprocess exited
            status = child.wait() => {
                match status {
                    Ok(s) => eprintln!("Child process exited with status: {}", s),
                    Err(e) => eprintln!("Error waiting for child: {}", e),
                }
                break;
            }
        }
    }

    // Ensure child is dead
    let _ = child.kill().await;

    Ok(())
}
