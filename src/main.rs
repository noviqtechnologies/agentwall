//! VEXA AgentWall — main entry point

use vexa::audit;
use vexa::check;
use vexa::cli;
use vexa::kill;
use vexa::policy;
use vexa::proxy;
use vexa::report;
use vexa::{log_error, log_info, log_warn};

use clap::Parser;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::watch;

use audit::logger::AuditLogger;
use cli::{Cli, Commands};
use kill::KillMode;
use policy::loader::{load_policy, PolicyLoadResult};
use proxy::handler::ProxyState;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Commands::Start {
            policy,
            listen,
            log_path,
            mcp_url,
            agent_pid,
            agent_pid_file,
            kill_mode,
            dry_run,
            rate_limit,
            log_max_bytes,
            report_path,
        } => {
            run_start(
                policy,
                listen,
                log_path,
                mcp_url,
                agent_pid,
                agent_pid_file,
                kill_mode,
                dry_run,
                rate_limit,
                log_max_bytes,
                report_path,
            )
            .await
        }
        Commands::Check {
            policy,
            fixture,
            dry_run,
        } => check::run_check(Path::new(&policy), Path::new(&fixture), dry_run),
        Commands::VerifyLog { log_path } => run_verify_log(&log_path),
        Commands::Report {
            log_path,
            output,
            format,
            report_include_params,
        } => run_report(&log_path, output.as_deref(), &format, report_include_params),
    };

    std::process::exit(exit_code);
}

async fn run_start(
    policy_path: Option<String>,
    listen: String,
    log_path: String,
    mcp_url: String,
    agent_pid: Option<u32>,
    agent_pid_file: Option<String>,
    kill_mode_str: String,
    dry_run: bool,
    rate_limit: Option<u32>,
    log_max_bytes: u64,
    report_path: Option<String>,
) -> i32 {
    // Parse kill mode
    let kill_mode = match KillMode::from_str(&kill_mode_str) {
        Ok(m) => m,
        Err(e) => {
            log_error!("startup_error", "reason": e);
            return 1;
        }
    };

    // Resolve agent PID
    let resolved_pid =
        agent_pid.or_else(|| agent_pid_file.as_ref().and_then(|f| kill::read_pid_file(f)));

    // NFR-203: Startup self-check
    // 1. Load policy
    let (compiled_policy, policy_hash, _warnings) = match policy_path.as_deref() {
        Some(path) => match load_policy(Path::new(path)) {
            PolicyLoadResult::Loaded {
                policy,
                raw_hash,
                warnings,
            } => (Some(policy), raw_hash, warnings),
            PolicyLoadResult::Degraded { reason } => {
                log_warn!("policy_degraded", "reason": reason);
                (None, "sha256:none".to_string(), vec![])
            }
            PolicyLoadResult::Fatal { error } => {
                log_error!("startup_error", "reason": error.to_string());
                return 1;
            }
        },
        None => {
            log_warn!("policy_degraded", "reason": "No policy file specified");
            (None, "sha256:none".to_string(), vec![])
        }
    };

    // 2. Check log path writable
    let mut log_dir = Path::new(&log_path).parent().unwrap_or(Path::new("."));
    if log_dir.as_os_str().is_empty() {
        log_dir = Path::new(".");
    }
    if !log_dir.exists() {
        log_error!("startup_error", "reason": format!("Log directory does not exist: {}", log_dir.display()));
        return 1;
    }
    // Write test byte
    let test_path = log_dir.join(".vexa_write_test");
    match std::fs::write(&test_path, b"t") {
        Ok(_) => {
            let _ = std::fs::remove_file(&test_path);
        }
        Err(e) => {
            log_error!("startup_error", "reason": format!("Log path not writable: {}", e));
            return 1;
        }
    }

    // 3. Parse listen address
    let listen_addr: SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(e) => {
            log_error!("startup_error", "reason": format!("Invalid listen address: {}", e));
            return 1;
        }
    };

    // Generate session secret (never written to disk)
    let session_secret: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let session_id = uuid::Uuid::new_v4().to_string();

    // Create audit logger
    let audit_logger = match AuditLogger::new(
        std::path::PathBuf::from(&log_path),
        session_id.clone(),
        session_secret,
        log_max_bytes,
    ) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            log_error!("startup_error", "reason": format!("Cannot create audit logger: {}", e));
            return 1;
        }
    };

    // Dry-run security event
    if dry_run {
        let msg = "SECURITY: dry-run mode is active. Policy violations will NOT be enforced. Do not use in production.";
        log_warn!("dry_run_active",
            "session": &session_id,
            "message": msg
        );
        let _ = audit_logger.write_entry(
            "dry_run_active",
            "system",
            None,
            Some(msg.to_string()),
            None,
        );
    }

    // Build proxy state
    let object_param_tools = compiled_policy
        .as_ref()
        .map(|p| p.object_param_tool_names())
        .unwrap_or_default();

    let rate_limit_val = rate_limit.unwrap_or_else(|| {
        compiled_policy
            .as_ref()
            .map(|p| p.max_calls_per_second)
            .unwrap_or(0)
    });

    let state = Arc::new(ProxyState {
        policy: compiled_policy,
        audit_logger: audit_logger.clone(),
        session_id: session_id.clone(),
        kill_mode: kill_mode.clone(),
        agent_pid: resolved_pid,
        upstream_url: mcp_url,
        dry_run,
        rate_limiter: proxy::handler::RateLimiter::new(rate_limit_val),
        http_client: reqwest::Client::new(),
        ready: true,
    });

    // Emit proxy_start event
    log_info!("proxy_start",
        "listen": &listen,
        "policy_hash": &policy_hash,
        "kill_mode": kill_mode.as_str(),
        "dry_run": dry_run
    );

    // Shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Handle SIGTERM (Unix) / Ctrl+C
    let shutdown_tx_clone = shutdown_tx.clone();
    let session_id_clone = session_id.clone();
    let report_path_clone = report_path.clone();
    let log_path_clone = log_path.clone();
    let policy_hash_clone = policy_hash.clone();
    let kill_mode_clone = kill_mode.clone();
    let object_param_tools_clone = object_param_tools.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();

        // Graceful shutdown
        let total = audit_logger.entry_count();
        log_info!("proxy_shutdown",
            "session": &session_id_clone,
            "total_calls": total,
            "allow_count": 0,
            "deny_count": 0
        );

        // Write session report if path specified
        if let Some(rp) = &report_path_clone {
            if let Ok(report) = report::generate_report(
                Path::new(&log_path_clone),
                false,
                &policy_hash_clone,
                kill_mode_clone.as_str(),
                dry_run,
                object_param_tools_clone,
            ) {
                if let Ok(json) = serde_json::to_string_pretty(&report) {
                    let _ = std::fs::write(rp, json);
                }
            }
        }

        let _ = shutdown_tx_clone.send(true);
    });

    // Run the server
    if let Err(e) = proxy::server::run_server(state, listen_addr, shutdown_rx).await {
        log_error!("server_error", "reason": e.to_string());
        return 1;
    }

    0
}

fn run_verify_log(log_path: &str) -> i32 {
    match audit::verifier::verify_chain(Path::new(log_path)) {
        audit::verifier::VerifyResult::Valid { entry_count } => {
            println!("OK: {} entries, chain intact", entry_count);
            0
        }
        audit::verifier::VerifyResult::Invalid {
            entry_index,
            reason,
        } => {
            println!(
                "INVALID: chain broken at entry_index {}: {}",
                entry_index, reason
            );
            1
        }
        audit::verifier::VerifyResult::Error(e) => {
            eprintln!("ERROR: {}", e);
            2
        }
    }
}

fn run_report(log_path: &str, output: Option<&str>, format: &str, include_params: bool) -> i32 {
    match report::generate_report(
        Path::new(log_path),
        include_params,
        "sha256:unknown",
        "unknown",
        false,
        vec![],
    ) {
        Ok(report) => {
            let out_str = if format == "text" {
                report::format_text_report(&report)
            } else {
                serde_json::to_string_pretty(&report).unwrap()
            };
            match output {
                Some(path) => {
                    if let Err(e) = std::fs::write(path, &out_str) {
                        eprintln!("ERROR: Cannot write report: {}", e);
                        return 2;
                    }
                }
                None => println!("{}", out_str),
            }
            0
        }
        Err(e) => {
            eprintln!("ERROR: {}", e);
            2
        }
    }
}
