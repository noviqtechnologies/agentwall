//! AgentWall — main entry point

use agentwall::audit;
use agentwall::check;
use agentwall::cli;
use agentwall::init;
use agentwall::kill;
use agentwall::policy;
use agentwall::promote;
use agentwall::proxy;
use agentwall::report;
use agentwall::wrap;
use agentwall::{log_error, log_warn};

use colored::*;

use clap::Parser;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::watch;

use audit::logger::AuditLogger;
use cli::{Cli, Commands};
use kill::KillMode;
use policy::loader::{load_policy, PolicyLoadResult};
use policy::safe_mode::SafeModeScanner;
use proxy::handler::ProxyState;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    
    // Suppress banner for commands that output machine-readable formats (FR-204)
    let suppress_banner = match &cli.command {
        Commands::Report { .. } => true,
        Commands::Test { .. } => true,
        Commands::Wrap { .. } => true,
        Commands::StdioProxy { .. } => true,
        _ => false,
    };

    if !suppress_banner {
        print_banner();
    }

    let exit_code = match cli.command {
        Commands::Wrap {
            command,
            auto_detect,
            policy,
            dry_run,
            kill_mode,
            log_path,
            balanced: _,
            strict: _,
            scan_responses,
            block_on_secrets,
            max_scan_bytes,
        } => run_wrap(
            command,
            auto_detect,
            policy,
            dry_run,
            kill_mode,
            log_path,
            scan_responses,
            block_on_secrets,
            max_scan_bytes,
        )
        .await,
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
            oidc_issuer,
            report_path,
            balanced: _,
            strict: _,
            scan_responses,
            block_on_secrets,
            max_scan_bytes,
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
                oidc_issuer,
                report_path,
                scan_responses,
                block_on_secrets,
                max_scan_bytes,
            )
            .await
        }
        Commands::Test {
            policy,
            fixture,
            dry_run,
        } => check::run_check(Path::new(&policy), Path::new(&fixture), dry_run),
        Commands::Promote { policy, key } => {
            promote::run_promote(&policy, key.as_deref())
        }
        Commands::VerifyLog { log_path } => run_verify_log(&log_path),
        Commands::Report {
            log_path,
            output,
            format,
            report_include_params,
        } => run_report(&log_path, output.as_deref(), &format, report_include_params),
        Commands::Init { from_log, output } => init::run_init(&from_log, &output),
        Commands::WrapClaude { dry_run, scan_responses, block_on_secrets: _ } => {
            run_wrap_claude(dry_run, scan_responses)
        }
        Commands::UnwrapClaude { force } => {
            run_unwrap_claude(force)
        }
        Commands::StdioProxy { args, scan_responses, block_on_secrets, max_scan_bytes } => {
            run_stdio_proxy(args, scan_responses, block_on_secrets, max_scan_bytes).await
        }
    };

    std::process::exit(exit_code);
}

fn print_banner() {
    println!("{}", "=".repeat(60).cyan());
    println!(
        "{} {}",
        " VEXA AgentWall ".bold().white().on_cyan(),
        "MCP Security Proxy".cyan()
    );
    println!("{}", "=".repeat(60).cyan());
}

async fn run_stdio_proxy(
    args: Vec<String>,
    scan_responses: bool,
    block_on_secrets: bool,
    max_scan_bytes: usize,
) -> i32 {
    if args.is_empty() {
        eprintln!("{} No command provided to stdio-proxy.", "✖".red());
        return 1;
    }

    let session_secret: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let session_id = uuid::Uuid::new_v4().to_string();

    // Resolve log path relative to binary (ensures writability when run from Claude)
    let bin_path = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("agentwall.exe"));
    let log_path = bin_path.parent().unwrap_or(std::path::Path::new(".")).join("audit.log");

    let audit_logger = match AuditLogger::new(
        log_path,
        session_id.clone(),
        session_secret,
        104857600, // 100MB
    ) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            eprintln!("{} Cannot create audit logger: {}", "✖".red(), e);
            return 1;
        }
    };

    let safe_mode_scanner = Arc::new(SafeModeScanner::new().expect("Failed to compile SafeMode regexes"));
    let response_scanner = Arc::new(policy::response_scanner::ResponseScanner::new().expect("Failed to compile ResponseScanner regexes"));
    
    let response_scan_config = policy::response_scanner::ResponseScanConfig {
        enabled: scan_responses,
        block_mode: block_on_secrets,
        dry_run: false,
        max_scan_bytes,
        scannable_tools: vec![
            "read_file".to_string(), "exec_command".to_string(), "run_shell".to_string(), 
            "run_command".to_string(), "http_get".to_string(), "http_post".to_string(), 
            "list_files".to_string(), "database_query".to_string(),
            "bash".to_string(), "execute".to_string(), "terminal".to_string(), 
            "read".to_string(), "cat".to_string(), "shell".to_string(), 
            "leak_secret".to_string(), "secret".to_string()
        ],
        safe_tools: vec![
            "tools/list".to_string(), "get_schema".to_string(), "get_metadata".to_string(), "ping".to_string(),
            "calculator".to_string(), "weather".to_string(), "datetime".to_string(), "search".to_string(), "grep".to_string()
        ],
    };

    let state = Arc::new(ProxyState {
        policy: None, // Safe Mode only for Claude wrap
        audit_logger,
        session_id,
        kill_mode: KillMode::Process,
        agent_pid: None,
        upstream_url: "".to_string(),
        dry_run: false,
        policy_loaded: false,
        rate_limiter: proxy::handler::RateLimiter::new(0),
        http_client: reqwest::Client::new(),
        safe_mode_scanner,
        ready: true,
        response_scanner,
        response_scan_config,
    });

    let mut parts = args.clone();
    let program = parts.remove(0);
    let (resolved_program, prefix_args) = proxy::stdio::resolve_command(&program);
    
    let mut final_args = prefix_args;
    final_args.extend(parts);

    let mut cmd = tokio::process::Command::new(resolved_program);
    cmd.args(final_args);

    if let Err(e) = proxy::stdio::run_stdio_bridge(state, cmd).await {
        eprintln!("{} Stdio proxy error: {}", "✖".red(), e);
        return 1;
    }

    0
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
    oidc_issuer: Option<String>,
    _report_path: Option<String>,
    scan_responses: bool,
    block_on_secrets: bool,
    max_scan_bytes: usize,
) -> i32 {
    println!("{} Loading configuration...", "ℹ".blue());

    // Parse kill mode
    let kill_mode = match KillMode::from_str(&kill_mode_str) {
        Ok(m) => m,
        Err(e) => {
            log_error!("startup_error", "reason": e);
            eprintln!("{} Invalid kill mode: {}", "✖".red(), e);
            return 1;
        }
    };

    // Resolve agent PID
    let resolved_pid =
        agent_pid.or_else(|| agent_pid_file.as_ref().and_then(|f| kill::read_pid_file(f)));

    // NFR-203: Startup self-check
    // 1. Load policy
    let (compiled_policy, _policy_hash, _warnings, policy_loaded) = match policy_path.as_deref() {
        Some(path) => {
            print!("{} Loading policy from {}... ", "ℹ".blue(), path.yellow());
            match load_policy(Path::new(path), oidc_issuer) {
                PolicyLoadResult::Loaded {
                    policy,
                    raw_hash,
                    warnings,
                } => {
                    println!("{}", "OK".green().bold());
                    (Some(policy), raw_hash, warnings, true)
                }
                PolicyLoadResult::Degraded { reason } => {
                    println!("{}", "DEGRADED".yellow().bold());
                    log_warn!("policy_degraded", "reason": reason);
                    (None, "sha256:none".to_string(), vec![], false)
                }
                PolicyLoadResult::Fatal { error } => {
                    println!("{}", "FAILED".red().bold());
                    log_error!("startup_error", "reason": error.to_string());
                    return 1;
                }
            }
        }
        None => {
            println!(
                "{} {}",
                "🛡".green(),
                "Safe Mode v1 enabled (Audit mode recommended). Blocking high-risk secrets & exfil.".green()
            );
            if !dry_run {
                println!("{} {}", "ℹ".blue(), "Run with --dry-run to preview.".blue());
            }
            (None, "sha256:none".to_string(), vec![], false)
        }
    };

    // 2. Check log path writable
    let mut log_dir = Path::new(&log_path).parent().unwrap_or(Path::new("."));
    if log_dir.as_os_str().is_empty() {
        log_dir = Path::new(".");
    }
    if !log_dir.exists() {
        eprintln!(
            "{} Log directory does not exist: {}",
            "✖".red(),
            log_dir.display()
        );
        return 1;
    }

    // 3. Parse listen address
    let listen_addr: SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{} Invalid listen address: {}", "✖".red(), e);
            return 1;
        }
    };

    // Generate session secret
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
            eprintln!("{} Cannot create audit logger: {}", "✖".red(), e);
            return 1;
        }
    };

    println!("{} Proxy session initialized: {}", "✓".green(), session_id.cyan());

    // Build proxy state
    let rate_limit_val = rate_limit.unwrap_or_else(|| {
        compiled_policy
            .as_ref()
            .map(|p| p.max_calls_per_second)
            .unwrap_or(0)
    });

    let safe_mode_scanner = Arc::new(SafeModeScanner::new().expect("Failed to compile SafeMode regexes"));
    println!(
        "{} Safe Mode v1 active — {} rules loaded. Run with {} to preview.",
        "✔".green(),
        safe_mode_scanner.rule_count.to_string().cyan(),
        "--dry-run".yellow()
    );
    
    // FR-303b: Initialize response scanner
    let response_scanner = Arc::new(policy::response_scanner::ResponseScanner::new().expect("Failed to compile ResponseScanner regexes"));
    
    let (sc_tools, sf_tools) = if let Some(p) = &compiled_policy {
        (p.scannable_tools.clone(), p.safe_tools.clone())
    } else {
        (
            vec![
                "read_file".to_string(), "exec_command".to_string(), "run_shell".to_string(), 
                "run_command".to_string(), "http_get".to_string(), "http_post".to_string(), 
                "list_files".to_string(), "database_query".to_string(),
                "bash".to_string(), "execute".to_string(), "terminal".to_string(), 
                "read".to_string(), "cat".to_string(), "shell".to_string(), 
                "leak_secret".to_string(), "secret".to_string()
            ],
            vec![
                "tools/list".to_string(), "get_schema".to_string(), "get_metadata".to_string(), "ping".to_string(),
                "calculator".to_string(), "weather".to_string(), "datetime".to_string(), "search".to_string(), "grep".to_string()
            ]
        )
    };

    let response_scan_config = policy::response_scanner::ResponseScanConfig {
        enabled: scan_responses,
        block_mode: block_on_secrets,
        dry_run,
        max_scan_bytes,
        scannable_tools: sc_tools,
        safe_tools: sf_tools,
    };

    let state = Arc::new(ProxyState {
        policy: compiled_policy,
        audit_logger: audit_logger.clone(),
        session_id: session_id.clone(),
        kill_mode: kill_mode.clone(),
        agent_pid: resolved_pid,
        upstream_url: mcp_url,
        dry_run,
        policy_loaded,
        rate_limiter: proxy::handler::RateLimiter::new(rate_limit_val),
        http_client: reqwest::Client::new(),
        safe_mode_scanner,
        ready: true,
        response_scanner,
        response_scan_config,
    });

    if dry_run {
        println!(
            "{} {} {}",
            "🛡".blue(),
            "Mode:".bold(),
            "DRY-RUN (Logging Only)".yellow().bold()
        );
    } else {
        println!(
            "{} {} {}",
            "🛡".blue(),
            "Mode:".bold(),
            "ENFORCEMENT (Active Blocking)".green().bold()
        );
    }

    println!(
        "{} {} {}",
        "📡".blue(),
        "Listening on:".bold(),
        listen.green().underline()
    );
    println!("{} Press Ctrl+C to stop", "⌨".blue());
    println!("{}", "-".repeat(60).cyan());

    // Shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Handle SIGTERM (Unix) / Ctrl+C
    let shutdown_tx_clone = shutdown_tx.clone();
    let _audit_logger_clone = audit_logger.clone();
    
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        println!("\n{} Shutdown signal received. Finishing logs...", "ℹ".blue());
        let _ = shutdown_tx_clone.send(true);
    });

    // Run the server
    if let Err(e) = proxy::server::run_server(state, listen_addr, shutdown_rx).await {
        eprintln!("{} Server error: {}", "✖".red(), e);
        return 1;
    }

    println!("{} Proxy stopped gracefully.", "✓".green());
    0
}

fn run_verify_log(log_path: &str) -> i32 {
    print!("{} Verifying log integrity for {}... ", "ℹ".blue(), log_path.yellow());
    match audit::verifier::verify_chain(Path::new(log_path)) {
        audit::verifier::VerifyResult::Valid { entry_count } => {
            println!("{}", "VALID".green().bold());
            println!("  {} {} entries found, cryptographic chain intact.", "✓".green(), entry_count);
            0
        }
        audit::verifier::VerifyResult::Invalid {
            entry_index,
            reason,
        } => {
            println!("{}", "INVALID".red().bold());
            println!("  {} Chain broken at index {}: {}", "✖".red(), entry_index, reason);
            1
        }
        audit::verifier::VerifyResult::Error(e) => {
            println!("{}", "ERROR".red().bold());
            eprintln!("  {} {}", "✖".red(), e);
            2
        }
    }
}

fn run_report(log_path: &str, output: Option<&str>, format: &str, include_params: bool) -> i32 {
    match report::generate_report(
        Path::new(log_path),
        include_params,
        "sha256:unknown",
        true,
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
                        eprintln!("{} Cannot write report: {}", "✖".red(), e);
                        return 2;
                    }
                    println!("{} Report saved to {}", "✓".green(), path.cyan());
                }
                None => println!("{}", out_str),
            }
            0
        }
        Err(e) => {
            eprintln!("{} {}", "✖".red(), e);
            2
        }
    }
}

async fn run_wrap(
    command: Option<String>,
    auto_detect: bool,
    policy_path: Option<String>,
    dry_run: bool,
    kill_mode: String,
    log_path: String,
    scan_responses: bool,
    block_on_secrets: bool,
    max_scan_bytes: usize,
) -> i32 {
    if auto_detect {
        println!("{} Auto-detect is not fully implemented yet (FR-301).", "ℹ".blue());
        println!("Please use --command explicitly for now.");
        return 1;
    }

    let cmd_str = match command {
        Some(c) => c,
        None => {
            eprintln!("{} You must provide a --command or use --auto-detect.", "✖".red());
            return 1;
        }
    };

    // Load policy
    let (compiled_policy, _policy_hash, _warnings, policy_loaded) = match policy_path.as_deref() {
        Some(path) => {
            match load_policy(Path::new(path), None) {
                PolicyLoadResult::Loaded { policy, raw_hash, warnings, .. } => {
                    (Some(policy), raw_hash, warnings, true)
                }
                PolicyLoadResult::Degraded { reason } => {
                    log_warn!("policy_degraded", "reason": reason);
                    (None, "sha256:none".to_string(), vec![], false)
                }
                PolicyLoadResult::Fatal { error } => {
                    log_error!("startup_error", "reason": error.to_string());
                    return 1;
                }
            }
        }
        None => {
            println!(
                "{} {}",
                "🛡".green(),
                "Safe Mode v1 enabled (Audit mode recommended). Blocking high-risk secrets & exfil.".green()
            );
            if !dry_run {
                println!("{} {}", "ℹ".blue(), "Run with --dry-run to preview.".blue());
            }
            (None, "sha256:none".to_string(), vec![], false)
        }
    };

    let session_secret: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let session_id = uuid::Uuid::new_v4().to_string();

    let audit_logger = match AuditLogger::new(
        std::path::PathBuf::from(&log_path),
        session_id.clone(),
        session_secret,
        104857600, // 100MB
    ) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            eprintln!("{} Cannot create audit logger: {}", "✖".red(), e);
            return 1;
        }
    };

    let safe_mode_scanner = Arc::new(SafeModeScanner::new().expect("Failed to compile SafeMode regexes"));
    eprintln!(
        "{} Safe Mode v1 active — {} rules loaded.",
        "✔".green(),
        safe_mode_scanner.rule_count.to_string().cyan()
    );

    // FR-303b: Initialize response scanner
    let response_scanner = Arc::new(policy::response_scanner::ResponseScanner::new().expect("Failed to compile ResponseScanner regexes"));
    
    let (sc_tools, sf_tools) = if let Some(p) = &compiled_policy {
        (p.scannable_tools.clone(), p.safe_tools.clone())
    } else {
        (
            vec![
                "read_file".to_string(), "exec_command".to_string(), "run_shell".to_string(), 
                "run_command".to_string(), "http_get".to_string(), "http_post".to_string(), 
                "list_files".to_string(), "database_query".to_string(),
                "bash".to_string(), "execute".to_string(), "terminal".to_string(), 
                "read".to_string(), "cat".to_string(), "shell".to_string(), 
                "leak_secret".to_string(), "secret".to_string()
            ],
            vec![
                "tools/list".to_string(), "get_schema".to_string(), "get_metadata".to_string(), "ping".to_string(),
                "calculator".to_string(), "weather".to_string(), "datetime".to_string(), "search".to_string(), "grep".to_string()
            ]
        )
    };

    let response_scan_config = policy::response_scanner::ResponseScanConfig {
        enabled: scan_responses,
        block_mode: block_on_secrets,
        dry_run,
        max_scan_bytes,
        scannable_tools: sc_tools,
        safe_tools: sf_tools,
    };

    let state = Arc::new(ProxyState {
        policy: compiled_policy,
        audit_logger,
        session_id,
        kill_mode: match kill_mode.as_str() {
            "connection" => KillMode::Connection,
            "process" => KillMode::Process,
            "both" => KillMode::Both,
            _ => KillMode::Process,
        },
        agent_pid: None,
        upstream_url: "".to_string(), // Not used in stdio proxy
        dry_run,
        policy_loaded,
        rate_limiter: proxy::handler::RateLimiter::new(0),
        http_client: reqwest::Client::new(),
        safe_mode_scanner,
        ready: true,
        response_scanner,
        response_scan_config,
    });

    // Parse the command string
    let mut parts = match shlex::split(&cmd_str) {
        Some(p) => p,
        None => {
            eprintln!("{} Failed to parse command string.", "✖".red());
            return 1;
        }
    };
    if parts.is_empty() {
        eprintln!("{} Empty command provided.", "✖".red());
        return 1;
    }

    let program = parts.remove(0);
    let (resolved_program, prefix_args) = proxy::stdio::resolve_command(&program);
    let mut cmd = tokio::process::Command::new(resolved_program);
    
    let mut final_args = prefix_args;
    final_args.extend(parts);
    cmd.args(final_args);

    if let Err(e) = proxy::stdio::run_stdio_bridge(state, cmd).await {
        eprintln!("{} Stdio proxy error: {}", "✖".red(), e);
        return 1;
    }

    0
}

// ─── FR-304: agentwall wrap-claude / unwrap-claude ──────────────────────────

fn run_wrap_claude(dry_run: bool, scan_responses: bool) -> i32 {
    if dry_run {
        println!("{} {} {}", "🔍".blue(), "Mode:".bold(), "DRY-RUN (no writes)".yellow().bold());
    } else {
        println!("{} Wrapping Claude Desktop...", "ℹ".blue());
    }

    match wrap::claude::wrap_claude(dry_run, scan_responses) {
        Ok(result) => {
            if !dry_run {
                wrap::claude::print_wrap_summary(&result);
            }
            0
        }
        Err(wrap::WrapError::AlreadyWrapped) => {
            println!(
                "{} {}",
                "ℹ".blue(),
                "Already wrapped. Run 'agentwall unwrap-claude' first if you want to re-wrap."
            );
            0 // Not an error — idempotent
        }
        Err(wrap::WrapError::NoMcpServers) => {
            println!(
                "{} No MCP servers found in Claude Desktop config. Nothing to wrap.",
                "⚠".yellow()
            );
            0
        }
        Err(e) => {
            eprintln!("{} {}", "✖".red(), e);
            1
        }
    }
}

fn run_unwrap_claude(force: bool) -> i32 {
    println!("{} Restoring Claude Desktop config...", "ℹ".blue());

    match wrap::claude::unwrap_claude(force) {
        Ok(result) => {
            wrap::claude::print_unwrap_summary(&result);
            0
        }
        Err(wrap::WrapError::NoBackupFound) if force => {
            // Instructions already printed inside unwrap_claude
            1
        }
        Err(e) => {
            eprintln!("{} {}", "✖".red(), e);
            1
        }
    }
}
