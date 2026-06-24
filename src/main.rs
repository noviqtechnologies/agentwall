//! AgentWall — main entry point
#![allow(deprecated)]

use agentwall::audit;
use agentwall::check;
use agentwall::cli;
use agentwall::init;
use agentwall::kill;
use agentwall::policy;
use agentwall::promote;
use agentwall::proxy;
use agentwall::report;
use agentwall::identity; // FR-22
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
    
    let suppress_banner = matches!(
        &cli.command,
        Commands::Report { .. }
            | Commands::Test { .. }
            | Commands::Wrap { .. }
            | Commands::StdioProxy { .. }
    );

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
            target,
        } => {
            if let Some(target) = target {
                agentwall::wrap::run_wrap_target(&target)
            } else {
                run_wrap(
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
                .await
            }
        }
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
            siem_backend,
            siem_endpoint,
            siem_token,
            siem_timeout_secs,
            include_params,
            shadow_mode,
            strict_credential_scope,
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
                siem_backend,
                siem_endpoint,
                siem_token,
                siem_timeout_secs,
                include_params,
                shadow_mode,
                strict_credential_scope,
            )
            .await
        }
        Commands::Test {
            policy,
            fixture,
            dry_run,
            gateway,
            oidc_token,
        } => check::run_check(
            Path::new(&policy),
            Path::new(&fixture),
            dry_run,
            gateway.as_deref(),
            oidc_token.as_deref(),
        ),
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
        Commands::Init { target } => init::run_init(&target),
        // FR-22: Identity subcommand dispatch
        Commands::Identity { command } => match command {
            cli::IdentityCommands::Create { agent, scope, ttl, rotation_policy } => {
                identity::run_identity(identity::IdentityCommand::Create {
                    agent, scope, ttl, rotation_policy
                })
            }
            cli::IdentityCommands::Rotate { agent, drain_secs } => {
                identity::run_identity(identity::IdentityCommand::Rotate { agent, drain_secs })
            }
            cli::IdentityCommands::Audit { agent, verify } => {
                identity::run_identity(identity::IdentityCommand::Audit { agent, verify })
            }
            cli::IdentityCommands::Scope { agent, tool, allow, deny, policy } => {
                let is_allow = allow || !deny; // default to allow if not explicitly denied
                identity::run_identity(identity::IdentityCommand::Scope {
                    agent, tool, allow: is_allow, policy_path: policy
                })
            }
            cli::IdentityCommands::Inspect { credential } => {
                identity::run_identity(identity::IdentityCommand::Inspect { credential_id: credential })
            }
        },
        Commands::Unwrap { target } => agentwall::wrap::run_unwrap_target(&target),
        Commands::StdioProxy { args, scan_responses, block_on_secrets, max_scan_bytes } => {
            run_stdio_proxy(args, scan_responses, block_on_secrets, max_scan_bytes).await
        }
        Commands::Dev {
            listen,
            mcp_url,
            stdio,
            no_browser,
            enforce,
            args,
        } => {
            run_dev(listen, mcp_url, stdio, no_browser, enforce, args).await
        }
        Commands::GeneratePolicy { output, decay_window } => {
            run_generate_policy(output, decay_window).await
        }
        Commands::Validate { policy, tool, payload } => {
            match agentwall::validate::execute(&policy, &tool, &payload) {
                Ok(_) => 0,
                Err(e) => {
                    eprintln!("{}", e);
                    1
                }
            }
        }

        Commands::Lint { policy } => {
            match agentwall::lint::execute(&policy) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("Lint failed: {}", e);
                    1
                }
            }
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

#[allow(deprecated)]
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

    let audit_logger = match AuditLogger::new(agentwall::audit::logger::AuditLoggerConfig {
        log_path,
        session_id: session_id.clone(),
        session_secret,
        max_bytes: 104857600, // 100MB
        siem_exporter: None,
        include_params: false,
    }) {
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

    let db_manager = Arc::new(agentwall::proxy::db::DbManager::init());

    let state = Arc::new(ProxyState {
        policy: std::sync::RwLock::new(None), // Safe Mode only for Claude wrap
        audit_logger,
        session_id,
        kill_mode: KillMode::Process,
        agent_pid: None,
        upstream_url: "".to_string(),
        dry_run: false,
        shadow_mode: false,
        policy_loaded: std::sync::atomic::AtomicBool::new(false),
        rate_limiter: proxy::handler::RateLimiter::new(0),
        http_client: reqwest::Client::new(),
        safe_mode_scanner,
        ready: true,
        db_manager,
        response_scanner,
        response_scan_config: std::sync::RwLock::new(response_scan_config),
        dlp_scanner: std::sync::Arc::new(crate::policy::dlp::DlpScanner::new(None).expect("Failed to compile DLP regexes")),
        semantic_scanner: std::sync::Arc::new(crate::policy::semantic::SemanticScanner::new(crate::policy::semantic::SemanticConfig::default())),
        injection_scanner: std::sync::Arc::new(crate::policy::injection::InjectionScanner::new().expect("Failed to compile Injection regexes")),
        tool_history: std::sync::Mutex::new(Vec::new()),
        sessions: dashmap::DashMap::new(),
        metrics_requests_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_allow_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_deny_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_rate_limited_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_firewall_cycle_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_siem_export_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_siem_export_failed_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        event_tx: tokio::sync::broadcast::channel(1024).0, // Fix 6: enlarged buffer to reduce event drops
        credential_scope_validator: Arc::new(policy::credential_scope::CredentialScopeValidator::new(false)),
        policy_path: None,
        gateway_start_time: std::time::Instant::now(),
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

#[allow(deprecated, clippy::too_many_arguments)]
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
    siem_backend: String,
    siem_endpoint: String,
    siem_token: String,
    siem_timeout_secs: u64,
    include_params: bool,
    shadow_mode: bool,
    strict_credential_scope: bool,
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

    let siem_backend_parsed = agentwall::audit::siem::SiemBackend::from_str(&siem_backend);
    let siem_exporter = if siem_backend_parsed == agentwall::audit::siem::SiemBackend::Local {
        None
    } else {
        Some(agentwall::audit::siem::SiemExporter::new(
            siem_backend_parsed,
            siem_endpoint,
            siem_token,
            siem_timeout_secs,
        ))
    };

    // Create audit logger
    let audit_logger = match AuditLogger::new(agentwall::audit::logger::AuditLoggerConfig {
        log_path: std::path::PathBuf::from(&log_path),
        session_id: session_id.clone(),
        session_secret,
        max_bytes: log_max_bytes,
        siem_exporter,
        include_params,
    }) {
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

    let db_manager = Arc::new(agentwall::proxy::db::DbManager::init());

    let credential_scope_validator = Arc::new(
        policy::credential_scope::CredentialScopeValidator::new(strict_credential_scope)
    );

    // Log credential scope mode at startup
    agentwall::logging::log_event(
        agentwall::logging::Level::Info,
        "credential_scope_mode",
        serde_json::json!({
            "strict": strict_credential_scope,
            "note": "FR-22 Identity Platform integration pending — stub validator active"
        }),
    );

    let state = Arc::new(ProxyState {
        policy: std::sync::RwLock::new(compiled_policy),
        audit_logger: audit_logger.clone(),
        session_id: session_id.clone(),
        kill_mode: kill_mode.clone(),
        agent_pid: resolved_pid,
        upstream_url: mcp_url,
        dry_run,
        shadow_mode,
        policy_loaded: std::sync::atomic::AtomicBool::new(policy_loaded),
        rate_limiter: proxy::handler::RateLimiter::new(rate_limit_val),
        http_client: reqwest::Client::new(),
        safe_mode_scanner,
        ready: true,
        db_manager,
        response_scanner,
        response_scan_config: std::sync::RwLock::new(response_scan_config),
        dlp_scanner: std::sync::Arc::new(crate::policy::dlp::DlpScanner::new(None).expect("Failed to compile DLP regexes")),
        semantic_scanner: std::sync::Arc::new(crate::policy::semantic::SemanticScanner::new(crate::policy::semantic::SemanticConfig::default())),
        injection_scanner: std::sync::Arc::new(crate::policy::injection::InjectionScanner::new().expect("Failed to compile Injection regexes")),
        tool_history: std::sync::Mutex::new(Vec::new()),
        sessions: dashmap::DashMap::new(),
        metrics_requests_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_allow_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_deny_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_rate_limited_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_firewall_cycle_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_siem_export_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_siem_export_failed_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        event_tx: tokio::sync::broadcast::channel(1024).0,
        // FR-5 v2.0: Credential scope validator
        credential_scope_validator,
        policy_path: policy_path.clone(),
        gateway_start_time: std::time::Instant::now(),
    });

    if shadow_mode {
        println!(
            "{} {} {}",
            "👁".blue(),
            "Mode:".bold(),
            "SHADOW (Observation Only — no enforcement)".cyan().bold()
        );
        println!("{} {}", "ℹ".blue(), "All tool calls forwarded and logged. Enforcement is OFF.".blue());
    } else if dry_run {
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

#[allow(clippy::too_many_arguments)]
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
        println!("{} Auto-detecting known agent configurations...", "ℹ".blue());
        
        let targets = vec![
            crate::cli::WrapTarget::Claude { dry_run, scan_responses, block_on_secrets },
            crate::cli::WrapTarget::Cursor { dry_run },
            crate::cli::WrapTarget::Vscode { dry_run },
            crate::cli::WrapTarget::Jetbrains { dry_run },
            crate::cli::WrapTarget::Zed { dry_run },
            crate::cli::WrapTarget::Cline { dry_run },
            crate::cli::WrapTarget::Opencode { dry_run },
            crate::cli::WrapTarget::Antigravity { dry_run },
        ];

        let mut wrapped_any = false;
        for target in targets {
            // run_wrap_target will print errors to stderr if config isn't found.
            // We temporarily suppress stderr? Or just let it print.
            // Actually, we can just call it. If it succeeds (returns 0), we set wrapped_any = true.
            if agentwall::wrap::run_wrap_target(&target) == 0 {
                wrapped_any = true;
            }
        }

        if wrapped_any {
            println!("{} Auto-detect wrap completed successfully.", "✓".green());
            return 0;
        } else {
            eprintln!("{} No supported agents found to wrap automatically.", "✖".red());
            return 1;
        }
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

    let audit_logger = match AuditLogger::new(agentwall::audit::logger::AuditLoggerConfig {
        log_path: std::path::PathBuf::from(&log_path),
        session_id: session_id.clone(),
        session_secret,
        max_bytes: 104857600, // 100MB
        siem_exporter: None,
        include_params: false,
    }) {
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

    let db_manager = Arc::new(agentwall::proxy::db::DbManager::init());

    let state = Arc::new(ProxyState {
        policy: std::sync::RwLock::new(compiled_policy),
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
        shadow_mode: false,
        policy_loaded: std::sync::atomic::AtomicBool::new(policy_loaded),
        rate_limiter: proxy::handler::RateLimiter::new(0),
        http_client: reqwest::Client::new(),
        safe_mode_scanner,
        ready: true,
        db_manager,
        response_scanner,
        response_scan_config: std::sync::RwLock::new(response_scan_config),
        dlp_scanner: std::sync::Arc::new(crate::policy::dlp::DlpScanner::new(None).expect("Failed to compile DLP regexes")),
        semantic_scanner: std::sync::Arc::new(crate::policy::semantic::SemanticScanner::new(crate::policy::semantic::SemanticConfig::default())),
        injection_scanner: std::sync::Arc::new(crate::policy::injection::InjectionScanner::new().expect("Failed to compile Injection regexes")),
        tool_history: std::sync::Mutex::new(Vec::new()),
        sessions: dashmap::DashMap::new(),
        metrics_requests_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_allow_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_deny_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_rate_limited_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_firewall_cycle_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_siem_export_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_siem_export_failed_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        event_tx: tokio::sync::broadcast::channel(1024).0, // Fix 6: enlarged buffer to reduce event drops
        credential_scope_validator: Arc::new(policy::credential_scope::CredentialScopeValidator::new(false)),
        policy_path: None,
        gateway_start_time: std::time::Instant::now(),
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

// FR-2: Shadow Mode (Dev) – observation only proxy (pass --enforce to activate blocking)
#[allow(deprecated)]
async fn run_dev(
    listen: String,
    mcp_url: String,
    stdio: bool,
    no_browser: bool,
    enforce: bool,
    args: Vec<String>,
) -> i32 {
    // Generate session secret and ID
    let session_secret: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let session_id = uuid::Uuid::new_v4().to_string();

    // Resolve log path (same as stdio proxy)
    let bin_path = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("agentwall.exe"));
    let log_path = bin_path.parent().unwrap_or(std::path::Path::new(".")).join("audit.log");

    let audit_logger = match AuditLogger::new(agentwall::audit::logger::AuditLoggerConfig {
        log_path,
        session_id: session_id.clone(),
        session_secret,
        max_bytes: 104857600,
        siem_exporter: None,
        include_params: false,
    }) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            eprintln!("{} Cannot create audit logger: {}", "✖".red(), e);
            return 1;
        }
    };

    let safe_mode_scanner = Arc::new(SafeModeScanner::new().expect("Failed to compile SafeMode regexes"));
    let response_scanner = Arc::new(policy::response_scanner::ResponseScanner::new().expect("Failed to compile ResponseScanner regexes"));

    let response_scan_config = policy::response_scanner::ResponseScanConfig {
        enabled: false,
        block_mode: false,
        dry_run: false,
        max_scan_bytes: 1048576,
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

    let db_manager = Arc::new(agentwall::proxy::db::DbManager::init());

    let state = Arc::new(ProxyState {
        policy: std::sync::RwLock::new(None),
        audit_logger,
        session_id,
        kill_mode: KillMode::Process,
        agent_pid: None,
        upstream_url: mcp_url,
        dry_run: false,
        // When --enforce is passed, shadow_mode is false → injection/DLP scanners block.
        // Default (no --enforce) keeps the original observation-only behaviour.
        shadow_mode: !enforce,
        policy_loaded: std::sync::atomic::AtomicBool::new(false),
        rate_limiter: proxy::handler::RateLimiter::new(0),
        http_client: reqwest::Client::new(),
        safe_mode_scanner,
        ready: true,
        db_manager,
        response_scanner,
        response_scan_config: std::sync::RwLock::new(response_scan_config),
        dlp_scanner: std::sync::Arc::new(crate::policy::dlp::DlpScanner::new(None).expect("Failed to compile DLP regexes")),
        semantic_scanner: std::sync::Arc::new(crate::policy::semantic::SemanticScanner::new(crate::policy::semantic::SemanticConfig::default())),
        injection_scanner: std::sync::Arc::new(crate::policy::injection::InjectionScanner::new().expect("Failed to compile Injection regexes")),
        tool_history: std::sync::Mutex::new(Vec::new()),
        sessions: dashmap::DashMap::new(),
        metrics_requests_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_allow_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_deny_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_rate_limited_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_firewall_cycle_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_siem_export_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        metrics_siem_export_failed_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        event_tx: tokio::sync::broadcast::channel(1024).0, // Fix 6: enlarged buffer to reduce event drops
        credential_scope_validator: Arc::new(policy::credential_scope::CredentialScopeValidator::new(false)),
        policy_path: None,
        gateway_start_time: std::time::Instant::now(),
    });

    if stdio {
        if !args.is_empty() {
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
        } else {
            if let Err(e) = proxy::stdio::run_stdio_to_http_bridge(state).await {
                eprintln!("{} Stdio bridge error: {}", "✖".red(), e);
                return 1;
            }
        }
        return 0;
    }

    // Parse listen address
    let listen_addr: SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{} Invalid listen address: {}", "✖".red(), e);
            return 1;
        }
    };

    println!(
        "{} {} {}",
        "👁".blue(),
        "Mode:".bold(),
        "SHADOW (Observation Only — no enforcement)".cyan().bold()
    );
    println!("{} {}", "ℹ".blue(), "All tool calls forwarded and logged. Enforcement is OFF.".blue());
    println!(
        "{} {} {}",
        "📡".blue(),
        "Listening on:".bold(),
        listen.green().underline()
    );
    println!("{} Press Ctrl+C to stop", "⌨".blue());
    println!("{}", "-".repeat(60).cyan());

    if !no_browser {
        let url = format!("http://{}", listen_addr);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            #[cfg(target_os = "windows")]
            let _ = std::process::Command::new("cmd").args(["/C", "start", &url]).spawn();
            #[cfg(target_os = "macos")]
            let _ = std::process::Command::new("open").arg(&url).spawn();
            #[cfg(target_os = "linux")]
            let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
        });
    }

    // Shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        println!("\n{} Shutdown signal received. Finishing logs...", "ℹ".blue());
        let _ = shutdown_tx_clone.send(true);
    });

    if let Err(e) = proxy::server::run_server(state, listen_addr, shutdown_rx).await {
        eprintln!("{} Server error: {}", "✖".red(), e);
        return 1;
    }
    0
}

// ─── FR-4: agentwall generate-policy ──────────────────────────────────────────

/// Run the auto-policy generator (FR-4).
///
/// Reads up to 500 events from the local SQLite event store (chronological order),
/// runs the analysis engine, and writes the resulting YAML to `output_path`.
async fn run_generate_policy(output_path: String, decay_window: u32) -> i32 {
    println!("{} Reading observed tool calls from event store...", "ℹ".blue());

    let db = agentwall::proxy::db::DbManager::init();
    let events = match db.get_all_events(500).await {
        Ok(evs) => evs,
        Err(e) => {
            eprintln!("{} Failed to read events: {}", "✖".red(), e);
            return 1;
        }
    };

    if events.is_empty() {
        println!(
            "{} No tool calls observed yet.",
            "⚠".yellow()
        );
        println!(
            "{} Start shadow mode first: {}",
            "ℹ".blue(),
            "agentwall dev".cyan()
        );
        return 1;
    }

    println!(
        "{} Analysing {} events across {} unique tools...",
        "ℹ".blue(),
        events.len().to_string().cyan(),
        events
            .iter()
            .filter_map(|e| e.url_path.as_deref())
            .collect::<std::collections::HashSet<_>>()
            .len()
            .to_string()
            .cyan()
    );

    let yaml = agentwall::generate_policy::generate_from_events(&events, decay_window);

    match std::fs::write(&output_path, &yaml) {
        Ok(_) => {
            println!(
                "{} Policy written to {}",
                "✓".green().bold(),
                output_path.cyan().underline()
            );
            println!(
                "{} Next steps:",
                "ℹ".blue()
            );
            println!("    1. Review {} carefully — check anomalies section.", output_path.cyan());
            println!("    2. Run {} to validate.", "agentwall lint agentwall-policy.yaml".yellow());
            println!("    3. Submit to your platform/security team for gateway deployment.");
            0
        }
        Err(e) => {
            eprintln!("{} Failed to write {}: {}", "✖".red(), output_path, e);
            1
        }
    }
}


