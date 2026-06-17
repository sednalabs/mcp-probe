use mcp_probe::admission::{
    evaluate_startup_admission, load_startup_admission_config, AdmissionEvaluation,
    AdmissionOutcome, StartupAdmissionConfig,
};
use mcp_probe::cli::run_cli;
use mcp_probe::provenance::{
    capture_runtime_provenance, RuntimeAdmissionExtension, RuntimeProvenance,
};
use mcp_probe::server::create_server;
use rmcp::serve_server;
use rmcp::transport::stdio;
use std::env;
use std::fs::{create_dir_all, OpenOptions};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;

const STARTUP_TRACE_ENV: &str = "MCP_PROBE_STARTUP_TRACE";
const STDIO_LOG_PATH_ENV: &str = "MCP_PROBE_STDIO_LOG_PATH";
const DEFAULT_STDIO_LOG: &str = "/tmp/mcp-probe.log";

fn resolve_stdio_log_path(stdin_is_tty: bool) -> Option<PathBuf> {
    if let Ok(path) = env::var(STDIO_LOG_PATH_ENV) {
        if path.trim().is_empty() {
            return None;
        }
        return Some(PathBuf::from(path));
    }
    if stdin_is_tty {
        return None;
    }
    Some(PathBuf::from(DEFAULT_STDIO_LOG))
}

fn write_diag(message: &str, stdin_is_tty: bool) {
    let Some(path) = resolve_stdio_log_path(stdin_is_tty) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = create_dir_all(parent);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = file.write_all(message.as_bytes());
    }
}

fn install_crash_handlers(stdin_is_tty: bool) {
    std::panic::set_hook(Box::new(move |info| {
        let message = if let Some(payload) = info.payload().downcast_ref::<&str>() {
            (*payload).to_string()
        } else if let Some(payload) = info.payload().downcast_ref::<String>() {
            payload.clone()
        } else {
            "panic".to_string()
        };
        let line = format!("[mcp-probe] panic {message}\n");
        eprint!("{line}");
        write_diag(&line, stdin_is_tty);
    }));
}

fn log_startup(args: &[String], stdin_is_tty: bool, provenance: &RuntimeProvenance) {
    if env::var(STARTUP_TRACE_ENV).is_err() && stdin_is_tty {
        return;
    }
    let payload = serde_json::json!({
        "argv": args,
        "stdin_is_tty": stdin_is_tty,
        "component": provenance.build.component,
        "server_version": provenance.build.server_version,
        "build_identity": provenance.build.build_identity,
        "source_fingerprint": provenance.build.source_fingerprint,
        "executable_path": provenance.process.executable_path,
    });
    let line = format!("[mcp-probe] startup {payload}\n");
    eprint!("{line}");
    write_diag(&line, stdin_is_tty);
}

fn runtime_admission_extension(
    config: &StartupAdmissionConfig,
    admission: &AdmissionEvaluation,
) -> RuntimeAdmissionExtension {
    RuntimeAdmissionExtension {
        enforcement_phase: config.mode.enforcement_phase().to_string(),
        required_gate_level: config.required_profile.label().to_string(),
        outcome: admission.outcome.as_str().to_string(),
        reason_code: admission.reason_code.clone(),
        override_active: admission.override_active,
    }
}

fn log_startup_admission(
    config: &StartupAdmissionConfig,
    admission: &AdmissionEvaluation,
    stdin_is_tty: bool,
) {
    let payload = serde_json::json!({
        "mode": config.mode.enforcement_phase(),
        "required_profile": config.required_profile.label(),
        "outcome": admission.outcome.as_str(),
        "reason_code": admission.reason_code.as_deref(),
        "detail": admission.detail.as_str(),
        "gate_path": admission.gate_path.display().to_string(),
        "override_active": admission.override_active,
        "production_mode": config.production_mode,
        "allow_production_bypass": config.allow_production_bypass,
    });
    let line = format!("[mcp-probe] startup_admission {payload}\n");
    let should_emit_stderr = !stdin_is_tty
        || env::var(STARTUP_TRACE_ENV).is_ok()
        || !matches!(admission.outcome, AdmissionOutcome::Passed);
    if should_emit_stderr {
        eprint!("{line}");
    }
    write_diag(&line, stdin_is_tty);
}

fn log_exit(code: i32, stdin_is_tty: bool) {
    let line = format!("[mcp-probe] exit {code}\n");
    write_diag(&line, stdin_is_tty);
}

fn should_run_server(args: &[String], _stdin_is_tty: bool) -> bool {
    if args.is_empty() {
        return true;
    }
    let command = args[0].as_str();
    if command == "server" || command == "stdio" {
        return true;
    }
    if args.iter().any(|arg| arg == "--stdio") {
        return true;
    }
    false
}

#[tokio::main]
async fn main() {
    let stdin_is_tty = std::io::stdin().is_terminal();
    install_crash_handlers(stdin_is_tty);
    let args: Vec<String> = env::args().skip(1).collect();
    let executable_path = env::current_exe().unwrap_or_else(|_| PathBuf::from("unknown"));
    let runtime_provenance = capture_runtime_provenance(&executable_path);
    log_startup(&args, stdin_is_tty, &runtime_provenance);

    if should_run_server(&args, stdin_is_tty) {
        let admission_config = match load_startup_admission_config() {
            Ok(config) => config,
            Err(err) => {
                eprintln!("mcp-probe failed to load startup admission config: {err}");
                log_exit(1, stdin_is_tty);
                std::process::exit(1);
            }
        };
        let admission =
            evaluate_startup_admission(&admission_config, &executable_path, &runtime_provenance);
        log_startup_admission(&admission_config, &admission, stdin_is_tty);
        if matches!(admission.outcome, AdmissionOutcome::Rejected) {
            let reason = admission.reason_code.as_deref().unwrap_or("unknown");
            eprintln!(
                "mcp-probe startup admission rejected ({reason}): {}",
                admission.detail
            );
            log_exit(1, stdin_is_tty);
            std::process::exit(1);
        }
        let runtime_admission = runtime_admission_extension(&admission_config, &admission);

        let server = match create_server(runtime_provenance.clone(), runtime_admission) {
            Ok(server) => server,
            Err(err) => {
                eprintln!("mcp-probe failed to start: {}", err);
                log_exit(1, stdin_is_tty);
                std::process::exit(1);
            }
        };
        let transport = stdio();
        let service = match serve_server(server, transport).await {
            Ok(service) => service,
            Err(err) => {
                eprintln!("mcp-probe failed to start: {}", err);
                log_exit(1, stdin_is_tty);
                std::process::exit(1);
            }
        };
        if let Err(err) = service.waiting().await {
            eprintln!("mcp-probe server terminated unexpectedly: {}", err);
            log_exit(1, stdin_is_tty);
            std::process::exit(1);
        }
        log_exit(0, stdin_is_tty);
        return;
    }

    let exit_code = run_cli(args).await;
    log_exit(exit_code, stdin_is_tty);
    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::should_run_server;

    #[test]
    fn explicit_http_smoke_command_stays_in_cli_mode_without_tty() {
        assert!(!should_run_server(&["http-smoke".to_string()], false));
    }

    #[test]
    fn no_args_defaults_to_server_mode() {
        assert!(should_run_server(&[], false));
    }

    #[test]
    fn explicit_server_mode_flags_are_respected() {
        assert!(should_run_server(&["server".to_string()], true));
        assert!(should_run_server(
            &["run".to_string(), "--stdio".to_string()],
            false
        ));
    }
}
