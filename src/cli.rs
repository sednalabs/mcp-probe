//! CLI entry points for the probe.

use crate::auth::{
    attach_access_token, attach_auth_header, read_access_token_from_path, run_oauth_flow,
    OAuthFlowOptions,
};
use crate::logging::{LogFormat, LogLevel};
use crate::probe::schema_compat::ToolDescriptorProfile;
use crate::probe::{
    build_prompt_render_params, run_http_smoke, run_probe, run_raw_request, ExpectError,
    HttpSmokeTarget, ProbeTarget, RawRequestTarget,
};
use crate::report::{
    apply_report_verbosity, now_iso, CatalogContract, CatalogProfile, ProbeReport, ProbeStep,
    ProbeStepStatus, RawRequestReport, ReportVerbosity,
};
use crate::scenario::runner::run_script_scenario;
use crate::scenario::types::ScriptScenario;
use crate::transport::TransportType;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;

const USAGE: &str = r#"Usage:
  mcp-probe run --transport stdio --command <cmd> [--arg <arg>...]
  mcp-probe run --transport sse --url <url> [--header "k:v"]
  mcp-probe run --transport streamable-http --url <url> [--header "k:v"]
  mcp-probe http-smoke --url <url> [--expect-auth-required] [--expect-registration-endpoint]
  mcp-probe prompt-render --prompt <name> [--prompt-arg <k=json>] --transport <transport> [target options]
  mcp-probe run --script <path> [--snapshot-write]
  mcp-probe auth --server <url> [options]
  mcp-probe server

Options:
  --transport <stdio|sse|streamable-http>
  --command <cmd>           Required for stdio transport.
  --arg <value>             Repeatable argument for stdio command.
  --url <url>               Required for sse/streamable-http.
  --header <k:v>            Repeatable header for HTTP transports.
  --pretty                  Pretty-print JSON output.
  --json                    Emit compact JSON output (default).
  --out <path>              Write the report to a file.
  --include-raw             Include raw responses in the output report.
  --timeout-ms <value>      Timeout per step (default: 10000).
  --retries <count>         Retry count for transient failures (default: 0).
  --retry-delay-ms <value>  Delay between retries (default: 250).
  --expect-auth-required    Fail unless an auth challenge is detected.
  --expect-registration-endpoint
                           Fail unless OAuth metadata advertises registration_endpoint.
  --use-auth                Attach cached OAuth token to HTTP requests.
  --access-token-path <path> Read access token from a file (raw token or JSON with access_token).
  --config <path>           Load target settings from a JSON file.
  --profile <name>          Select a named profile from the config file.
  --log-level <value>       Enable structured logs (debug|info|warn|error).
  --log-format <value>      Log format (json|logfmt).
  --trace                   Capture JSON-RPC wire trace (redacted).
  --trace-limit <value>     Max trace entries (default: 200).
  --trace-max-bytes <value> Max bytes per trace message (default: 4096).
  --descriptor-profile <value>
                           Tool descriptor audit profile (basic|chatgpt_tool|apps_sdk_ui).
  --catalog-profile <value>
                           Host catalog profile (raw_mcp|chatgpt_tool|apps_sdk_ui|codex_deferred|claude_code|gemini_cli).
  --catalog-contract <path>
                           Read a JSON catalog contract and compare it with live discovery.
  --prompt <name>           Prompt name for prompt-render.
  --prompt-arg <k=json>     Repeatable prompt-render argument.
  --arguments-json <json>   Prompt-render arguments object.
  --expect-error            Expect prompt-render to fail.
  --expect-error-contains <text>
                           Expect prompt-render to fail with matching error text.
  --verbosity <value>       Output verbosity (summary|full).
  --cwd <path>              Working directory for stdio commands.
  --env <k=v>               Repeatable env override for stdio commands.
  --script <path>           Run a scripted scenario from a JSON file.
  --snapshot-write          Update snapshot files during script runs.
  --help                    Show this help text.

Note:
  stdio probes are disabled by default. Set MCP_PROBE_ALLOW_STDIO=1 to enable.

Auth options:
  --server <url>            MCP server URL for auth flow.
  --scope <value>           Override OAuth scope (space-separated).
  --client-id <value>       Pre-registered OAuth client ID.
  --client-secret <value>   Pre-registered OAuth client secret.
  --allow-dcr               Allow dynamic client registration if no client ID.
  --redirect-host <value>   Redirect callback host (default: 127.0.0.1).
  --redirect-port <value>   Redirect callback port (default: 3333).
  --open                    Open browser automatically.
"#;

#[derive(Debug)]
struct ParseError {
    error: String,
    help: bool,
}

#[derive(Debug, Default, Clone)]
struct ProbeTargetOverrides {
    transport_type: Option<TransportType>,
    command: Option<String>,
    args: Option<Vec<String>>,
    cwd: Option<String>,
    env: Option<HashMap<String, String>>,
    url: Option<String>,
    headers: Option<HashMap<String, String>>,
    timeout_ms: Option<u64>,
    retries: Option<u32>,
    retry_delay_ms: Option<u64>,
    expect_auth_required: Option<bool>,
    log_level: Option<LogLevel>,
    log_format: Option<LogFormat>,
    trace: Option<bool>,
    trace_limit: Option<usize>,
    trace_max_bytes: Option<usize>,
    descriptor_profile: Option<ToolDescriptorProfile>,
    catalog_profile: Option<CatalogProfile>,
    catalog_contract: Option<CatalogContract>,
    catalog_contract_path: Option<String>,
}

#[derive(Debug)]
struct ParsedArgs {
    overrides: ProbeTargetOverrides,
    pretty: bool,
    out_path: Option<String>,
    include_raw: bool,
    verbosity: Option<ReportVerbosity>,
    config_path: Option<String>,
    profile: Option<String>,
    use_auth: Option<bool>,
    access_token_path: Option<String>,
    script_path: Option<String>,
    snapshot_write: bool,
}

#[derive(Debug)]
struct HttpSmokeArgs {
    url: String,
    pretty: bool,
    out_path: Option<String>,
    timeout_ms: Option<u64>,
    expect_auth_required: Option<bool>,
    expect_registration_endpoint: Option<bool>,
}

#[derive(Debug)]
struct PromptRenderArgs {
    target: ParsedArgs,
    prompt_name: String,
    arguments: Option<HashMap<String, serde_json::Value>>,
    expect_error: Option<ExpectError>,
}

#[derive(Debug)]
struct AuthArgs {
    server_url: String,
    scope: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    allow_dcr: bool,
    expect_registration_endpoint: bool,
    redirect_host: String,
    redirect_port: u16,
    open_browser: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
struct ProbeTargetConfig {
    transport: Option<TransportType>,
    command: Option<String>,
    args: Option<Vec<String>>,
    cwd: Option<String>,
    env: Option<HashMap<String, String>>,
    url: Option<String>,
    headers: Option<HashMap<String, String>>,
    timeout_ms: Option<u64>,
    retries: Option<u32>,
    retry_delay_ms: Option<u64>,
    expect_auth_required: Option<bool>,
    log_level: Option<LogLevel>,
    log_format: Option<LogFormat>,
    trace: Option<bool>,
    trace_limit: Option<usize>,
    trace_max_bytes: Option<usize>,
    descriptor_profile: Option<ToolDescriptorProfile>,
    catalog_profile: Option<CatalogProfile>,
    catalog_contract: Option<CatalogContract>,
    catalog_contract_path: Option<String>,
    use_auth: Option<bool>,
    access_token_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProbeConfigFile {
    profiles: Option<HashMap<String, ProbeTargetConfig>>,
    target: Option<ProbeTargetConfig>,
    #[serde(flatten)]
    direct: ProbeTargetConfig,
}

fn map_config_to_overrides(config: &ProbeTargetConfig) -> ProbeTargetOverrides {
    ProbeTargetOverrides {
        transport_type: config.transport,
        command: config.command.clone(),
        args: config.args.clone(),
        cwd: config.cwd.clone(),
        env: config.env.clone(),
        url: config.url.clone(),
        headers: config.headers.clone(),
        timeout_ms: config.timeout_ms,
        retries: config.retries,
        retry_delay_ms: config.retry_delay_ms,
        expect_auth_required: config.expect_auth_required,
        log_level: config.log_level,
        log_format: config.log_format,
        trace: config.trace,
        trace_limit: config.trace_limit,
        trace_max_bytes: config.trace_max_bytes,
        descriptor_profile: config.descriptor_profile,
        catalog_profile: config.catalog_profile,
        catalog_contract: config.catalog_contract.clone(),
        catalog_contract_path: config.catalog_contract_path.clone(),
    }
}

fn config_has_target_fields(config: &ProbeTargetConfig) -> bool {
    config.transport.is_some() || config.command.is_some() || config.url.is_some()
}

async fn resolve_target(
    overrides: ProbeTargetOverrides,
    config_path: Option<&str>,
    profile: Option<&str>,
    use_auth_override: Option<bool>,
    access_token_path_override: Option<&str>,
) -> Result<(ProbeTarget, bool, Option<String>)> {
    let mut base = ProbeTargetOverrides::default();
    let mut base_use_auth: Option<bool> = None;
    let mut base_access_token_path: Option<String> = None;

    if let Some(config_path) = config_path {
        let raw = tokio::fs::read_to_string(config_path).await?;
        let parsed: ProbeConfigFile = serde_json::from_str(&raw)?;
        if let Some(profile) = profile {
            let profiles = parsed.profiles.unwrap_or_default();
            let profile_config = profiles
                .get(profile)
                .ok_or_else(|| anyhow::anyhow!("Profile {profile} not found in {config_path}"))?;
            base = map_config_to_overrides(profile_config);
            base_use_auth = profile_config.use_auth;
            base_access_token_path = profile_config.access_token_path.clone();
        } else if parsed.target.is_some() || config_has_target_fields(&parsed.direct) {
            let config = parsed.target.as_ref().unwrap_or(&parsed.direct);
            base = map_config_to_overrides(config);
            base_use_auth = config.use_auth;
            base_access_token_path = config.access_token_path.clone();
        } else {
            return Err(anyhow::anyhow!(
                "No target configuration found in {config_path}"
            ));
        }
    }

    let merged_headers = merge_maps(base.headers.clone(), overrides.headers.clone());
    let merged_env = merge_maps(base.env.clone(), overrides.env.clone());

    let transport_type = overrides
        .transport_type
        .or(base.transport_type)
        .ok_or_else(|| anyhow::anyhow!("Missing transport configuration."))?;

    let catalog_contract = resolve_catalog_contract(
        overrides.catalog_contract.clone(),
        overrides.catalog_contract_path.clone(),
        base.catalog_contract.clone(),
        base.catalog_contract_path.clone(),
    )
    .await?;

    let target = ProbeTarget {
        transport_type,
        command: overrides.command.or(base.command),
        args: overrides.args.or(base.args),
        cwd: overrides.cwd.or(base.cwd),
        env: if merged_env.is_empty() {
            None
        } else {
            Some(merged_env)
        },
        url: overrides.url.or(base.url),
        headers: if merged_headers.is_empty() {
            None
        } else {
            Some(merged_headers)
        },
        timeout_ms: overrides.timeout_ms.or(base.timeout_ms),
        retries: overrides.retries.or(base.retries),
        retry_delay_ms: overrides.retry_delay_ms.or(base.retry_delay_ms),
        expect_auth_required: overrides.expect_auth_required.or(base.expect_auth_required),
        log_level: overrides.log_level.or(base.log_level),
        log_format: overrides.log_format.or(base.log_format),
        trace: overrides.trace.or(base.trace),
        trace_limit: overrides.trace_limit.or(base.trace_limit),
        trace_max_bytes: overrides.trace_max_bytes.or(base.trace_max_bytes),
        descriptor_profile: overrides.descriptor_profile.or(base.descriptor_profile),
        catalog_profile: overrides.catalog_profile.or(base.catalog_profile),
        catalog_contract,
    };

    validate_target(&target)?;

    let use_auth = use_auth_override.or(base_use_auth).unwrap_or(false);
    let access_token_path = access_token_path_override
        .map(|value| value.to_string())
        .or(base_access_token_path);

    Ok((target, use_auth, access_token_path))
}

fn merge_maps(
    base: Option<HashMap<String, String>>,
    overrides: Option<HashMap<String, String>>,
) -> HashMap<String, String> {
    let mut merged = base.unwrap_or_default();
    if let Some(overrides) = overrides {
        merged.extend(overrides);
    }
    merged
}

async fn resolve_catalog_contract(
    override_contract: Option<CatalogContract>,
    override_path: Option<String>,
    base_contract: Option<CatalogContract>,
    base_path: Option<String>,
) -> Result<Option<CatalogContract>> {
    if let Some(path) = override_path.or(base_path) {
        let raw = tokio::fs::read_to_string(&path)
            .await
            .map_err(|err| anyhow::anyhow!("Failed to read catalog contract {path}: {err}"))?;
        let contract = serde_json::from_str(&raw)
            .map_err(|err| anyhow::anyhow!("Invalid catalog contract JSON in {path}: {err}"))?;
        return Ok(Some(contract));
    }
    Ok(override_contract.or(base_contract))
}

fn validate_target(target: &ProbeTarget) -> Result<()> {
    match target.transport_type {
        TransportType::Stdio => {
            if target.command.is_none() {
                return Err(anyhow::anyhow!("Missing command for stdio transport."));
            }
        }
        _ => {
            if target.url.is_none() {
                return Err(anyhow::anyhow!("Missing URL for HTTP transport."));
            }
        }
    }
    Ok(())
}

fn parse_auth_args(argv: &[String]) -> Result<AuthArgs, ParseError> {
    if argv.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Err(ParseError {
            error: "help requested".to_string(),
            help: true,
        });
    }

    let mut server_url: Option<String> = None;
    let mut scope: Option<String> = None;
    let mut client_id: Option<String> = None;
    let mut client_secret: Option<String> = None;
    let mut allow_dcr = false;
    let mut expect_registration_endpoint = false;
    let mut redirect_host = "127.0.0.1".to_string();
    let mut redirect_port: u16 = 3333;
    let mut open_browser = false;

    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--server" => {
                let value = argv.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --server".to_string(),
                    help: false,
                })?;
                server_url = Some(value);
                i += 1;
            }
            "--scope" => {
                let value = argv.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --scope".to_string(),
                    help: false,
                })?;
                scope = Some(value);
                i += 1;
            }
            "--client-id" => {
                let value = argv.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --client-id".to_string(),
                    help: false,
                })?;
                client_id = Some(value);
                i += 1;
            }
            "--client-secret" => {
                let value = argv.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --client-secret".to_string(),
                    help: false,
                })?;
                client_secret = Some(value);
                i += 1;
            }
            "--allow-dcr" => {
                allow_dcr = true;
            }
            "--expect-registration-endpoint" => {
                expect_registration_endpoint = true;
            }
            "--redirect-host" => {
                let value = argv.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --redirect-host".to_string(),
                    help: false,
                })?;
                redirect_host = value;
                i += 1;
            }
            "--redirect-port" => {
                let value = argv.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --redirect-port".to_string(),
                    help: false,
                })?;
                let parsed: u16 = value.parse().map_err(|_| ParseError {
                    error: "Invalid --redirect-port value".to_string(),
                    help: false,
                })?;
                redirect_port = parsed;
                i += 1;
            }
            "--open" => {
                open_browser = true;
            }
            other => {
                return Err(ParseError {
                    error: format!("Unknown auth argument: {other}"),
                    help: false,
                });
            }
        }
        i += 1;
    }

    let server_url = server_url.ok_or_else(|| ParseError {
        error: "Missing --server".to_string(),
        help: false,
    })?;

    Ok(AuthArgs {
        server_url,
        scope,
        client_id,
        client_secret,
        allow_dcr,
        expect_registration_endpoint,
        redirect_host,
        redirect_port,
        open_browser,
    })
}

fn parse_http_smoke_args(argv: &[String]) -> Result<HttpSmokeArgs, ParseError> {
    if argv.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Err(ParseError {
            error: "help requested".to_string(),
            help: true,
        });
    }

    let mut url: Option<String> = None;
    let mut pretty = false;
    let mut out_path: Option<String> = None;
    let mut timeout_ms: Option<u64> = None;
    let mut expect_auth_required: Option<bool> = None;
    let mut expect_registration_endpoint: Option<bool> = None;

    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--url" => {
                let value = argv.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --url".to_string(),
                    help: false,
                })?;
                url = Some(value);
                i += 1;
            }
            "--pretty" => {
                pretty = true;
            }
            "--json" => {
                pretty = false;
            }
            "--out" => {
                let value = argv.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --out".to_string(),
                    help: false,
                })?;
                out_path = Some(value);
                i += 1;
            }
            "--timeout-ms" => {
                let value = argv.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --timeout-ms".to_string(),
                    help: false,
                })?;
                let parsed: u64 = value.parse().map_err(|_| ParseError {
                    error: "Invalid --timeout-ms value".to_string(),
                    help: false,
                })?;
                timeout_ms = Some(parsed);
                i += 1;
            }
            "--expect-auth-required" => {
                expect_auth_required = Some(true);
            }
            "--expect-registration-endpoint" => {
                expect_registration_endpoint = Some(true);
            }
            other => {
                return Err(ParseError {
                    error: format!("Unknown http-smoke argument: {other}"),
                    help: false,
                });
            }
        }
        i += 1;
    }

    let url = url.ok_or_else(|| ParseError {
        error: "Missing --url".to_string(),
        help: false,
    })?;

    Ok(HttpSmokeArgs {
        url,
        pretty,
        out_path,
        timeout_ms,
        expect_auth_required,
        expect_registration_endpoint,
    })
}

fn parse_prompt_argument(raw: &str) -> Result<(String, serde_json::Value), ParseError> {
    let idx = raw.find('=').ok_or_else(|| ParseError {
        error: "Prompt argument must be in key=json form".to_string(),
        help: false,
    })?;
    if idx == 0 {
        return Err(ParseError {
            error: "Prompt argument key cannot be empty".to_string(),
            help: false,
        });
    }
    let key = raw[..idx].trim().to_string();
    if key.is_empty() {
        return Err(ParseError {
            error: "Prompt argument key cannot be empty".to_string(),
            help: false,
        });
    }
    let raw_value = raw[idx + 1..].trim();
    let value = serde_json::from_str(raw_value)
        .unwrap_or_else(|_| serde_json::Value::String(raw_value.to_string()));
    Ok((key, value))
}

fn merge_arguments_json(
    raw: &str,
    arguments: &mut HashMap<String, serde_json::Value>,
) -> Result<(), ParseError> {
    let parsed: serde_json::Value = serde_json::from_str(raw).map_err(|err| ParseError {
        error: format!("Invalid --arguments-json value: {err}"),
        help: false,
    })?;
    let serde_json::Value::Object(map) = parsed else {
        return Err(ParseError {
            error: "--arguments-json must be a JSON object".to_string(),
            help: false,
        });
    };
    arguments.extend(map);
    Ok(())
}

fn parse_prompt_render_args(argv: &[String]) -> Result<PromptRenderArgs, ParseError> {
    if argv.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Err(ParseError {
            error: "help requested".to_string(),
            help: true,
        });
    }

    let mut prompt_name: Option<String> = None;
    let mut arguments: HashMap<String, serde_json::Value> = HashMap::new();
    let mut expect_error: Option<ExpectError> = None;
    let mut target_args: Vec<String> = Vec::new();

    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--prompt" | "--prompt-name" => {
                let value = argv.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --prompt".to_string(),
                    help: false,
                })?;
                prompt_name = Some(value);
                i += 1;
            }
            "--prompt-arg" | "--argument" => {
                let value = argv.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --prompt-arg".to_string(),
                    help: false,
                })?;
                let (key, value) = parse_prompt_argument(&value)?;
                arguments.insert(key, value);
                i += 1;
            }
            "--arguments-json" => {
                let value = argv.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --arguments-json".to_string(),
                    help: false,
                })?;
                merge_arguments_json(&value, &mut arguments)?;
                i += 1;
            }
            "--expect-error" => {
                expect_error = Some(ExpectError::Bool(true));
            }
            "--expect-error-contains" => {
                let value = argv.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --expect-error-contains".to_string(),
                    help: false,
                })?;
                expect_error = Some(ExpectError::String(value));
                i += 1;
            }
            other => {
                target_args.push(other.to_string());
                if option_consumes_value(other) {
                    let value = argv.get(i + 1).cloned().ok_or_else(|| ParseError {
                        error: format!("Missing value for {other}"),
                        help: false,
                    })?;
                    target_args.push(value);
                    i += 1;
                }
            }
        }
        i += 1;
    }

    let prompt_name = prompt_name.ok_or_else(|| ParseError {
        error: "Missing --prompt".to_string(),
        help: false,
    })?;
    let target = parse_args(&target_args)?;
    if target.script_path.is_some() {
        return Err(ParseError {
            error: "prompt-render cannot be combined with --script".to_string(),
            help: false,
        });
    }
    Ok(PromptRenderArgs {
        target,
        prompt_name,
        arguments: if arguments.is_empty() {
            None
        } else {
            Some(arguments)
        },
        expect_error,
    })
}

fn option_consumes_value(option: &str) -> bool {
    matches!(
        option,
        "--transport"
            | "--command"
            | "--arg"
            | "--url"
            | "--header"
            | "--out"
            | "--timeout-ms"
            | "--retries"
            | "--retry-delay-ms"
            | "--access-token-path"
            | "--config"
            | "--profile"
            | "--log-level"
            | "--log-format"
            | "--trace-limit"
            | "--trace-max-bytes"
            | "--descriptor-profile"
            | "--catalog-profile"
            | "--catalog-contract"
            | "--verbosity"
            | "--cwd"
            | "--env"
            | "--script"
    )
}

fn parse_args(argv: &[String]) -> Result<ParsedArgs, ParseError> {
    if argv.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Err(ParseError {
            error: "help requested".to_string(),
            help: true,
        });
    }

    let mut args = argv.to_vec();
    if args.first().map(|v| v == "run").unwrap_or(false) {
        args.remove(0);
    }

    let mut transport: Option<TransportType> = None;
    let mut command: Option<String> = None;
    let mut cmd_args: Vec<String> = Vec::new();
    let mut url: Option<String> = None;
    let mut headers: HashMap<String, String> = HashMap::new();
    let mut pretty = false;
    let mut out_path: Option<String> = None;
    let mut include_raw = false;
    let mut timeout_ms: Option<u64> = None;
    let mut retries: Option<u32> = None;
    let mut retry_delay_ms: Option<u64> = None;
    let mut expect_auth_required: Option<bool> = None;
    let mut config_path: Option<String> = None;
    let mut profile: Option<String> = None;
    let mut log_level: Option<LogLevel> = None;
    let mut log_format: Option<LogFormat> = None;
    let mut trace: Option<bool> = None;
    let mut trace_limit: Option<usize> = None;
    let mut trace_max_bytes: Option<usize> = None;
    let mut descriptor_profile: Option<ToolDescriptorProfile> = None;
    let mut catalog_profile: Option<CatalogProfile> = None;
    let mut catalog_contract_path: Option<String> = None;
    let mut verbosity: Option<ReportVerbosity> = None;
    let mut cwd: Option<String> = None;
    let mut env: HashMap<String, String> = HashMap::new();
    let mut use_auth: Option<bool> = None;
    let mut access_token_path: Option<String> = None;
    let mut script_path: Option<String> = None;
    let mut snapshot_write = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--transport" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --transport".to_string(),
                    help: false,
                })?;
                transport = Some(value.parse().map_err(|err: String| ParseError {
                    error: err,
                    help: false,
                })?);
                i += 1;
            }
            "--command" => {
                command = args.get(i + 1).cloned();
                i += 1;
            }
            "--arg" => {
                if let Some(value) = args.get(i + 1) {
                    cmd_args.push(value.to_string());
                }
                i += 1;
            }
            "--url" => {
                url = args.get(i + 1).cloned();
                i += 1;
            }
            "--header" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --header".to_string(),
                    help: false,
                })?;
                let idx = value.find(':').ok_or_else(|| ParseError {
                    error: "Header must be in key:value form".to_string(),
                    help: false,
                })?;
                if idx == 0 {
                    return Err(ParseError {
                        error: "Header must be in key:value form".to_string(),
                        help: false,
                    });
                }
                let key = value[..idx].trim().to_string();
                let header_value = value[idx + 1..].trim().to_string();
                headers.insert(key, header_value);
                i += 1;
            }
            "--pretty" => {
                pretty = true;
            }
            "--json" => {
                pretty = false;
            }
            "--out" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --out".to_string(),
                    help: false,
                })?;
                out_path = Some(value);
                i += 1;
            }
            "--include-raw" => {
                include_raw = true;
            }
            "--timeout-ms" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --timeout-ms".to_string(),
                    help: false,
                })?;
                let parsed: u64 = value.parse().map_err(|_| ParseError {
                    error: "Invalid --timeout-ms value".to_string(),
                    help: false,
                })?;
                timeout_ms = Some(parsed);
                i += 1;
            }
            "--retries" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --retries".to_string(),
                    help: false,
                })?;
                let parsed: u32 = value.parse().map_err(|_| ParseError {
                    error: "Invalid --retries value".to_string(),
                    help: false,
                })?;
                retries = Some(parsed);
                i += 1;
            }
            "--retry-delay-ms" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --retry-delay-ms".to_string(),
                    help: false,
                })?;
                let parsed: u64 = value.parse().map_err(|_| ParseError {
                    error: "Invalid --retry-delay-ms value".to_string(),
                    help: false,
                })?;
                retry_delay_ms = Some(parsed);
                i += 1;
            }
            "--expect-auth-required" => {
                expect_auth_required = Some(true);
            }
            "--use-auth" => {
                use_auth = Some(true);
            }
            "--access-token-path" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --access-token-path".to_string(),
                    help: false,
                })?;
                access_token_path = Some(value);
                i += 1;
            }
            "--config" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --config".to_string(),
                    help: false,
                })?;
                config_path = Some(value);
                i += 1;
            }
            "--profile" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --profile".to_string(),
                    help: false,
                })?;
                profile = Some(value);
                i += 1;
            }
            "--log-level" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --log-level".to_string(),
                    help: false,
                })?;
                let level = LogLevel::parse(&value).ok_or_else(|| ParseError {
                    error: "Invalid --log-level value".to_string(),
                    help: false,
                })?;
                log_level = Some(level);
                i += 1;
            }
            "--log-format" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --log-format".to_string(),
                    help: false,
                })?;
                let format = LogFormat::parse(&value).ok_or_else(|| ParseError {
                    error: "Invalid --log-format value".to_string(),
                    help: false,
                })?;
                log_format = Some(format);
                i += 1;
            }
            "--trace" => {
                trace = Some(true);
            }
            "--trace-limit" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --trace-limit".to_string(),
                    help: false,
                })?;
                let parsed: usize = value.parse().map_err(|_| ParseError {
                    error: "Invalid --trace-limit value".to_string(),
                    help: false,
                })?;
                if parsed == 0 {
                    return Err(ParseError {
                        error: "Invalid --trace-limit value".to_string(),
                        help: false,
                    });
                }
                trace_limit = Some(parsed);
                i += 1;
            }
            "--trace-max-bytes" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --trace-max-bytes".to_string(),
                    help: false,
                })?;
                let parsed: usize = value.parse().map_err(|_| ParseError {
                    error: "Invalid --trace-max-bytes value".to_string(),
                    help: false,
                })?;
                if parsed == 0 {
                    return Err(ParseError {
                        error: "Invalid --trace-max-bytes value".to_string(),
                        help: false,
                    });
                }
                trace_max_bytes = Some(parsed);
                i += 1;
            }
            "--descriptor-profile" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --descriptor-profile".to_string(),
                    help: false,
                })?;
                descriptor_profile = Some(value.parse().map_err(|err: String| ParseError {
                    error: err,
                    help: false,
                })?);
                i += 1;
            }
            "--catalog-profile" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --catalog-profile".to_string(),
                    help: false,
                })?;
                catalog_profile = Some(value.parse().map_err(|err: String| ParseError {
                    error: err,
                    help: false,
                })?);
                i += 1;
            }
            "--catalog-contract" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --catalog-contract".to_string(),
                    help: false,
                })?;
                catalog_contract_path = Some(value);
                i += 1;
            }
            "--verbosity" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --verbosity".to_string(),
                    help: false,
                })?;
                let verbosity_value = match value.as_str() {
                    "summary" => ReportVerbosity::Summary,
                    "full" => ReportVerbosity::Full,
                    _ => {
                        return Err(ParseError {
                            error: "Invalid --verbosity value".to_string(),
                            help: false,
                        })
                    }
                };
                verbosity = Some(verbosity_value);
                i += 1;
            }
            "--cwd" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --cwd".to_string(),
                    help: false,
                })?;
                cwd = Some(value);
                i += 1;
            }
            "--env" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --env".to_string(),
                    help: false,
                })?;
                let idx = value.find('=').ok_or_else(|| ParseError {
                    error: "Env must be in key=value form".to_string(),
                    help: false,
                })?;
                if idx == 0 {
                    return Err(ParseError {
                        error: "Env key cannot be empty".to_string(),
                        help: false,
                    });
                }
                let key = value[..idx].trim().to_string();
                let env_value = value[idx + 1..].to_string();
                env.insert(key, env_value);
                i += 1;
            }
            "--script" => {
                let value = args.get(i + 1).cloned().ok_or_else(|| ParseError {
                    error: "Missing value for --script".to_string(),
                    help: false,
                })?;
                script_path = Some(value);
                i += 1;
            }
            "--snapshot-write" => {
                snapshot_write = true;
            }
            other => {
                return Err(ParseError {
                    error: format!("Unknown argument: {other}"),
                    help: false,
                });
            }
        }
        i += 1;
    }

    if let Some(script_path) = script_path.as_ref() {
        let has_conflicts = transport.is_some()
            || command.is_some()
            || url.is_some()
            || !cmd_args.is_empty()
            || !headers.is_empty()
            || config_path.is_some()
            || profile.is_some()
            || use_auth.is_some()
            || access_token_path.is_some()
            || trace.is_some()
            || trace_limit.is_some()
            || trace_max_bytes.is_some()
            || descriptor_profile.is_some()
            || catalog_profile.is_some()
            || catalog_contract_path.is_some()
            || verbosity.is_some()
            || cwd.is_some()
            || !env.is_empty();
        if has_conflicts {
            return Err(ParseError {
                error: "Do not mix --script with transport/command/url/header/cwd/env/config/profile/auth/trace/descriptor/catalog/contract/verbosity options.".to_string(),
                help: false,
            });
        }
        let overrides = ProbeTargetOverrides::default();
        return Ok(ParsedArgs {
            overrides,
            pretty,
            out_path,
            include_raw,
            verbosity,
            config_path,
            profile,
            use_auth,
            access_token_path,
            script_path: Some(script_path.clone()),
            snapshot_write,
        });
    }

    if transport.is_none() && config_path.is_none() {
        return Err(ParseError {
            error: "Missing --transport (or --config)".to_string(),
            help: false,
        });
    }

    let overrides = ProbeTargetOverrides {
        transport_type: transport,
        command,
        args: if cmd_args.is_empty() {
            None
        } else {
            Some(cmd_args)
        },
        cwd,
        env: if env.is_empty() { None } else { Some(env) },
        url,
        headers: if headers.is_empty() {
            None
        } else {
            Some(headers)
        },
        timeout_ms,
        retries,
        retry_delay_ms,
        expect_auth_required,
        log_level,
        log_format,
        trace,
        trace_limit,
        trace_max_bytes,
        descriptor_profile,
        catalog_profile,
        catalog_contract: None,
        catalog_contract_path,
    };

    Ok(ParsedArgs {
        overrides,
        pretty,
        out_path,
        include_raw,
        verbosity,
        config_path,
        profile,
        use_auth,
        access_token_path,
        script_path,
        snapshot_write,
    })
}

fn format_json<T: Serialize>(value: &T, pretty: bool) -> String {
    if pretty {
        serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string())
    } else {
        serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())
    }
}

fn strip_raw(mut report: ProbeReport, include_raw: bool) -> ProbeReport {
    if include_raw {
        return report;
    }
    report.auth = None;
    report.server_info = None;
    report.capabilities = None;
    report.tools = None;
    report.resources = None;
    report.resource_templates = None;
    report.prompts = None;
    if let Some(catalog) = report.catalog.as_mut() {
        catalog.server_info = None;
        catalog.capabilities = None;
        catalog.tools = None;
        catalog.resources = None;
        catalog.resource_templates = None;
        catalog.prompts = None;
    }
    report.trace = None;
    report
}

fn build_error_report(message: &str) -> ProbeReport {
    ProbeReport {
        ok: false,
        started_at: now_iso(),
        finished_at: now_iso(),
        steps: vec![ProbeStep {
            name: "cli".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some(message.to_string()),
            data: None,
        }],
        auth: None,
        server_info: None,
        capabilities: None,
        tools: None,
        resources: None,
        resource_templates: None,
        prompts: None,
        catalog: None,
        trace: None,
    }
}

fn strip_raw_request_report(
    mut report: RawRequestReport,
    include_raw: bool,
    verbosity: Option<ReportVerbosity>,
) -> RawRequestReport {
    if include_raw || matches!(verbosity, Some(ReportVerbosity::Full)) {
        return report;
    }
    report.auth = None;
    report.server_info = None;
    report.capabilities = None;
    report.trace = None;
    report
}

async fn apply_auth_header(target: &mut ProbeTarget) -> Result<()> {
    if target.transport_type == TransportType::Stdio {
        return Err(anyhow::anyhow!(
            "use-auth is only supported for HTTP transports."
        ));
    }
    let url = target
        .url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Missing target URL for auth header injection."))?;
    let headers = attach_auth_header(target.headers.clone(), url).await?;
    target.headers = Some(headers);
    Ok(())
}

fn raw_target_from_probe_target(
    target: ProbeTarget,
    method: String,
    params: Option<serde_json::Value>,
    expect_error: Option<ExpectError>,
) -> RawRequestTarget {
    RawRequestTarget {
        transport_type: target.transport_type,
        command: target.command,
        args: target.args,
        cwd: target.cwd,
        env: target.env,
        url: target.url,
        headers: target.headers,
        timeout_ms: target.timeout_ms,
        retries: target.retries,
        retry_delay_ms: target.retry_delay_ms,
        expect_auth_required: target.expect_auth_required,
        log_level: target.log_level,
        log_format: target.log_format,
        trace: target.trace,
        trace_limit: target.trace_limit,
        trace_max_bytes: target.trace_max_bytes,
        method,
        params,
        expect_error,
    }
}

pub async fn run_cli(argv: Vec<String>) -> i32 {
    if argv.first().map(|value| value == "auth").unwrap_or(false) {
        let args = &argv[1..];
        match parse_auth_args(args) {
            Ok(parsed) => {
                match run_oauth_flow(OAuthFlowOptions {
                    server_url: parsed.server_url,
                    scope: parsed.scope,
                    client_id: parsed.client_id,
                    client_secret: parsed.client_secret,
                    allow_dcr: parsed.allow_dcr,
                    expect_registration_endpoint: parsed.expect_registration_endpoint,
                    redirect_host: parsed.redirect_host,
                    redirect_port: parsed.redirect_port,
                    open_browser: parsed.open_browser,
                })
                .await
                {
                    Ok(tokens) => {
                        println!("OAuth tokens cached successfully.");
                        if let Some(expires_at) = tokens.expires_at {
                            let now = time::OffsetDateTime::now_utc().unix_timestamp();
                            let remaining = expires_at - now;
                            if remaining > 0 {
                                println!("Access token expires in {remaining} seconds.");
                            }
                        }
                        0
                    }
                    Err(err) => {
                        eprintln!("Auth failed: {}", err);
                        1
                    }
                }
            }
            Err(err) => {
                if err.help {
                    print!("{USAGE}");
                    0
                } else {
                    eprintln!("{}", err.error);
                    eprintln!("{USAGE}");
                    2
                }
            }
        }
    } else if argv
        .first()
        .map(|value| value == "http-smoke")
        .unwrap_or(false)
    {
        let args = &argv[1..];
        match parse_http_smoke_args(args) {
            Ok(parsed) => {
                let report = run_http_smoke(HttpSmokeTarget {
                    url: Some(parsed.url.clone()),
                    timeout_ms: parsed.timeout_ms,
                    expect_auth_required: parsed.expect_auth_required,
                    expect_registration_endpoint: parsed.expect_registration_endpoint,
                })
                .await;
                let output = format_json(&report, parsed.pretty);
                println!("{output}");
                if let Some(path) = parsed.out_path {
                    let _ = tokio::fs::write(path, format!("{output}\n")).await;
                }
                if report.ok {
                    0
                } else {
                    1
                }
            }
            Err(err) => {
                if err.help {
                    print!("{USAGE}");
                    0
                } else {
                    eprintln!("{}", err.error);
                    eprintln!("{USAGE}");
                    2
                }
            }
        }
    } else if argv
        .first()
        .map(|value| value == "prompt-render")
        .unwrap_or(false)
    {
        let args = &argv[1..];
        match parse_prompt_render_args(args) {
            Ok(parsed) => {
                let target_args = parsed.target;
                let resolved = resolve_target(
                    target_args.overrides.clone(),
                    target_args.config_path.as_deref(),
                    target_args.profile.as_deref(),
                    target_args.use_auth,
                    target_args.access_token_path.as_deref(),
                )
                .await;
                let (mut target, use_auth, access_token_path) = match resolved {
                    Ok(result) => result,
                    Err(err) => {
                        let report = build_error_report(&err.to_string());
                        let output = format_json(&strip_raw(report, true), true);
                        println!("{output}");
                        return 1;
                    }
                };

                if use_auth && access_token_path.is_some() {
                    let report = build_error_report(
                        "Specify only one auth source: use-auth or access-token-path.",
                    );
                    let output = format_json(&strip_raw(report, true), true);
                    println!("{output}");
                    return 1;
                }

                if let Some(path) = access_token_path {
                    if target.transport_type == TransportType::Stdio {
                        let report = build_error_report(
                            "access-token-path is only supported for HTTP transports.",
                        );
                        let output = format_json(&strip_raw(report, true), true);
                        println!("{output}");
                        return 1;
                    }
                    if target.url.is_none() {
                        let report =
                            build_error_report("Missing target URL for access-token-path.");
                        let output = format_json(&strip_raw(report, true), true);
                        println!("{output}");
                        return 1;
                    }
                    match read_access_token_from_path(&path).await {
                        Ok(token) => {
                            let headers = attach_access_token(target.headers.clone(), &token);
                            match headers {
                                Ok(headers) => target.headers = Some(headers),
                                Err(err) => {
                                    let report = build_error_report(&err.to_string());
                                    let output = format_json(&strip_raw(report, true), true);
                                    println!("{output}");
                                    return 1;
                                }
                            }
                        }
                        Err(err) => {
                            let report = build_error_report(&err.to_string());
                            let output = format_json(&strip_raw(report, true), true);
                            println!("{output}");
                            return 1;
                        }
                    }
                } else if use_auth {
                    if let Err(err) = apply_auth_header(&mut target).await {
                        let report = build_error_report(&err.to_string());
                        let output = format_json(&strip_raw(report, true), true);
                        println!("{output}");
                        return 1;
                    }
                }

                let report = run_raw_request(
                    raw_target_from_probe_target(
                        target,
                        "prompts/get".to_string(),
                        Some(build_prompt_render_params(
                            &parsed.prompt_name,
                            parsed.arguments,
                        )),
                        parsed.expect_error,
                    ),
                    None,
                    None,
                )
                .await;
                let output_report = strip_raw_request_report(
                    report.clone(),
                    target_args.include_raw,
                    target_args.verbosity,
                );
                let output = format_json(&output_report, target_args.pretty);
                println!("{output}");
                if let Some(path) = target_args.out_path {
                    let _ = tokio::fs::write(path, format!("{output}\n")).await;
                }
                if report.ok {
                    0
                } else {
                    1
                }
            }
            Err(err) => {
                if err.help {
                    print!("{USAGE}");
                    0
                } else {
                    eprintln!("{}", err.error);
                    eprintln!("{USAGE}");
                    let report = build_error_report(&err.error);
                    let output = format_json(&strip_raw(report, true), true);
                    println!("{output}");
                    2
                }
            }
        }
    } else {
        match parse_args(&argv) {
            Ok(parsed) => {
                if let Some(script_path) = parsed.script_path.as_ref() {
                    match tokio::fs::read_to_string(script_path).await {
                        Ok(raw) => {
                            let scenario: ScriptScenario = match serde_json::from_str(&raw) {
                                Ok(scenario) => scenario,
                                Err(err) => {
                                    eprintln!("Invalid script JSON: {err}");
                                    return 1;
                                }
                            };
                            let report = run_script_scenario(
                                scenario,
                                crate::scenario::types::ScriptRunOptions {
                                    snapshot_write: parsed.snapshot_write,
                                    scenario_path: Some(script_path.to_string()),
                                    client_info: None,
                                },
                            )
                            .await;
                            let output = format_json(&report, parsed.pretty);
                            println!("{output}");
                            if let Some(path) = parsed.out_path {
                                let _ = tokio::fs::write(path, format!("{output}\n")).await;
                            }
                            if report.ok {
                                0
                            } else {
                                1
                            }
                        }
                        Err(err) => {
                            eprintln!("Failed to read script: {err}");
                            1
                        }
                    }
                } else {
                    let resolved = resolve_target(
                        parsed.overrides.clone(),
                        parsed.config_path.as_deref(),
                        parsed.profile.as_deref(),
                        parsed.use_auth,
                        parsed.access_token_path.as_deref(),
                    )
                    .await;
                    let (mut target, use_auth, access_token_path) = match resolved {
                        Ok(result) => result,
                        Err(err) => {
                            let report = build_error_report(&err.to_string());
                            let output = format_json(&strip_raw(report, true), true);
                            println!("{output}");
                            return 1;
                        }
                    };

                    if use_auth && access_token_path.is_some() {
                        let report = build_error_report(
                            "Specify only one auth source: use-auth or access-token-path.",
                        );
                        let output = format_json(&strip_raw(report, true), true);
                        println!("{output}");
                        return 1;
                    }

                    if let Some(path) = access_token_path {
                        if target.transport_type == TransportType::Stdio {
                            let report = build_error_report(
                                "access-token-path is only supported for HTTP transports.",
                            );
                            let output = format_json(&strip_raw(report, true), true);
                            println!("{output}");
                            return 1;
                        }
                        if target.url.is_none() {
                            let report =
                                build_error_report("Missing target URL for access-token-path.");
                            let output = format_json(&strip_raw(report, true), true);
                            println!("{output}");
                            return 1;
                        }
                        match read_access_token_from_path(&path).await {
                            Ok(token) => {
                                let headers = attach_access_token(target.headers.clone(), &token);
                                match headers {
                                    Ok(headers) => target.headers = Some(headers),
                                    Err(err) => {
                                        let report = build_error_report(&err.to_string());
                                        let output = format_json(&strip_raw(report, true), true);
                                        println!("{output}");
                                        return 1;
                                    }
                                }
                            }
                            Err(err) => {
                                let report = build_error_report(&err.to_string());
                                let output = format_json(&strip_raw(report, true), true);
                                println!("{output}");
                                return 1;
                            }
                        }
                    } else if use_auth {
                        if let Err(err) = apply_auth_header(&mut target).await {
                            let report = build_error_report(&err.to_string());
                            let output = format_json(&strip_raw(report, true), true);
                            println!("{output}");
                            return 1;
                        }
                    }

                    let report = run_probe(target, None, None).await;
                    let effective_verbosity = parsed.verbosity.or({
                        if parsed.include_raw {
                            Some(ReportVerbosity::Full)
                        } else {
                            None
                        }
                    });
                    let output_report = if let Some(verbosity) = effective_verbosity {
                        apply_report_verbosity(report.clone(), Some(verbosity))
                    } else {
                        strip_raw(report.clone(), false)
                    };
                    let output = format_json(&output_report, parsed.pretty);
                    println!("{output}");
                    if let Some(path) = parsed.out_path {
                        let _ = tokio::fs::write(path, format!("{output}\n")).await;
                    }
                    if report.ok {
                        0
                    } else {
                        1
                    }
                }
            }
            Err(err) => {
                if err.help {
                    print!("{USAGE}");
                    0
                } else {
                    eprintln!("{}", err.error);
                    eprintln!("{USAGE}");
                    let report = build_error_report(&err.error);
                    let output = format_json(&strip_raw(report, true), true);
                    println!("{output}");
                    2
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_args, parse_auth_args, parse_prompt_argument, parse_prompt_render_args};
    use serde_json::json;

    #[test]
    fn parse_auth_args_accepts_expect_registration_endpoint() {
        let parsed = parse_auth_args(&[
            "--server".to_string(),
            "http://127.0.0.1:9526/mcp".to_string(),
            "--expect-registration-endpoint".to_string(),
        ])
        .expect("auth args should parse");

        assert_eq!(parsed.server_url, "http://127.0.0.1:9526/mcp");
        assert!(parsed.expect_registration_endpoint);
    }

    #[test]
    fn parse_prompt_argument_accepts_json_values() {
        let (key, value) = parse_prompt_argument("case={\"id\":\"C123\",\"include\":true}")
            .expect("prompt argument should parse");

        assert_eq!(key, "case");
        assert_eq!(value, json!({ "id": "C123", "include": true }));
    }

    #[test]
    fn parse_prompt_render_args_reuses_target_parser() {
        let parsed = parse_prompt_render_args(&[
            "--prompt".to_string(),
            "summarize_case".to_string(),
            "--prompt-arg".to_string(),
            "case_id=\"C123\"".to_string(),
            "--transport".to_string(),
            "streamable-http".to_string(),
            "--url".to_string(),
            "http://127.0.0.1:9526/mcp".to_string(),
            "--verbosity".to_string(),
            "full".to_string(),
            "--expect-error-contains".to_string(),
            "missing".to_string(),
        ])
        .expect("prompt render args should parse");

        assert_eq!(parsed.prompt_name, "summarize_case");
        assert_eq!(
            parsed
                .arguments
                .as_ref()
                .and_then(|args| args.get("case_id")),
            Some(&json!("C123"))
        );
        assert_eq!(
            parsed.target.overrides.url.as_deref(),
            Some("http://127.0.0.1:9526/mcp")
        );
        assert!(parsed.expect_error.is_some());
    }

    #[test]
    fn parse_args_accepts_catalog_contract_path() {
        let parsed = parse_args(&[
            "--transport".to_string(),
            "streamable-http".to_string(),
            "--url".to_string(),
            "http://127.0.0.1:9526/mcp".to_string(),
            "--catalog-contract".to_string(),
            "catalog-contract.json".to_string(),
        ])
        .expect("args should parse");

        assert_eq!(
            parsed.overrides.catalog_contract_path.as_deref(),
            Some("catalog-contract.json")
        );
    }
}
