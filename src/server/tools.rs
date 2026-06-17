//! MCP tool handlers for the probe server.

use crate::auth::{
    attach_access_token, attach_auth_header, format_auth_source_error, read_access_token_from_path,
    read_refresh_token_from_path, refresh_access_token, RefreshTokenOptions,
};
use crate::guidance::{
    build_common_guidance_from_error, build_common_guidance_from_report, format_failure_summary,
    format_guidance,
};
use crate::help_text::{
    format_probe_call_tool_example, format_probe_discover_auth_example,
    format_probe_handshake_example, format_probe_help_text, format_probe_http_smoke_example,
    format_probe_prompt_render_example, format_probe_raw_request_example,
    format_probe_replay_example, format_probe_resource_read_example,
    format_probe_resource_subscribe_example, format_probe_run_examples_for,
    format_probe_script_example, list_probe_tools, ProbeRunExampleId,
};
use crate::probe::schema_compat::ToolDescriptorProfile;
use crate::probe::{
    build_prompt_render_params, build_resource_uri_params, run_auth_discovery, run_http_smoke,
    run_probe, run_probe_handshake, run_raw_request, AuthDiscoveryTarget, HttpSmokeTarget,
    ProbeTarget, RawRequestTarget,
};
use crate::replay::{run_replay_probe, ReplayProbeTarget};
use crate::report::{
    apply_report_verbosity, AuthDiscovery, ProbeReport, ProbeStep, ProbeStepStatus,
    RawRequestReport, ReportVerbosity,
};
use crate::scenario::runner::run_script_scenario;
use crate::scenario::types::{ScriptRunOptions, ScriptScenario};
use crate::transport::TransportType;
use crate::version::SERVER_NAME;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content};
use rmcp::tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::ProbeMcp;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
struct ProbeRunArgs {
    transport: TransportType,
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
    log_level: Option<crate::logging::LogLevel>,
    log_format: Option<crate::logging::LogFormat>,
    verbosity: Option<ReportVerbosity>,
    trace: Option<bool>,
    trace_limit: Option<usize>,
    trace_max_bytes: Option<usize>,
    descriptor_profile: Option<ToolDescriptorProfile>,
    use_auth: Option<bool>,
    access_token: Option<String>,
    access_token_path: Option<String>,
    refresh_token: Option<String>,
    refresh_token_path: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    token_endpoint: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
struct ProbeHandshakeArgs {
    transport: TransportType,
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
    log_level: Option<crate::logging::LogLevel>,
    log_format: Option<crate::logging::LogFormat>,
    verbosity: Option<ReportVerbosity>,
    trace: Option<bool>,
    trace_limit: Option<usize>,
    trace_max_bytes: Option<usize>,
    descriptor_profile: Option<ToolDescriptorProfile>,
    use_auth: Option<bool>,
    access_token: Option<String>,
    access_token_path: Option<String>,
    refresh_token: Option<String>,
    refresh_token_path: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    token_endpoint: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
struct ProbeHttpSmokeArgs {
    url: String,
    timeout_ms: Option<u64>,
    expect_auth_required: Option<bool>,
    expect_registration_endpoint: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
struct ProbeDiscoverAuthArgs {
    url: String,
    timeout_ms: Option<u64>,
    expect_auth_required: Option<bool>,
    expect_registration_endpoint: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
struct ProbeRawRequestArgs {
    transport: TransportType,
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
    log_level: Option<crate::logging::LogLevel>,
    log_format: Option<crate::logging::LogFormat>,
    verbosity: Option<ReportVerbosity>,
    trace: Option<bool>,
    trace_limit: Option<usize>,
    trace_max_bytes: Option<usize>,
    use_auth: Option<bool>,
    access_token: Option<String>,
    access_token_path: Option<String>,
    refresh_token: Option<String>,
    refresh_token_path: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    token_endpoint: Option<String>,
    scope: Option<String>,
    method: String,
    params: Option<HashMap<String, Value>>,
    expect_error: Option<crate::probe::ExpectError>,
    allow_tool_calls: Option<bool>,
    dry_run: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
struct ProbeCallToolArgs {
    transport: TransportType,
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
    log_level: Option<crate::logging::LogLevel>,
    log_format: Option<crate::logging::LogFormat>,
    verbosity: Option<ReportVerbosity>,
    trace: Option<bool>,
    trace_limit: Option<usize>,
    trace_max_bytes: Option<usize>,
    use_auth: Option<bool>,
    access_token: Option<String>,
    access_token_path: Option<String>,
    refresh_token: Option<String>,
    refresh_token_path: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    token_endpoint: Option<String>,
    scope: Option<String>,
    tool_name: String,
    arguments: Option<HashMap<String, Value>>,
    allow_tool_calls: Option<bool>,
    dry_run: Option<bool>,
    expect_error: Option<crate::probe::ExpectError>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
struct ProbePromptRenderArgs {
    transport: TransportType,
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
    log_level: Option<crate::logging::LogLevel>,
    log_format: Option<crate::logging::LogFormat>,
    verbosity: Option<ReportVerbosity>,
    trace: Option<bool>,
    trace_limit: Option<usize>,
    trace_max_bytes: Option<usize>,
    use_auth: Option<bool>,
    access_token: Option<String>,
    access_token_path: Option<String>,
    refresh_token: Option<String>,
    refresh_token_path: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    token_endpoint: Option<String>,
    scope: Option<String>,
    prompt_name: String,
    arguments: Option<HashMap<String, Value>>,
    dry_run: Option<bool>,
    expect_error: Option<crate::probe::ExpectError>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
struct ProbeResourceReadArgs {
    transport: TransportType,
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
    log_level: Option<crate::logging::LogLevel>,
    log_format: Option<crate::logging::LogFormat>,
    verbosity: Option<ReportVerbosity>,
    trace: Option<bool>,
    trace_limit: Option<usize>,
    trace_max_bytes: Option<usize>,
    use_auth: Option<bool>,
    access_token: Option<String>,
    access_token_path: Option<String>,
    refresh_token: Option<String>,
    refresh_token_path: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    token_endpoint: Option<String>,
    scope: Option<String>,
    uri: String,
    dry_run: Option<bool>,
    expect_error: Option<crate::probe::ExpectError>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
struct ProbeResourceSubscribeArgs {
    transport: TransportType,
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
    log_level: Option<crate::logging::LogLevel>,
    log_format: Option<crate::logging::LogFormat>,
    verbosity: Option<ReportVerbosity>,
    trace: Option<bool>,
    trace_limit: Option<usize>,
    trace_max_bytes: Option<usize>,
    use_auth: Option<bool>,
    access_token: Option<String>,
    access_token_path: Option<String>,
    refresh_token: Option<String>,
    refresh_token_path: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    token_endpoint: Option<String>,
    scope: Option<String>,
    uri: String,
    dry_run: Option<bool>,
    expect_error: Option<crate::probe::ExpectError>,
    unsubscribe_expect_error: Option<crate::probe::ExpectError>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
struct ProbeReplayArgs {
    transport: Option<TransportType>,
    url: String,
    headers: Option<HashMap<String, String>>,
    timeout_ms: Option<u64>,
    use_auth: Option<bool>,
    access_token: Option<String>,
    access_token_path: Option<String>,
    refresh_token: Option<String>,
    refresh_token_path: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    token_endpoint: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
struct ProbeScriptArgs {
    scenario: ScriptScenario,
    snapshot_write: Option<bool>,
    scenario_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
struct ProbeHelpArgs {
    tool: Option<String>,
}

struct AuthResolution {
    headers: Option<HashMap<String, String>>,
    auth_source: String,
    refresh_skipped: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct FailureDiagnostics {
    stage: String,
    layer: String,
    timed_out: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    elapsed_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    next_steps: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_target: Option<String>,
}

fn collect_auth_sources(
    use_auth: Option<bool>,
    access_token: Option<&str>,
    access_token_path: Option<&str>,
    refresh_token: Option<&str>,
    refresh_token_path: Option<&str>,
) -> Vec<String> {
    let mut sources = Vec::new();
    if use_auth.unwrap_or(false) {
        sources.push("use_auth".to_string());
    }
    if access_token.is_some() {
        sources.push("access_token".to_string());
    }
    if access_token_path.is_some() {
        sources.push("access_token_path".to_string());
    }
    if refresh_token.is_some() {
        sources.push("refresh_token".to_string());
    }
    if refresh_token_path.is_some() {
        sources.push("refresh_token_path".to_string());
    }
    sources
}

#[allow(clippy::too_many_arguments)]
async fn resolve_auth_headers(
    transport: TransportType,
    url: Option<&str>,
    headers: Option<HashMap<String, String>>,
    use_auth: Option<bool>,
    access_token: Option<&str>,
    access_token_path: Option<&str>,
    refresh_token: Option<&str>,
    refresh_token_path: Option<&str>,
    client_id: Option<&str>,
    client_secret: Option<&str>,
    token_endpoint: Option<&str>,
    scope: Option<&str>,
    timeout_ms: Option<u64>,
    dry_run: bool,
) -> Result<AuthResolution, String> {
    let auth_sources = collect_auth_sources(
        use_auth,
        access_token,
        access_token_path,
        refresh_token,
        refresh_token_path,
    );

    if !auth_sources.is_empty() && url.is_none() {
        return Err("Auth headers require a target URL.".to_string());
    }
    if auth_sources.len() > 1 {
        return Err(format_auth_source_error(&auth_sources));
    }

    let auth_source = auth_sources
        .first()
        .cloned()
        .unwrap_or_else(|| "none".to_string());
    let auth_refresh_requested = refresh_token.is_some() || refresh_token_path.is_some();
    let refresh_skipped = dry_run && auth_refresh_requested;

    let mut headers = headers;

    if let Some(path) = access_token_path {
        let token = read_access_token_from_path(path)
            .await
            .map_err(|err| err.to_string())?;
        headers = Some(attach_access_token(headers, &token).map_err(|err| err.to_string())?);
        return Ok(AuthResolution {
            headers,
            auth_source,
            refresh_skipped,
        });
    }

    if let Some(token) = access_token {
        headers = Some(attach_access_token(headers, token).map_err(|err| err.to_string())?);
        return Ok(AuthResolution {
            headers,
            auth_source,
            refresh_skipped,
        });
    }

    if refresh_token.is_some() || refresh_token_path.is_some() {
        if transport == TransportType::Stdio {
            return Err("refresh_token auth is only supported for HTTP transports.".to_string());
        }
        let file_data = if let Some(path) = refresh_token_path {
            Some(
                read_refresh_token_from_path(path)
                    .await
                    .map_err(|err| err.to_string())?,
            )
        } else {
            None
        };
        let refresh_token = refresh_token
            .map(|value| value.to_string())
            .or_else(|| file_data.as_ref().map(|data| data.refresh_token.clone()));
        let client_id = client_id
            .map(|value| value.to_string())
            .or_else(|| file_data.as_ref().and_then(|data| data.client_id.clone()));
        let client_secret = client_secret.map(|value| value.to_string()).or_else(|| {
            file_data
                .as_ref()
                .and_then(|data| data.client_secret.clone())
        });
        let token_endpoint = token_endpoint.map(|value| value.to_string()).or_else(|| {
            file_data
                .as_ref()
                .and_then(|data| data.token_endpoint.clone())
        });
        let scope = scope
            .map(|value| value.to_string())
            .or_else(|| file_data.as_ref().and_then(|data| data.scope.clone()));
        let server_url = url
            .map(|value| value.to_string())
            .or_else(|| file_data.as_ref().and_then(|data| data.server_url.clone()));

        let Some(refresh_token) = refresh_token else {
            return Err("refresh_token is required.".to_string());
        };
        let Some(client_id) = client_id else {
            return Err("client_id is required to refresh tokens.".to_string());
        };

        if dry_run {
            headers =
                Some(attach_access_token(headers, "[REDACTED]").map_err(|err| err.to_string())?);
        } else {
            let refreshed = refresh_access_token(RefreshTokenOptions {
                refresh_token,
                client_id,
                client_secret,
                scope,
                server_url,
                token_endpoint,
                timeout_ms,
            })
            .await
            .map_err(|err| err.to_string())?;
            headers = Some(
                attach_access_token(headers, &refreshed.access_token)
                    .map_err(|err| err.to_string())?,
            );
        }

        return Ok(AuthResolution {
            headers,
            auth_source,
            refresh_skipped,
        });
    }

    if use_auth.unwrap_or(false) {
        let url = url.unwrap_or_default();
        headers = Some(
            attach_auth_header(headers, url)
                .await
                .map_err(|err| err.to_string())?,
        );
    }

    Ok(AuthResolution {
        headers,
        auth_source,
        refresh_skipped,
    })
}

fn build_result(text: String, structured: Value, is_error: bool) -> CallToolResult {
    let mut result = if is_error {
        CallToolResult::error(vec![Content::text(text)])
    } else {
        CallToolResult::success(vec![Content::text(text)])
    };
    result.structured_content = Some(structured);
    result
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

fn is_timeout_detail(detail: &str) -> bool {
    contains_ci(detail, "timed out") || contains_ci(detail, "timeout")
}

fn extract_timeout_ms(detail: &str) -> Option<u64> {
    let marker = "timed out after ";
    let lower = detail.to_ascii_lowercase();
    let start = lower.find(marker)?;
    let suffix = &detail[(start + marker.len())..];
    let digits: String = suffix
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

fn elapsed_ms_between(started_at: &str, finished_at: &str) -> Option<u64> {
    let started = OffsetDateTime::parse(started_at, &Rfc3339).ok()?;
    let finished = OffsetDateTime::parse(finished_at, &Rfc3339).ok()?;
    let elapsed = (finished - started).whole_milliseconds();
    if elapsed < 0 {
        None
    } else {
        Some(elapsed as u64)
    }
}

fn classify_failure_layer(stage: &str) -> &'static str {
    if stage.starts_with("auth.") {
        "auth"
    } else if stage.starts_with("allowlist.")
        || stage == "connect"
        || stage == "disconnect"
        || stage == "stdio.stderr"
        || stage.starts_with("http.")
    {
        "transport"
    } else if stage == "server.info"
        || stage == "capabilities"
        || stage == "ping"
        || stage == "tools.list"
        || stage == "resources.list"
        || stage == "prompts.list"
    {
        "handshake"
    } else if stage == "tools.schema_compatibility" {
        "tool_schema"
    } else if stage == "request:prompts/get" {
        "prompt_render"
    } else if stage == "request:resources/read" {
        "resource_read"
    } else if stage == "request:resources/subscribe" || stage == "request:resources/unsubscribe" {
        "resource_subscription"
    } else if stage.starts_with("request:") {
        "tool_execution"
    } else {
        "probe"
    }
}

fn build_next_steps(
    layer: &str,
    timed_out: bool,
    request_target: Option<&str>,
    transport: Option<TransportType>,
) -> Vec<String> {
    let mut steps = Vec::new();

    if timed_out {
        steps.push(
            "Timeout path: re-run with trace=true to capture stage-level request/response flow."
                .to_string(),
        );
    }

    match layer {
        "transport" => {
            if matches!(
                transport,
                Some(TransportType::Sse | TransportType::StreamableHttp)
            ) {
                steps.push(
                    "Run probe_http_smoke on the same URL to isolate host reachability and auth challenge behavior."
                        .to_string(),
                );
                steps.push(
                    "Run probe_discover_auth on the same URL to validate PRM/OAuth metadata independently."
                        .to_string(),
                );
            } else {
                steps.push(
                    "Confirm the stdio command, cwd, and env are correct, then re-run with trace=true to capture child-process stderr."
                        .to_string(),
                );
                steps.push(
                    "If the child process never starts, fix the command or working directory and retry probe_handshake with a higher timeout_ms."
                        .to_string(),
                );
            }
        }
        "auth" => {
            steps.push(
                "Verify auth source selection: choose one of use_auth, access_token(_path), or refresh_token(_path)."
                    .to_string(),
            );
            steps.push(
                "Run probe_discover_auth first, then retry with access_token or refresh_token + client_id."
                    .to_string(),
            );
        }
        "handshake" => {
            steps.push(
                "Run probe_handshake with a higher timeout_ms to separate connection readiness from full probe discovery."
                    .to_string(),
            );
            steps.push(
                "If handshake keeps failing, use probe_raw_request for tools/list to inspect the raw MCP response."
                    .to_string(),
            );
        }
        "tool_execution" => {
            if let Some(target) = request_target {
                steps.push(format!(
                    "Nested target `{target}` failed during tools/call; confirm the target tool is available and healthy."
                ));
            }
            steps.push(
                "Run probe_call_tool with dry_run=true to validate transport/url/tool_name/arguments before dispatch."
                    .to_string(),
            );
            steps.push(
                "Run probe_handshake first; if it succeeds, retry tools/call with a higher timeout_ms."
                    .to_string(),
            );
            steps.push(
                "Use probe_raw_request with method \"tools/call\" for low-level payload/error inspection."
                    .to_string(),
            );
        }
        "prompt_render" => {
            if let Some(target) = request_target {
                steps.push(format!(
                    "Prompt target `{target}` failed; confirm the prompt name and required argument keys from prompts/list."
                ));
            }
            steps.push(
                "Run probe_prompt_render with dry_run=true to validate transport/url/prompt_name/arguments before dispatch."
                    .to_string(),
            );
            steps.push(
                "Run probe_run with verbosity=full to inspect prompts.list metadata and required prompt arguments."
                    .to_string(),
            );
            steps.push(
                "Use probe_raw_request with method \"prompts/get\" only when low-level payload/error inspection is needed."
                    .to_string(),
            );
        }
        "resource_read" => {
            if let Some(target) = request_target {
                steps.push(format!(
                    "Resource target `{target}` failed; confirm the URI is present in resources/list and readable for this token."
                ));
            }
            steps.push(
                "Run probe_resource_read with dry_run=true to validate transport/url/uri/auth before dispatch."
                    .to_string(),
            );
            steps.push(
                "Run probe_run with verbosity=full to inspect resources.list metadata such as mimeType and description."
                    .to_string(),
            );
            steps.push(
                "Use probe_raw_request with method \"resources/read\" only when low-level payload/error inspection is needed."
                    .to_string(),
            );
        }
        "resource_subscription" => {
            if let Some(target) = request_target {
                steps.push(format!(
                    "Resource subscription target `{target}` failed; confirm the resource supports subscribe/unsubscribe and the URI is exact."
                ));
            }
            steps.push(
                "Run probe_resource_subscribe with dry_run=true to validate transport/url/uri/auth before dispatch."
                    .to_string(),
            );
            steps.push(
                "Enable trace=true when debugging resource update notifications during subscribe/unsubscribe."
                    .to_string(),
            );
            steps.push(
                "Use probe_raw_request with resources/subscribe or resources/unsubscribe only for low-level payload/error inspection."
                    .to_string(),
            );
        }
        "tool_schema" => {
            steps.push(
                "Inspect structuredContent.report.steps[].data.findings for the exact tool_name, schema_path, offending fragment, and remediation hint."
                    .to_string(),
            );
            steps.push(
                "Fix the advertised inputSchema before exposing the server to MCP clients; array schemas need object-valued `items`, and raw Value/boolean schema escape hatches need typed wrappers."
                    .to_string(),
            );
            steps.push(
                "After rebuilding/restarting the target server, rerun probe_run with verbosity=full to confirm tools/list is client-compatible."
                    .to_string(),
            );
        }
        _ => {
            steps.push(
                "Re-run probe_run with trace=true and review structuredContent.report.steps for the first failing stage."
                    .to_string(),
            );
        }
    }

    steps
}

fn failure_diagnostics_from_steps(
    steps: &[ProbeStep],
    started_at: &str,
    finished_at: &str,
    request_target: Option<String>,
    transport: Option<TransportType>,
) -> Option<FailureDiagnostics> {
    let failed_step = steps
        .iter()
        .find(|step| step.status == ProbeStepStatus::Error)?;
    let detail = failed_step.detail.clone();
    let timed_out = detail.as_deref().map(is_timeout_detail).unwrap_or(false);
    let timeout_ms = detail.as_deref().and_then(extract_timeout_ms);
    let layer = classify_failure_layer(&failed_step.name).to_string();
    let next_steps = build_next_steps(&layer, timed_out, request_target.as_deref(), transport);

    Some(FailureDiagnostics {
        stage: failed_step.name.clone(),
        layer,
        timed_out,
        timeout_ms,
        elapsed_ms: elapsed_ms_between(started_at, finished_at),
        detail,
        next_steps,
        request_target,
    })
}

fn failure_diagnostics_from_probe_report(
    report: &ProbeReport,
    transport: Option<TransportType>,
) -> Option<FailureDiagnostics> {
    failure_diagnostics_from_steps(
        &report.steps,
        &report.started_at,
        &report.finished_at,
        None,
        transport,
    )
}

fn failure_diagnostics_from_raw_report(
    report: &RawRequestReport,
    request_target: Option<String>,
    transport: Option<TransportType>,
) -> Option<FailureDiagnostics> {
    failure_diagnostics_from_steps(
        &report.steps,
        &report.started_at,
        &report.finished_at,
        request_target,
        transport,
    )
}

fn merge_diagnostic_hints(hints: &mut Vec<String>, diagnostics: &FailureDiagnostics) {
    let context = if diagnostics.timed_out {
        match diagnostics.timeout_ms {
            Some(timeout_ms) => format!(
                "Likely stalled stage: {} (layer: {}, timeout: {}ms).",
                diagnostics.stage, diagnostics.layer, timeout_ms
            ),
            None => format!(
                "Likely stalled stage: {} (layer: {}, timeout observed).",
                diagnostics.stage, diagnostics.layer
            ),
        }
    } else {
        format!(
            "Likely failure stage: {} (layer: {}).",
            diagnostics.stage, diagnostics.layer
        )
    };

    if !hints.iter().any(|hint| hint == &context) {
        hints.push(context);
    }
    for next_step in diagnostics.next_steps.iter() {
        if !hints.iter().any(|hint| hint == next_step) {
            hints.push(next_step.clone());
        }
    }
}

fn is_auth_failure_detail(detail: &str) -> bool {
    contains_ci(detail, "auth.")
        || contains_ci(detail, "token")
        || contains_ci(detail, "bearer")
        || contains_ci(detail, "unauthorized")
        || contains_ci(detail, "forbidden")
        || contains_ci(detail, "invalid_token")
}

fn select_probe_run_examples(
    auth_source: Option<&str>,
    auth_failure: bool,
) -> Vec<ProbeRunExampleId> {
    match auth_source {
        Some("use_auth") => vec![ProbeRunExampleId::Cached],
        Some("access_token") | Some("access_token_path") => vec![ProbeRunExampleId::Explicit],
        Some("refresh_token") | Some("refresh_token_path") => vec![ProbeRunExampleId::Refresh],
        _ => {
            if auth_failure {
                vec![
                    ProbeRunExampleId::Explicit,
                    ProbeRunExampleId::Refresh,
                    ProbeRunExampleId::Cached,
                ]
            } else {
                vec![ProbeRunExampleId::Unauthenticated]
            }
        }
    }
}

fn auth_failure_from_report(report: &ProbeReport) -> bool {
    report.steps.iter().any(|step| {
        step.status == crate::report::ProbeStepStatus::Error
            && (step.name.starts_with("auth")
                || step
                    .detail
                    .as_deref()
                    .map(is_auth_failure_detail)
                    .unwrap_or(false))
    })
}

fn handshake_auth_required_as_expected(report: &ProbeReport) -> bool {
    report.steps.iter().any(|step| {
        step.name == "connect.auth_required"
            && step.status == crate::report::ProbeStepStatus::Ok
            && step
                .data
                .as_ref()
                .and_then(|value| value.get("expected_auth_required"))
                .and_then(Value::as_bool)
                == Some(true)
    })
}

fn summarize_auth(auth: Option<AuthDiscovery>) -> Option<AuthDiscovery> {
    let auth = auth?;
    let mut summary = AuthDiscovery {
        resource_metadata_url: None,
        resource_metadata: None,
        authorization_server: None,
        oauth_metadata_url: None,
        oauth_metadata: None,
        registration_endpoint: None,
    };
    if auth.resource_metadata_url.is_some() {
        summary.resource_metadata_url = auth.resource_metadata_url;
    }
    if auth.authorization_server.is_some() {
        summary.authorization_server = auth.authorization_server;
    }
    if auth.oauth_metadata_url.is_some() {
        summary.oauth_metadata_url = auth.oauth_metadata_url;
    }
    if auth.registration_endpoint.is_some() {
        summary.registration_endpoint = auth.registration_endpoint;
    }
    if summary.resource_metadata_url.is_none()
        && summary.authorization_server.is_none()
        && summary.oauth_metadata_url.is_none()
        && summary.registration_endpoint.is_none()
    {
        None
    } else {
        Some(summary)
    }
}

fn apply_raw_report_verbosity(
    mut report: RawRequestReport,
    verbosity: Option<ReportVerbosity>,
) -> RawRequestReport {
    match verbosity {
        Some(ReportVerbosity::Full) => report,
        _ => {
            report.trace = None;
            report.auth = summarize_auth(report.auth);
            report
        }
    }
}

fn structured_base(tool: &str) -> serde_json::Map<String, Value> {
    let mut map = serde_json::Map::new();
    map.insert("tool".to_string(), Value::String(tool.to_string()));
    map.insert("server".to_string(), Value::String(SERVER_NAME.to_string()));
    map
}

fn translate_verbosity_error(message: &str) -> String {
    let normalized = message.to_lowercase();
    let summary_clause = normalized.contains("summary") && normalized.contains("full");
    let expected_clause = normalized.contains("expected summary or full")
        || normalized.contains("expected one of \"summary\", \"full\"");
    if summary_clause && (expected_clause || normalized.contains("invalid")) {
        return "Invalid verbosity: allowed values are `summary` or `full` (use `summary` instead of legacy `normal`).".to_string();
    }
    message.to_string()
}

mod core;
mod http;
mod raw;
mod script;

#[cfg(test)]
mod translate_verbosity_error_tests {
    use super::translate_verbosity_error;

    #[test]
    fn translate_verbosity_summary_error() {
        let message = "invalid value: string \"normal\", expected summary or full";
        assert_eq!(
            translate_verbosity_error(message),
            "Invalid verbosity: allowed values are `summary` or `full` (use `summary` instead of legacy `normal`)."
        );
    }

    #[test]
    fn translate_verbosity_preserves_other_errors() {
        let message = "unknown tool: foo";
        assert_eq!(translate_verbosity_error(message), message);
    }
}

impl ProbeMcp {
    pub fn tool_router_probe() -> ToolRouter<ProbeMcp> {
        Self::tool_router_probe_core()
            + Self::tool_router_probe_http()
            + Self::tool_router_probe_raw()
            + Self::tool_router_probe_script()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error_step(name: &str, detail: &str) -> ProbeStep {
        ProbeStep {
            name: name.to_string(),
            status: ProbeStepStatus::Error,
            detail: Some(detail.to_string()),
            data: None,
        }
    }

    #[test]
    fn timeout_diagnostics_classify_tools_call_as_tool_execution() {
        let steps = vec![error_step(
            "request:tools/call",
            "request:tools/call timed out after 120000ms",
        )];
        let diagnostics = failure_diagnostics_from_steps(
            &steps,
            "2026-03-21T00:00:00Z",
            "2026-03-21T00:02:01Z",
            Some("status.get".to_string()),
            Some(TransportType::StreamableHttp),
        )
        .expect("diagnostics");

        assert_eq!(diagnostics.layer, "tool_execution");
        assert_eq!(diagnostics.stage, "request:tools/call");
        assert_eq!(diagnostics.timeout_ms, Some(120000));
        assert!(diagnostics.timed_out);
        assert!(diagnostics
            .next_steps
            .iter()
            .any(|line| line.contains("probe_handshake")));
    }

    #[test]
    fn timeout_diagnostics_classify_connect_as_transport() {
        let steps = vec![error_step("connect", "connect timed out after 15000ms")];
        let diagnostics = failure_diagnostics_from_steps(
            &steps,
            "2026-03-21T00:00:00Z",
            "2026-03-21T00:00:16Z",
            None,
            Some(TransportType::Stdio),
        )
        .expect("diagnostics");

        assert_eq!(diagnostics.layer, "transport");
        assert_eq!(diagnostics.timeout_ms, Some(15000));
        assert!(diagnostics
            .next_steps
            .iter()
            .any(|line| line.contains("stdio command")));
        assert!(!diagnostics
            .next_steps
            .iter()
            .any(|line| line.contains("probe_http_smoke")));
    }

    #[test]
    fn extract_timeout_ms_returns_none_for_non_timeout_detail() {
        assert_eq!(extract_timeout_ms("connection refused"), None);
    }

    #[test]
    fn transport_diagnostics_for_http_keep_http_followups() {
        let steps = vec![error_step("connect", "connect timed out after 15000ms")];
        let diagnostics = failure_diagnostics_from_steps(
            &steps,
            "2026-03-21T00:00:00Z",
            "2026-03-21T00:00:16Z",
            None,
            Some(TransportType::StreamableHttp),
        )
        .expect("diagnostics");

        assert!(diagnostics
            .next_steps
            .iter()
            .any(|line| line.contains("probe_http_smoke")));
        assert!(diagnostics
            .next_steps
            .iter()
            .any(|line| line.contains("probe_discover_auth")));
    }

    #[test]
    fn schema_compatibility_diagnostics_classify_as_tool_schema() {
        let steps = vec![error_step(
            "tools.schema_compatibility",
            "1 tool schema compatibility error(s); see data.findings",
        )];
        let diagnostics = failure_diagnostics_from_steps(
            &steps,
            "2026-03-21T00:00:00Z",
            "2026-03-21T00:00:01Z",
            None,
            Some(TransportType::StreamableHttp),
        )
        .expect("diagnostics");

        assert_eq!(diagnostics.layer, "tool_schema");
        assert!(diagnostics
            .next_steps
            .iter()
            .any(|line| line.contains("tool_name") && line.contains("schema_path")));
        assert!(diagnostics
            .next_steps
            .iter()
            .any(|line| line.contains("array schemas need object-valued `items`")));
    }

    #[test]
    fn prompt_render_diagnostics_classify_prompts_get() {
        let steps = vec![error_step(
            "request:prompts/get",
            "missing required argument: case_id",
        )];
        let diagnostics = failure_diagnostics_from_steps(
            &steps,
            "2026-03-21T00:00:00Z",
            "2026-03-21T00:00:01Z",
            Some("prompts/get -> summarize_case".to_string()),
            Some(TransportType::StreamableHttp),
        )
        .expect("diagnostics");

        assert_eq!(diagnostics.layer, "prompt_render");
        assert!(diagnostics
            .next_steps
            .iter()
            .any(|line| line.contains("prompts/list")));
        assert!(diagnostics
            .next_steps
            .iter()
            .any(|line| line.contains("probe_prompt_render")));
    }

    #[test]
    fn resource_read_diagnostics_classify_resources_read() {
        let steps = vec![error_step("request:resources/read", "resource not found")];
        let diagnostics = failure_diagnostics_from_steps(
            &steps,
            "2026-03-21T00:00:00Z",
            "2026-03-21T00:00:01Z",
            Some("resources/read -> mcp-probe://missing".to_string()),
            Some(TransportType::StreamableHttp),
        )
        .expect("diagnostics");

        assert_eq!(diagnostics.layer, "resource_read");
        assert!(diagnostics
            .next_steps
            .iter()
            .any(|line| line.contains("resources/list")));
        assert!(diagnostics
            .next_steps
            .iter()
            .any(|line| line.contains("probe_resource_read")));
    }

    #[test]
    fn resource_subscription_diagnostics_classify_subscribe() {
        let steps = vec![error_step(
            "request:resources/subscribe",
            "subscriptions unsupported",
        )];
        let diagnostics = failure_diagnostics_from_steps(
            &steps,
            "2026-03-21T00:00:00Z",
            "2026-03-21T00:00:01Z",
            Some("resources/subscribe -> mcp-probe://status".to_string()),
            Some(TransportType::StreamableHttp),
        )
        .expect("diagnostics");

        assert_eq!(diagnostics.layer, "resource_subscription");
        assert!(diagnostics
            .next_steps
            .iter()
            .any(|line| line.contains("probe_resource_subscribe")));
        assert!(diagnostics
            .next_steps
            .iter()
            .any(|line| line.contains("trace=true")));
    }

    #[test]
    fn handshake_auth_required_as_expected_detects_expected_connect_step() {
        let report = ProbeReport {
            ok: true,
            started_at: "2026-03-21T00:00:00Z".to_string(),
            finished_at: "2026-03-21T00:00:01Z".to_string(),
            steps: vec![ProbeStep {
                name: "connect.auth_required".to_string(),
                status: ProbeStepStatus::Ok,
                detail: Some("Auth challenge detected as expected".to_string()),
                data: Some(json!({ "expected_auth_required": true })),
            }],
            auth: None,
            server_info: None,
            capabilities: None,
            tools: None,
            resources: None,
            prompts: None,
            trace: None,
        };

        assert!(handshake_auth_required_as_expected(&report));
    }
}
