//! Probe runners for validating MCP targets over supported transports.

pub mod auth_diagnostics;
pub mod auth_discovery;
pub mod catalog_contract;
pub mod catalog_profile;
pub mod connect;
pub mod errors;
pub mod options;
pub mod schema_compat;
pub mod timing;

use crate::allowlist::{
    apply_expect_auth_required, enforce_host_allowlist, enforce_stdio_allowlist,
    parse_allowed_hosts_env,
};
use crate::logging::{stderr_logger, LogFormat, LogLevel, Logger};
use crate::probe::auth_diagnostics::classify_stateful_session_required_response;
use crate::probe::auth_discovery::discover_auth;
use crate::probe::catalog_contract::{
    build_catalog_contract_step, effective_descriptor_profile, evaluate_catalog_contract,
    CatalogContractSnapshot,
};
use crate::probe::catalog_profile::{build_catalog_profile_step, evaluate_catalog_profile};
use crate::probe::connect::{connect_with_retry, ProbeConnectError, ProbeConnection};
use crate::probe::errors::{describe_error, error_data};
use crate::probe::schema_compat::{
    build_tool_schema_compatibility_step_for_profile, ToolDescriptorProfile,
};
use crate::report::{
    build_catalog_artifact, now_iso, AuthDiscovery, CatalogContract, CatalogMethodSummary,
    CatalogPayloadRefs, CatalogProfile, HttpSmokeReport, ProbeReport, ProbeStep, ProbeStepStatus,
    RawRequestReport, TraceEntry,
};
use crate::transport::TransportType;
use anyhow::anyhow;
use mcp_toolkit_core::rmcp_models;
use rmcp::model::{
    ClientRequest, CustomRequest, ListPromptsResult, ListResourceTemplatesResult,
    ListResourcesResult, ListToolsResult, PingRequest,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

/// Default client name used for probe connections.
pub const DEFAULT_CLIENT_NAME: &str = "mcp-toolkit";
/// Default client version used for probe connections.
pub const DEFAULT_CLIENT_VERSION: &str = "0.0.0";
const MAX_DISCOVERY_LIST_PAGES: usize = 64;

/// Probe target configuration for connection-based checks.
#[derive(Debug, Clone)]
pub struct ProbeTarget {
    pub transport_type: TransportType,
    pub command: Option<String>,
    pub args: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub env: Option<HashMap<String, String>>,
    pub url: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub timeout_ms: Option<u64>,
    pub retries: Option<u32>,
    pub retry_delay_ms: Option<u64>,
    pub expect_auth_required: Option<bool>,
    pub log_level: Option<LogLevel>,
    pub log_format: Option<LogFormat>,
    pub trace: Option<bool>,
    pub trace_limit: Option<usize>,
    pub trace_max_bytes: Option<usize>,
    pub descriptor_profile: Option<ToolDescriptorProfile>,
    pub catalog_profile: Option<CatalogProfile>,
    pub catalog_contract: Option<CatalogContract>,
}

/// Target configuration for auth discovery.
#[derive(Debug, Clone)]
pub struct AuthDiscoveryTarget {
    pub url: Option<String>,
    pub timeout_ms: Option<u64>,
    pub expect_auth_required: Option<bool>,
    pub expect_registration_endpoint: Option<bool>,
}

/// Target configuration for HTTP smoke checks.
pub type HttpSmokeTarget = AuthDiscoveryTarget;

fn apply_expect_registration_endpoint(
    steps: &mut Vec<ProbeStep>,
    auth: Option<&AuthDiscovery>,
    expect_registration_endpoint: Option<bool>,
) {
    let advertised = auth
        .and_then(|value| value.registration_endpoint.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some();
    let expected = expect_registration_endpoint.unwrap_or(false);
    let (status, detail) = if expected {
        if advertised {
            (
                ProbeStepStatus::Ok,
                "registration_endpoint advertised".to_string(),
            )
        } else {
            (
                ProbeStepStatus::Error,
                "Missing registration_endpoint in OAuth metadata".to_string(),
            )
        }
    } else if advertised {
        (
            ProbeStepStatus::Ok,
            "registration_endpoint advertised".to_string(),
        )
    } else {
        (
            ProbeStepStatus::Ok,
            "registration_endpoint not advertised".to_string(),
        )
    };
    steps.push(ProbeStep {
        name: "auth.oauth.registration".to_string(),
        status,
        detail: Some(detail),
        data: auth
            .and_then(|value| value.registration_endpoint.as_ref())
            .map(|value| serde_json::json!({ "registration_endpoint": value })),
    });
}

/// Expected error configuration for raw requests.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ExpectError {
    Bool(bool),
    String(String),
}

/// Target configuration for raw JSON-RPC requests.
#[derive(Debug, Clone)]
pub struct RawRequestTarget {
    pub transport_type: TransportType,
    pub command: Option<String>,
    pub args: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub env: Option<HashMap<String, String>>,
    pub url: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub timeout_ms: Option<u64>,
    pub retries: Option<u32>,
    pub retry_delay_ms: Option<u64>,
    pub expect_auth_required: Option<bool>,
    pub log_level: Option<LogLevel>,
    pub log_format: Option<LogFormat>,
    pub trace: Option<bool>,
    pub trace_limit: Option<usize>,
    pub trace_max_bytes: Option<usize>,
    pub method: String,
    pub params: Option<Value>,
    pub expect_error: Option<ExpectError>,
}

/// Build the canonical MCP prompts/get params object used by prompt render probes.
pub fn build_prompt_render_params(
    prompt_name: &str,
    arguments: Option<HashMap<String, Value>>,
) -> Value {
    let mut params = Map::new();
    params.insert("name".to_string(), Value::String(prompt_name.to_string()));
    if let Some(arguments) = arguments {
        params.insert(
            "arguments".to_string(),
            Value::Object(arguments.into_iter().collect()),
        );
    }
    Value::Object(params)
}

/// Build the canonical MCP resource params object used by resource probes.
pub fn build_resource_uri_params(uri: &str) -> Value {
    let mut params = Map::new();
    params.insert("uri".to_string(), Value::String(uri.to_string()));
    Value::Object(params)
}

fn resolve_expect_error(expect_error: &Option<ExpectError>) -> (bool, Option<&str>) {
    match expect_error {
        Some(ExpectError::Bool(true)) => (true, None),
        Some(ExpectError::Bool(false)) | None => (false, None),
        Some(ExpectError::String(value)) => (true, Some(value.as_str())),
    }
}

fn probe_logger(log_level: Option<LogLevel>, log_format: Option<LogFormat>) -> Option<Logger> {
    log_level.map(|level| {
        let format = log_format.unwrap_or(LogFormat::Json);
        stderr_logger(level, format)
    })
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

fn is_expected_auth_required_connect_error(
    steps: &[ProbeStep],
    auth: Option<&AuthDiscovery>,
    message: &str,
    expect_auth_required: Option<bool>,
) -> bool {
    expect_auth_required == Some(true)
        && steps
            .iter()
            .any(|step| step.name == "expect.auth_required" && step.status == ProbeStepStatus::Ok)
        && auth
            .map(|discovery| {
                discovery.resource_metadata_url.is_some()
                    || discovery.resource_metadata.is_some()
                    || discovery.authorization_server.is_some()
            })
            .unwrap_or(false)
        && (contains_ci(message, "missing token")
            || contains_ci(message, "missing bearer")
            || contains_ci(message, "auth required")
            || contains_ci(message, "auth.missing_token")
            || contains_ci(message, "unauthorized")
            || contains_ci(message, "401"))
}

fn map_error_step(
    name: &str,
    error: anyhow::Error,
    stdio: Option<Value>,
    trace: Option<Value>,
) -> ProbeStep {
    let details = describe_error(&error);
    let mut data_map = serde_json::Map::new();
    if let Some(data) = error_data(&details) {
        if let Value::Object(map) = data {
            data_map.extend(map);
        } else {
            data_map.insert("error".to_string(), data);
        }
    }
    if let Some(stdio) = stdio {
        data_map.insert("stdio".to_string(), stdio);
    }
    if let Some(trace) = trace {
        data_map.insert("trace".to_string(), trace);
    }
    ProbeStep {
        name: name.to_string(),
        status: ProbeStepStatus::Error,
        detail: Some(details.message),
        data: if data_map.is_empty() {
            None
        } else {
            Some(Value::Object(data_map))
        },
    }
}

fn map_expected_auth_required_connect_step(
    error: &anyhow::Error,
    stdio: Option<Value>,
    trace: Option<Value>,
) -> ProbeStep {
    let details = describe_error(error);
    let mut data_map = serde_json::Map::new();
    data_map.insert("expected_auth_required".to_string(), Value::Bool(true));
    data_map.insert(
        "connect_error".to_string(),
        Value::String(details.message.clone()),
    );
    if let Some(data) = error_data(&details) {
        data_map.insert("connect_error_data".to_string(), data);
    }
    if let Some(stdio) = stdio {
        data_map.insert("stdio".to_string(), stdio);
    }
    if let Some(trace) = trace {
        data_map.insert("trace".to_string(), trace);
    }
    ProbeStep {
        name: "connect.auth_required".to_string(),
        status: ProbeStepStatus::Ok,
        detail: Some(
            "Auth challenge detected as expected; handshake stopped before authenticated initialization."
                .to_string(),
        ),
        data: Some(Value::Object(data_map)),
    }
}

fn connection_error_payload(error: &anyhow::Error) -> (Option<Value>, Option<Value>) {
    let Some(connect_error) = error.downcast_ref::<ProbeConnectError>() else {
        return (None, None);
    };
    let stdio = connect_error
        .stdio
        .as_ref()
        .and_then(|snapshot| serde_json::to_value(snapshot).ok());
    let trace = connect_error
        .trace
        .as_ref()
        .and_then(|entries| serde_json::to_value(entries).ok());
    (stdio, trace)
}

fn push_tool_schema_compatibility_step(
    steps: &mut Vec<ProbeStep>,
    tools_value: Option<&Value>,
    descriptor_profile: Option<ToolDescriptorProfile>,
    logger: &mut Option<Logger>,
) {
    let Some(tools_value) = tools_value else {
        return;
    };
    let step = build_tool_schema_compatibility_step_for_profile(
        tools_value,
        descriptor_profile.unwrap_or_default(),
    );
    if let Some(logger) = logger.as_mut() {
        if step.status == ProbeStepStatus::Ok {
            logger.info("probe.tools.schema_compatibility.ok", step.data.clone());
        } else {
            logger.error("probe.tools.schema_compatibility.error", step.data.clone());
        }
    }
    steps.push(step);
}

struct ToolListPages {
    result: ListToolsResult,
    page_count: usize,
    tool_names: Vec<String>,
}

struct ResourceListPages {
    result: ListResourcesResult,
    page_count: usize,
    resource_uris: Vec<String>,
}

struct ResourceTemplateListPages {
    result: ListResourceTemplatesResult,
    page_count: usize,
    resource_template_uris: Vec<String>,
}

struct PromptListPages {
    result: ListPromptsResult,
    page_count: usize,
    prompt_names: Vec<String>,
}

async fn list_all_tool_pages(
    connection: &ProbeConnection,
    probe_options: &options::ProbeOptions,
    logger: &mut Option<Logger>,
) -> anyhow::Result<ToolListPages> {
    let mut cursor: Option<String> = None;
    let mut tools = Vec::new();
    let mut tool_names = Vec::new();
    let mut page_count = 0usize;

    loop {
        let cursor_for_request = cursor.clone();
        let result = timing::with_retry(
            || {
                timing::with_timeout(
                    connection
                        .service
                        .list_tools(Some(rmcp_models::paginated_request_params(
                            cursor_for_request.clone(),
                        ))),
                    probe_options.timeout_ms,
                    "tools.list",
                )
            },
            probe_options.retries,
            probe_options.retry_delay_ms,
        )
        .await?;

        page_count += 1;
        let page_tool_names: Vec<String> = result
            .tools
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        if let Some(logger) = logger.as_mut() {
            logger.info(
                "probe.tools.list.page.ok",
                Some(json!({
                    "page": page_count,
                    "count": page_tool_names.len(),
                    "next_cursor_present": result
                        .next_cursor
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty()),
                    "tool_names": page_tool_names,
                })),
            );
        }

        tool_names.extend(result.tools.iter().map(|tool| tool.name.to_string()));
        tools.extend(result.tools);

        let Some(next_cursor) = result
            .next_cursor
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
        else {
            break;
        };
        if page_count >= MAX_DISCOVERY_LIST_PAGES {
            return Err(anyhow!(
                "tools/list pagination exceeded {MAX_DISCOVERY_LIST_PAGES} pages without reaching the end"
            ));
        }
        cursor = Some(next_cursor);
    }

    Ok(ToolListPages {
        result: ListToolsResult {
            meta: None,
            tools,
            next_cursor: None,
        },
        page_count,
        tool_names,
    })
}

async fn list_all_resource_pages(
    connection: &ProbeConnection,
    probe_options: &options::ProbeOptions,
    logger: &mut Option<Logger>,
) -> anyhow::Result<ResourceListPages> {
    let mut cursor: Option<String> = None;
    let mut resources = Vec::new();
    let mut resource_uris = Vec::new();
    let mut page_count = 0usize;

    loop {
        let cursor_for_request = cursor.clone();
        let result =
            timing::with_retry(
                || {
                    timing::with_timeout(
                        connection.service.list_resources(Some(
                            rmcp_models::paginated_request_params(cursor_for_request.clone()),
                        )),
                        probe_options.timeout_ms,
                        "resources.list",
                    )
                },
                probe_options.retries,
                probe_options.retry_delay_ms,
            )
            .await?;

        page_count += 1;
        let page_resource_uris: Vec<String> = result
            .resources
            .iter()
            .map(|resource| resource.uri.clone())
            .collect();
        if let Some(logger) = logger.as_mut() {
            logger.info(
                "probe.resources.list.page.ok",
                Some(json!({
                    "page": page_count,
                    "count": page_resource_uris.len(),
                    "next_cursor_present": result
                        .next_cursor
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty()),
                    "resource_uris": page_resource_uris,
                })),
            );
        }

        resource_uris.extend(page_resource_uris.clone());
        resources.extend(result.resources);

        let Some(next_cursor) = result
            .next_cursor
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
        else {
            break;
        };
        if page_count >= MAX_DISCOVERY_LIST_PAGES {
            return Err(anyhow!(
                "resources/list pagination exceeded {MAX_DISCOVERY_LIST_PAGES} pages without reaching the end"
            ));
        }
        cursor = Some(next_cursor);
    }

    Ok(ResourceListPages {
        result: ListResourcesResult {
            meta: None,
            resources,
            next_cursor: None,
        },
        page_count,
        resource_uris,
    })
}

async fn list_all_resource_template_pages(
    connection: &ProbeConnection,
    probe_options: &options::ProbeOptions,
    logger: &mut Option<Logger>,
) -> anyhow::Result<ResourceTemplateListPages> {
    let mut cursor: Option<String> = None;
    let mut resource_templates = Vec::new();
    let mut resource_template_uris = Vec::new();
    let mut page_count = 0usize;

    loop {
        let cursor_for_request = cursor.clone();
        let result = timing::with_retry(
            || {
                timing::with_timeout(
                    connection.service.list_resource_templates(Some(
                        rmcp_models::paginated_request_params(cursor_for_request.clone()),
                    )),
                    probe_options.timeout_ms,
                    "resources.templates.list",
                )
            },
            probe_options.retries,
            probe_options.retry_delay_ms,
        )
        .await?;

        page_count += 1;
        let page_template_uris: Vec<String> = result
            .resource_templates
            .iter()
            .map(|template| template.uri_template.clone())
            .collect();
        if let Some(logger) = logger.as_mut() {
            logger.info(
                "probe.resource_templates.list.page.ok",
                Some(json!({
                    "page": page_count,
                    "count": page_template_uris.len(),
                    "next_cursor_present": result
                        .next_cursor
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty()),
                    "resource_template_uris": page_template_uris,
                })),
            );
        }

        resource_template_uris.extend(page_template_uris.clone());
        resource_templates.extend(result.resource_templates);

        let Some(next_cursor) = result
            .next_cursor
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
        else {
            break;
        };
        if page_count >= MAX_DISCOVERY_LIST_PAGES {
            return Err(anyhow!(
                "resources/templates/list pagination exceeded {MAX_DISCOVERY_LIST_PAGES} pages without reaching the end"
            ));
        }
        cursor = Some(next_cursor);
    }

    Ok(ResourceTemplateListPages {
        result: ListResourceTemplatesResult {
            meta: None,
            resource_templates,
            next_cursor: None,
        },
        page_count,
        resource_template_uris,
    })
}

async fn list_all_prompt_pages(
    connection: &ProbeConnection,
    probe_options: &options::ProbeOptions,
    logger: &mut Option<Logger>,
) -> anyhow::Result<PromptListPages> {
    let mut cursor: Option<String> = None;
    let mut prompts = Vec::new();
    let mut prompt_names = Vec::new();
    let mut page_count = 0usize;

    loop {
        let cursor_for_request = cursor.clone();
        let result =
            timing::with_retry(
                || {
                    timing::with_timeout(
                        connection.service.list_prompts(Some(
                            rmcp_models::paginated_request_params(cursor_for_request.clone()),
                        )),
                        probe_options.timeout_ms,
                        "prompts.list",
                    )
                },
                probe_options.retries,
                probe_options.retry_delay_ms,
            )
            .await?;

        page_count += 1;
        let page_prompt_names: Vec<String> = result
            .prompts
            .iter()
            .map(|prompt| prompt.name.clone())
            .collect();
        if let Some(logger) = logger.as_mut() {
            logger.info(
                "probe.prompts.list.page.ok",
                Some(json!({
                    "page": page_count,
                    "count": page_prompt_names.len(),
                    "next_cursor_present": result
                        .next_cursor
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty()),
                    "prompt_names": page_prompt_names,
                })),
            );
        }

        prompt_names.extend(page_prompt_names.clone());
        prompts.extend(result.prompts);

        let Some(next_cursor) = result
            .next_cursor
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
        else {
            break;
        };
        if page_count >= MAX_DISCOVERY_LIST_PAGES {
            return Err(anyhow!(
                "prompts/list pagination exceeded {MAX_DISCOVERY_LIST_PAGES} pages without reaching the end"
            ));
        }
        cursor = Some(next_cursor);
    }

    Ok(PromptListPages {
        result: ListPromptsResult {
            meta: None,
            prompts,
            next_cursor: None,
        },
        page_count,
        prompt_names,
    })
}

/// Run a full probe (connect + discovery).
pub async fn run_probe(
    target: ProbeTarget,
    client_name: Option<&str>,
    client_version: Option<&str>,
) -> ProbeReport {
    let started_at = now_iso();
    let mut steps: Vec<ProbeStep> = Vec::new();
    let probe_options =
        options::resolve_probe_options(target.timeout_ms, target.retries, target.retry_delay_ms);
    let allowed_hosts = parse_allowed_hosts_env();
    let mut logger = probe_logger(target.log_level, target.log_format);

    let stdio_ok = enforce_stdio_allowlist(target.transport_type.as_str(), &mut steps);
    let allowlist_ok = if stdio_ok {
        enforce_host_allowlist(
            target.transport_type.as_str(),
            target.url.as_deref(),
            &mut steps,
            allowed_hosts.as_deref(),
        )
    } else {
        false
    };
    let auth = if stdio_ok && allowlist_ok {
        discover_auth(
            target.transport_type,
            target.url.as_deref(),
            &mut steps,
            probe_options.timeout_ms,
            allowed_hosts.as_deref(),
        )
        .await
    } else {
        None
    };

    if !stdio_ok || !allowlist_ok {
        return ProbeReport {
            ok: false,
            started_at,
            finished_at: now_iso(),
            steps,
            auth,
            server_info: None,
            capabilities: None,
            tools: None,
            resources: None,
            resource_templates: None,
            prompts: None,
            catalog: None,
            trace: None,
        };
    }

    apply_expect_auth_required(&mut steps, target.expect_auth_required);

    let connect_result = connect_with_retry(
        target.transport_type,
        target.command.as_deref(),
        target.args.as_deref(),
        target.cwd.as_deref(),
        target.env.as_ref(),
        target.url.as_deref(),
        target.headers.as_ref(),
        probe_options,
        target.trace.unwrap_or(false),
        target.trace_limit,
        target.trace_max_bytes,
        client_name.unwrap_or(DEFAULT_CLIENT_NAME),
        client_version.unwrap_or(DEFAULT_CLIENT_VERSION),
    )
    .await;

    let mut connection = match connect_result {
        Ok(connection) => {
            steps.push(ProbeStep {
                name: "connect".to_string(),
                status: ProbeStepStatus::Ok,
                detail: None,
                data: None,
            });
            if let Some(logger) = logger.as_mut() {
                logger.info("probe.connect.ok", None);
            }
            connection
        }
        Err(error) => {
            let (stdio, trace) = connection_error_payload(&error);
            let details = describe_error(&error);
            if is_expected_auth_required_connect_error(
                &steps,
                auth.as_ref(),
                &details.message,
                target.expect_auth_required,
            ) {
                steps.push(map_expected_auth_required_connect_step(
                    &error, stdio, trace,
                ));
                if let Some(logger) = logger.as_mut() {
                    logger.info("probe.connect.auth_required_expected", None);
                }
                return ProbeReport {
                    ok: true,
                    started_at,
                    finished_at: now_iso(),
                    steps,
                    auth,
                    server_info: None,
                    capabilities: None,
                    tools: None,
                    resources: None,
                    resource_templates: None,
                    prompts: None,
                    catalog: None,
                    trace: None,
                };
            }
            steps.push(map_error_step("connect", error, stdio, trace));
            if let Some(logger) = logger.as_mut() {
                logger.error("probe.connect.error", None);
            }
            return ProbeReport {
                ok: false,
                started_at,
                finished_at: now_iso(),
                steps,
                auth: None,
                server_info: None,
                capabilities: None,
                tools: None,
                resources: None,
                resource_templates: None,
                prompts: None,
                catalog: None,
                trace: None,
            };
        }
    };

    let peer_info = connection.service.peer_info().cloned();
    let server_info_value = peer_info
        .as_ref()
        .and_then(|info| serde_json::to_value(&info.server_info).ok());
    let capabilities_value = peer_info
        .as_ref()
        .and_then(|info| serde_json::to_value(&info.capabilities).ok());

    steps.push(ProbeStep {
        name: "server.info".to_string(),
        status: ProbeStepStatus::Ok,
        detail: if server_info_value.is_some() {
            None
        } else {
            Some("not available".to_string())
        },
        data: None,
    });

    steps.push(ProbeStep {
        name: "capabilities".to_string(),
        status: ProbeStepStatus::Ok,
        detail: if capabilities_value.is_some() {
            None
        } else {
            Some("not available".to_string())
        },
        data: None,
    });

    let mut tools_value: Option<Value> = None;
    let mut resources_value: Option<Value> = None;
    let mut resource_templates_value: Option<Value> = None;
    let mut prompts_value: Option<Value> = None;
    let mut catalog_methods = Vec::new();

    let list_tools = list_all_tool_pages(&connection, &probe_options, &mut logger).await;
    match list_tools {
        Ok(result) => {
            let detail = format!(
                "discovered {} tools across {} page(s)",
                result.tool_names.len(),
                result.page_count
            );
            catalog_methods.push(CatalogMethodSummary {
                method: "tools/list".to_string(),
                status: ProbeStepStatus::Ok,
                detail: Some(detail.clone()),
                page_count: Some(result.page_count),
                item_count: Some(result.tool_names.len()),
            });
            tools_value = serde_json::to_value(result.result).ok();
            steps.push(ProbeStep {
                name: "tools.list".to_string(),
                status: ProbeStepStatus::Ok,
                detail: Some(detail),
                data: Some(json!({
                    "page_count": result.page_count,
                    "tool_count": result.tool_names.len(),
                    "tool_names": result.tool_names,
                })),
            });
            if let Some(logger) = logger.as_mut() {
                logger.info(
                    "probe.tools.list.ok",
                    steps.last().and_then(|step| step.data.clone()),
                );
            }
        }
        Err(error) => {
            let details = describe_error(&error);
            catalog_methods.push(CatalogMethodSummary {
                method: "tools/list".to_string(),
                status: ProbeStepStatus::Error,
                detail: Some(details.message.clone()),
                page_count: None,
                item_count: None,
            });
            steps.push(ProbeStep {
                name: "tools.list".to_string(),
                status: ProbeStepStatus::Error,
                detail: Some(details.message.clone()),
                data: error_data(&details),
            });
            if let Some(logger) = logger.as_mut() {
                logger.error("probe.tools.list.error", None);
            }
        }
    }
    let descriptor_profile =
        effective_descriptor_profile(target.descriptor_profile, target.catalog_profile);
    push_tool_schema_compatibility_step(
        &mut steps,
        tools_value.as_ref(),
        Some(descriptor_profile),
        &mut logger,
    );

    let resources_supported = peer_info
        .as_ref()
        .and_then(|info| info.capabilities.resources.as_ref())
        .is_some();
    if resources_supported {
        let list_resources =
            list_all_resource_pages(&connection, &probe_options, &mut logger).await;
        match list_resources {
            Ok(result) => {
                let detail = format!(
                    "discovered {} resources across {} page(s)",
                    result.resource_uris.len(),
                    result.page_count
                );
                catalog_methods.push(CatalogMethodSummary {
                    method: "resources/list".to_string(),
                    status: ProbeStepStatus::Ok,
                    detail: Some(detail.clone()),
                    page_count: Some(result.page_count),
                    item_count: Some(result.resource_uris.len()),
                });
                resources_value = serde_json::to_value(result.result).ok();
                steps.push(ProbeStep {
                    name: "resources.list".to_string(),
                    status: ProbeStepStatus::Ok,
                    detail: Some(detail),
                    data: Some(json!({
                        "page_count": result.page_count,
                        "resource_count": result.resource_uris.len(),
                        "resource_uris": result.resource_uris,
                    })),
                });
                if let Some(logger) = logger.as_mut() {
                    logger.info(
                        "probe.resources.list.ok",
                        steps.last().and_then(|step| step.data.clone()),
                    );
                }
            }
            Err(error) => {
                let details = describe_error(&error);
                catalog_methods.push(CatalogMethodSummary {
                    method: "resources/list".to_string(),
                    status: ProbeStepStatus::Error,
                    detail: Some(details.message.clone()),
                    page_count: None,
                    item_count: None,
                });
                steps.push(ProbeStep {
                    name: "resources.list".to_string(),
                    status: ProbeStepStatus::Error,
                    detail: Some(details.message.clone()),
                    data: error_data(&details),
                });
                if let Some(logger) = logger.as_mut() {
                    logger.error("probe.resources.list.error", None);
                }
            }
        }
        let list_resource_templates =
            list_all_resource_template_pages(&connection, &probe_options, &mut logger).await;
        match list_resource_templates {
            Ok(result) => {
                let detail = format!(
                    "discovered {} resource templates across {} page(s)",
                    result.resource_template_uris.len(),
                    result.page_count
                );
                catalog_methods.push(CatalogMethodSummary {
                    method: "resources/templates/list".to_string(),
                    status: ProbeStepStatus::Ok,
                    detail: Some(detail.clone()),
                    page_count: Some(result.page_count),
                    item_count: Some(result.resource_template_uris.len()),
                });
                resource_templates_value = serde_json::to_value(result.result).ok();
                steps.push(ProbeStep {
                    name: "resources.templates.list".to_string(),
                    status: ProbeStepStatus::Ok,
                    detail: Some(detail),
                    data: Some(json!({
                        "page_count": result.page_count,
                        "resource_template_count": result.resource_template_uris.len(),
                        "resource_template_uris": result.resource_template_uris,
                    })),
                });
                if let Some(logger) = logger.as_mut() {
                    logger.info(
                        "probe.resource_templates.list.ok",
                        steps.last().and_then(|step| step.data.clone()),
                    );
                }
            }
            Err(error) => {
                let details = describe_error(&error);
                catalog_methods.push(CatalogMethodSummary {
                    method: "resources/templates/list".to_string(),
                    status: ProbeStepStatus::Error,
                    detail: Some(details.message.clone()),
                    page_count: None,
                    item_count: None,
                });
                steps.push(ProbeStep {
                    name: "resources.templates.list".to_string(),
                    status: ProbeStepStatus::Error,
                    detail: Some(details.message.clone()),
                    data: error_data(&details),
                });
                if let Some(logger) = logger.as_mut() {
                    logger.error("probe.resource_templates.list.error", None);
                }
            }
        }
    } else {
        catalog_methods.push(CatalogMethodSummary {
            method: "resources/list".to_string(),
            status: ProbeStepStatus::Ok,
            detail: Some("not supported".to_string()),
            page_count: None,
            item_count: None,
        });
        catalog_methods.push(CatalogMethodSummary {
            method: "resources/templates/list".to_string(),
            status: ProbeStepStatus::Ok,
            detail: Some("not supported".to_string()),
            page_count: None,
            item_count: None,
        });
        steps.push(ProbeStep {
            name: "resources.list".to_string(),
            status: ProbeStepStatus::Ok,
            detail: Some("not supported".to_string()),
            data: None,
        });
        steps.push(ProbeStep {
            name: "resources.templates.list".to_string(),
            status: ProbeStepStatus::Ok,
            detail: Some("not supported".to_string()),
            data: None,
        });
    }

    let prompts_supported = peer_info
        .as_ref()
        .and_then(|info| info.capabilities.prompts.as_ref())
        .is_some();
    if prompts_supported {
        let list_prompts = list_all_prompt_pages(&connection, &probe_options, &mut logger).await;
        match list_prompts {
            Ok(result) => {
                let detail = format!(
                    "discovered {} prompts across {} page(s)",
                    result.prompt_names.len(),
                    result.page_count
                );
                catalog_methods.push(CatalogMethodSummary {
                    method: "prompts/list".to_string(),
                    status: ProbeStepStatus::Ok,
                    detail: Some(detail.clone()),
                    page_count: Some(result.page_count),
                    item_count: Some(result.prompt_names.len()),
                });
                prompts_value = serde_json::to_value(result.result).ok();
                steps.push(ProbeStep {
                    name: "prompts.list".to_string(),
                    status: ProbeStepStatus::Ok,
                    detail: Some(detail),
                    data: Some(json!({
                        "page_count": result.page_count,
                        "prompt_count": result.prompt_names.len(),
                        "prompt_names": result.prompt_names,
                    })),
                });
                if let Some(logger) = logger.as_mut() {
                    logger.info(
                        "probe.prompts.list.ok",
                        steps.last().and_then(|step| step.data.clone()),
                    );
                }
            }
            Err(error) => {
                let details = describe_error(&error);
                catalog_methods.push(CatalogMethodSummary {
                    method: "prompts/list".to_string(),
                    status: ProbeStepStatus::Error,
                    detail: Some(details.message.clone()),
                    page_count: None,
                    item_count: None,
                });
                steps.push(ProbeStep {
                    name: "prompts.list".to_string(),
                    status: ProbeStepStatus::Error,
                    detail: Some(details.message.clone()),
                    data: error_data(&details),
                });
                if let Some(logger) = logger.as_mut() {
                    logger.error("probe.prompts.list.error", None);
                }
            }
        }
    } else {
        catalog_methods.push(CatalogMethodSummary {
            method: "prompts/list".to_string(),
            status: ProbeStepStatus::Ok,
            detail: Some("not supported".to_string()),
            page_count: None,
            item_count: None,
        });
        steps.push(ProbeStep {
            name: "prompts.list".to_string(),
            status: ProbeStepStatus::Ok,
            detail: Some("not supported".to_string()),
            data: None,
        });
    }

    let disconnect_result = connection.service.close().await;
    match disconnect_result {
        Ok(_) => {
            steps.push(ProbeStep {
                name: "disconnect".to_string(),
                status: ProbeStepStatus::Ok,
                detail: None,
                data: None,
            });
            if let Some(logger) = logger.as_mut() {
                logger.info("probe.disconnect.ok", None);
            }
        }
        Err(err) => {
            let error = anyhow!(err);
            let details = describe_error(&error);
            steps.push(ProbeStep {
                name: "disconnect".to_string(),
                status: ProbeStepStatus::Error,
                detail: Some(details.message.clone()),
                data: error_data(&details),
            });
            if let Some(logger) = logger.as_mut() {
                logger.error("probe.disconnect.error", None);
            }
        }
    }

    if let Some(stdio) = connection.stdio.take() {
        let snapshot = stdio.snapshot();
        stdio.stop();
        if !snapshot.lines.is_empty() || snapshot.exit_code.is_some() || snapshot.signal.is_some() {
            if let Ok(data) = serde_json::to_value(snapshot) {
                steps.push(ProbeStep {
                    name: "stdio.stderr".to_string(),
                    status: ProbeStepStatus::Ok,
                    detail: None,
                    data: Some(data),
                });
            }
        }
    }

    let catalog_profile_verdict = target
        .catalog_profile
        .map(|profile| evaluate_catalog_profile(profile, &catalog_methods));
    if let Some(verdict) = catalog_profile_verdict.as_ref() {
        steps.push(build_catalog_profile_step(verdict));
    }
    let catalog_contract_verdict = target.catalog_contract.as_ref().map(|contract| {
        evaluate_catalog_contract(
            contract,
            CatalogContractSnapshot {
                transport: target.transport_type,
                catalog_profile: target.catalog_profile,
                descriptor_profile,
                tools: tools_value.as_ref(),
                resources: resources_value.as_ref(),
                resource_templates: resource_templates_value.as_ref(),
                prompts: prompts_value.as_ref(),
            },
        )
    });
    if let Some(verdict) = catalog_contract_verdict.as_ref() {
        steps.push(build_catalog_contract_step(verdict));
    }

    let trace_entries: Option<Vec<TraceEntry>> =
        connection.trace.map(|collector| collector.entries());

    let ok = steps.iter().all(|step| step.status == ProbeStepStatus::Ok);
    if let Some(logger) = logger.as_mut() {
        logger.info("probe.finished", Some(Value::Bool(ok)));
    }
    let finished_at = now_iso();
    let catalog = Some(build_catalog_artifact(
        finished_at.clone(),
        catalog_methods,
        catalog_profile_verdict,
        catalog_contract_verdict,
        CatalogPayloadRefs {
            server_info: server_info_value.as_ref(),
            capabilities: capabilities_value.as_ref(),
            tools: tools_value.as_ref(),
            resources: resources_value.as_ref(),
            resource_templates: resource_templates_value.as_ref(),
            prompts: prompts_value.as_ref(),
        },
    ));
    ProbeReport {
        ok,
        started_at,
        finished_at,
        steps,
        auth,
        server_info: server_info_value,
        capabilities: capabilities_value,
        tools: tools_value,
        resources: resources_value,
        resource_templates: resource_templates_value,
        prompts: prompts_value,
        catalog,
        trace: trace_entries,
    }
}

/// Run a fast handshake probe (connect + ping + list tools).
pub async fn run_probe_handshake(
    target: ProbeTarget,
    client_name: Option<&str>,
    client_version: Option<&str>,
) -> ProbeReport {
    let started_at = now_iso();
    let mut steps: Vec<ProbeStep> = Vec::new();
    let probe_options =
        options::resolve_probe_options(target.timeout_ms, target.retries, target.retry_delay_ms);
    let allowed_hosts = parse_allowed_hosts_env();
    let mut logger = probe_logger(target.log_level, target.log_format);

    let stdio_ok = enforce_stdio_allowlist(target.transport_type.as_str(), &mut steps);
    let allowlist_ok = if stdio_ok {
        enforce_host_allowlist(
            target.transport_type.as_str(),
            target.url.as_deref(),
            &mut steps,
            allowed_hosts.as_deref(),
        )
    } else {
        false
    };
    let auth = if stdio_ok && allowlist_ok {
        discover_auth(
            target.transport_type,
            target.url.as_deref(),
            &mut steps,
            probe_options.timeout_ms,
            allowed_hosts.as_deref(),
        )
        .await
    } else {
        None
    };

    if !stdio_ok || !allowlist_ok {
        return ProbeReport {
            ok: false,
            started_at,
            finished_at: now_iso(),
            steps,
            auth,
            server_info: None,
            capabilities: None,
            tools: None,
            resources: None,
            resource_templates: None,
            prompts: None,
            catalog: None,
            trace: None,
        };
    }

    apply_expect_auth_required(&mut steps, target.expect_auth_required);

    let connect_result = connect_with_retry(
        target.transport_type,
        target.command.as_deref(),
        target.args.as_deref(),
        target.cwd.as_deref(),
        target.env.as_ref(),
        target.url.as_deref(),
        target.headers.as_ref(),
        probe_options,
        target.trace.unwrap_or(false),
        target.trace_limit,
        target.trace_max_bytes,
        client_name.unwrap_or(DEFAULT_CLIENT_NAME),
        client_version.unwrap_or(DEFAULT_CLIENT_VERSION),
    )
    .await;

    let mut connection = match connect_result {
        Ok(connection) => {
            steps.push(ProbeStep {
                name: "connect".to_string(),
                status: ProbeStepStatus::Ok,
                detail: None,
                data: None,
            });
            if let Some(logger) = logger.as_mut() {
                logger.info("probe.connect.ok", None);
            }
            connection
        }
        Err(error) => {
            let (stdio, trace) = connection_error_payload(&error);
            let details = describe_error(&error);
            if is_expected_auth_required_connect_error(
                &steps,
                auth.as_ref(),
                &details.message,
                target.expect_auth_required,
            ) {
                steps.push(map_expected_auth_required_connect_step(
                    &error, stdio, trace,
                ));
                if let Some(logger) = logger.as_mut() {
                    logger.info("probe.connect.auth_required_expected", None);
                }
                return ProbeReport {
                    ok: true,
                    started_at,
                    finished_at: now_iso(),
                    steps,
                    auth,
                    server_info: None,
                    capabilities: None,
                    tools: None,
                    resources: None,
                    resource_templates: None,
                    prompts: None,
                    catalog: None,
                    trace: None,
                };
            }
            steps.push(map_error_step("connect", error, stdio, trace));
            if let Some(logger) = logger.as_mut() {
                logger.error("probe.connect.error", None);
            }
            return ProbeReport {
                ok: false,
                started_at,
                finished_at: now_iso(),
                steps,
                auth,
                server_info: None,
                capabilities: None,
                tools: None,
                resources: None,
                resource_templates: None,
                prompts: None,
                catalog: None,
                trace: None,
            };
        }
    };

    let peer_info = connection.service.peer_info().cloned();
    let server_info_value = peer_info
        .as_ref()
        .and_then(|info| serde_json::to_value(&info.server_info).ok());
    let capabilities_value = peer_info
        .as_ref()
        .and_then(|info| serde_json::to_value(&info.capabilities).ok());

    steps.push(ProbeStep {
        name: "server.info".to_string(),
        status: ProbeStepStatus::Ok,
        detail: if server_info_value.is_some() {
            None
        } else {
            Some("not available".to_string())
        },
        data: None,
    });

    steps.push(ProbeStep {
        name: "capabilities".to_string(),
        status: ProbeStepStatus::Ok,
        detail: if capabilities_value.is_some() {
            None
        } else {
            Some("not available".to_string())
        },
        data: None,
    });

    let ping_result = timing::with_retry(
        || {
            timing::with_timeout(
                connection
                    .service
                    .send_request(ClientRequest::PingRequest(PingRequest::default())),
                probe_options.timeout_ms,
                "ping",
            )
        },
        probe_options.retries,
        probe_options.retry_delay_ms,
    )
    .await;
    match ping_result {
        Ok(result) => {
            let data = serde_json::to_value(result).ok();
            steps.push(ProbeStep {
                name: "ping".to_string(),
                status: ProbeStepStatus::Ok,
                detail: None,
                data,
            });
            if let Some(logger) = logger.as_mut() {
                logger.info("probe.ping.ok", None);
            }
        }
        Err(error) => {
            let details = describe_error(&error);
            steps.push(ProbeStep {
                name: "ping".to_string(),
                status: ProbeStepStatus::Error,
                detail: Some(details.message.clone()),
                data: error_data(&details),
            });
            if let Some(logger) = logger.as_mut() {
                logger.error("probe.ping.error", None);
            }
        }
    }

    let mut tools_value: Option<Value> = None;
    let list_tools = list_all_tool_pages(&connection, &probe_options, &mut logger).await;
    match list_tools {
        Ok(result) => {
            tools_value = serde_json::to_value(result.result).ok();
            steps.push(ProbeStep {
                name: "tools.list".to_string(),
                status: ProbeStepStatus::Ok,
                detail: Some(format!(
                    "discovered {} tools across {} page(s)",
                    result.tool_names.len(),
                    result.page_count
                )),
                data: Some(json!({
                    "page_count": result.page_count,
                    "tool_count": result.tool_names.len(),
                    "tool_names": result.tool_names,
                })),
            });
            if let Some(logger) = logger.as_mut() {
                logger.info(
                    "probe.tools.list.ok",
                    steps.last().and_then(|step| step.data.clone()),
                );
            }
        }
        Err(error) => {
            let details = describe_error(&error);
            steps.push(ProbeStep {
                name: "tools.list".to_string(),
                status: ProbeStepStatus::Error,
                detail: Some(details.message.clone()),
                data: error_data(&details),
            });
            if let Some(logger) = logger.as_mut() {
                logger.error("probe.tools.list.error", None);
            }
        }
    }
    push_tool_schema_compatibility_step(
        &mut steps,
        tools_value.as_ref(),
        Some(effective_descriptor_profile(
            target.descriptor_profile,
            target.catalog_profile,
        )),
        &mut logger,
    );

    let _ = connection.service.close().await;

    if let Some(stdio) = connection.stdio.take() {
        let snapshot = stdio.snapshot();
        stdio.stop();
        if !snapshot.lines.is_empty() || snapshot.exit_code.is_some() || snapshot.signal.is_some() {
            if let Ok(data) = serde_json::to_value(snapshot) {
                steps.push(ProbeStep {
                    name: "stdio.stderr".to_string(),
                    status: ProbeStepStatus::Ok,
                    detail: None,
                    data: Some(data),
                });
            }
        }
    }

    let trace_entries: Option<Vec<TraceEntry>> =
        connection.trace.map(|collector| collector.entries());
    let ok = steps.iter().all(|step| step.status == ProbeStepStatus::Ok);
    if let Some(logger) = logger.as_mut() {
        logger.info("probe.handshake.finished", Some(Value::Bool(ok)));
    }
    ProbeReport {
        ok,
        started_at,
        finished_at: now_iso(),
        steps,
        auth,
        server_info: server_info_value,
        capabilities: capabilities_value,
        tools: tools_value,
        resources: None,
        resource_templates: None,
        prompts: None,
        catalog: None,
        trace: trace_entries,
    }
}

/// Run auth discovery without connecting.
pub async fn run_auth_discovery(target: AuthDiscoveryTarget) -> HttpSmokeReport {
    let started_at = now_iso();
    let mut steps: Vec<ProbeStep> = Vec::new();
    let allowed_hosts = parse_allowed_hosts_env();
    let probe_options = options::resolve_probe_options(target.timeout_ms, None, None);

    let allowlist_ok = enforce_host_allowlist(
        TransportType::StreamableHttp.as_str(),
        target.url.as_deref(),
        &mut steps,
        allowed_hosts.as_deref(),
    );
    let auth = if allowlist_ok {
        discover_auth(
            TransportType::StreamableHttp,
            target.url.as_deref(),
            &mut steps,
            probe_options.timeout_ms,
            allowed_hosts.as_deref(),
        )
        .await
    } else {
        None
    };
    if !allowlist_ok {
        return HttpSmokeReport {
            ok: false,
            started_at,
            finished_at: now_iso(),
            steps,
            auth,
        };
    }

    apply_expect_registration_endpoint(
        &mut steps,
        auth.as_ref(),
        target.expect_registration_endpoint,
    );
    apply_expect_auth_required(&mut steps, target.expect_auth_required);
    let ok = steps.iter().all(|step| step.status == ProbeStepStatus::Ok);
    HttpSmokeReport {
        ok,
        started_at,
        finished_at: now_iso(),
        steps,
        auth,
    }
}

/// Run an HTTP smoke check for auth metadata endpoints.
pub async fn run_http_smoke(target: HttpSmokeTarget) -> HttpSmokeReport {
    let started_at = now_iso();
    let mut steps: Vec<ProbeStep> = Vec::new();
    let allowed_hosts = parse_allowed_hosts_env();
    let probe_options = options::resolve_probe_options(target.timeout_ms, None, None);

    let allowlist_ok = enforce_host_allowlist(
        TransportType::StreamableHttp.as_str(),
        target.url.as_deref(),
        &mut steps,
        allowed_hosts.as_deref(),
    );
    if !allowlist_ok {
        return HttpSmokeReport {
            ok: false,
            started_at,
            finished_at: now_iso(),
            steps,
            auth: None,
        };
    }

    let Some(url) = target.url.as_deref() else {
        steps.push(ProbeStep {
            name: "http.get".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some("Missing target URL.".to_string()),
            data: None,
        });
        return HttpSmokeReport {
            ok: false,
            started_at,
            finished_at: now_iso(),
            steps,
            auth: None,
        };
    };

    let client = reqwest::Client::new();
    let response =
        crate::http::fetch_with_timeout(&client, client.get(url), probe_options.timeout_ms).await;
    let response = match response {
        Ok(resp) => resp,
        Err(err) => {
            let error = anyhow!(err);
            let (detail, data) =
                crate::probe::auth_diagnostics::classify_request_error("target", url, &error);
            steps.push(ProbeStep {
                name: "http.get".to_string(),
                status: ProbeStepStatus::Error,
                detail: Some(detail),
                data: Some(data),
            });
            return HttpSmokeReport {
                ok: false,
                started_at,
                finished_at: now_iso(),
                steps,
                auth: None,
            };
        }
    };

    let status = response.status();
    if let Some((_detail, data)) =
        classify_stateful_session_required_response("target", url, response).await
    {
        steps.push(ProbeStep {
            name: "http.get".to_string(),
            status: ProbeStepStatus::Ok,
            detail: Some(
                "HTTP 400 Bad Request (stateful MCP endpoint requires session initialization)"
                    .to_string(),
            ),
            data: Some(data),
        });
    } else {
        let ok_status = status.is_success() || status.as_u16() == 401 || status.as_u16() == 403;
        steps.push(ProbeStep {
            name: "http.get".to_string(),
            status: if ok_status {
                ProbeStepStatus::Ok
            } else {
                ProbeStepStatus::Error
            },
            detail: Some(format!("HTTP {}", status)),
            data: None,
        });
    }
    let auth = discover_auth(
        TransportType::StreamableHttp,
        Some(url),
        &mut steps,
        probe_options.timeout_ms,
        allowed_hosts.as_deref(),
    )
    .await;

    apply_expect_registration_endpoint(
        &mut steps,
        auth.as_ref(),
        target.expect_registration_endpoint,
    );
    apply_expect_auth_required(&mut steps, target.expect_auth_required);

    let ok = steps.iter().all(|step| step.status == ProbeStepStatus::Ok);
    HttpSmokeReport {
        ok,
        started_at,
        finished_at: now_iso(),
        steps,
        auth: auth.filter(|auth| {
            auth.resource_metadata_url.is_some()
                || auth.authorization_server.is_some()
                || auth.oauth_metadata_url.is_some()
        }),
    }
}

/// Run a raw MCP request by method name.
pub async fn run_raw_request(
    target: RawRequestTarget,
    client_name: Option<&str>,
    client_version: Option<&str>,
) -> RawRequestReport {
    let started_at = now_iso();
    let mut steps: Vec<ProbeStep> = Vec::new();
    let probe_options =
        options::resolve_probe_options(target.timeout_ms, target.retries, target.retry_delay_ms);
    let allowed_hosts = parse_allowed_hosts_env();
    let mut logger = probe_logger(target.log_level, target.log_format);

    let stdio_ok = enforce_stdio_allowlist(target.transport_type.as_str(), &mut steps);
    let allowlist_ok = if stdio_ok {
        enforce_host_allowlist(
            target.transport_type.as_str(),
            target.url.as_deref(),
            &mut steps,
            allowed_hosts.as_deref(),
        )
    } else {
        false
    };
    let auth = if stdio_ok && allowlist_ok {
        discover_auth(
            target.transport_type,
            target.url.as_deref(),
            &mut steps,
            probe_options.timeout_ms,
            allowed_hosts.as_deref(),
        )
        .await
    } else {
        None
    };

    if !stdio_ok || !allowlist_ok {
        return RawRequestReport {
            ok: false,
            started_at,
            finished_at: now_iso(),
            steps,
            auth,
            server_info: None,
            capabilities: None,
            result: None,
            error: None,
            trace: None,
        };
    }

    apply_expect_auth_required(&mut steps, target.expect_auth_required);

    let connect_result = connect_with_retry(
        target.transport_type,
        target.command.as_deref(),
        target.args.as_deref(),
        target.cwd.as_deref(),
        target.env.as_ref(),
        target.url.as_deref(),
        target.headers.as_ref(),
        probe_options,
        target.trace.unwrap_or(false),
        target.trace_limit,
        target.trace_max_bytes,
        client_name.unwrap_or(DEFAULT_CLIENT_NAME),
        client_version.unwrap_or(DEFAULT_CLIENT_VERSION),
    )
    .await;

    let mut connection = match connect_result {
        Ok(connection) => {
            steps.push(ProbeStep {
                name: "connect".to_string(),
                status: ProbeStepStatus::Ok,
                detail: None,
                data: None,
            });
            if let Some(logger) = logger.as_mut() {
                logger.info("probe.connect.ok", None);
            }
            connection
        }
        Err(error) => {
            let (stdio, trace) = connection_error_payload(&error);
            steps.push(map_error_step("connect", error, stdio, trace));
            if let Some(logger) = logger.as_mut() {
                logger.error("probe.connect.error", None);
            }
            return RawRequestReport {
                ok: false,
                started_at,
                finished_at: now_iso(),
                steps,
                auth,
                server_info: None,
                capabilities: None,
                result: None,
                error: None,
                trace: None,
            };
        }
    };

    let peer_info = connection.service.peer_info().cloned();
    let server_info_value = peer_info
        .as_ref()
        .and_then(|info| serde_json::to_value(&info.server_info).ok());
    let capabilities_value = peer_info
        .as_ref()
        .and_then(|info| serde_json::to_value(&info.capabilities).ok());

    steps.push(ProbeStep {
        name: "server.info".to_string(),
        status: ProbeStepStatus::Ok,
        detail: if server_info_value.is_some() {
            None
        } else {
            Some("not available".to_string())
        },
        data: None,
    });

    steps.push(ProbeStep {
        name: "capabilities".to_string(),
        status: ProbeStepStatus::Ok,
        detail: if capabilities_value.is_some() {
            None
        } else {
            Some("not available".to_string())
        },
        data: None,
    });

    let (expect_error, expect_match) = resolve_expect_error(&target.expect_error);
    let request_name = format!("request:{}", target.method);
    let params_value = target.params.clone().filter(|value| !value.is_null());
    let raw_request = CustomRequest::new(target.method.clone(), params_value);
    let request_result = timing::with_retry(
        || {
            timing::with_timeout(
                connection
                    .service
                    .send_request(ClientRequest::CustomRequest(raw_request.clone())),
                probe_options.timeout_ms,
                &request_name,
            )
        },
        probe_options.retries,
        probe_options.retry_delay_ms,
    )
    .await;

    let mut result_value: Option<Value> = None;
    let mut error_message: Option<String> = None;

    match request_result {
        Ok(result) => {
            result_value = serde_json::to_value(result).ok();
            if expect_error {
                steps.push(ProbeStep {
                    name: request_name.clone(),
                    status: ProbeStepStatus::Error,
                    detail: Some("Expected request to fail but it succeeded.".to_string()),
                    data: None,
                });
            } else {
                steps.push(ProbeStep {
                    name: request_name.clone(),
                    status: ProbeStepStatus::Ok,
                    detail: None,
                    data: None,
                });
            }
        }
        Err(error) => {
            let details = describe_error(&error);
            error_message = Some(details.message.clone());
            let matches = if expect_error {
                match expect_match {
                    Some(expected) => details.message.contains(expected),
                    None => true,
                }
            } else {
                false
            };
            steps.push(ProbeStep {
                name: request_name.clone(),
                status: if matches {
                    ProbeStepStatus::Ok
                } else {
                    ProbeStepStatus::Error
                },
                detail: Some(details.message.clone()),
                data: error_data(&details),
            });
        }
    }

    let _ = connection.service.close().await;
    if let Some(stdio) = connection.stdio.take() {
        let snapshot = stdio.snapshot();
        stdio.stop();
        if !snapshot.lines.is_empty() || snapshot.exit_code.is_some() || snapshot.signal.is_some() {
            if let Ok(data) = serde_json::to_value(snapshot) {
                steps.push(ProbeStep {
                    name: "stdio.stderr".to_string(),
                    status: ProbeStepStatus::Ok,
                    detail: None,
                    data: Some(data),
                });
            }
        }
    }

    let trace_entries: Option<Vec<TraceEntry>> =
        connection.trace.map(|collector| collector.entries());
    let ok = steps.iter().all(|step| step.status == ProbeStepStatus::Ok);
    if let Some(logger) = logger.as_mut() {
        logger.info("probe.raw_request.finished", Some(Value::Bool(ok)));
    }
    RawRequestReport {
        ok,
        started_at,
        finished_at: now_iso(),
        steps,
        auth,
        server_info: server_info_value,
        capabilities: capabilities_value,
        result: result_value,
        error: error_message,
        trace: trace_entries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use serde_json::Value;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    fn ok_step(name: &str) -> ProbeStep {
        ProbeStep {
            name: name.to_string(),
            status: ProbeStepStatus::Ok,
            detail: None,
            data: None,
        }
    }

    #[test]
    fn expected_auth_required_connect_error_is_detected() {
        let steps = vec![ok_step("auth.prm"), ok_step("expect.auth_required")];
        let auth = AuthDiscovery {
            resource_metadata_url: Some(
                "https://example.test/.well-known/oauth-protected-resource".to_string(),
            ),
            resource_metadata: None,
            authorization_server: None,
            oauth_metadata_url: None,
            oauth_metadata: None,
            registration_endpoint: None,
        };

        assert!(is_expected_auth_required_connect_error(
            &steps,
            Some(&auth),
            "Error POSTing to endpoint: {\"code\":\"auth.missing_token\"}",
            Some(true),
        ));
    }

    #[test]
    fn expected_auth_required_connect_error_detects_rmcp_initialize_message() {
        let steps = vec![
            ok_step("auth.prm"),
            ok_step("auth.prm.fetch"),
            ok_step("auth.oauth.fetch"),
            ok_step("expect.auth_required"),
        ];
        let auth = AuthDiscovery {
            resource_metadata_url: Some(
                "https://example.test/.well-known/oauth-protected-resource".to_string(),
            ),
            resource_metadata: None,
            authorization_server: Some("https://auth.example.test/realms/example/".to_string()),
            oauth_metadata_url: None,
            oauth_metadata: None,
            registration_endpoint: None,
        };

        assert!(is_expected_auth_required_connect_error(
            &steps,
            Some(&auth),
            concat!(
                "Send message error Transport ",
                "[rmcp::transport::worker::WorkerTransport<",
                "rmcp::transport::streamable_http_client::StreamableHttpClientWorker<",
                "reqwest::async_impl::client::Client>>] error: Auth required, ",
                "when send initialize request"
            ),
            Some(true),
        ));
    }

    #[test]
    fn expected_auth_required_connect_error_requires_expectation() {
        let steps = vec![ok_step("auth.prm"), ok_step("expect.auth_required")];
        let auth = AuthDiscovery {
            resource_metadata_url: Some(
                "https://example.test/.well-known/oauth-protected-resource".to_string(),
            ),
            resource_metadata: None,
            authorization_server: None,
            oauth_metadata_url: None,
            oauth_metadata: None,
            registration_endpoint: None,
        };

        assert!(!is_expected_auth_required_connect_error(
            &steps,
            Some(&auth),
            "auth.missing_token",
            None,
        ));
    }

    #[test]
    fn expected_auth_required_connect_step_is_machine_readable() {
        let step = map_expected_auth_required_connect_step(
            &anyhow!("auth.missing_token: Missing bearer token."),
            None,
            None,
        );

        assert_eq!(step.name, "connect.auth_required");
        assert_eq!(step.status, ProbeStepStatus::Ok);
        assert!(step
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("Auth challenge detected as expected"));
        let data = step.data.expect("machine-readable data");
        assert_eq!(data["expected_auth_required"], Value::Bool(true));
        let connect_error = data["connect_error"]
            .as_str()
            .expect("connect_error string");
        assert!(connect_error.contains("auth.missing_token"));
    }

    #[test]
    fn prompt_render_params_include_name_and_arguments() {
        let params = build_prompt_render_params(
            "summarize_case",
            Some(HashMap::from([(
                "case_id".to_string(),
                Value::String("C123".to_string()),
            )])),
        );

        assert_eq!(
            params,
            serde_json::json!({
                "name": "summarize_case",
                "arguments": {
                    "case_id": "C123"
                }
            })
        );
    }

    #[test]
    fn resource_uri_params_include_uri() {
        let params = build_resource_uri_params("mcp-probe://status");

        assert_eq!(
            params,
            serde_json::json!({
                "uri": "mcp-probe://status"
            })
        );
    }

    #[derive(Clone)]
    struct TestResponse {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    }

    fn reason_phrase(status: u16) -> &'static str {
        match status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            _ => "Error",
        }
    }

    async fn spawn_server<F>(handler: F) -> (String, JoinHandle<()>)
    where
        F: Fn(&str) -> TestResponse + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("listener addr");
        let base_url = format!("http://{addr}");
        let handler = Arc::new(handler);

        let task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let handler = handler.clone();
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    let read = socket.read(&mut buffer).await.unwrap_or(0);
                    if read == 0 {
                        return;
                    }
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let response = handler(path);
                    let mut payload = format!(
                        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                        response.status,
                        reason_phrase(response.status),
                        response.body.len()
                    );
                    for (name, value) in response.headers {
                        payload.push_str(&name);
                        payload.push_str(": ");
                        payload.push_str(&value);
                        payload.push_str("\r\n");
                    }
                    payload.push_str("\r\n");
                    payload.push_str(&response.body);
                    let _ = socket.write_all(payload.as_bytes()).await;
                });
            }
        });
        (base_url, task)
    }

    #[tokio::test]
    async fn http_smoke_accepts_stateful_session_required_target_without_auth() {
        let (base, task) = spawn_server(|path| match path {
            "/mcp" => TestResponse {
                status: 400,
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: r#"{"status":"error","error":"Missing session ID.","hint":"Initialize with POST /mcp to obtain a session id."}"#.to_string(),
            },
            _ => TestResponse {
                status: 404,
                headers: Vec::new(),
                body: String::new(),
            },
        })
        .await;

        let report = run_http_smoke(HttpSmokeTarget {
            url: Some(format!("{base}/mcp")),
            timeout_ms: Some(1_000),
            expect_auth_required: Some(false),
            expect_registration_endpoint: Some(false),
        })
        .await;
        task.abort();

        assert!(report.ok);
        let http_get = report
            .steps
            .iter()
            .find(|step| step.name == "http.get")
            .expect("http.get step");
        assert_eq!(http_get.status, ProbeStepStatus::Ok);
        assert!(http_get
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("stateful MCP endpoint requires session initialization"));
        assert_eq!(
            http_get
                .data
                .as_ref()
                .and_then(|data| data.get("classification"))
                .and_then(Value::as_str),
            Some("stateful_mcp_requires_session")
        );
    }

    #[tokio::test]
    async fn http_smoke_accepts_plain_text_stateful_session_required_target_without_auth() {
        let (base, task) = spawn_server(|path| match path {
            "/mcp" => TestResponse {
                status: 400,
                headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                body: "Missing session ID. Initialize with POST /mcp to obtain a session id."
                    .to_string(),
            },
            _ => TestResponse {
                status: 404,
                headers: Vec::new(),
                body: String::new(),
            },
        })
        .await;

        let report = run_http_smoke(HttpSmokeTarget {
            url: Some(format!("{base}/mcp")),
            timeout_ms: Some(1_000),
            expect_auth_required: Some(false),
            expect_registration_endpoint: Some(false),
        })
        .await;
        task.abort();

        assert!(report.ok);
        let http_get = report
            .steps
            .iter()
            .find(|step| step.name == "http.get")
            .expect("http.get step");
        assert_eq!(http_get.status, ProbeStepStatus::Ok);
        assert_eq!(
            http_get
                .data
                .as_ref()
                .and_then(|data| data.get("code"))
                .and_then(Value::as_str),
            Some("stateful_session_required")
        );
    }
}
