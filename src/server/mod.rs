//! MCP server implementation for the probe tool.

use crate::logging::{stderr_logger, LogLevel};
use crate::provenance::{RuntimeAdmissionExtension, RuntimeProvenance};
use crate::server::resources::{list_resources, read_resource};
use crate::version::{latest_protocol_version, SERVER_NAME};
use mcp_toolkit_core::rmcp_models;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Implementation, ListResourceTemplatesResult,
    ListResourcesResult, ListToolsResult, LoggingLevel, LoggingMessageNotificationParam,
    PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResult, ServerCapabilities,
    ServerInfo, SetLevelRequestParams,
};
use rmcp::service::{NotificationContext, RequestContext};
use rmcp::{RoleServer, ServerHandler};
use serde_json::Value;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Instant;

mod resources;
pub mod tools;

const MCP_LOGGER_NAME: &str = "mcp-probe";
const MCP_LOGGING_ENV: &str = "MCP_PROBE_MCP_LOGGING";
const MCP_LOG_LEVEL_ENV: &str = "MCP_PROBE_MCP_LOG_LEVEL";
const MCP_LOG_RATE_LIMIT_PER_S_ENV: &str = "MCP_PROBE_MCP_LOG_RATE_LIMIT_PER_S";
const MCP_LOG_RATE_LIMIT_BURST_ENV: &str = "MCP_PROBE_MCP_LOG_RATE_LIMIT_BURST";
const MCP_LOG_TO_CLIENT_LOGGER_ENV: &str = "MCP_PROBE_MCP_LOG_TO_CLIENT_LOGGER";
const MAX_LOG_PAYLOAD_BYTES: usize = 4096;

/// MCP server handler for the probe tool surface.
#[derive(Clone)]
pub struct ProbeMcp {
    tool_router: ToolRouter<ProbeMcp>,
    log_state: Option<Arc<McpLogState>>,
    provenance: Arc<RuntimeProvenance>,
    runtime_admission: Arc<RuntimeAdmissionExtension>,
}

impl ProbeMcp {
    /// Construct a probe server handler with optional MCP logging.
    fn new(
        log_state: Option<Arc<McpLogState>>,
        provenance: RuntimeProvenance,
        runtime_admission: RuntimeAdmissionExtension,
    ) -> Self {
        let tool_router = Self::tool_router_probe();
        Self {
            tool_router,
            log_state,
            provenance: Arc::new(provenance),
            runtime_admission: Arc::new(runtime_admission),
        }
    }

    fn capabilities(&self) -> ServerCapabilities {
        if self.log_state.is_some() {
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_logging()
                .build()
        } else {
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build()
        }
    }
}

impl ServerHandler for ProbeMcp {
    fn get_info(&self) -> ServerInfo {
        rmcp_models::server_info(
            latest_protocol_version(),
            self.capabilities(),
            Implementation::new(SERVER_NAME, self.provenance.build.server_version.clone()),
            Some(
                "Headless MCP probe server. Use probe_run, probe_handshake, or probe_help to validate MCP servers."
                    .to_string(),
            ),
        )
    }

    fn initialize(
        &self,
        request: rmcp::model::InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<rmcp::model::InitializeResult, rmcp::ErrorData>> + Send + '_
    {
        let request_id = context.id.to_string();
        let peer = context.peer.clone();
        let client_name = request.client_info.name.clone();
        let client_version = request.client_info.version.clone();
        let protocol_version = request.protocol_version.to_string();
        let info = self.get_info();
        async move {
            if peer.peer_info().is_none() {
                peer.set_peer_info(request);
            }
            let data = serde_json::json!({
                "protocol_version": protocol_version,
                "client_name": client_name,
                "client_version": client_version,
            });
            if let Some(state) = &self.log_state {
                state
                    .emit(
                        &peer,
                        LoggingLevel::Info,
                        "session.initialize",
                        Some(data),
                        Some(&request_id),
                    )
                    .await;
            }
            Ok(info)
        }
    }

    fn on_initialized(
        &self,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + Send + '_ {
        let peer = context.peer;
        async move {
            if let Some(state) = &self.log_state {
                state
                    .emit(&peer, LoggingLevel::Info, "session.initialized", None, None)
                    .await;
            }
        }
    }

    fn set_level(
        &self,
        request: SetLevelRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), rmcp::ErrorData>> + Send + '_ {
        let request_id = context.id.to_string();
        let peer = context.peer.clone();
        let level = request.level;
        async move {
            let Some(state) = &self.log_state else {
                return Err(rmcp::ErrorData::method_not_found::<
                    rmcp::model::SetLevelRequestMethod,
                >());
            };
            state.set_level(level);
            state
                .emit(
                    &peer,
                    LoggingLevel::Info,
                    "logging.set_level",
                    Some(serde_json::json!({ "level": level })),
                    Some(&request_id),
                )
                .await;
            Ok(())
        }
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, rmcp::ErrorData>> + Send + '_ {
        let request_id = context.id.to_string();
        let peer = context.peer.clone();
        let tools = self.tool_router.list_all();
        let start = Instant::now();
        async move {
            if let Some(state) = &self.log_state {
                state
                    .emit(
                        &peer,
                        LoggingLevel::Info,
                        "discovery.tools.list.start",
                        None,
                        Some(&request_id),
                    )
                    .await;
            }
            let result = ListToolsResult {
                meta: None,
                tools,
                next_cursor: None,
            };
            if let Some(state) = &self.log_state {
                let duration = start.elapsed().as_millis() as u64;
                state
                    .emit(
                        &peer,
                        LoggingLevel::Info,
                        "discovery.tools.list.finish",
                        Some(serde_json::json!({
                            "duration_ms": duration,
                            "count": result.tools.len(),
                            "error": false
                        })),
                        Some(&request_id),
                    )
                    .await;
            }
            Ok(result)
        }
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResult, rmcp::ErrorData>> + Send + '_ {
        let request_id = context.id.to_string();
        let peer = context.peer.clone();
        let tool_name = request.name.to_string();
        let arg_keys: Vec<String> = request
            .arguments
            .as_ref()
            .map(|map| map.keys().cloned().collect())
            .unwrap_or_default();
        let start = Instant::now();
        let log_state = self.log_state.clone();
        let tool_context = ToolCallContext::new(self, request, context);
        async move {
            if let Some(state) = &log_state {
                state
                    .emit(
                        &peer,
                        LoggingLevel::Info,
                        "tool.call.start",
                        Some(serde_json::json!({
                            "tool_name": tool_name,
                            "arg_keys": arg_keys,
                        })),
                        Some(&request_id),
                    )
                    .await;
            }

            let result = self.tool_router.call(tool_context).await;

            let duration = start.elapsed().as_millis() as u64;
            let mut errored = false;

            if let Err(err) = &result {
                errored = true;
                if let Some(state) = &log_state {
                    let error_message = err.message.clone();
                    state
                        .emit(
                            &peer,
                            LoggingLevel::Error,
                            "tool.call.error",
                            Some(serde_json::json!({
                                "tool_name": tool_name,
                                "error": error_message,
                            })),
                            Some(&request_id),
                        )
                        .await;
                }
            } else if let Ok(result) = &result {
                if result.is_error.unwrap_or(false) {
                    errored = true;
                    if let Some(state) = &log_state {
                        state
                            .emit(
                                &peer,
                                LoggingLevel::Error,
                                "tool.call.error",
                                Some(serde_json::json!({
                                    "tool_name": tool_name,
                                    "error": extract_error_message(result).unwrap_or_else(|| "tool returned error".to_string()),
                                })),
                                Some(&request_id),
                            )
                            .await;
                    }
                }
            }

            if let Some(state) = &log_state {
                state
                    .emit(
                        &peer,
                        LoggingLevel::Info,
                        "tool.call.finish",
                        Some(serde_json::json!({
                            "tool_name": tool_name,
                            "duration_ms": duration,
                            "error": errored
                        })),
                        Some(&request_id),
                    )
                    .await;
            }

            result
        }
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, rmcp::ErrorData>> + Send + '_ {
        let request_id = context.id.to_string();
        let peer = context.peer.clone();
        let start = Instant::now();
        async move {
            if let Some(state) = &self.log_state {
                state
                    .emit(
                        &peer,
                        LoggingLevel::Info,
                        "discovery.resources.list.start",
                        None,
                        Some(&request_id),
                    )
                    .await;
            }

            let resources = list_resources();
            let result = ListResourcesResult {
                meta: None,
                resources,
                next_cursor: None,
            };

            if let Some(state) = &self.log_state {
                let duration = start.elapsed().as_millis() as u64;
                state
                    .emit(
                        &peer,
                        LoggingLevel::Info,
                        "discovery.resources.list.finish",
                        Some(serde_json::json!({
                            "duration_ms": duration,
                            "count": result.resources.len(),
                            "error": false
                        })),
                        Some(&request_id),
                    )
                    .await;
            }

            Ok(result)
        }
    }

    fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourceTemplatesResult, rmcp::ErrorData>> + Send + '_
    {
        let request_id = context.id.to_string();
        let peer = context.peer.clone();
        let start = Instant::now();
        async move {
            if let Some(state) = &self.log_state {
                state
                    .emit(
                        &peer,
                        LoggingLevel::Info,
                        "discovery.resource_templates.list.start",
                        None,
                        Some(&request_id),
                    )
                    .await;
            }

            let result = ListResourceTemplatesResult {
                meta: None,
                resource_templates: Vec::new(),
                next_cursor: None,
            };

            if let Some(state) = &self.log_state {
                let duration = start.elapsed().as_millis() as u64;
                state
                    .emit(
                        &peer,
                        LoggingLevel::Info,
                        "discovery.resource_templates.list.finish",
                        Some(serde_json::json!({
                            "duration_ms": duration,
                            "count": 0,
                            "error": false
                        })),
                        Some(&request_id),
                    )
                    .await;
            }

            Ok(result)
        }
    }

    fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<rmcp::model::ListPromptsResult, rmcp::ErrorData>> + Send + '_
    {
        let request_id = context.id.to_string();
        let peer = context.peer.clone();
        let start = Instant::now();
        async move {
            if let Some(state) = &self.log_state {
                state
                    .emit(
                        &peer,
                        LoggingLevel::Info,
                        "discovery.prompts.list.start",
                        None,
                        Some(&request_id),
                    )
                    .await;
            }
            let result = rmcp::model::ListPromptsResult {
                meta: None,
                prompts: Vec::new(),
                next_cursor: None,
            };
            if let Some(state) = &self.log_state {
                let duration = start.elapsed().as_millis() as u64;
                state
                    .emit(
                        &peer,
                        LoggingLevel::Info,
                        "discovery.prompts.list.finish",
                        Some(serde_json::json!({
                            "duration_ms": duration,
                            "count": 0,
                            "error": false
                        })),
                        Some(&request_id),
                    )
                    .await;
            }
            Ok(result)
        }
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceResult, rmcp::ErrorData>> + Send + '_ {
        let request_id = context.id.to_string();
        let peer = context.peer.clone();
        let uri = request.uri.clone();
        let start = Instant::now();
        async move {
            if let Some(state) = &self.log_state {
                state
                    .emit(
                        &peer,
                        LoggingLevel::Info,
                        "resource.read.start",
                        Some(serde_json::json!({ "uri": uri })),
                        Some(&request_id),
                    )
                    .await;
            }

            let result = read_resource(
                &request.uri,
                self.provenance.as_ref(),
                self.runtime_admission.as_ref(),
            );

            if let Some(state) = &self.log_state {
                let duration = start.elapsed().as_millis() as u64;
                let errored = result.is_err();
                if let Err(err) = &result {
                    let error_message = err.message.clone();
                    state
                        .emit(
                            &peer,
                            LoggingLevel::Error,
                            "resource.read.error",
                            Some(serde_json::json!({
                                "uri": request.uri,
                                "error": error_message,
                            })),
                            Some(&request_id),
                        )
                        .await;
                }
                state
                    .emit(
                        &peer,
                        LoggingLevel::Info,
                        "resource.read.finish",
                        Some(serde_json::json!({
                            "uri": request.uri,
                            "duration_ms": duration,
                            "error": errored
                        })),
                        Some(&request_id),
                    )
                    .await;
            }

            result
        }
    }
}

/// Create a probe server with logging settings derived from the environment.
pub fn create_server(
    provenance: RuntimeProvenance,
    runtime_admission: RuntimeAdmissionExtension,
) -> anyhow::Result<ProbeMcp> {
    let logging_enabled = parse_bool_env(MCP_LOGGING_ENV, false)?;
    let log_state = if logging_enabled {
        let log_level = parse_log_level_env(MCP_LOG_LEVEL_ENV, LogLevel::Info)?;
        let rate_limit_per_second = parse_number_env(MCP_LOG_RATE_LIMIT_PER_S_ENV, 60.0)?;
        let rate_limit_burst = parse_number_env(MCP_LOG_RATE_LIMIT_BURST_ENV, 120.0)?;
        let log_to_client = parse_bool_env(MCP_LOG_TO_CLIENT_LOGGER_ENV, false)?;
        if rate_limit_per_second < 0.0 || rate_limit_burst < 0.0 {
            return Err(anyhow::anyhow!(
                "{} and {} must be >= 0.",
                MCP_LOG_RATE_LIMIT_PER_S_ENV,
                MCP_LOG_RATE_LIMIT_BURST_ENV
            ));
        }
        let logger = if log_to_client {
            Some(Mutex::new(stderr_logger(
                log_level,
                crate::logging::LogFormat::Json,
            )))
        } else {
            None
        };
        Some(Arc::new(McpLogState::new(
            log_level,
            rate_limit_per_second,
            rate_limit_burst,
            logger,
        )))
    } else {
        None
    };

    Ok(ProbeMcp::new(log_state, provenance, runtime_admission))
}

fn parse_bool_env(name: &str, fallback: bool) -> anyhow::Result<bool> {
    let raw = std::env::var(name).ok();
    let Some(value) = raw else {
        return Ok(fallback);
    };
    let normalized = value.trim().to_lowercase();
    if ["1", "true", "yes", "on"].contains(&normalized.as_str()) {
        return Ok(true);
    }
    if ["0", "false", "no", "off"].contains(&normalized.as_str()) {
        return Ok(false);
    }
    Err(anyhow::anyhow!(
        "Invalid {name}={value} (expected true/false)."
    ))
}

fn parse_log_level_env(name: &str, fallback: LogLevel) -> anyhow::Result<LogLevel> {
    let raw = std::env::var(name).ok();
    let Some(value) = raw else {
        return Ok(fallback);
    };
    LogLevel::parse(&value).ok_or_else(|| anyhow::anyhow!("Invalid {name}={value}."))
}

fn parse_number_env(name: &str, fallback: f64) -> anyhow::Result<f64> {
    let raw = std::env::var(name).ok();
    let Some(value) = raw else {
        return Ok(fallback);
    };
    let parsed: f64 = value
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid {name}={value} (expected number)."))?;
    Ok(parsed)
}

#[derive(Debug)]
struct TokenBucket {
    capacity: f64,
    refill_rate: f64,
    tokens: f64,
    updated_at: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            capacity,
            refill_rate,
            tokens: capacity,
            updated_at: Instant::now(),
        }
    }

    fn consume(&mut self, cost: f64) -> bool {
        if self.capacity <= 0.0 || self.refill_rate <= 0.0 {
            return false;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(self.updated_at).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.updated_at = now;
        if self.tokens < cost {
            return false;
        }
        self.tokens -= cost;
        true
    }
}

struct McpLogState {
    level: Mutex<LoggingLevel>,
    bucket: Mutex<TokenBucket>,
    client_logger: Option<Mutex<crate::logging::Logger>>,
}

impl McpLogState {
    fn new(
        level: LogLevel,
        rate_limit_per_second: f64,
        rate_limit_burst: f64,
        client_logger: Option<Mutex<crate::logging::Logger>>,
    ) -> Self {
        let logging_level = match level {
            LogLevel::Debug => LoggingLevel::Debug,
            LogLevel::Info => LoggingLevel::Info,
            LogLevel::Warn => LoggingLevel::Warning,
            LogLevel::Error => LoggingLevel::Error,
        };
        Self {
            level: Mutex::new(logging_level),
            bucket: Mutex::new(TokenBucket::new(rate_limit_burst, rate_limit_per_second)),
            client_logger,
        }
    }

    fn set_level(&self, level: LoggingLevel) {
        if let Ok(mut guard) = self.level.lock() {
            *guard = level;
        }
    }

    fn level_value(level: LoggingLevel) -> u8 {
        match level {
            LoggingLevel::Debug => 10,
            LoggingLevel::Info => 20,
            LoggingLevel::Notice => 25,
            LoggingLevel::Warning => 30,
            LoggingLevel::Error => 40,
            LoggingLevel::Critical => 50,
            LoggingLevel::Alert => 60,
            LoggingLevel::Emergency => 70,
        }
    }

    fn allowed_by_level(&self, level: LoggingLevel) -> bool {
        let Ok(guard) = self.level.lock() else {
            return true;
        };
        Self::level_value(level) >= Self::level_value(*guard)
    }

    fn should_rate_limit(&self, level: LoggingLevel) -> bool {
        Self::level_value(level) < Self::level_value(LoggingLevel::Error)
    }

    fn allow_token(&self) -> bool {
        let Ok(mut bucket) = self.bucket.lock() else {
            return true;
        };
        bucket.consume(1.0)
    }

    async fn emit(
        &self,
        peer: &rmcp::service::Peer<RoleServer>,
        level: LoggingLevel,
        event: &str,
        data: Option<Value>,
        request_id: Option<&str>,
    ) {
        if !self.allowed_by_level(level) {
            return;
        }
        if self.should_rate_limit(level) && !self.allow_token() {
            return;
        }
        let payload = sanitize_log_payload(event, data, request_id);
        let _ = peer
            .notify_logging_message(LoggingMessageNotificationParam {
                level,
                logger: Some(MCP_LOGGER_NAME.to_string()),
                data: payload.clone(),
            })
            .await;

        if let Some(logger) = &self.client_logger {
            if let Ok(mut guard) = logger.lock() {
                let level = match level {
                    LoggingLevel::Debug => LogLevel::Debug,
                    LoggingLevel::Info | LoggingLevel::Notice => LogLevel::Info,
                    LoggingLevel::Warning => LogLevel::Warn,
                    _ => LogLevel::Error,
                };
                guard.log(level, "mcp.notify", Some(payload));
            }
        }
    }
}

fn extract_error_message(result: &CallToolResult) -> Option<String> {
    result
        .content
        .iter()
        .find_map(|content| match &content.raw {
            rmcp::model::RawContent::Text(text) => Some(text.text.clone()),
            _ => None,
        })
}

fn sanitize_log_payload(event: &str, data: Option<Value>, request_id: Option<&str>) -> Value {
    let mut map = serde_json::Map::new();
    map.insert(
        "event".to_string(),
        Value::String(mcp_toolkit_observability::redaction::redact_telemetry_text(
            event,
        )),
    );
    if let Some(data) = data {
        let sanitized = sanitize_log_value(data);
        match sanitized {
            Value::Object(obj) => {
                for (key, value) in obj {
                    map.insert(key, value);
                }
            }
            other => {
                map.insert("data".to_string(), other);
            }
        }
    }
    if let Some(request_id) = request_id {
        map.insert(
            "request_id".to_string(),
            Value::String(request_id.to_string()),
        );
    }
    clamp_payload(Value::Object(map), MAX_LOG_PAYLOAD_BYTES)
}

fn sanitize_log_value(mut value: Value) -> Value {
    if value.is_object() {
        mcp_toolkit_observability::redaction::redact_json_keys(
            &mut value,
            mcp_toolkit_observability::redaction::DEFAULT_REDACT_KEYS,
            mcp_toolkit_observability::redaction::DEFAULT_REDACT_VALUE,
        );
    }
    redact_strings(value)
}

fn redact_strings(value: Value) -> Value {
    match value {
        Value::String(text) => Value::String(
            mcp_toolkit_observability::redaction::redact_telemetry_text(&text),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(redact_strings).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, redact_strings(value)))
                .collect(),
        ),
        other => other,
    }
}

fn clamp_payload(value: Value, max_bytes: usize) -> Value {
    let serialized = serde_json::to_string(&value);
    match serialized {
        Ok(text) => {
            if text.len() <= max_bytes {
                value
            } else {
                serde_json::json!({
                    "truncated": true,
                    "bytes": text.len(),
                    "preview": text.chars().take(max_bytes).collect::<String>(),
                })
            }
        }
        Err(err) => serde_json::json!({
            "truncated": true,
            "preview": format!("Unserializable log payload: {err}"),
        }),
    }
}
