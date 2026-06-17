use crate::probe::options::ProbeOptions;
use crate::report::TraceEntry;
use crate::trace::TraceCollector;
use crate::transport::TransportType;
use crate::version::{latest_protocol_version, MCP_PROTOCOL_VERSION};
use anyhow::{anyhow, Context, Result};
use mcp_toolkit_core::rmcp_models;
use rmcp::model::{ClientCapabilities, ClientInfo, Implementation};
use rmcp::service::{serve_client, RoleClient, RunningService};
use rmcp::transport::{
    streamable_http_client::StreamableHttpClientTransportConfig, StreamableHttpClientTransport,
    TokioChildProcess, Transport,
};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::task::JoinHandle;

const DEFAULT_STDIO_STDERR_LINES: usize = 200;
const DEFAULT_TRACE_LIMIT: usize = 200;
const DEFAULT_TRACE_MAX_BYTES: usize = 4096;

/// Snapshot of captured stdio stderr output.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StdioSnapshot {
    pub lines: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
}

/// Captures stderr output from a stdio transport.
#[derive(Debug)]
pub struct StdioCapture {
    lines: Arc<Mutex<VecDeque<String>>>,
    handle: JoinHandle<()>,
}

impl StdioCapture {
    /// Take a snapshot of captured stderr output.
    pub fn snapshot(&self) -> StdioSnapshot {
        let guard = self.lines.lock().expect("stderr capture lock");
        StdioSnapshot {
            lines: guard.iter().cloned().collect(),
            exit_code: None,
            signal: None,
        }
    }

    /// Stop capturing stderr output.
    pub fn stop(&self) {
        self.handle.abort();
    }
}

/// Connection state for a probe run.
pub struct ProbeConnection {
    pub service: RunningService<RoleClient, ClientInfo>,
    pub stdio: Option<StdioCapture>,
    pub trace: Option<TraceCollector>,
}

/// Error returned when probe connection fails.
#[derive(Debug)]
pub struct ProbeConnectError {
    pub error: anyhow::Error,
    pub stdio: Option<StdioSnapshot>,
    pub trace: Option<Vec<TraceEntry>>,
}

impl std::fmt::Display for ProbeConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl std::error::Error for ProbeConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}

fn build_client_info(name: &str, version: &str, _transport_type: TransportType) -> ClientInfo {
    rmcp_models::client_info(
        latest_protocol_version(),
        ClientCapabilities::default(),
        Implementation::new(name, version),
    )
}

fn trace_value<T: Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value)
        .unwrap_or_else(|err| serde_json::Value::String(format!("unserializable: {err}")))
}

struct TraceTransport<T> {
    inner: T,
    trace: TraceCollector,
}

impl<T> TraceTransport<T> {
    fn new(inner: T, trace: TraceCollector) -> Self {
        Self { inner, trace }
    }
}

impl<T> Transport<RoleClient> for TraceTransport<T>
where
    T: Transport<RoleClient>,
{
    type Error = T::Error;

    fn send(
        &mut self,
        item: rmcp::service::TxJsonRpcMessage<RoleClient>,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static {
        self.trace.add("client->server", trace_value(&item));
        self.inner.send(item)
    }

    fn receive(
        &mut self,
    ) -> impl std::future::Future<Output = Option<rmcp::service::RxJsonRpcMessage<RoleClient>>> + Send
    {
        let trace = self.trace.clone();
        async move {
            let message = self.inner.receive().await;
            if let Some(ref msg) = message {
                trace.add("server->client", trace_value(msg));
            }
            message
        }
    }

    fn close(&mut self) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        self.inner.close()
    }
}

fn build_header_map(headers: Option<&HashMap<String, String>>) -> reqwest::header::HeaderMap {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    let mut map = HeaderMap::new();
    let Some(headers) = headers else {
        let protocol_name = HeaderName::from_static("mcp-protocol-version");
        let protocol_value =
            HeaderValue::from_str(MCP_PROTOCOL_VERSION).expect("valid MCP protocol version header");
        map.insert(protocol_name, protocol_value);
        return map;
    };
    for (name, value) in headers {
        let name = match HeaderName::from_bytes(name.as_bytes()) {
            Ok(name) => name,
            Err(_) => continue,
        };
        let value = match HeaderValue::from_str(value) {
            Ok(value) => value,
            Err(_) => continue,
        };
        map.insert(name, value);
    }
    let protocol_name = HeaderName::from_static("mcp-protocol-version");
    if !map.contains_key(&protocol_name) {
        let protocol_value =
            HeaderValue::from_str(MCP_PROTOCOL_VERSION).expect("valid MCP protocol version header");
        map.insert(protocol_name, protocol_value);
    }
    map
}

fn spawn_stdio_capture(stderr: tokio::process::ChildStderr, max_lines: usize) -> StdioCapture {
    let lines = Arc::new(Mutex::new(VecDeque::with_capacity(max_lines)));
    let lines_ref = Arc::clone(&lines);
    let handle = tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            let mut guard = lines_ref.lock().expect("stderr capture lock");
            guard.push_back(line);
            if guard.len() > max_lines {
                guard.pop_front();
            }
        }
    });
    StdioCapture { lines, handle }
}

async fn build_stdio_transport(
    command: &str,
    args: &[String],
    cwd: Option<&str>,
    env: Option<&HashMap<String, String>>,
) -> Result<(TokioChildProcess, Option<StdioCapture>)> {
    let mut cmd = Command::new(command);
    cmd.kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if !args.is_empty() {
        cmd.args(args);
    }

    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    if let Some(env) = env {
        cmd.envs(env);
    }

    let (transport, stderr) = TokioChildProcess::builder(cmd).spawn()?;
    let capture = stderr.map(|stderr| spawn_stdio_capture(stderr, DEFAULT_STDIO_STDERR_LINES));
    Ok((transport, capture))
}

fn build_streamable_http_transport(
    url: &str,
    headers: Option<&HashMap<String, String>>,
) -> Result<StreamableHttpClientTransport<reqwest::Client>> {
    let header_map = build_header_map(headers);
    let client = if header_map.is_empty() {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .context("failed to build HTTP client")?
    } else {
        reqwest::Client::builder()
            .default_headers(header_map)
            .no_proxy()
            .build()
            .context("failed to build HTTP client")?
    };
    let config = StreamableHttpClientTransportConfig::with_uri(url.to_string());
    Ok(StreamableHttpClientTransport::with_client(client, config))
}

/// Connect to the target transport and return a running MCP client.
pub async fn connect_with_retry(
    transport_type: TransportType,
    command: Option<&str>,
    args: Option<&[String]>,
    cwd: Option<&str>,
    env: Option<&HashMap<String, String>>,
    url: Option<&str>,
    headers: Option<&HashMap<String, String>>,
    probe_options: ProbeOptions,
    trace_enabled: bool,
    trace_limit: Option<usize>,
    trace_max_bytes: Option<usize>,
    client_name: &str,
    client_version: &str,
) -> Result<ProbeConnection> {
    let attempt = || async {
        let trace = if trace_enabled {
            Some(TraceCollector::new(
                trace_limit.unwrap_or(DEFAULT_TRACE_LIMIT),
                trace_max_bytes.unwrap_or(DEFAULT_TRACE_MAX_BYTES),
            ))
        } else {
            None
        };

        let (service, stdio) = match transport_type {
            TransportType::Stdio => {
                let cmd = command.ok_or_else(|| anyhow!("command is required for stdio"))?;
                let args = args.unwrap_or_default();
                let (transport, stdio) = build_stdio_transport(cmd, args, cwd, env).await?;
                let client_info = build_client_info(client_name, client_version, transport_type);
                let service_result = if let Some(trace) = trace.clone() {
                    let transport = TraceTransport::new(transport, trace);
                    crate::probe::timing::with_timeout(
                        serve_client(client_info, transport),
                        probe_options.timeout_ms,
                        "connect",
                    )
                    .await
                } else {
                    crate::probe::timing::with_timeout(
                        serve_client(client_info, transport),
                        probe_options.timeout_ms,
                        "connect",
                    )
                    .await
                };
                let service = match service_result {
                    Ok(service) => service,
                    Err(error) => {
                        return Err(anyhow::Error::new(connect_error(
                            error,
                            stdio,
                            trace.clone(),
                        )))
                    }
                };
                (service, stdio)
            }
            TransportType::Sse | TransportType::StreamableHttp => {
                let url = url.ok_or_else(|| anyhow!("url is required for HTTP transports"))?;
                let transport = build_streamable_http_transport(url, headers)?;
                let client_info = build_client_info(client_name, client_version, transport_type);
                let service_result = if let Some(trace) = trace.clone() {
                    let transport = TraceTransport::new(transport, trace);
                    crate::probe::timing::with_timeout(
                        serve_client(client_info, transport),
                        probe_options.timeout_ms,
                        "connect",
                    )
                    .await
                } else {
                    crate::probe::timing::with_timeout(
                        serve_client(client_info, transport),
                        probe_options.timeout_ms,
                        "connect",
                    )
                    .await
                };
                let service = match service_result {
                    Ok(service) => service,
                    Err(error) => {
                        return Err(anyhow::Error::new(connect_error(
                            error,
                            None,
                            trace.clone(),
                        )))
                    }
                };
                (service, None)
            }
        };

        Ok(ProbeConnection {
            service,
            stdio,
            trace,
        })
    };

    crate::probe::timing::with_retry(attempt, probe_options.retries, probe_options.retry_delay_ms)
        .await
}

/// Convert a connection failure into a structured error.
pub fn connect_error(
    error: anyhow::Error,
    stdio: Option<StdioCapture>,
    trace: Option<TraceCollector>,
) -> ProbeConnectError {
    let stdio_snapshot = stdio.as_ref().map(|capture| capture.snapshot());
    if let Some(capture) = stdio {
        capture.stop();
    }
    let trace_entries = trace.map(|collector| collector.entries());
    ProbeConnectError {
        error,
        stdio: stdio_snapshot,
        trace: trace_entries,
    }
}
