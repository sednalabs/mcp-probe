//! Streamable HTTP replay probe for Last-Event-ID support.

use crate::allowlist::{enforce_host_allowlist, parse_allowed_hosts_env};
use crate::probe::options::resolve_probe_options;
use crate::report::{now_iso, ProbeStep, ProbeStepStatus, ReplayProbeReport};
use crate::transport::TransportType;
use crate::version::MCP_PROTOCOL_VERSION;
use anyhow::Result;
use futures_util::StreamExt;
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;

const ACCEPT_MCP: &str = "application/json, text/event-stream";

/// Target configuration for replay probes.
#[derive(Debug, Clone)]
pub struct ReplayProbeTarget {
    pub transport_type: Option<TransportType>,
    pub url: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone)]
struct ReplayIds {
    last_event_id: String,
}

fn build_header_map(headers: &HashMap<String, String>) -> reqwest::header::HeaderMap {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    let mut map = HeaderMap::new();
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

fn derive_replay_ids(event_id: &str) -> Option<ReplayIds> {
    let trimmed = event_id.trim();
    let mut parts = trimmed.splitn(2, '/');
    let index_str = parts.next()?;
    let suffix = parts.next();
    let index: i64 = index_str.parse().ok()?;
    let prev_index = index - 1;
    let last_event_id = match suffix {
        Some(suffix) => format!("{prev_index}/{suffix}"),
        None => format!("{prev_index}"),
    };
    Some(ReplayIds { last_event_id })
}

async fn read_sse_event_id(response: reqwest::Response, timeout_ms: u64) -> Result<Option<String>> {
    let mut stream = response.bytes_stream();
    let mut buffer = String::new();
    let deadline = if timeout_ms == 0 {
        None
    } else {
        Some(Duration::from_millis(timeout_ms))
    };

    let read_future = async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            buffer.push_str(&String::from_utf8_lossy(&chunk));
            let mut lines: Vec<String> = buffer.split('\n').map(str::to_string).collect();
            let last = lines.pop().unwrap_or_default();
            buffer = last;
            for line in lines {
                let line = line.trim_end_matches('\r');
                if let Some(stripped) = line.strip_prefix("id:") {
                    return Ok(Some(stripped.trim().to_string()));
                }
            }
        }
        Ok(None)
    };

    match deadline {
        Some(duration) => match tokio::time::timeout(duration, read_future).await {
            Ok(result) => result,
            Err(_) => Ok(None),
        },
        None => read_future.await,
    }
}

/// Run a Last-Event-ID replay probe against a streamable HTTP endpoint.
pub async fn run_replay_probe(target: ReplayProbeTarget) -> ReplayProbeReport {
    let started_at = now_iso();
    let mut steps: Vec<ProbeStep> = Vec::new();
    let probe_options = resolve_probe_options(target.timeout_ms, None, None);
    let allowed_hosts = parse_allowed_hosts_env();

    if let Some(transport) = target.transport_type {
        if transport != TransportType::StreamableHttp {
            steps.push(ProbeStep {
                name: "replay.transport".to_string(),
                status: ProbeStepStatus::Error,
                detail: Some("Replay probe only supports streamable-http transport.".to_string()),
                data: None,
            });
            return ReplayProbeReport {
                ok: false,
                started_at,
                finished_at: now_iso(),
                steps,
                session_id: None,
                event_id: None,
                last_event_id: None,
            };
        }
    }

    let allowlist_ok = enforce_host_allowlist(
        TransportType::StreamableHttp.as_str(),
        target.url.as_deref(),
        &mut steps,
        allowed_hosts.as_deref(),
    );
    if !allowlist_ok {
        return ReplayProbeReport {
            ok: false,
            started_at,
            finished_at: now_iso(),
            steps,
            session_id: None,
            event_id: None,
            last_event_id: None,
        };
    }

    let Some(url) = target.url.as_deref() else {
        steps.push(ProbeStep {
            name: "replay.init".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some("Missing target URL.".to_string()),
            data: None,
        });
        return ReplayProbeReport {
            ok: false,
            started_at,
            finished_at: now_iso(),
            steps,
            session_id: None,
            event_id: None,
            last_event_id: None,
        };
    };

    let headers = target.headers.clone().unwrap_or_default();
    let client = reqwest::Client::new();
    let mut session_id: Option<String> = None;
    let mut event_id: Option<String> = None;
    let mut last_event_id: Option<String> = None;

    let header_map = build_header_map(&headers);
    let init_response = crate::http::fetch_with_timeout(
        &client,
        client
            .post(url)
            .headers(header_map.clone())
            .header("Accept", ACCEPT_MCP)
            .header("Content-Type", "application/json")
            .body(
                serde_json::to_string(&json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": { "name": "mcp-probe", "version": "0.1" }
                    }
                }))
                .unwrap_or_default(),
            ),
        probe_options.timeout_ms,
    )
    .await;

    let init_response = match init_response {
        Ok(resp) => resp,
        Err(err) => {
            steps.push(ProbeStep {
                name: "replay.init".to_string(),
                status: ProbeStepStatus::Error,
                detail: Some(err.to_string()),
                data: None,
            });
            return ReplayProbeReport {
                ok: false,
                started_at,
                finished_at: now_iso(),
                steps,
                session_id,
                event_id,
                last_event_id,
            };
        }
    };

    if !init_response.status().is_success() {
        steps.push(ProbeStep {
            name: "replay.init".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some(format!("HTTP {}", init_response.status())),
            data: None,
        });
        return ReplayProbeReport {
            ok: false,
            started_at,
            finished_at: now_iso(),
            steps,
            session_id,
            event_id,
            last_event_id,
        };
    }

    session_id = init_response
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if session_id.is_none() {
        steps.push(ProbeStep {
            name: "replay.init".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some("Missing Mcp-Session-Id header.".to_string()),
            data: None,
        });
        return ReplayProbeReport {
            ok: false,
            started_at,
            finished_at: now_iso(),
            steps,
            session_id,
            event_id,
            last_event_id,
        };
    }
    steps.push(ProbeStep {
        name: "replay.init".to_string(),
        status: ProbeStepStatus::Ok,
        detail: None,
        data: None,
    });

    let sse_response = client
        .get(url)
        .headers(header_map.clone())
        .header("Accept", "text/event-stream")
        .header("Mcp-Session-Id", session_id.clone().unwrap_or_default())
        .send()
        .await;

    let sse_response = match sse_response {
        Ok(resp) => resp,
        Err(err) => {
            steps.push(ProbeStep {
                name: "replay.stream.open".to_string(),
                status: ProbeStepStatus::Error,
                detail: Some(err.to_string()),
                data: None,
            });
            return ReplayProbeReport {
                ok: false,
                started_at,
                finished_at: now_iso(),
                steps,
                session_id,
                event_id,
                last_event_id,
            };
        }
    };

    if !sse_response.status().is_success() {
        steps.push(ProbeStep {
            name: "replay.stream.open".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some(format!("HTTP {}", sse_response.status())),
            data: None,
        });
        return ReplayProbeReport {
            ok: false,
            started_at,
            finished_at: now_iso(),
            steps,
            session_id,
            event_id,
            last_event_id,
        };
    }

    steps.push(ProbeStep {
        name: "replay.stream.open".to_string(),
        status: ProbeStepStatus::Ok,
        detail: None,
        data: None,
    });

    let sse_task = tokio::spawn(read_sse_event_id(sse_response, probe_options.timeout_ms));

    let list_response = crate::http::fetch_with_timeout(
        &client,
        client
            .post(url)
            .headers(header_map.clone())
            .header("Accept", ACCEPT_MCP)
            .header("Content-Type", "application/json")
            .header("Mcp-Session-Id", session_id.clone().unwrap_or_default())
            .body(
                serde_json::to_string(&json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {}
                }))
                .unwrap_or_default(),
            ),
        probe_options.timeout_ms,
    )
    .await;

    match list_response {
        Ok(resp) if resp.status().is_success() => steps.push(ProbeStep {
            name: "replay.trigger".to_string(),
            status: ProbeStepStatus::Ok,
            detail: None,
            data: None,
        }),
        Ok(resp) => steps.push(ProbeStep {
            name: "replay.trigger".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some(format!("HTTP {}", resp.status())),
            data: None,
        }),
        Err(err) => steps.push(ProbeStep {
            name: "replay.trigger".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some(err.to_string()),
            data: None,
        }),
    }

    event_id = match sse_task.await {
        Ok(Ok(value)) => value,
        Ok(Err(err)) => {
            steps.push(ProbeStep {
                name: "replay.capture".to_string(),
                status: ProbeStepStatus::Error,
                detail: Some(err.to_string()),
                data: None,
            });
            None
        }
        Err(err) => {
            steps.push(ProbeStep {
                name: "replay.capture".to_string(),
                status: ProbeStepStatus::Error,
                detail: Some(err.to_string()),
                data: None,
            });
            None
        }
    };

    if event_id.is_none() {
        steps.push(ProbeStep {
            name: "replay.capture".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some("No event id captured from SSE stream.".to_string()),
            data: None,
        });
        return ReplayProbeReport {
            ok: false,
            started_at,
            finished_at: now_iso(),
            steps,
            session_id,
            event_id,
            last_event_id,
        };
    }

    let replay_ids = derive_replay_ids(event_id.as_deref().unwrap_or(""));
    if replay_ids.is_none() {
        steps.push(ProbeStep {
            name: "replay.capture".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some(format!(
                "Unexpected event id format: {}",
                event_id.clone().unwrap_or_default()
            )),
            data: None,
        });
        return ReplayProbeReport {
            ok: false,
            started_at,
            finished_at: now_iso(),
            steps,
            session_id,
            event_id,
            last_event_id,
        };
    }

    let replay_ids = replay_ids.unwrap();
    last_event_id = Some(replay_ids.last_event_id.clone());
    steps.push(ProbeStep {
        name: "replay.capture".to_string(),
        status: ProbeStepStatus::Ok,
        detail: None,
        data: None,
    });

    let close_response = crate::http::fetch_with_timeout(
        &client,
        client
            .delete(url)
            .headers(header_map.clone())
            .header("Mcp-Session-Id", session_id.clone().unwrap_or_default()),
        probe_options.timeout_ms,
    )
    .await;
    match close_response {
        Ok(resp) if resp.status().is_success() => steps.push(ProbeStep {
            name: "replay.close".to_string(),
            status: ProbeStepStatus::Ok,
            detail: None,
            data: None,
        }),
        Ok(resp) => steps.push(ProbeStep {
            name: "replay.close".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some(format!("HTTP {}", resp.status())),
            data: None,
        }),
        Err(err) => steps.push(ProbeStep {
            name: "replay.close".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some(err.to_string()),
            data: None,
        }),
    }

    let replay_response = client
        .get(url)
        .headers(header_map)
        .header("Accept", "text/event-stream")
        .header("Mcp-Session-Id", session_id.clone().unwrap_or_default())
        .header("Last-Event-ID", replay_ids.last_event_id)
        .send()
        .await;

    let replay_response = match replay_response {
        Ok(resp) => resp,
        Err(err) => {
            steps.push(ProbeStep {
                name: "replay.resume".to_string(),
                status: ProbeStepStatus::Error,
                detail: Some(err.to_string()),
                data: None,
            });
            return ReplayProbeReport {
                ok: false,
                started_at,
                finished_at: now_iso(),
                steps,
                session_id,
                event_id,
                last_event_id,
            };
        }
    };

    if !replay_response.status().is_success() {
        steps.push(ProbeStep {
            name: "replay.resume".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some(format!("HTTP {}", replay_response.status())),
            data: None,
        });
        return ReplayProbeReport {
            ok: false,
            started_at,
            finished_at: now_iso(),
            steps,
            session_id,
            event_id,
            last_event_id,
        };
    }

    let replay_event_id = read_sse_event_id(replay_response, probe_options.timeout_ms)
        .await
        .ok()
        .flatten();
    if replay_event_id.is_none() {
        steps.push(ProbeStep {
            name: "replay.resume".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some("No replay event received.".to_string()),
            data: None,
        });
        return ReplayProbeReport {
            ok: false,
            started_at,
            finished_at: now_iso(),
            steps,
            session_id,
            event_id,
            last_event_id,
        };
    }

    steps.push(ProbeStep {
        name: "replay.resume".to_string(),
        status: ProbeStepStatus::Ok,
        detail: None,
        data: None,
    });

    let ok = steps.iter().all(|step| step.status == ProbeStepStatus::Ok);
    ReplayProbeReport {
        ok,
        started_at,
        finished_at: now_iso(),
        steps,
        session_id,
        event_id,
        last_event_id,
    }
}
