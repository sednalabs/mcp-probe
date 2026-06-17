use crate::report::{ProbeStep, ProbeStepStatus};
use serde_json::json;
use std::env;
use url::Url;

const DEFAULT_ALLOWED_HOSTS: &[&str] = &["localhost", "127.0.0.1", "::1"];
const STDIO_ALLOW_ENV: &str = "MCP_PROBE_ALLOW_STDIO";

fn is_truthy(value: &str) -> bool {
    let normalized = value.trim().to_lowercase();
    !matches!(normalized.as_str(), "0" | "false" | "no" | "off")
}

/// Return true when stdio transport is explicitly enabled.
pub fn is_stdio_allowed() -> bool {
    let raw = env::var(STDIO_ALLOW_ENV).ok();
    match raw {
        Some(value) => is_truthy(&value),
        None => false,
    }
}

/// Parse the outbound host allowlist from the environment.
///
/// Notes:
/// - Defaults to localhost-only when unset or empty.
pub fn parse_allowed_hosts_env() -> Option<Vec<String>> {
    let raw = env::var("MCP_PROBE_ALLOWED_HOSTS").ok();
    match raw {
        None => Some(
            DEFAULT_ALLOWED_HOSTS
                .iter()
                .map(|host| host.to_string())
                .collect(),
        ),
        Some(value) => {
            if value.trim().is_empty() {
                return Some(
                    DEFAULT_ALLOWED_HOSTS
                        .iter()
                        .map(|host| host.to_string())
                        .collect(),
                );
            }
            let hosts: Vec<String> = value
                .split(|c: char| c == ',' || c.is_whitespace())
                .map(|entry| entry.trim())
                .filter(|entry| !entry.is_empty())
                .map(|entry| entry.to_string())
                .collect();
            if hosts.is_empty() {
                None
            } else {
                Some(hosts)
            }
        }
    }
}

/// Check whether a URL matches the host allowlist.
pub fn is_host_allowed(url: &str, allowed_hosts: Option<&[String]>) -> bool {
    let Some(allowed) = allowed_hosts else {
        return true;
    };
    if allowed.is_empty() {
        return true;
    }
    let parsed = Url::parse(url).ok();
    let Some(parsed) = parsed else {
        return false;
    };
    let hostname = parsed.host_str().unwrap_or_default();
    let host_with_port = match parsed.port_or_known_default() {
        Some(port) => format!("{hostname}:{port}"),
        None => hostname.to_string(),
    };
    let origin = parsed.origin().ascii_serialization();
    allowed
        .iter()
        .any(|entry| entry == hostname || entry == &host_with_port || entry == &origin)
}

/// Ensure a URL's host is permitted by the allowlist.
///
/// # Errors
/// Returns an error when the host is not allowed or the URL is invalid.
pub fn ensure_host_allowed(
    url: &str,
    allowed_hosts: Option<&[String]>,
    label: &str,
) -> anyhow::Result<()> {
    if !is_host_allowed(url, allowed_hosts) {
        return Err(anyhow::anyhow!("{label} host is not in the allowlist"));
    }
    Ok(())
}

/// Enforce stdio transport allowlist policy and record a step.
///
/// Returns `true` when stdio is permitted.
pub fn enforce_stdio_allowlist(transport: &str, steps: &mut Vec<ProbeStep>) -> bool {
    if transport != "stdio" {
        return true;
    }
    if is_stdio_allowed() {
        steps.push(ProbeStep {
            name: "stdio.allowlist".to_string(),
            status: ProbeStepStatus::Ok,
            detail: None,
            data: None,
        });
        return true;
    }
    steps.push(ProbeStep {
        name: "stdio.allowlist".to_string(),
        status: ProbeStepStatus::Error,
        detail: Some(format!(
            "stdio transport disabled. Set {STDIO_ALLOW_ENV}=1 to enable."
        )),
        data: None,
    });
    false
}

/// Enforce host allowlist policy for HTTP transports and record a step.
///
/// Returns `true` when the host is permitted or not applicable.
pub fn enforce_host_allowlist(
    transport: &str,
    url: Option<&str>,
    steps: &mut Vec<ProbeStep>,
    allowed_hosts: Option<&[String]>,
) -> bool {
    let allowlist_configured = env::var("MCP_PROBE_ALLOWED_HOSTS").is_ok();
    if transport == "stdio" {
        steps.push(ProbeStep {
            name: "host.allowlist".to_string(),
            status: ProbeStepStatus::Ok,
            detail: Some("not applicable".to_string()),
            data: None,
        });
        return true;
    }
    let Some(allowed) = allowed_hosts else {
        steps.push(ProbeStep {
            name: "host.allowlist".to_string(),
            status: ProbeStepStatus::Ok,
            detail: Some("not configured".to_string()),
            data: None,
        });
        return true;
    };
    if allowed.is_empty() {
        steps.push(ProbeStep {
            name: "host.allowlist".to_string(),
            status: ProbeStepStatus::Ok,
            detail: Some("not configured".to_string()),
            data: None,
        });
        return true;
    }
    let Some(url) = url else {
        steps.push(ProbeStep {
            name: "host.allowlist".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some("Missing target URL".to_string()),
            data: None,
        });
        return false;
    };

    if !is_host_allowed(url, Some(allowed)) {
        let parsed = Url::parse(url);
        let Err(parse_error) = parsed.as_ref() else {
            let host = parsed
                .ok()
                .and_then(|parsed| parsed.host_str().map(|value| value.to_string()))
                .unwrap_or_else(|| "unknown".to_string());
            steps.push(ProbeStep {
                name: "host.allowlist".to_string(),
                status: ProbeStepStatus::Error,
                detail: Some(format!("Host not allowed: {host}")),
                data: Some(json!({
                    "code": "host_not_allowed",
                    "url": url,
                    "host": host
                })),
            });
            return false;
        };
        steps.push(ProbeStep {
            name: "host.allowlist".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some("Malformed target URL".to_string()),
            data: Some(json!({
                "code": "url_malformed",
                "endpoint": "target",
                "url": url,
                "error": parse_error.to_string()
            })),
        });
        return false;
    }

    steps.push(ProbeStep {
        name: "host.allowlist".to_string(),
        status: ProbeStepStatus::Ok,
        detail: if allowlist_configured {
            None
        } else {
            Some("default (localhost only)".to_string())
        },
        data: None,
    });
    true
}

/// Add an expect-auth-required check to probe steps.
pub fn apply_expect_auth_required(steps: &mut Vec<ProbeStep>, expect_auth_required: Option<bool>) {
    if expect_auth_required != Some(true) {
        return;
    }
    let prm_step = steps.iter().find(|step| step.name == "auth.prm");
    let ok = prm_step
        .map(|step| {
            step.status == ProbeStepStatus::Ok
                && step.detail.as_deref() != Some("no auth required")
                && step.detail.as_deref() != Some("not applicable")
        })
        .unwrap_or(false);
    let detail = if ok {
        None
    } else {
        Some("Expected an auth challenge but none was detected".to_string())
    };
    steps.push(ProbeStep {
        name: "expect.auth_required".to_string(),
        status: if ok {
            ProbeStepStatus::Ok
        } else {
            ProbeStepStatus::Error
        },
        detail,
        data: None,
    });
}
