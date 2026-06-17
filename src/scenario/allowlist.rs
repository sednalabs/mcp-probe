use crate::allowlist::is_host_allowed;
use crate::report::{ProbeStep, ProbeStepStatus};
use crate::transport::TransportType;

/// Enforce host allowlist policy for scripted scenarios.
pub fn enforce_host_allowlist(
    transport: TransportType,
    url: Option<&str>,
    steps: &mut Vec<ProbeStep>,
    allowed_hosts: Option<&[String]>,
) -> bool {
    let allowlist_configured = std::env::var("MCP_PROBE_ALLOWED_HOSTS").is_ok();
    if transport == TransportType::Stdio {
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
        let host = url::Url::parse(url)
            .ok()
            .and_then(|parsed| parsed.host_str().map(|value| value.to_string()))
            .unwrap_or_else(|| "unknown".to_string());
        steps.push(ProbeStep {
            name: "host.allowlist".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some(format!("Host not allowed: {host}")),
            data: None,
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
