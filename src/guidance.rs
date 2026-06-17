use crate::report::ProbeStep;

fn add_hint(hints: &mut Vec<String>, hint: &str) {
    if !hints.iter().any(|entry| entry == hint) {
        hints.push(hint.to_string());
    }
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// Build common guidance hints from an error message.
pub fn build_common_guidance_from_error(message: &str) -> Vec<String> {
    let mut hints = Vec::new();
    if contains_ci(message, "missing token")
        || contains_ci(message, "missing bearer")
        || contains_ci(message, "auth.missing_token")
    {
        add_hint(
            &mut hints,
            "Auth required: pass access_token (Bearer token) or (HTTP only) refresh_token + client_id. If the probe server has cached tokens for this URL, set use_auth: true.",
        );
    }
    if contains_ci(message, "no cached tokens found")
        || contains_ci(message, "cached access token has expired")
    {
        add_hint(
            &mut hints,
            "Auth cache missing or expired: pass access_token or (HTTP only) refresh_token + client_id. access_token_path/refresh_token_path are also supported if token files are available on the probe server.",
        );
    }
    if contains_ci(message, "specify only one auth source") {
        add_hint(
            &mut hints,
            "Auth sources are mutually exclusive. Choose one: use_auth (cached), access_token/access_token_path, or refresh_token/refresh_token_path.",
        );
    }
    if contains_ci(message, "refresh_token is required") {
        add_hint(
            &mut hints,
            "Provide refresh_token directly or via refresh_token_path (JSON with refresh_token).",
        );
    }
    if contains_ci(message, "client_id is required to refresh tokens") {
        add_hint(
            &mut hints,
            "Provide client_id when using refresh_token (either argument or inside refresh_token_path JSON).",
        );
    }
    if contains_ci(
        message,
        "refresh_token auth is only supported for http transports",
    ) {
        add_hint(
            &mut hints,
            "refresh_token auth only works with HTTP transports (sse/streamable-http). For stdio, pass access_token/access_token_path.",
        );
    }
    if contains_ci(message, "token path is outside the allowed directory") {
        add_hint(
            &mut hints,
            "Token file path is outside the probe server token directory (restricted for safety).",
        );
    }
    if contains_ci(message, "host is not in the allowlist")
        || contains_ci(message, "host not allowed")
    {
        add_hint(
            &mut hints,
            "Host blocked by probe allowlist. Use an allowed host (often localhost) or ask the probe operator to allow the target host.",
        );
    }
    if contains_ci(message, "malformed") && contains_ci(message, "url") {
        add_hint(
            &mut hints,
            "Malformed URL: use an absolute HTTP(S) URL with scheme + host, for example `http://127.0.0.1:8002/mcp`.",
        );
    }
    if contains_ci(message, "stdio transport disabled") {
        add_hint(
            &mut hints,
            "stdio transport is disabled by probe policy. Use sse/streamable-http, or ask the probe operator to enable stdio.",
        );
    }
    if contains_ci(message, "oauth metadata") && contains_ci(message, "404")
        || contains_ci(message, "auth.prm") && contains_ci(message, "404")
        || contains_ci(message, "resource_metadata") && contains_ci(message, "404")
    {
        add_hint(
            &mut hints,
            "Server appears to be missing PRM discovery. Ensure it serves `/.well-known/oauth-protected-resource` and returns WWW-Authenticate resource_metadata.",
        );
    }
    if contains_ci(message, "missing resource_metadata") {
        add_hint(
            &mut hints,
            "WWW-Authenticate should include resource_metadata for PRM discovery. Add the header and ensure the URL is reachable.",
        );
    }
    if contains_ci(message, "transport closed") {
        add_hint(
            &mut hints,
            "Transport closed often means the target server crashed or wrote non-JSON-RPC output. Try trace:true for diagnostics; for stdio servers, ensure logs go to stderr (not stdout).",
        );
    }
    hints
}

/// Build common guidance hints from probe steps.
pub fn build_common_guidance_from_report(steps: &[ProbeStep]) -> Vec<String> {
    let mut hints = Vec::new();
    let details: Vec<String> = steps
        .iter()
        .map(|step| step.detail.clone().unwrap_or_default())
        .collect();

    if details.iter().any(|d| {
        contains_ci(d, "missing token")
            || contains_ci(d, "missing bearer")
            || contains_ci(d, "auth.missing_token")
    }) {
        add_hint(
            &mut hints,
            "Auth required: pass access_token (Bearer token) or (HTTP only) refresh_token + client_id. If the probe server has cached tokens for this URL, set use_auth: true.",
        );
    }
    if details.iter().any(|d| {
        contains_ci(d, "no cached tokens found")
            || contains_ci(d, "cached access token has expired")
    }) {
        add_hint(
            &mut hints,
            "Auth cache missing or expired: pass access_token or (HTTP only) refresh_token + client_id. access_token_path/refresh_token_path are also supported if token files are available on the probe server.",
        );
    }
    if details
        .iter()
        .any(|d| contains_ci(d, "specify only one auth source"))
    {
        add_hint(
            &mut hints,
            "Auth sources are mutually exclusive. Choose one: use_auth (cached), access_token/access_token_path, or refresh_token/refresh_token_path.",
        );
    }
    if details
        .iter()
        .any(|d| contains_ci(d, "refresh_token is required"))
    {
        add_hint(
            &mut hints,
            "Provide refresh_token directly or via refresh_token_path (JSON with refresh_token).",
        );
    }
    if details
        .iter()
        .any(|d| contains_ci(d, "client_id is required to refresh tokens"))
    {
        add_hint(
            &mut hints,
            "Provide client_id when using refresh_token (either argument or inside refresh_token_path JSON).",
        );
    }
    if details.iter().any(|d| {
        contains_ci(
            d,
            "refresh_token auth is only supported for http transports",
        )
    }) {
        add_hint(
            &mut hints,
            "refresh_token auth only works with HTTP transports (sse/streamable-http). For stdio, pass access_token/access_token_path.",
        );
    }
    if details
        .iter()
        .any(|d| contains_ci(d, "token path is outside the allowed directory"))
    {
        add_hint(
            &mut hints,
            "Token file path is outside the probe server token directory (restricted for safety).",
        );
    }
    if details.iter().any(|d| {
        contains_ci(d, "host not allowed") || contains_ci(d, "host is not in the allowlist")
    }) {
        add_hint(
            &mut hints,
            "Host blocked by probe allowlist. Use an allowed host (often localhost) or ask the probe operator to allow the target host.",
        );
    }
    if details
        .iter()
        .any(|d| contains_ci(d, "malformed") && contains_ci(d, "url"))
    {
        add_hint(
            &mut hints,
            "Malformed URL: use an absolute HTTP(S) URL with scheme + host, for example `http://127.0.0.1:8002/mcp`.",
        );
    }
    if details
        .iter()
        .any(|d| contains_ci(d, "stdio transport disabled"))
    {
        add_hint(
            &mut hints,
            "stdio transport is disabled by probe policy. Use sse/streamable-http, or ask the probe operator to enable stdio.",
        );
    }
    if steps.iter().any(|step| {
        step.name == "auth.oauth.fetch"
            && step.status == crate::report::ProbeStepStatus::Error
            && step
                .detail
                .as_deref()
                .map(|d| contains_ci(d, "404"))
                .unwrap_or(false)
    }) {
        add_hint(
            &mut hints,
            "PRM discovery failed (404). Ensure server exposes `/.well-known/oauth-protected-resource` and WWW-Authenticate resource_metadata.",
        );
    }
    if details
        .iter()
        .any(|d| contains_ci(d, "missing resource_metadata"))
    {
        add_hint(
            &mut hints,
            "WWW-Authenticate should include resource_metadata for PRM discovery. Add the header and ensure the URL is reachable.",
        );
    }
    if details
        .iter()
        .any(|d| contains_ci(d, "issuer does not match"))
    {
        add_hint(
            &mut hints,
            "Issuer mismatch: align PRM authorization_servers with OAuth metadata issuer on the same host/path lineage.",
        );
    }
    if steps.iter().any(|step| {
        step.name == "resources.list"
            && step.status == crate::report::ProbeStepStatus::Error
            && step
                .detail
                .as_deref()
                .map(|d| contains_ci(d, "typeerror"))
                .unwrap_or(false)
    }) {
        add_hint(
            &mut hints,
            "resources.list threw a TypeError. This usually means the server responded with a malformed resources list or advertised resources capability incorrectly. Try probe_raw_request with method \"resources/list\" to inspect the raw response.",
        );
    }
    if steps.iter().any(|step| {
        step.name == "tools.schema_compatibility"
            && step.status == crate::report::ProbeStepStatus::Error
    }) {
        add_hint(
            &mut hints,
            "Tool schema compatibility failed: inspect report.steps[].data.findings for tool_name, schema_path, fragment, and remediation hint.",
        );
    }
    hints
}

/// Format guidance hints as a bullet list.
pub fn format_guidance(hints: &[String]) -> Option<String> {
    if hints.is_empty() {
        None
    } else {
        Some(format!("Hints:\n- {}", hints.join("\n- ")))
    }
}

/// Summarize failure steps for quick reading.
pub fn format_failure_summary(steps: &[ProbeStep], limit: usize) -> Option<String> {
    let failures: Vec<&ProbeStep> = steps
        .iter()
        .filter(|step| step.status != crate::report::ProbeStepStatus::Ok)
        .collect();
    if failures.is_empty() {
        return None;
    }
    let lines: Vec<String> = failures
        .iter()
        .take(limit)
        .map(|step| {
            if let Some(detail) = &step.detail {
                format!("{}: {}", step.name, detail)
            } else {
                step.name.clone()
            }
        })
        .collect();
    let extra = failures.len().saturating_sub(lines.len());
    let suffix = if extra > 0 {
        Some(format!("- ...and {extra} more"))
    } else {
        None
    };
    let mut parts = vec!["Failures:".to_string(), format!("- {}", lines.join("\n- "))];
    if let Some(suffix) = suffix {
        parts.push(suffix);
    }
    parts.push("See structuredContent.report.steps for full details.".to_string());
    Some(parts.join("\n"))
}
