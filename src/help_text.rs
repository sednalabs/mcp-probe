/// Help entry describing a probe tool.
#[derive(Debug, Clone)]
pub struct ToolHelpEntry {
    pub name: String,
    pub summary: String,
    pub example: Vec<String>,
}

/// Example IDs for probe_run usage snippets.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProbeRunExampleId {
    Unauthenticated,
    Cached,
    Explicit,
    Refresh,
}

struct ProbeRunExample {
    id: ProbeRunExampleId,
    title: &'static str,
    line: &'static str,
}

const PROBE_RUN_EXAMPLES: &[ProbeRunExample] = &[
    ProbeRunExample {
        id: ProbeRunExampleId::Unauthenticated,
        title: "Unauthenticated probe",
        line: "{ \"transport\": \"streamable-http\", \"url\": \"http://127.0.0.1:8002/mcp\" }",
    },
    ProbeRunExample {
        id: ProbeRunExampleId::Cached,
        title: "Auth with cached token (if available on the probe server)",
        line: "{ \"transport\": \"streamable-http\", \"url\": \"http://127.0.0.1:8002/mcp\", \"use_auth\": true }",
    },
    ProbeRunExample {
        id: ProbeRunExampleId::Explicit,
        title: "Auth with explicit token",
        line: "{ \"transport\": \"streamable-http\", \"url\": \"http://127.0.0.1:8002/mcp\", \"access_token\": \"<token>\" }",
    },
    ProbeRunExample {
        id: ProbeRunExampleId::Refresh,
        title: "Refresh access token (OAuth refresh_token)",
        line: "{ \"transport\": \"streamable-http\", \"url\": \"http://127.0.0.1:8002/mcp\", \"refresh_token\": \"<refresh_token>\", \"client_id\": \"my-client\" }",
    },
];

fn format_probe_run_example_lines(ids: Option<&[ProbeRunExampleId]>) -> Vec<String> {
    let selection: Vec<ProbeRunExampleId> = ids
        .map(|slice| slice.to_vec())
        .unwrap_or_else(|| PROBE_RUN_EXAMPLES.iter().map(|item| item.id).collect());
    let selected: Vec<&ProbeRunExample> = PROBE_RUN_EXAMPLES
        .iter()
        .filter(|item| selection.contains(&item.id))
        .collect();
    let mut lines = vec!["Examples:".to_string()];
    for (index, item) in selected.iter().enumerate() {
        lines.push(format!("{}{}) {}:", index + 1, "", item.title));
        lines.push(format!("   {}", item.line));
    }
    lines
}

fn base_tool_entries() -> Vec<ToolHelpEntry> {
    vec![
        ToolHelpEntry {
            name: "probe_run".to_string(),
            summary: "Full probe: connect + list tools/resources/prompts.".to_string(),
            example: Vec::new(),
        },
        ToolHelpEntry {
            name: "probe_run_script".to_string(),
            summary: "Scripted probe with assertions and snapshots.".to_string(),
            example: vec![
                "Example script:",
                "{",
                "  \"scenario\": {",
                "    \"transport\": \"streamable-http\",",
                "    \"url\": \"http://127.0.0.1:8002/mcp\",",
                "    \"access_token\": \"<token>\",",
                "    \"steps\": [",
                "      { \"tool\": \"ping\" }",
                "    ]",
                "  }",
                "}",
            ]
            .into_iter()
            .map(|line| line.to_string())
            .collect(),
        },
        ToolHelpEntry {
            name: "probe_help".to_string(),
            summary: "List tools, examples, and usage notes.".to_string(),
            example: vec!["{ }".to_string()],
        },
        ToolHelpEntry {
            name: "probe_discover_auth".to_string(),
            summary: "Check PRM + OAuth metadata discovery without connecting.".to_string(),
            example: vec!["{ \"url\": \"http://127.0.0.1:8002/mcp\" }".to_string()],
        },
        ToolHelpEntry {
            name: "probe_handshake".to_string(),
            summary:
                "Connect + ping + list tools, or confirm an expected bearer challenge before authenticated requests."
                    .to_string(),
            example: vec![
                "{ \"transport\": \"streamable-http\", \"url\": \"http://127.0.0.1:8002/mcp\" }"
                    .to_string(),
                "{ \"transport\": \"streamable-http\", \"url\": \"http://127.0.0.1:8002/mcp\", \"expect_auth_required\": true }"
                    .to_string(),
            ],
        },
        ToolHelpEntry {
            name: "probe_http_smoke".to_string(),
            summary: "HTTP smoke check for PRM + OAuth metadata endpoints.".to_string(),
            example: vec![
                "{ \"url\": \"http://127.0.0.1:8002/mcp\" }".to_string(),
                "{ \"url\": \"http://127.0.0.1:8002/mcp\", \"expect_registration_endpoint\": true }"
                    .to_string(),
            ],
        },
        ToolHelpEntry {
            name: "probe_replay".to_string(),
            summary: "Validate Last-Event-ID replay for streamable HTTP.".to_string(),
            example: vec![
                "{ \"url\": \"http://127.0.0.1:8002/mcp\", \"use_auth\": true }".to_string(),
            ],
        },
        ToolHelpEntry {
            name: "probe_raw_request".to_string(),
            summary: "Send a raw MCP request (method + params).".to_string(),
            example: vec![
                "{",
                "  \"transport\": \"streamable-http\",",
                "  \"url\": \"http://127.0.0.1:8002/mcp\",",
                "  \"method\": \"tools/list\"",
                "}",
            ]
            .into_iter()
            .map(|line| line.to_string())
            .collect(),
        },
        ToolHelpEntry {
            name: "probe_call_tool".to_string(),
            summary: "Connect and call a single MCP tool.".to_string(),
            example: vec![
                "{",
                "  \"transport\": \"streamable-http\",",
                "  \"url\": \"http://127.0.0.1:8002/mcp\",",
                "  \"tool_name\": \"status.get\",",
                "  \"arguments\": {}",
                "}",
            ]
            .into_iter()
            .map(|line| line.to_string())
            .collect(),
        },
        ToolHelpEntry {
            name: "probe_prompt_render".to_string(),
            summary: "Connect and render a single MCP prompt.".to_string(),
            example: vec![
                "{",
                "  \"transport\": \"streamable-http\",",
                "  \"url\": \"http://127.0.0.1:8002/mcp\",",
                "  \"prompt_name\": \"summarize_case\",",
                "  \"arguments\": { \"case_id\": \"C123\" }",
                "}",
            ]
            .into_iter()
            .map(|line| line.to_string())
            .collect(),
        },
        ToolHelpEntry {
            name: "probe_resource_read".to_string(),
            summary: "Connect and read a single MCP resource.".to_string(),
            example: vec![
                "{",
                "  \"transport\": \"streamable-http\",",
                "  \"url\": \"http://127.0.0.1:8002/mcp\",",
                "  \"uri\": \"mcp-probe://status\"",
                "}",
            ]
            .into_iter()
            .map(|line| line.to_string())
            .collect(),
        },
        ToolHelpEntry {
            name: "probe_resource_subscribe".to_string(),
            summary: "Connect, subscribe to a resource URI, then unsubscribe.".to_string(),
            example: vec![
                "{",
                "  \"transport\": \"streamable-http\",",
                "  \"url\": \"http://127.0.0.1:8002/mcp\",",
                "  \"uri\": \"mcp-probe://status\",",
                "  \"trace\": true",
                "}",
            ]
            .into_iter()
            .map(|line| line.to_string())
            .collect(),
        },
    ]
}

const NOTES: &[&str] = &[
    "Notes:",
    "- transport: stdio | sse | streamable-http (alias streamable_http)",
    "- log_format: json | logfmt (alias text)",
    "- auth: for protected servers, pass access_token (Bearer token). For OAuth refresh flows, pass refresh_token + client_id (HTTP transports only).",
    "- expect_auth_required: for protected HTTP servers, allows probe_handshake to stop cleanly once the expected bearer challenge is confirmed.",
    "- use_auth: true uses a cached token if the probe server has one configured for the target URL.",
    "- *_token_path options read a token JSON file; paths are restricted to the probe server token directory for safety.",
    "- refresh_token auth: token_endpoint is discovered from server_url if omitted.",
    "- verbosity: summary (default) omits tools/resources/resource_templates/prompts raw payloads; full returns full report payloads and the redacted catalog artifact.",
    "- descriptor_profile: basic (default) checks generic input schemas; chatgpt_tool also checks tool-only ChatGPT connector metadata; apps_sdk_ui requires at least one UI template descriptor.",
    "- trace: true captures JSON-RPC traffic (may be large).",
    "- stdio cwd/env: set cwd or env for stdio transports when probing monorepos.",
    "- stdio may be disabled by probe policy; if so, use sse/streamable-http.",
    "- outbound URL hosts may be restricted by probe policy; localhost is commonly allowed.",
    "- probe_raw_request params must be an object when provided (null is treated as omitted).",
    "- probe_prompt_render sends prompts/get with prompt_name and optional arguments; use dry_run first to preview target/auth/argument keys.",
    "- probe_resource_read sends resources/read for one URI; probe_resource_subscribe sends resources/subscribe then resources/unsubscribe.",
    "- For resource subscription update-notification debugging, pass trace: true and inspect the returned trace in full verbosity.",
    "- probe_replay only supports streamable-http and opens a short SSE stream to capture event ids.",
    "- dry_run: true skips sending the request and returns a preview.",
];

const AUTH_GOTCHAS: &[&str] = &[
    "Auth gotchas:",
    "- use_auth (cached tokens) is mutually exclusive with access_token* and refresh_token* options.",
    "- refresh_token auth only works for HTTP transports (sse/streamable-http).",
    "- expect_registration_endpoint: true fails auth discovery/smoke unless OAuth metadata includes registration_endpoint.",
    "- token file paths must be within the probe server token directory (enforced for safety).",
];

/// Return help entries for all probe tools.
pub fn list_probe_tools() -> Vec<ToolHelpEntry> {
    let mut entries = base_tool_entries();
    for entry in entries.iter_mut() {
        if entry.name == "probe_run" {
            entry.example = format_probe_run_example_lines(None);
        }
    }
    entries
}

fn find_entry(name: &str) -> Option<ToolHelpEntry> {
    base_tool_entries()
        .into_iter()
        .find(|entry| entry.name == name)
}

/// Format help text for a specific tool or a global summary.
pub fn format_probe_help_text(tool_name: Option<&str>) -> String {
    if let Some(tool_name) = tool_name {
        if let Some(entry) = find_entry(tool_name) {
            let mut parts: Vec<String> = Vec::new();
            parts.push(format!("Tool: {}", entry.name));
            parts.push(entry.summary);
            parts.push(String::new());
            parts.extend(entry.example);
            parts.push(String::new());
            parts.extend(NOTES.iter().map(|line| line.to_string()));
            parts.push(String::new());
            parts.extend(AUTH_GOTCHAS.iter().map(|line| line.to_string()));
            return parts.join("\n");
        }
        let known = base_tool_entries()
            .iter()
            .map(|tool| tool.name.clone())
            .collect::<Vec<_>>()
            .join(", ");
        return format!("Unknown tool \"{tool_name}\". Known tools: {known}.");
    }

    let mut parts: Vec<String> = Vec::new();
    parts.push("mcp-probe tools:".to_string());
    for (index, entry) in base_tool_entries().iter().enumerate() {
        parts.push(format!(
            "{}{}) {} - {}",
            index + 1,
            "",
            entry.name,
            entry.summary
        ));
    }
    parts.push(String::new());
    parts.extend(NOTES.iter().map(|line| line.to_string()));
    parts.push(String::new());
    parts.extend(AUTH_GOTCHAS.iter().map(|line| line.to_string()));
    parts.join("\n")
}

/// Format probe_run examples.
pub fn format_probe_run_examples() -> String {
    format_probe_run_example_lines(None).join("\n")
}

/// Format probe_run examples for selected IDs.
pub fn format_probe_run_examples_for(ids: &[ProbeRunExampleId]) -> String {
    format_probe_run_example_lines(Some(ids)).join("\n")
}

/// Format the probe_run_script example payload.
pub fn format_probe_script_example() -> String {
    find_entry("probe_run_script")
        .map(|entry| entry.example.join("\n"))
        .unwrap_or_default()
}

/// Format the probe_discover_auth example payload.
pub fn format_probe_discover_auth_example() -> String {
    find_entry("probe_discover_auth")
        .map(|entry| entry.example.join("\n"))
        .unwrap_or_default()
}

/// Format the probe_handshake example payload.
pub fn format_probe_handshake_example() -> String {
    find_entry("probe_handshake")
        .map(|entry| entry.example.join("\n"))
        .unwrap_or_default()
}

/// Format the probe_http_smoke example payload.
pub fn format_probe_http_smoke_example() -> String {
    find_entry("probe_http_smoke")
        .map(|entry| entry.example.join("\n"))
        .unwrap_or_default()
}

/// Format the probe_replay example payload.
pub fn format_probe_replay_example() -> String {
    find_entry("probe_replay")
        .map(|entry| entry.example.join("\n"))
        .unwrap_or_default()
}

/// Format the probe_raw_request example payload.
pub fn format_probe_raw_request_example() -> String {
    find_entry("probe_raw_request")
        .map(|entry| entry.example.join("\n"))
        .unwrap_or_default()
}

/// Format the probe_call_tool example payload.
pub fn format_probe_call_tool_example() -> String {
    find_entry("probe_call_tool")
        .map(|entry| entry.example.join("\n"))
        .unwrap_or_default()
}

/// Format the probe_prompt_render example payload.
pub fn format_probe_prompt_render_example() -> String {
    find_entry("probe_prompt_render")
        .map(|entry| entry.example.join("\n"))
        .unwrap_or_default()
}

/// Format the probe_resource_read example payload.
pub fn format_probe_resource_read_example() -> String {
    find_entry("probe_resource_read")
        .map(|entry| entry.example.join("\n"))
        .unwrap_or_default()
}

/// Format the probe_resource_subscribe example payload.
pub fn format_probe_resource_subscribe_example() -> String {
    find_entry("probe_resource_subscribe")
        .map(|entry| entry.example.join("\n"))
        .unwrap_or_default()
}
