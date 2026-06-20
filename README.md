# mcp-probe

`mcp-probe` is a headless Rust CLI and MCP server for validating Model Context
Protocol servers. It is built for repeatable connector-readiness checks,
diagnostic reports, and CI-friendly compatibility evidence.

## What It Checks

- Transport connectivity over stdio and streamable HTTP.
- OAuth protected-resource and authorization-server discovery.
- MCP initialize, ping, tools, resources, and prompts surfaces.
- Paginated `tools/list`, `resources/list`, `resources/templates/list`, and
  `prompts/list` handling.
- Complete tool schema compatibility.
- ChatGPT connector descriptor profiles for tool-only and Apps SDK UI surfaces.
- Prompt rendering, resource read/subscribe flows, raw requests, and tool calls.
- Last-Event-ID replay behavior for streamable HTTP sessions.

## Install From Source

```bash
cargo install --git https://github.com/sednalabs/mcp-probe.git
```

Crates.io publication is planned but not required to use the current repository
source package.

## CLI Examples

Run a streamable HTTP probe:

```bash
mcp-probe run --transport streamable-http --url http://127.0.0.1:8000/mcp
```

Run a ChatGPT tool descriptor check:

```bash
mcp-probe run \
  --transport streamable-http \
  --url http://127.0.0.1:8000/mcp \
  --descriptor-profile chatgpt_tool
```

The `chatgpt_tool` profile checks ChatGPT connector metadata without requiring
UI template fields. Optional Apps SDK compatibility fields that have documented
defaults may be omitted; explicitly conflicting values are reported.

Require Apps SDK UI template metadata:

```bash
mcp-probe run \
  --transport streamable-http \
  --url http://127.0.0.1:8000/mcp \
  --descriptor-profile apps_sdk_ui
```

The `apps_sdk_ui` profile accepts the standard `_meta.ui.resourceUri` template
link and the ChatGPT compatibility alias `_meta["openai/outputTemplate"]`.

Capture a full catalog evidence artifact:

```bash
mcp-probe run \
  --transport streamable-http \
  --url http://127.0.0.1:8000/mcp \
  --verbosity full
```

Full probe reports include a redacted `catalog` artifact with server metadata,
capabilities, tools, resources, resource templates, prompts, method status,
page counts, and item counts. Summary output keeps the method/count receipt and
omits large raw catalog payloads. The catalog artifact applies the probe's
default key and telemetry-text redaction so tokens and common secret-like
strings are masked before the artifact is shared.

Render a prompt:

```bash
mcp-probe prompt-render \
  --transport streamable-http \
  --url http://127.0.0.1:8000/mcp \
  --prompt summarize_case \
  --arguments-json '{"case_id":"C123"}'
```

## MCP Tool Surface

When launched as an MCP server, the probe exposes:

- `probe_run`: full probe across discovery and advertised MCP surfaces.
- `probe_run_script`: scripted probe with assertions and snapshots.
- `probe_handshake`: fast initialize, ping, and tools-list check.
- `probe_discover_auth`: protected-resource and OAuth metadata discovery.
- `probe_http_smoke`: HTTP smoke check for auth challenge and metadata routes.
- `probe_replay`: streamable HTTP replay validation.
- `probe_raw_request`: direct MCP method call for low-level debugging.
- `probe_call_tool`: call a target tool with JSON arguments.
- `probe_prompt_render`: render a target prompt with arguments.
- `probe_resource_read`: read a target resource URI.
- `probe_resource_subscribe`: subscribe and unsubscribe to a target resource.
- `probe_help`: usage notes and tool examples.

## Registry Name Notes

This repository is distinct from similarly named third-party packages. See
[`docs/registry-name-review.md`](docs/registry-name-review.md) for the current
neutral comparison and publication notes.

## Security and Dependency Checks

The public repository is expected to run:

- Rust formatting, clippy, and tests.
- Dependency governance through `cargo-deny`, `cargo-audit`, and
  `cargo-outdated`.
- CodeQL with security and quality queries.
- OSSF Scorecard with SARIF uploaded to GitHub code scanning.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
