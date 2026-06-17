# Security Policy

## Reporting a Vulnerability

Please report security issues through GitHub private vulnerability reporting if
it is available for this repository:
https://github.com/sednalabs/mcp-probe/security/advisories/new

If that is not available, open a minimal public issue that requests a
maintainer security contact without including exploit details, secrets, private
endpoints, or sensitive logs.

## Supported Surface

Security support currently covers the Rust `mcp-probe` CLI, Rust MCP server
tool surface, GitHub Actions workflows, and public package metadata in this
repository.

## Public Report Hygiene

When sharing diagnostics publicly, redact tokens, cookies, host-specific
secrets, private URLs, user names, local filesystem paths, and unique internal
identifiers. Prefer minimal reproduction steps and synthetic endpoints.
