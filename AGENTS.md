# MCP Probe Repository Instructions

## Mission

Build a robust, headless MCP probe for validating MCP server behavior: discovery,
authorization metadata, handshake correctness, transport semantics, descriptor
quality, and reportability.

## Scope and Precedence

- These instructions apply repo-wide unless a closer instruction file overrides
  them.
- Keep changes small, reviewable, and backed by the most relevant hosted
  validation available.

## Public Repository Rules

- Treat all repository content, workflows, logs, artifacts, branch names, and
  commit messages as public surfaces.
- Do not include local credentials, machine paths, private endpoints, private
  workflow names, or maintainer-only operational details.
- Prefer neutral public wording for package-name, registry, or compatibility
  discussions.

## Implementation Principles

- Favor small, incremental, reversible changes.
- Keep the probe core transport-aware but not transport-entangled.
- Put reusable protocol/reporting behavior in library code and keep CLI/server
  adapters thin.
- Avoid new dependencies unless they materially improve correctness,
  interoperability, or security.
- Diagnostics should be structured, concise, and safe to publish.

## Testing and Tooling

- For behavior changes, add or update tests at the natural assertion boundary.
- Use hosted GitHub Actions as the normal validation surface.
- Relevant local commands, when needed for metadata-only checks, are:
  `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo test --all-targets --all-features`, and
  `./scripts/dependency_governance_check.sh`.
