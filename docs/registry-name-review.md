# Registry Name Review

This note records current package-name observations so maintainers can avoid
confusing consumers when publishing MCP probe and toolkit packages.

## Rust Crates

`mcp-probe` is not currently returned by a crates.io search. The closest
published Rust package observed during release preparation is
`mcp-probe-core` version `0.3.0`.

`mcp-probe-core` describes itself as core MCP types, traits, and transport
implementations. Its public metadata points at `github.com/conikeec/mcp-probe`
and uses the MIT license.

This repository is different in purpose: it is a headless probe application and
MCP server for running compatibility checks, descriptor-profile checks,
auth-discovery checks, tool/resource/prompt checks, replay checks, and
structured diagnostic reports.

## Python Packages

The PyPI name `mcp-probe` is already used by a different project describing
itself as an MCP server security scanner. The org-prefixed
`sednalabs-mcp-probe` name was not observed as published during release
preparation.

The PyPI names `mcp-toolkit` and `sednalabs-mcp-toolkit` should be rechecked
before any Python toolkit publication because package ownership can change.

## npm Packages

The unscoped npm name `mcp-toolkit` is already used by a third-party TypeScript
package for managing MCP servers and tool calls. Sedna package publication
should use scoped names such as `@sednalabs/mcp-toolkit` and
`@sednalabs/mcp-probe` if the TypeScript surfaces are published.

Do not add a dependency on the unscoped npm `mcp-toolkit` package unless that is
an intentional dependency on the third-party package.

## Maintainer Guidance

- Prefer org-scoped or org-prefixed names where registries support them.
- Compare names live immediately before publishing.
- Use neutral wording when distinguishing similarly named projects.
- Do not imply official ownership by another vendor or standards body.
