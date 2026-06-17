# Contributing

Thanks for improving `mcp-probe`.

## Development

Use the standard Rust workflow:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

For dependency changes, also run:

```bash
./scripts/dependency_governance_check.sh
```

Hosted GitHub Actions are the expected proof surface for pull requests.

## Pull Requests

- Keep changes focused and reversible.
- Include tests or explain why no test seam exists.
- Include dependency-governance notes for new crates or major upgrades.
- Keep examples and logs public-safe.
- Do not include credentials, private endpoints, local machine paths, or
  maintainer-only operational details.
