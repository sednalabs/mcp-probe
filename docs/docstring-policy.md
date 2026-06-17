# Docstring Policy (Lean)

## Goal
Docstrings should give humans and agents enough local context to act safely without
searching elsewhere. Keep them short, precise, and maintained.

## When to document
- Public exports, tools, CLI entrypoints, and security/IO boundaries.
- Complex logic or non-obvious constraints.
- Skip trivial helpers where the name and signature are enough.

## Minimal format
- 1-3 sentences: what it does and the observable behavior.
- Add a "Decision:" sentence only when a tradeoff or non-obvious choice matters.
- Add a short "Notes:" list only for invariants, side effects, errors, or footguns.

## Must mention when relevant
- Side effects (IO, network, state changes).
- Error/return semantics.
- Security boundaries (auth, scopes, destructive vs read-only).
- Determinism or performance constraints.

## Maintenance
- Update docstrings when behavior changes.
- Prefer removing stale docstrings over keeping misleading ones.
