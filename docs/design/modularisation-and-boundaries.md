# Modularisation and Boundaries (Documentation-Only Policy)

## Context

This repository contains:

- Rust probe implementation (`src/`)
- build and provenance helpers (`build.rs`, `build_support.rs`)
- integration tests (`tests/`)
- public usage and governance docs (`docs/`)

To keep the codebase easy to evolve, we prefer modularization that reduces
coupling, preserves auditability, and supports incremental refactors.

## Status and enforcement

This is a **documentation-only policy** at the time of writing: guidance, not a
hard CI gate. Structural changes should be incremental, reversible, and tied to
real delivery work.

## Definitions

### Monolith (what we mean here)

A monolith is not just a large file. It is a unit (module/package/workflow)
that:

- mixes unrelated responsibilities (protocol orchestration + transport IO +
  persistence + policy), or
- becomes a widely imported "god module" with hidden coupling.

### Large cohesive rulebook (acceptable when deliberate)

Some modules are intentionally large because they are a rulebook (for example,
a scenario manifest or contract normalization table). This is acceptable when:

- there is one clear domain and reason to change,
- the public facade stays small and stable,
- sections are clearly structured, and
- tests validate the external contract.

### Distributed monolith (anti-pattern)

A distributed monolith is many small modules with tight coupling:

- deep import chains,
- cyclic dependencies, or
- file-count splits that do not create real domain boundaries.

Split by cohesive seams, not by line count.

## Dependency direction (boundaries)

Prefer one simple rule: **dependencies point from orchestration toward
primitives**.

High-level guidance:

- CLI/server entrypoints orchestrate behavior but should not own core protocol
  logic.
- Probe core logic should be transport-agnostic and reusable.
- Transport adapters (stdio/HTTP/SSE/child process) should remain thin.
- Report/schema normalization should be centralized to avoid per-tool drift.
- Test helpers and fixtures should not leak into production paths.

## Blessed homes (where new code goes)

To reduce ambiguity:

- Protocol and result-shaping logic: `src/`
- Transport-specific wiring: transport adapter modules near entrypoints
- End-to-end scenarios and fixtures: `tests/`
- Stable user-facing reference material: `docs/`
- Build/release/support scripts: `scripts/`

## Refactor posture (how to apply this policy safely)

1. **Forward-first.** New work follows the current best structure.
2. **Opportunistic retrofit.** Refactor modules when touching behavior, not as
   churn-only PRs.
3. **Facade first.** Introduce a small facade API, then extract one cohesive
   sub-component per PR.
4. **Prefer contract tests over internals.** Validate behavior via stable
   inputs/outputs.

## References

- `AGENTS.md`
- `README.md`
- `docs/dependency-governance.md`
