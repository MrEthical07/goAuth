# Contributing to goAuth

Thank you for your interest in contributing. This document covers conventions for documentation, code, and the changelog.

## Documentation Rules

### Module Docs

Every module doc in `docs/` must follow this template, in order:

1. **Purpose** — what the module does
2. **Public Primitives (APIs)** — signature table, linked to API reference
3. **Strategies / Modes / Config Knobs** — configurable behaviors and defaults
4. **Flow Ownership** — which flows this module participates in (link to `docs/flows.md`)
5. **Examples** — minimal + advanced usage snippets
6. **Return/Failure Examples** — error tables and common failure scenarios
7. **Security Notes** — enumeration resistance, replay protections, etc.
8. **Performance Notes** — alloc/latency hotpaths, Redis ops count
9. **Edge Cases & Guarantees** — known limitations and workarounds
10. **Testing Evidence** — test file names and benchmark names
11. **See Also** — links to related docs

### GoDoc Comments

Every exported symbol must have:

```go
// ShortSummary does X.
//
// Flow: FlowName
// Docs: docs/flows.md#flow-name, docs/module.md#section
//
// Performance: O(1), Redis: N commands.
// Security: relevant security property.
```

### Cross-Linking

All module docs must link to:
- Relevant flow section in `docs/flows.md`
- Relevant config knobs in `docs/config.md`
- Relevant security references
- The minimal example (`examples/http-minimal`)

## Updating the Changelog

1. Add entries under `## [Unreleased]` in `CHANGELOG.md`.
2. Follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.
3. Use categories: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`.
4. On release, move `[Unreleased]` entries to a versioned section.

## Code Conventions

- No public API changes without discussion.
- All exported symbols must have GoDoc comments with Flow + Docs pointers.
- Run `go test -race ./...` before submitting.
- Run `Config.Lint()` and ensure no HIGH-severity warnings.
- Benchmarks must not regress > 30% (enforced by CI gate).

## Testing

- Add tests for any new behavior.
- Name test files `*_test.go` matching the source file.
- Use `miniredis` for unit tests, real Redis for integration tests.
- Fuzz targets go in `*_fuzz_test.go` files.

## Submitting Changes

1. Fork and create a feature branch.
2. Make changes following the conventions above.
3. Run `go test ./...` and `go test -race ./...`.
4. Update `CHANGELOG.md` under `[Unreleased]`.
5. Update relevant docs if behavior changes.
6. Submit a pull request with a clear description.
