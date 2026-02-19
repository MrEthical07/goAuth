# goAuth Documentation Index

This directory contains the authoritative documentation for the goAuth authentication engine.

## Quick Navigation

| Goal | Start Here |
|------|-----------|
| **First integration** | [README](../README.md) → [usage.md](usage.md) → [examples/http-minimal](../examples/http-minimal/) |
| **Choose validation mode** | [jwt.md § Validation Modes](jwt.md) → [config.md § Validation Mode](config.md#validation-mode-configvalidationmode) |
| **Add MFA** | [mfa.md](mfa.md) → [flows.md § TOTP](flows.md#totp-setup) |
| **Add password reset / email verification** | [password_reset.md](password_reset.md) · [email_verification.md](email_verification.md) |
| **Understand all flows** | [flows.md](flows.md) (consolidated flow catalog) |
| **Ops & scaling** | [ops.md](ops.md) → [performance.md](performance.md) → [capacity.md](capacity.md) |
| **Security review** | [security.md](security.md) → [security-model.md](security-model.md) |
| **Full API surface** | [api-reference.md](api-reference.md) |
| **Config tuning** | [config.md](config.md) → [config-presets.md](config-presets.md) → [config_lint.md](config_lint.md) |

## Module Documentation

Per-module guides covering primitives, usage examples, configuration, strategies, and gotchas.

| Module | Description |
|--------|-------------|
| [engine.md](engine.md) | Core Engine API: login, validate, refresh, logout, account ops |
| [jwt.md](jwt.md) | JWT Manager: token issuance, verification, key rotation |
| [session.md](session.md) | Session Store: Redis-backed persistence, binary encoding, sliding expiry |
| [permission.md](permission.md) | Permission system: bitmask types, registry, role manager |
| [password.md](password.md) | Password hashing: Argon2id implementation |
| [middleware.md](middleware.md) | HTTP middleware: JWT-only, hybrid, strict guards |
| [mfa.md](mfa.md) | Multi-factor authentication: TOTP + backup codes |
| [password_reset.md](password_reset.md) | Password reset lifecycle: strategies, flows, rate limiting |
| [email_verification.md](email_verification.md) | Email verification lifecycle: strategies, flows |
| [rate_limiting.md](rate_limiting.md) | Rate limiting: IP throttle, refresh throttle, per-flow limiters |
| [audit.md](audit.md) | Audit system: event dispatching, sinks, buffering |
| [metrics.md](metrics.md) | Metrics system: counters, histograms, exporters |
| [introspection.md](introspection.md) | Session introspection: active sessions, health checks |
| [device_binding.md](device_binding.md) | Device binding: IP/UA fingerprint enforcement |
| [config.md](config.md) | Full configuration reference (all fields, defaults, types) |
| [config-presets.md](config-presets.md) | Configuration presets: Default, HighSecurity, HighThroughput |
| [config_lint.md](config_lint.md) | Configuration lint: severity levels, AsError helper |

## Cross-Cutting Guides

| Document | Description |
|----------|-------------|
| [flows.md](flows.md) | **Consolidated flow catalog** — every operation step-by-step |
| [performance.md](performance.md) | Benchmark methodology, Redis command budgets, sizing |
| [security.md](security.md) | Threat model, mitigations, invariants, scanner tooling |
| [roadmap.md](roadmap.md) | Future improvements and priorities |

## Architecture & Operations

| Document | Description |
|----------|-------------|
| [architecture.md](architecture.md) | System architecture and module boundaries |
| [concurrency-model.md](concurrency-model.md) | Concurrency safety guarantees |
| [security-model.md](security-model.md) | Security model and threat analysis |
| [migrations.md](migrations.md) | Session schema versioning and migration |
| [ops.md](ops.md) | Operations guide: deployment, monitoring, runbooks |
| [perf-budgets.md](perf-budgets.md) | Performance budgets and regression gates |
| [capacity.md](capacity.md) | Capacity planning guidance |
| [benchmarks.md](benchmarks.md) | Benchmark methodology and results |
| [api-reference.md](api-reference.md) | Full public API reference |
| [usage.md](usage.md) | Getting started and integration guide |

## Flow Documentation (detailed)

Detailed per-flow documentation (supplementary to [flows.md](flows.md)):

| Flow | Description |
|------|-------------|
| [functionality-login.md](functionality-login.md) | Login and session issuance |
| [functionality-validation-and-rbac.md](functionality-validation-and-rbac.md) | Access validation and RBAC |
| [functionality-refresh-rotation.md](functionality-refresh-rotation.md) | Refresh token rotation |
| [functionality-logout-and-invalidation.md](functionality-logout-and-invalidation.md) | Logout and session invalidation |
| [functionality-mfa.md](functionality-mfa.md) | MFA flows |
| [functionality-password-reset.md](functionality-password-reset.md) | Password reset lifecycle |
| [functionality-email-verification.md](functionality-email-verification.md) | Email verification lifecycle |
| [functionality-account-status.md](functionality-account-status.md) | Account status management |
| [functionality-audit-and-metrics.md](functionality-audit-and-metrics.md) | Audit and metrics emission |

## Root Documents (project-level)

| Document | Location |
|----------|----------|
| [README.md](../README.md) | Quickstart, features, installation |
| [CHANGELOG.md](../CHANGELOG.md) | Release changelog (SemVer) |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Documentation and code conventions |
| [THREAT_MODEL.md](../THREAT_MODEL.md) | Threat model |
| [SECURITY.md](../SECURITY.md) | Security policy |
| [SECURITY_REVIEW_CHECKLIST.md](../SECURITY_REVIEW_CHECKLIST.md) | Review checklist |
| [SECURITY_FINDINGS.md](../SECURITY_FINDINGS.md) | Findings register |
| [ARCHITECTURE_INVARIANTS.md](../ARCHITECTURE_INVARIANTS.md) | Architecture invariants |
