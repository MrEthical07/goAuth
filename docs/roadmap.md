# Roadmap

Planned improvements and future work for goAuth, organized by category and priority.

**Last updated:** 2026-02-19

---

## Priority Definitions

| Priority | Meaning |
|----------|---------|
| **P0** | Critical — blocks production use or creates security risk |
| **P1** | High — significant improvement to security, performance, or DX |
| **P2** | Medium — quality-of-life improvements, nice-to-have |

---

## Security

| Item | Priority | Owner | Status | Expected Impact |
|------|----------|-------|--------|-----------------|
| Sliding-window rate limiter option | P1 | maintainer | planned | Security: eliminates 2× boundary burst vulnerability |
| Key rotation ceremony tooling | P2 | maintainer | planned | Security: safer Ed25519 key rotation in production |
| Session binding to TLS channel (channel binding) | P2 | maintainer | planned | Security: prevents session export across TLS sessions |

---

## Performance

| Item | Priority | Owner | Status | Expected Impact |
|------|----------|-------|--------|-----------------|
| `DeleteAllForUser` atomicity improvement | P1 | maintainer | planned | Perf/Correctness: single Lua script for atomic session wipe |
| Fuzz corpus caching in CI | P2 | maintainer | planned | Perf: faster fuzz runs, better coverage over time |
| Connection pool auto-tuning guidance | P2 | maintainer | planned | Perf: documentation for Redis pool sizing under load |

---

## API

| Item | Priority | Owner | Status | Expected Impact |
|------|----------|-------|--------|-----------------|
| `Engine.RevokePermission` for dynamic permission changes | P2 | maintainer | planned | API: runtime permission mutation without rebuild |
| Typed error wrapping with `errors.Is` chains | P2 | maintainer | planned | API: better error introspection for callers |
| WebAuthn / FIDO2 second-factor support | P2 | maintainer | planned | API: modern passwordless MFA option |

---

## Documentation

| Item | Priority | Owner | Status | Expected Impact |
|------|----------|-------|--------|-----------------|
| Stricter changelog format enforcement (CI linter) | P2 | maintainer | planned | Docs: consistent release notes |
| Auto-generated API reference from GoDoc | P2 | maintainer | planned | Docs: always-current API docs |
| Video walkthrough for integration | P2 | maintainer | planned | Docs: onboarding improvement |

---

## Operations

| Item | Priority | Owner | Status | Expected Impact |
|------|----------|-------|--------|-----------------|
| Helm chart / Docker Compose production template | P1 | maintainer | planned | Ops: faster production deployment |
| Grafana dashboard JSON export | P1 | maintainer | planned | Ops: out-of-box monitoring |
| Redis Sentinel / Cluster topology documentation | P2 | maintainer | planned | Ops: HA deployment guidance |
| Structured logging adapter (slog integration) | P2 | maintainer | planned | Ops: better observability integration |

---

## Completed (Recent)

Items previously on the roadmap that have been resolved:

| Item | Priority | Resolved In | Impact |
|------|----------|-------------|--------|
| Automatic account lockout after N failures | P1 | v0.1.0 | Security |
| Max password length DoS prevention | P2 | v0.1.0 | Security |
| RequireIAT enforcement fix | P2 | v0.1.0 | Security |
| Permission version drift → session delete | P2 | v0.1.0 | Correctness |
| Empty password timing oracle elimination | P2 | v0.1.0 | Security |
| Fixed-window boundary burst documentation | P2 | v0.1.0 | Docs |
| `DeleteAllForUser` atomicity documentation | P2 | v0.1.0 | Docs |
| Configurable TOTP rate limiter thresholds | P2 | v0.1.0 | Security |

---

## Contributing

To propose a roadmap item, open an issue with:

1. Category (Security/Performance/API/Docs/Ops)
2. Priority justification
3. Expected impact on API surface, performance, or security posture
4. Whether it introduces breaking changes

See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines.

---

## See Also

- [release-readiness.md](release-readiness.md) — Current release status
- [security.md](security.md) — Security model and mitigations
- [performance.md](performance.md) — Performance budgets
- [CHANGELOG.md](../CHANGELOG.md) — Release history
