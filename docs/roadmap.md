# Roadmap

Planned improvements and future work for goAuth, organized by category and priority.

**Last updated:** 2026-07-14

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
| SSO / OIDC + OAuth2 social login | P1 | maintainer | planned (v0.5.0, own cycle) | API: enterprise SSO and consumer social login via external IdPs |
| WebAuthn passwordless / usernameless login | P2 | maintainer | planned | API: extend the v0.4.0 second-factor support to full passwordless (credential model already retains the needed flags) |

### Note: SSO / OIDC + OAuth2 (deferred)

SSO was evaluated during the v0.4.0 cycle and deferred to its own release. It is a
subsystem rather than a single feature (provider abstraction, JWKS fetch/cache, code
exchange, ID-token validation, identity linking, and callback orchestration), it adds
outbound HTTP to third-party IdPs plus new dependencies, and its identity-linking policy
is a security-sensitive design decision (account-takeover risk on unverified emails) that
warrants a dedicated design pass. When picked up, it should be split into two phases:

1. **Library-shaped (in scope for the engine):** OIDC ID-token verification (JWKS +
   `iss`/`aud`/`nonce`/`exp`) and the `ExternalIdentityProvider` linking primitive
   (following the `WebAuthnCredentialProvider` capability-interface pattern). The host app
   owns the redirect dance and hands goAuth the result.
2. **Framework-shaped (optional subpackage):** full OAuth2 authorization-code + PKCE
   redirect/callback orchestration and per-provider connectors, kept out of the core so the
   engine stays lean and dependency-light.

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

---

## Completed (Recent)

Items previously on the roadmap that have been resolved:

| Item | Priority | Resolved In | Impact |
|------|----------|-------------|--------|
| Remember-me logins + configurable absolute session ceiling (`MaxSessionDuration`) | P1 | v0.4.0 | Security/API |
| Hybrid mode aligned with per-route selection design (`RequireHybrid`, explicit-override fix) | P1 | v0.4.0 | Correctness |
| Graceful logout with expired access tokens | P2 | v0.4.0 | Correctness/DX |
| Unknown-identifier login timing oracle eliminated | P2 | v0.4.0 | Security |
| Sliding-window rate limiter option (removes 2× boundary burst) | P1 | v0.4.0 | Security |
| Ed25519 key-rotation tooling (`VerifyKeys`, `goauth-keygen`, rotation runbook) | P2 | v0.4.0 | Security |
| WebAuthn / FIDO2 second-factor support | P2 | v0.4.0 | API |
| Lint warnings for inert/no-op config fields (`*_noop` codes) | P2 | v0.4.0 | API/DX |
| Atomic limiter increments (INCR/EXPIRE orphaned-counter fix) | P2 | v0.4.0 | Correctness |
| Canonical `AuthError` public error boundary | P1 | v0.3.0 | API |
| Typed error wrapping with `errors.Is` chains | P2 | v0.3.0 | API |
| Automatic account lockout after N failures | P1 | v0.1.0 | Security |
| Max password length DoS prevention | P2 | v0.1.0 | Security |
| RequireIAT enforcement fix | P2 | v0.1.0 | Security |
| Permission version drift → session delete | P2 | v0.1.0 | Correctness |
| Empty password timing oracle elimination | P2 | v0.1.0 | Security |
| Fixed-window boundary burst documentation | P2 | v0.1.0 | Docs |
| `DeleteAllForUser` atomicity documentation | P2 | v0.1.0 | Docs |
| Configurable TOTP rate limiter thresholds | P2 | v0.1.0 | Security |
| Structured logging adapter (slog integration) | P2 | v0.1.0 | Ops |

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
