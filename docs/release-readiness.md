# Release Readiness Assessment

Date: 2026-07-14
Branch: feature/v0.4.0-auth-suite
Release Target: v0.4.0
Status: Ready for release

---

## Summary

v0.4.0 is a backward-compatible minor release: every public API change is
additive, and the only behavior changes are deliberate, documented fixes
(expired-token logout now succeeds; explicit `ModeHybrid` route overrides no
longer error). It ships remember-me durable sessions, the hybrid per-route
validation model, graceful expired-token logout, an opt-in sliding-window rate
limiter, Ed25519 key-rotation tooling, WebAuthn/FIDO2 second-factor support,
and no-op-config lint warnings.

---

## Scope (v0.4.0)

1. Remember-me + configurable durable sessions — `Session.MaxSessionDuration`,
   `LoginOptions`/`LoginWithOptions`, `CreateAccountRequest.RememberMe`;
   existing signatures and session lifetimes unchanged.
2. Hybrid mode aligned with its per-route design — explicit `ModeHybrid`
   overrides valid, `middleware.RequireHybrid`, stateless resolved-Hybrid
   semantics documented as the contract.
3. Logout with expired-but-authentic access tokens succeeds (was
   `ErrTokenInvalid`); forged/invalid tokens still rejected.
4. Sliding-window rate limiting (opt-in via `Security.LimiterWindowMode`),
   all seven limiter domains, shared atomic window primitive.
5. Ed25519 key rotation — `JWT.VerifyKeys` on the engine config, build-time
   guardrails, `jwt.GenerateEd25519Key`/`Ed25519KeyFingerprint`,
   `cmd/goauth-keygen`, documented rotation runbook.
6. WebAuthn/FIDO2 second factor — registration + login ceremonies,
   `WebAuthnCredentialProvider` capability interface, single-use TTL'd
   ceremony sessions, clone detection.
7. Login timing-oracle fix (unknown identifiers), atomic limiter increments,
   and `*_noop` lint warnings for config knobs the engine never reads.

Deferred: SSO/OIDC + OAuth2 social login (see docs/roadmap.md — moved to its
own cycle).

---

## Compatibility & migration notes

- No public signature changes; all additions are new methods, fields, or
  config. Existing configs resolve to identical session lifetimes (the
  `MaxSessionDuration` default is raised to the effective current lifetime).
- Behavior changes callers may observe:
  - `LogoutByAccessToken` on an expired-but-authentic token now returns nil
    (was `ErrTokenInvalid`).
  - `Validate`/`Guard` with an explicit `ModeHybrid` route mode now validates
    statelessly (previously always `ErrInvalidRouteMode`/401). An explicit
    route mode always wins over the engine mode — a route override can
    downgrade a Strict engine; review route wiring (see docs/security.md).
- Mixed-version rollout caveat: MFA login challenges written by v0.4.0 use
  record v2; older binaries cannot decode them during the ≤ 3 minute
  challenge TTL window of a rolling deploy.

---

## Verification Gates

### Full test suite (local, Windows)

```bash
go test ./...
```

Result: PASS — all 12 packages (engine root, internal, flows, stores, window,
jwt, otel/prometheus exporters, password, permission, session, test).

### Race detector

`go test -race ./...` is enforced by the `go-race` CI workflow (Linux); local
race builds are unavailable on the release machine. CI must be green before
tagging.

### Boundary guardrails

```bash
go test ./... -run "TestEngineErrorBoundaryStatic|TestEngineErrorBoundaryRuntime"
```

Result: PASS (included in the full-suite run).

### Dependency audit

New in v0.4.0: `github.com/go-webauthn/webauthn` (+ transitives) and
test-only `github.com/descope/virtualwebauthn`. No OIDC/OAuth2 dependencies.

---

## Release Checklist

- [x] All v0.4.0 features implemented with tests and docs
- [x] CHANGELOG moved from [Unreleased] to [0.4.0] with migration notes
- [x] Behavior changes and rollout caveats documented
- [x] Docs reconciled against the v0.4.0 code (config, flows, middleware,
      jwt, ops, security, webauthn, rate limiting, api-reference, examples)
- [x] Full local test suite passes
- [ ] `go-race` and all other CI workflows green on the release branch
- [ ] Annotated tag `v0.4.0` created after merge to `main`
