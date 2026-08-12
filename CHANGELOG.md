# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

Minor release (SemVer): additive. One new optional interface, no changed
public signatures, no removed or renamed config fields. Every behavior change
is gated on `MultiTenant.Enabled`, which defaults to `false` and is not set by
any shipped preset — deployments that do not opt in behave exactly as they did
in v0.4.0.

### Security

All three fixes below apply only when `MultiTenant.Enabled = true`. They are
live vulnerabilities for any deployment running more than one tenant; the
`Enabled = false` path was never affected.

- **Cross-tenant account takeover via password reset (unauthenticated).** The
  password-reset request path resolved the identifier tenant-blind and then
  stored the reset record under the **resolved user's** tenant rather than the
  request's. A reset requested under tenant B for an address belonging to
  tenant A wrote a valid, redeemable reset record into tenant A's keyspace,
  which the confirm path honored. Reachable by anyone who could reach the
  reset endpoint and guess an email address. The lookup is now scoped to the
  request's tenant and the record is always stored under it.
- **Cross-tenant credential attack on login.** Login resolved the user
  tenant-blind and never compared the resolved user's tenant to the request's.
  Valid tenant-A credentials presented against tenant-B's context
  authenticated, yielding a token cryptographically stamped tenant B while
  carrying tenant A's user id and role. Login now resolves within the request's
  tenant and rejects a mismatch with the same generic invalid-credentials error
  as a wrong password.
- **Cross-tenant email verification.** Same shape as the reset hole: a
  tenant-blind lookup plus record binding to the resolved user's tenant. Now
  scoped and bound to the request's tenant.

Enumeration resistance is preserved on every path: a cross-tenant identifier
is indistinguishable from a nonexistent one in response shape, error value,
and timing posture. Rejections are recorded in the audit trail with
`reason: "tenant_mismatch"` against the context tenant. **Audit events must
not be surfaced to tenant users** — the stream distinguishes cases the
response deliberately does not.

### Added

- `TenantAwareUserProvider` — optional capability interface with
  context-taking, tenant-scoped variants of both user lookups
  (`GetUserByIdentifierInTenant`, `GetUserByIDInTenant`). Detected by type
  assertion at `Builder.Build()`, the same mechanism as
  `WebAuthnCredentialProvider`. The existing `UserProvider` interface is
  unchanged and existing implementations continue to compile.
- Fail-fast build validation: `Builder.Build()` now fails when
  `MultiTenant.Enabled` is set and the user provider does not implement
  `TenantAwareUserProvider`. A silent fallback to tenant-blind lookup in a
  multi-tenant deployment must be impossible to configure. Safe for existing
  consumers, who default to `Enabled = false`.
- `docs/multi_tenancy.md` — tenant model, provider contract with
  implementation guidance, enforced paths, enumeration-resistance notes, and
  adoption steps.
- New lint warnings: `tenant_enforce_isolation_noop` and
  `account_duplicate_identifier_provider_owned`.

### Changed

- With `MultiTenant.Enabled = true`, every user lookup — including the
  authenticated id-keyed paths (change password, account status transitions,
  backup codes, TOTP provisioning, WebAuthn ceremonies) — is scoped to the
  request's tenant. Previously these resolved across all tenants, so a user id
  from another tenant was honored. With `Enabled = false` they remain
  tenant-blind.
- `MultiTenant.EnforceIsolation` no longer defaults to `true` in
  `defaultConfig()`. The field is unread, so this changes no behavior; it
  previously implied an enforcement the engine never performed and would now
  emit a deprecation warning for every default config.

### Fixed

- Email-verification confirm no longer consumes a valid link when the
  request context's tenant is absent or differs from the tenant embedded in
  the challenge. `ConfirmEmailVerification` is documented as the
  cross-tenant entry point — the challenge carries its own tenant, and the
  record is loaded and consumed under that tenant — but the user lookup and
  the status transition were scoped to the context tenant, so a divergent
  context deleted the record and then failed to resolve the user. Both now
  use the tenant the record was loaded under. Affects
  `MultiTenant.Enabled = true` only.
- Tenant-scoped ID lookups now verify the returned record's `TenantID`
  against the requested tenant and fail closed as not-found on mismatch. A
  provider that satisfies `TenantAwareUserProvider` without honouring the
  tenant predicate would otherwise hand the id-keyed paths (change password,
  account status, backup codes, TOTP, WebAuthn) a foreign-tenant record that
  callers go on to mutate. The identifier paths already had this backstop.
- Bumped `go.opentelemetry.io/otel` and its `metric`, `trace`, `sdk`, and
  `sdk/metric` modules from v1.43.0 to v1.44.0, clearing advisory
  GO-2026-5158 (baggage parsing no longer caps raw header length). goAuth
  does not call the affected code — `govulncheck` reports zero reachable
  vulnerabilities on v1.43.0 — so this is a hygiene upgrade rather than an
  exploitable fix. Unrelated to the tenant work in this release.

### Deprecated

No fields removed; all continue to be accepted.

- `MultiTenant.EnforceIsolation` — no-op that never gated anything. Tenant
  enforcement is governed entirely by `MultiTenant.Enabled`.
- `MultiTenant.TenantHeader` — no-op. The engine is transport-agnostic and
  will not read HTTP headers; extract the tenant in your HTTP layer and attach
  it with `WithTenantID`.
- `Account.AllowDuplicateIdentifierAcrossTenants` — documented as a
  provider-owned contract. goAuth never queries across tenants and so cannot
  enforce global identifier uniqueness; only the provider's schema can.

---

## [0.4.0] - 2026-07-14

Minor release (SemVer): every public API change is additive — new config
fields, new methods, new optional interfaces — with no breaking signature or
config changes. The two observable behavior changes (expired-token logout now
succeeds; explicit `ModeHybrid` route overrides no longer error) are fixes
that align behavior with the documented intent, called out under **Changed**
and **Fixed** with migration notes in `docs/migrations.md`.

### Added

- Remember-me and configurable durable sessions:
	- `Config.Session.MaxSessionDuration` — absolute session ceiling beyond which no session can be created or extended, regardless of sliding renewal. Unset (0) resolves at `Builder.Build()` to a per-validation-mode default (24 h for `ModeStrict`, 7 days for `ModeHybrid`/`ModeJWTOnly`), raised to the effective default session lifetime (`min(RefreshTTL, AbsoluteSessionLifetime)`) when that is longer, so existing configurations keep their exact session lifetimes. Validated at build time (0 or ≥ 1 minute).
	- `LoginOptions` and `Engine.LoginWithOptions` — per-login remember-me flag; remember-me sessions are created with the `MaxSessionDuration` lifetime, default logins keep the existing shorter lifetime. Existing `Login`/`LoginWithResult`/`LoginWithTOTP`/`LoginWithBackupCode` signatures are unchanged and behave as remember-me = false.
	- `CreateAccountRequest.RememberMe` — additive field; applies the durable lifetime to `AutoLogin` sessions.
	- Remember-me survives the MFA hop: the flag is persisted with the MFA login challenge (record version 2, backward-compatible decode of v1 records) and honored by `ConfirmLoginMFA`/`ConfirmLoginMFAWithType` without signature changes.
	- New lint warnings: `max_session_duration_caps_default` (explicit ceiling below the default session lifetime caps all sessions) and `max_session_duration_long` (effective ceiling > 30 days).
- Hybrid validation mode aligned with its intended per-route design:
	- `middleware.RequireHybrid` — shorthand for `Guard(engine, ModeHybrid)`, parallel to `RequireJWTOnly`/`RequireStrict`.
	- New advisory lint `hybrid_enforcement_strict_routes_only` (info) — Hybrid mode with enforced device binding; enforcement runs only on routes resolved to `ModeStrict`.
- Sliding-window rate limiting (opt-in): `Security.LimiterWindowMode = "sliding"` switches every limiter domain (login failure, lockout, account creation, TOTP, backup codes, password reset, email verification) to a weighted two-bucket sliding-window counter, removing the fixed-window 2× boundary-burst weakness. Defaults to the existing fixed-window behavior (`""`/`"fixed"`); validated at build time. All limiters now count through a single shared window primitive (`internal/window`).
- WebAuthn / FIDO2 second-factor support (security keys, platform authenticators, passkeys as a second factor):
	- `Config.WebAuthn` — relying-party settings (`RPID`, `RPDisplayName`, `RPOrigins`), attestation (default `"none"`) and user-verification preferences, `CeremonyTTL`, `RequireForLogin`, and `RejectClonedAuthenticators`; validated at build time.
	- `WebAuthnCredentialProvider` — optional capability interface detected on the `UserProvider` via type assertion at `Builder.Build()`; existing `UserProvider` implementations are unaffected, and enabling WebAuthn without the capability fails the build. Credentials persist through goAuth-owned `WebAuthnCredential` records (no library types in the public API).
	- Registration ceremonies: `Engine.BeginWebAuthnRegistration` / `FinishWebAuthnRegistration`, plus `ListWebAuthnCredentials` / `RemoveWebAuthnCredential`. The engine exchanges raw CredentialCreation/CredentialRequest JSON with the caller and stays transport-agnostic.
	- Login integration: with `WebAuthn.RequireForLogin`, users holding registered credentials get an MFA challenge answered via `Engine.BeginWebAuthnLogin` + the existing `ConfirmLoginMFAWithType(..., "webauthn")` — no signature changes. `LoginResult` gains an additive `MFATypes []string`; `MFAType` prefers `"webauthn"` over `"totp"` when both are available (TOTP-only deployments see identical behavior). Remember-me survives the WebAuthn hop.
	- Security posture: ceremony sessions are single-use (atomic `GETDEL`, new `awn:` Redis keys) and TTL-bounded; origin/RPID enforced per config; signature-counter regression fails the login with `ErrWebAuthnCloneDetected` and destroys the challenge; failed assertions consume MFA challenge attempts like wrong TOTP codes, while ceremony-expired failures do not (no verification happened).
	- New sentinels: `ErrWebAuthnDisabled`, `ErrWebAuthnInvalid`, `ErrWebAuthnCeremonyExpired`, `ErrWebAuthnCloneDetected`, `ErrWebAuthnCredentialNotFound`, `ErrWebAuthnUnavailable`.
	- New dependency: `github.com/go-webauthn/webauthn` (ceremony verification); tests use `github.com/descope/virtualwebauthn` (test-only authenticator emulator).
- Ed25519 key-rotation tooling:
	- `Config.JWT.VerifyKeys` (`kid` → verification key map) — exposes the jwt layer's existing multi-key verification on the engine config, enabling zero-downtime signing-key rotation via a verify-overlap ceremony (documented step-by-step in `docs/ops.md`). Build-time guardrails: `VerifyKeys` requires a `KeyID` naming one of its entries, and the entry under the signing kid must match the signing key — misconfigurations that would reject every self-issued token cannot build.
	- `jwt.GenerateEd25519Key` and `jwt.Ed25519KeyFingerprint` helpers, plus a `cmd/goauth-keygen` CLI (keypair generation in raw-base64 or PEM, `-fingerprint` for kid derivation from existing public keys).
	- New lint `keyid_missing` (info) — Ed25519 signing without a `KeyID`; setting one from day one avoids a flag day on the first rotation.
- Lint warnings for no-op config knobs — several fields are accepted (and validated) but never read by the engine; `Config.Lint()` now says so instead of letting integrators believe a protection is active: `security_ip_binding_noop` (warn), `security_ip_signal_noop` (warn), `cache_lru_noop` (warn), `cookie_settings_noop` (info), `database_config_noop` (info), `tenant_header_noop` (info). The fields themselves are unchanged (backward compatible); doc comments and `docs/config.md` now mark each one **no-op**.

### Changed

- The store-level sliding-renewal clamp now uses the resolved `MaxSessionDuration` ceiling instead of the default session lifetime; per-session expiry is carried entirely by the session's stored `ExpiresAt` (written once at creation, as before). Existing sessions are unaffected.
- `LogoutByAccessToken` now succeeds for expired-but-authentic access tokens: the token's session (if any) is destroyed and nil is returned, instead of failing with `ErrTokenInvalid`. Signature, algorithm, kid, issuer, audience, not-before, and iat checks are still enforced (new `jwt.Manager.ParseAccessAllowExpired`, wired only into the logout flow — `Validate`/`Refresh` keep the strict parser). Expired-token logouts carry `expired_token: "true"` audit metadata. Callers that matched on `ErrTokenInvalid` when logging out expired sessions will now receive nil.
- Hybrid validation semantics are now an explicit, documented contract: routes resolved to `ModeHybrid` (inherited or explicit) validate statelessly — signature, claims, and clock-skew checks with zero Redis — and individual routes opt into `ModeStrict` (session-backed revocation/version/status/device checks) or `ModeJWTOnly` per call. This matches the existing runtime behavior of inherited Hybrid; documentation that implied an opportunistic session lookup ("Redis lookup used when available") has been corrected.

### Fixed

- Login timing oracle on unknown identifiers: the user-not-found path now performs the same dummy Argon2 verification as the wrong-password path, closing a username-enumeration side channel.
- Limiter increments are now atomic (single Lua script instead of `INCR` followed by `EXPIRE`): a crash between the two commands could previously leave a counter key without a TTL, rate-limiting that identifier until manual cleanup.
- Explicit `ModeHybrid` route overrides (e.g. `middleware.Guard(engine, ModeHybrid)`, `Validate(ctx, token, ModeHybrid)`) no longer fail with `ErrInvalidRouteMode`; they resolve to the stateless Hybrid path. An explicit route mode always wins over the engine default. The `ValidationMode` zero value remains invalid (`ModeJWTOnly` is `1`).

### Dependencies

- Added `github.com/go-webauthn/webauthn` (WebAuthn ceremony verification) and its transitive dependencies; test-only `github.com/descope/virtualwebauthn`.
- Bumped `golang.org/x/crypto` to v0.54.0 and pinned the `go1.26.5` toolchain to clear known stdlib advisories (GO-2026-4970, GO-2026-5856) in the security scanner gate. No OIDC/OAuth2 dependencies were added (SSO is deferred).

### Notes

- Mixed-version rollout: MFA login challenges written by this version use record v2; binaries older than this version cannot decode them during the (≤ 3 minute) challenge TTL window of a rolling deploy.
- Security caveat: an explicit per-route validation mode always overrides the engine mode — a route validated with `ModeJWTOnly` or `ModeHybrid` skips session-backed checks even on a `ModeStrict` engine. Audit route wiring when adopting per-route modes (see `docs/security.md`).
- Deferred to a future cycle: SSO / OIDC + OAuth2 social login (see `docs/roadmap.md`).

---

## [0.3.0] - 2026-04-06

### Breaking

- Public engine failures are now normalized to a canonical `*AuthError` boundary; raw internal/store/limiter/session errors are no longer returned from exported `Engine` methods.
- Removed refresh-throttle configuration and behavior (`Security.EnableRefreshThrottle`, `Security.MaxRefreshAttempts`, `Security.RefreshCooldownDuration`) and retired refresh rate-limit signaling from the public surface.
- Renamed config fields for abuse controls:
	- `Security.EnableIPThrottle` -> `Security.EnableLoginFailureLimiter`
	- `PasswordReset.EnableIPThrottle` / `PasswordReset.EnableIdentifierThrottle` -> `PasswordReset.EnableRequestLimiter` / `PasswordReset.EnableConfirmFailureLimiter`
	- `EmailVerification.EnableIPThrottle` / `EmailVerification.EnableIdentifierThrottle` -> `EmailVerification.EnableRequestLimiter` / `EmailVerification.EnableConfirmFailureLimiter`
	- `Account.EnableIPThrottle` / `Account.EnableIdentifierThrottle` -> `Account.EnableCreationLimiter`
- Limiter keyspace moved to tenant-scoped `rl:*` prefixes; legacy limiter keys are not reused.

### Added

- Canonical public error model:
	- `AuthError` with stable `Category` and `Code`
	- Full `AuthCode` registry
	- `NewAuthError` and `WrapAuthError`
	- Boundary mapper (`mapToAuthError`) and canonical fallbacks (`ErrSystemInternal`, `ErrSystemUnavailable`)
- CI guardrails for error-boundary regressions:
	- Static boundary scanner (`engine_error_boundary_static_test.go`)
	- Runtime boundary contract tests (`engine_error_boundary_runtime_test.go`)
- New observability counters for limiter behavior and lockout:
	- `MetricLimiterCheck`
	- `MetricLimiterTrigger`
	- `MetricLimiterFailOpen`
	- `MetricLockoutTrigger`
- New error-model documentation (`docs/error-model.md`).

### Changed

- Login limiter now uses tenant+identifier scoping and no longer depends on IP pairing.
- Password reset and email verification abuse controls are split into explicit request-phase and confirm-failure limiter paths.
- Limiter backend failures in runtime flow wrappers now follow fail-open policy with audit + metric signals (`limiter_fail_open`) while preserving explicit limiter denials.
- Security report and docs now reflect `EnableLoginFailureLimiter` as the login abuse-control gate.

### Removed

- `ErrRefreshRateLimited` and `MetricRefreshRateLimited` from the public model.
- Refresh-throttle flow path and associated refresh rate-limit audit branch.

### Docs

- Updated API, config, flow, security, operations, and rate-limiting docs to align with v0.3.0 semantics.
- Added boundary enforcement policy details under the error-model documentation.

### Tests

- Migrated limiter and config tests to new semantics and keyspace.
- Added static + runtime tests that hard-fail CI on boundary contract drift.
- Targeted guardrail run passes: `go test ./... -run "TestEngineErrorBoundaryStatic|TestEngineErrorBoundaryRuntime"`.

---

## [0.2.1] - 2026-03-31

### Changed

- Permission registry and role manager read helpers now elide read locks after `Build()` freeze, while keeping write-path locking intact.
- `Engine.HasPermission` behavior and API remain unchanged, but now benefit from lock-free frozen permission lookup paths.

### Performance

- Reduced CPU overhead in hot RBAC lookup paths by removing post-freeze read-lock contention from permission and role lookups.
- Added focused benchmarks for permission helper paths: registry bit lookup and end-to-end `HasPermission`.

### Docs

- Updated permission, RBAC validation, API reference, methods guide, and performance docs to reflect frozen lock-free lookup behavior and updated benchmark coverage.

### Tests

- Added benchmark coverage for permission lookup helpers and validated existing auth flow behavior without API changes.

---

## [0.2.0] - 2026-03-16

### Added

- String tenant IDs end-to-end in JWT claims and validation, including backward-compatible parsing for legacy numeric `tid` claims.
- `AuditSinkErrors()` engine metric plus Prometheus / OpenTelemetry export for audit sink write failures.
- `SlogAuditSink` / `NewSlogAuditSink(...)` for forwarding audit events into existing `slog` pipelines.

### Changed

- TOTP direct verification attempt limits now use `TOTP.MFALoginMaxAttempts` so setup confirmation and direct verify share the MFA budget.
- Audit-enabled builds now fail fast when no audit sink is configured instead of silently discarding events.
- Audit docs, metrics docs, API reference, JWT docs, and roadmap were updated to match the current behavior.

### Fixed

- Backup-code audit coverage now records invalid-format, rate-limited, generation, and regeneration failures consistently.
- JSON audit writer sinks now count encoding / write failures instead of swallowing them invisibly.
- JWT-only / hybrid claim-derived auth results now preserve string tenant IDs correctly.

### Tests

- Added regression coverage for TOTP limiter wiring, legacy numeric tenant claim parsing, JWT-only tenant round-tripping, audit sink misconfiguration, slog sink output, sink error counting, and backup-code audit failures.
- `go test ./...` passes with the new coverage.

---

## [0.1.0] - 2026-02-19

### Added

- **Core engine** - `Engine` with `Builder` pattern for configuration, Redis wiring, and permission/role registration.
- **Authentication flows** - `Login`, `LoginWithResult`, `LoginWithTOTP`, `LoginWithBackupCode`, `ConfirmLoginMFA`, `ConfirmLoginMFAWithType`.
- **Token management** - JWT access tokens (Ed25519/HS256) with `ValidateAccess`, `Validate`, `HasPermission`.
- **Refresh rotation** - `Refresh` with atomic Lua CAS, replay detection, and session family destruction.
- **Logout** - `Logout`, `LogoutInTenant`, `LogoutByAccessToken`, `LogoutAll`, `LogoutAllInTenant`, `InvalidateUserSessions`.
- **Password management** - `ChangePassword` with reuse detection; Argon2id hashing via `password` package.
- **Password reset** - `RequestPasswordReset`, `ConfirmPasswordReset`, `ConfirmPasswordResetWithTOTP/BackupCode/MFA` with Token/OTP/UUID strategies.
- **Email verification** - `RequestEmailVerification`, `ConfirmEmailVerification`, `ConfirmEmailVerificationCode` with enumeration resistance and Lua CAS consumption.
- **MFA (TOTP + backup codes)** - `GenerateTOTPSetup`, `ProvisionTOTP`, `ConfirmTOTPSetup`, `VerifyTOTP`, `DisableTOTP`, `GenerateBackupCodes`, `RegenerateBackupCodes`, `VerifyBackupCode`.
- **Account management** - `CreateAccount`, `DisableAccount`, `EnableAccount`, `UnlockAccount`, `LockAccount`, `DeleteAccount`.
- **Automatic account lockout** - Persistent failure counter with configurable threshold and duration.
- **Session management** - Binary-encoded sessions (schema v5) with sliding expiration, jitter, and read-time migration (v1-v5).
- **Permission system** - 64/128/256/512-bit bitmasks, frozen registry, role-to-mask compilation.
- **Middleware** - `Guard`, `RequireJWTOnly`, `RequireStrict`, `AuthResultFromContext`.
- **Rate limiting** - 7-domain fixed-window limiters (login, refresh, account creation, TOTP, backup codes, password reset, email verification).
- **Device binding** - IP/UA hash enforcement or anomaly detection modes.
- **Audit system** - Async dispatcher with `ChannelSink`, `JSONWriterSink`, `NoOpSink`; drop-if-full mode.
- **Metrics** - 44 counters + 1 histogram, lock-free cache-line-padded; Prometheus and OpenTelemetry exporters.
- **Introspection** - `GetActiveSessionCount`, `ListActiveSessions`, `GetSessionInfo`, `ActiveSessionEstimate`, `Health`, `GetLoginAttempts`.
- **Configuration** - `DefaultConfig`, `HighSecurityConfig`, `HighThroughputConfig` presets; `Validate()` and `Lint()` with 16 warning codes.
- **Multi-tenancy** - Tenant-scoped sessions, counters, and rate limits.
- **Context helpers** - `WithClientIP`, `WithTenantID`, `WithUserAgent`.
- **Max password length** - `MaxPasswordBytes` (default 1024) applied before Argon2.
- **RequireIAT enforcement** - Explicit nil-check for `iat` claim when `RequireIAT=true`.

### Security

- Constant-time comparison on all secret paths (passwords, TOTP, reset tokens, verification codes, backup codes).
- Enumeration resistance for password reset and email verification (fake challenges + timing delay).
- Empty password timing oracle eliminated.
- Permission version drift triggers session deletion (alignment with role/account version behavior).
- Device binding uses SHA-256 hashes - no plaintext IPs stored.
- All rate limiters fail open on Redis unavailability (availability over correctness for rate limits).
- Strict validation mode fails closed on Redis unavailability.

### Documentation

- Full module documentation for all 14 subsystems.
- Flow catalog documenting all authentication/authorization workflows.
- Configuration reference with presets and lint rules.
- Architecture, security model, concurrency model, and capacity planning guides.
- Performance budgets with CI regression gates.
- Operational guidance with deployment checklist.
- Minimal HTTP example with 4 endpoints.

### Tests

- 266 tests across 9 packages, all passing.
- Race detector clean (`go test -race ./...`).
- 4 fuzz targets (refresh token, JWT parse, permission codec, refresh session).
- Redis 7-alpine integration tests via Docker Compose.
- 13 benchmarks covering metrics, validation, and export paths.

---

[0.3.0]: https://github.com/MrEthical07/goAuth/releases/tag/v0.3.0
[0.2.1]: https://github.com/MrEthical07/goAuth/releases/tag/v0.2.1
[0.2.0]: https://github.com/MrEthical07/goAuth/releases/tag/v0.2.0
[0.1.0]: https://github.com/MrEthical07/goAuth/releases/tag/v0.1.0
[Unreleased]: https://github.com/MrEthical07/goAuth/compare/v0.3.0...HEAD
