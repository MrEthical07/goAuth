# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- Remember-me and configurable durable sessions:
	- `Config.Session.MaxSessionDuration` — absolute session ceiling beyond which no session can be created or extended, regardless of sliding renewal. Unset (0) resolves at `Builder.Build()` to a per-validation-mode default (24 h for `ModeStrict`, 7 days for `ModeHybrid`/`ModeJWTOnly`), raised to the effective default session lifetime (`min(RefreshTTL, AbsoluteSessionLifetime)`) when that is longer, so existing configurations keep their exact session lifetimes. Validated at build time (0 or ≥ 1 minute).
	- `LoginOptions` and `Engine.LoginWithOptions` — per-login remember-me flag; remember-me sessions are created with the `MaxSessionDuration` lifetime, default logins keep the existing shorter lifetime. Existing `Login`/`LoginWithResult`/`LoginWithTOTP`/`LoginWithBackupCode` signatures are unchanged and behave as remember-me = false.
	- `CreateAccountRequest.RememberMe` — additive field; applies the durable lifetime to `AutoLogin` sessions.
	- Remember-me survives the MFA hop: the flag is persisted with the MFA login challenge (record version 2, backward-compatible decode of v1 records) and honored by `ConfirmLoginMFA`/`ConfirmLoginMFAWithType` without signature changes.
	- New lint warnings: `max_session_duration_caps_default` (explicit ceiling below the default session lifetime caps all sessions) and `max_session_duration_long` (effective ceiling > 30 days).

### Changed

- The store-level sliding-renewal clamp now uses the resolved `MaxSessionDuration` ceiling instead of the default session lifetime; per-session expiry is carried entirely by the session's stored `ExpiresAt` (written once at creation, as before). Existing sessions are unaffected.

### Notes

- Mixed-version rollout: MFA login challenges written by this version use record v2; binaries older than this version cannot decode them during the (≤ 3 minute) challenge TTL window of a rolling deploy.

### Planned

- Sliding-window rate limiter option (see [roadmap](docs/roadmap.md))
- `DeleteAllForUser` atomicity improvement
- Grafana dashboard JSON export
- Helm chart / Docker Compose production template

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
