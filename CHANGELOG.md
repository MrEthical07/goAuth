# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2026-02-19

### Added

- **Core engine** — `Engine` with `Builder` pattern for configuration, Redis wiring, and permission/role registration.
- **Authentication flows** — `Login`, `LoginWithResult`, `LoginWithTOTP`, `LoginWithBackupCode`, `ConfirmLoginMFA`, `ConfirmLoginMFAWithType`.
- **Token management** — JWT access tokens (Ed25519/HS256) with `ValidateAccess`, `Validate`, `HasPermission`.
- **Refresh rotation** — `Refresh` with atomic Lua CAS, replay detection, and session family destruction.
- **Logout** — `Logout`, `LogoutInTenant`, `LogoutByAccessToken`, `LogoutAll`, `LogoutAllInTenant`, `InvalidateUserSessions`.
- **Password management** — `ChangePassword` with reuse detection; Argon2id hashing via `password` package.
- **Password reset** — `RequestPasswordReset`, `ConfirmPasswordReset`, `ConfirmPasswordResetWithTOTP/BackupCode/MFA` with Token/OTP/UUID strategies.
- **Email verification** — `RequestEmailVerification`, `ConfirmEmailVerification`, `ConfirmEmailVerificationCode` with enumeration resistance and Lua CAS consumption.
- **MFA (TOTP + backup codes)** — `GenerateTOTPSetup`, `ProvisionTOTP`, `ConfirmTOTPSetup`, `VerifyTOTP`, `DisableTOTP`, `GenerateBackupCodes`, `RegenerateBackupCodes`, `VerifyBackupCode`.
- **Account management** — `CreateAccount`, `DisableAccount`, `EnableAccount`, `UnlockAccount`, `LockAccount`, `DeleteAccount`.
- **Automatic account lockout** — Persistent failure counter with configurable threshold and duration.
- **Session management** — Binary-encoded sessions (schema v5) with sliding expiration, jitter, and read-time migration (v1–v5).
- **Permission system** — 64/128/256/512-bit bitmasks, frozen registry, role-to-mask compilation.
- **Middleware** — `Guard`, `RequireJWTOnly`, `RequireStrict`, `AuthResultFromContext`.
- **Rate limiting** — 7-domain fixed-window limiters (login, refresh, account creation, TOTP, backup codes, password reset, email verification).
- **Device binding** — IP/UA hash enforcement or anomaly detection modes.
- **Audit system** — Async dispatcher with `ChannelSink`, `JSONWriterSink`, `NoOpSink`; drop-if-full mode.
- **Metrics** — 44 counters + 1 histogram, lock-free cache-line-padded; Prometheus and OpenTelemetry exporters.
- **Introspection** — `GetActiveSessionCount`, `ListActiveSessions`, `GetSessionInfo`, `ActiveSessionEstimate`, `Health`, `GetLoginAttempts`.
- **Configuration** — `DefaultConfig`, `HighSecurityConfig`, `HighThroughputConfig` presets; `Validate()` and `Lint()` with 16 warning codes.
- **Multi-tenancy** — Tenant-scoped sessions, counters, and rate limits.
- **Context helpers** — `WithClientIP`, `WithTenantID`, `WithUserAgent`.
- **Max password length** — `MaxPasswordBytes` (default 1024) applied before Argon2.
- **RequireIAT enforcement** — Explicit nil-check for `iat` claim when `RequireIAT=true`.

### Security

- Constant-time comparison on all secret paths (passwords, TOTP, reset tokens, verification codes, backup codes).
- Enumeration resistance for password reset and email verification (fake challenges + timing delay).
- Empty password timing oracle eliminated.
- Permission version drift triggers session deletion (alignment with role/account version behavior).
- Device binding uses SHA-256 hashes — no plaintext IPs stored.
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

## [Unreleased]

### Planned

- Sliding-window rate limiter option (see [roadmap](docs/roadmap.md))
- `DeleteAllForUser` atomicity improvement
- Grafana dashboard JSON export
- Helm chart / Docker Compose production template

---

[0.1.0]: https://github.com/MrEthical07/goAuth/releases/tag/v0.1.0
[Unreleased]: https://github.com/MrEthical07/goAuth/compare/v0.1.0...HEAD
