# goAuth Methods Guide (Root Package)

This file documents the public methods and functions in package `goAuth` that an application can call to initialize and run the auth engine.

Scope of this file:

- Root package only (`goAuth`), not sub-packages like `jwt`, `session`, or `permission`
- Public methods/functions (exported API surface)
- How to invoke each method and what parameters to pass

## Quick Start (Engine Initialization)

```go
cfg := goAuth.DefaultConfig()

engine, err := goAuth.New().
    WithConfig(cfg).
    WithRedis(rdb).
    WithPermissions([]string{"user.read", "user.write"}).
    WithRoles(map[string][]string{
        "admin": {"user.read", "user.write"},
    }).
    WithUserProvider(provider).
    WithAuditSink(goAuth.NewSlogAuditSink(logger)).
    Build()
if err != nil {
    return err
}
defer engine.Close()
```

## Common Context Pattern

Most engine methods receive `ctx context.Context`.

You can enrich context before calling engine methods:

```go
ctx := context.Background()
ctx = goAuth.WithTenantID(ctx, "tenant-a")
ctx = goAuth.WithClientIP(ctx, "203.0.113.10")
ctx = goAuth.WithUserAgent(ctx, "my-app/1.0")
```

## 1) Builder Methods (Initialization)

| Method | Invocation | Parameters | Returns / Notes |
|---|---|---|---|
| `New` | `goAuth.New()` | none | `*Builder` |
| `WithConfig` | `b.WithConfig(cfg)` | `cfg Config` | `*Builder`; replace builder config |
| `WithRedis` | `b.WithRedis(client)` | `client redis.UniversalClient` | `*Builder`; Redis client used by sessions/rate-limits/stores |
| `WithPermissions` | `b.WithPermissions(perms)` | `perms []string` | `*Builder`; required before `Build()` |
| `WithRoles` | `b.WithRoles(roleMap)` | `roleMap map[string][]string` (role -> permissions) | `*Builder`; required before `Build()` |
| `WithUserProvider` | `b.WithUserProvider(up)` | `up UserProvider` | `*Builder`; required before `Build()` |
| `WithAuditSink` | `b.WithAuditSink(sink)` | `sink AuditSink` | `*Builder`; required when `cfg.Audit.Enabled == true` |
| `WithMetricsEnabled` | `b.WithMetricsEnabled(enabled)` | `enabled bool` | `*Builder`; toggles in-process metrics |
| `WithLatencyHistograms` | `b.WithLatencyHistograms(enabled)` | `enabled bool` | `*Builder`; toggles latency histograms |
| `Build` | `b.Build()` | none | `(*Engine, error)`; validates config and builds immutable engine |

## 2) Config and Lint Methods

| Method | Invocation | Parameters | Returns / Notes |
|---|---|---|---|
| `DefaultConfig` | `goAuth.DefaultConfig()` | none | `Config`; production-safe baseline |
| `HighSecurityConfig` | `goAuth.HighSecurityConfig()` | none | `Config`; stricter defaults |
| `HighThroughputConfig` | `goAuth.HighThroughputConfig()` | none | `Config`; throughput-oriented defaults |
| `Validate` | `cfg.Validate()` | none | `error`; fatal config validation |
| `Lint` | `cfg.Lint()` | none | `LintResult`; advisory warnings |
| `AsError` | `lint.AsError(goAuth.LintHigh)` | `minSeverity LintSeverity` | `error`; promote lint warnings to startup failure |
| `BySeverity` | `lint.BySeverity(goAuth.LintWarn)` | `minSeverity LintSeverity` | `LintResult`; filtered warnings |
| `Codes` | `lint.Codes()` | none | `[]string`; warning code list |
| `String` | `severity.String()` | none | `string`; `INFO`, `WARN`, `HIGH` |

## 3) Context Helper Functions

| Function | Invocation | Parameters | Returns / Notes |
|---|---|---|---|
| `WithClientIP` | `goAuth.WithClientIP(ctx, ip)` | `ctx context.Context`, `ip string` | `context.Context`; used by rate limiting and device binding |
| `WithTenantID` | `goAuth.WithTenantID(ctx, tenantID)` | `ctx context.Context`, `tenantID string` | `context.Context`; controls tenant scoping |
| `WithUserAgent` | `goAuth.WithUserAgent(ctx, ua)` | `ctx context.Context`, `ua string` | `context.Context`; used for device binding checks |

## 4) Optional Utility Constructors

| Function | Invocation | Parameters | Returns / Notes |
|---|---|---|---|
| `NewChannelSink` | `goAuth.NewChannelSink(buffer)` | `buffer int` | `*ChannelSink`; buffered audit sink |
| `NewJSONWriterSink` | `goAuth.NewJSONWriterSink(w)` | `w io.Writer` | `*JSONWriterSink`; JSON audit sink |
| `NewSlogAuditSink` | `goAuth.NewSlogAuditSink(logger)` | `logger *slog.Logger` | `*SlogAuditSink`; slog-based audit sink |
| `NewMetrics` | `goAuth.NewMetrics(cfg)` | `cfg MetricsConfig` | `*Metrics`; standalone metrics instance |

## 5) Engine Methods

### 5.1 Core Lifecycle and Diagnostics

| Method | Invocation | Parameters | Returns / Purpose |
|---|---|---|---|
| `Close` | `engine.Close()` | none | `void`; stop audit dispatcher and release engine resources |
| `AuditDropped` | `engine.AuditDropped()` | none | `uint64`; dropped audit event count |
| `AuditSinkErrors` | `engine.AuditSinkErrors()` | none | `uint64`; sink write error count |
| `MetricsSnapshot` | `engine.MetricsSnapshot()` | none | `MetricsSnapshot`; counters/histograms snapshot |
| `SecurityReport` | `engine.SecurityReport()` | none | `SecurityReport`; current security posture |

### 5.2 Authentication and MFA Login

| Method | Invocation | Parameters | Returns / Purpose |
|---|---|---|---|
| `Login` | `engine.Login(ctx, username, password)` | `ctx context.Context`, `username string`, `password string` | `(accessToken string, refreshToken string, err error)` |
| `LoginWithResult` | `engine.LoginWithResult(ctx, username, password)` | `ctx`, `username`, `password` | `(*LoginResult, error)`; for two-step MFA flow |
| `ConfirmLoginMFA` | `engine.ConfirmLoginMFA(ctx, challengeID, code)` | `ctx`, `challengeID string`, `code string` | `(*LoginResult, error)`; TOTP MFA completion |
| `ConfirmLoginMFAWithType` | `engine.ConfirmLoginMFAWithType(ctx, challengeID, code, mfaType)` | `ctx`, `challengeID string`, `code string`, `mfaType string` (`"totp"` or `"backup"`) | `(*LoginResult, error)` |
| `LoginWithTOTP` | `engine.LoginWithTOTP(ctx, username, password, totpCode)` | `ctx`, `username`, `password`, `totpCode string` | `(accessToken, refreshToken, error)` |
| `LoginWithBackupCode` | `engine.LoginWithBackupCode(ctx, username, password, backupCode)` | `ctx`, `username`, `password`, `backupCode string` | `(accessToken, refreshToken, error)` |
| `Refresh` | `engine.Refresh(ctx, refreshToken)` | `ctx`, `refreshToken string` | `(newAccess string, newRefresh string, err error)` |

### 5.3 Token Validation and Permissions

| Method | Invocation | Parameters | Returns / Purpose |
|---|---|---|---|
| `ValidateAccess` | `engine.ValidateAccess(ctx, tokenStr)` | `ctx`, `tokenStr string` | `(*AuthResult, error)`; uses engine default validation mode |
| `Validate` | `engine.Validate(ctx, tokenStr, routeMode)` | `ctx`, `tokenStr string`, `routeMode RouteMode` (`goAuth.ModeInherit`, `goAuth.ModeJWTOnly`, `goAuth.ModeHybrid`, `goAuth.ModeStrict`) | `(*AuthResult, error)` |
| `HasPermission` | `engine.HasPermission(mask, perm)` | `mask interface{}` (permission mask), `perm string` | `bool`; frozen-registry permission lookup + O(1) bitmask check |

### 5.4 Logout and Session Invalidation

| Method | Invocation | Parameters | Returns / Purpose |
|---|---|---|---|
| `Logout` | `engine.Logout(ctx, sessionID)` | `ctx`, `sessionID string` | `error`; delete one session in tenant from context |
| `LogoutInTenant` | `engine.LogoutInTenant(ctx, tenantID, sessionID)` | `ctx`, `tenantID string`, `sessionID string` | `error`; delete one session in explicit tenant |
| `LogoutByAccessToken` | `engine.LogoutByAccessToken(ctx, tokenStr)` | `ctx`, `tokenStr string` | `error`; parse access token and invalidate its session |
| `LogoutAll` | `engine.LogoutAll(ctx, userID)` | `ctx`, `userID string` | `error`; delete all sessions for user in context tenant |
| `LogoutAllInTenant` | `engine.LogoutAllInTenant(ctx, tenantID, userID)` | `ctx`, `tenantID string`, `userID string` | `error`; delete all sessions for user in explicit tenant |
| `InvalidateUserSessions` | `engine.InvalidateUserSessions(ctx, userID)` | `ctx`, `userID string` | `error`; alias of `LogoutAll` |

### 5.5 Account Lifecycle and Password Change

| Method | Invocation | Parameters | Returns / Purpose |
|---|---|---|---|
| `CreateAccount` | `engine.CreateAccount(ctx, req)` | `ctx`, `req CreateAccountRequest` | `(*CreateAccountResult, error)` |
| `ChangePassword` | `engine.ChangePassword(ctx, userID, oldPassword, newPassword)` | `ctx`, `userID string`, `oldPassword string`, `newPassword string` | `error`; invalidates all user sessions on success |
| `DisableAccount` | `engine.DisableAccount(ctx, userID)` | `ctx`, `userID string` | `error` |
| `EnableAccount` | `engine.EnableAccount(ctx, userID)` | `ctx`, `userID string` | `error` |
| `UnlockAccount` | `engine.UnlockAccount(ctx, userID)` | `ctx`, `userID string` | `error`; unlocks account and resets lockout counter |
| `LockAccount` | `engine.LockAccount(ctx, userID)` | `ctx`, `userID string` | `error` |
| `DeleteAccount` | `engine.DeleteAccount(ctx, userID)` | `ctx`, `userID string` | `error`; marks account deleted and invalidates sessions |

### 5.6 TOTP and Backup Codes

| Method | Invocation | Parameters | Returns / Purpose |
|---|---|---|---|
| `GenerateTOTPSetup` | `engine.GenerateTOTPSetup(ctx, userID)` | `ctx`, `userID string` | `(*TOTPSetup, error)`; returns base32 secret + QR URL |
| `ProvisionTOTP` | `engine.ProvisionTOTP(ctx, userID)` | `ctx`, `userID string` | `(*TOTPProvision, error)`; returns raw secret + URI |
| `ConfirmTOTPSetup` | `engine.ConfirmTOTPSetup(ctx, userID, code)` | `ctx`, `userID string`, `code string` | `error`; verifies and enables TOTP |
| `VerifyTOTP` | `engine.VerifyTOTP(ctx, userID, code)` | `ctx`, `userID string`, `code string` | `error`; standalone TOTP verification |
| `DisableTOTP` | `engine.DisableTOTP(ctx, userID)` | `ctx`, `userID string` | `error`; disables TOTP |
| `GenerateBackupCodes` | `engine.GenerateBackupCodes(ctx, userID)` | `ctx`, `userID string` | `([]string, error)`; returns plaintext backup codes once |
| `RegenerateBackupCodes` | `engine.RegenerateBackupCodes(ctx, userID, totpCode)` | `ctx`, `userID string`, `totpCode string` | `([]string, error)`; requires valid TOTP |
| `VerifyBackupCode` | `engine.VerifyBackupCode(ctx, userID, code)` | `ctx`, `userID string`, `code string` | `error`; consumes one backup code |
| `VerifyBackupCodeInTenant` | `engine.VerifyBackupCodeInTenant(ctx, tenantID, userID, code)` | `ctx`, `tenantID string`, `userID string`, `code string` | `error`; tenant-explicit backup verification |

### 5.7 Password Reset

| Method | Invocation | Parameters | Returns / Purpose |
|---|---|---|---|
| `RequestPasswordReset` | `engine.RequestPasswordReset(ctx, identifier)` | `ctx`, `identifier string` | `(challenge string, err error)` |
| `ConfirmPasswordReset` | `engine.ConfirmPasswordReset(ctx, challenge, newPassword)` | `ctx`, `challenge string`, `newPassword string` | `error` |
| `ConfirmPasswordResetWithTOTP` | `engine.ConfirmPasswordResetWithTOTP(ctx, challenge, newPassword, totpCode)` | `ctx`, `challenge string`, `newPassword string`, `totpCode string` | `error` |
| `ConfirmPasswordResetWithBackupCode` | `engine.ConfirmPasswordResetWithBackupCode(ctx, challenge, newPassword, backupCode)` | `ctx`, `challenge string`, `newPassword string`, `backupCode string` | `error` |
| `ConfirmPasswordResetWithMFA` | `engine.ConfirmPasswordResetWithMFA(ctx, challenge, newPassword, mfaType, mfaCode)` | `ctx`, `challenge string`, `newPassword string`, `mfaType string`, `mfaCode string` | `error`; `mfaType` supports `"totp"` and `"backup"` |

### 5.8 Email Verification

| Method | Invocation | Parameters | Returns / Purpose |
|---|---|---|---|
| `RequestEmailVerification` | `engine.RequestEmailVerification(ctx, identifier)` | `ctx`, `identifier string` | `(challenge string, err error)` |
| `ConfirmEmailVerification` | `engine.ConfirmEmailVerification(ctx, challenge)` | `ctx`, `challenge string` | `error`; full challenge form |
| `ConfirmEmailVerificationCode` | `engine.ConfirmEmailVerificationCode(ctx, verificationID, code)` | `ctx`, `verificationID string`, `code string` | `error`; preferred split-ID + code API |

### 5.9 Introspection and Operational Methods

| Method | Invocation | Parameters | Returns / Purpose |
|---|---|---|---|
| `GetActiveSessionCount` | `engine.GetActiveSessionCount(ctx, userID)` | `ctx`, `userID string` | `(int, error)` |
| `ListActiveSessions` | `engine.ListActiveSessions(ctx, userID)` | `ctx`, `userID string` | `([]SessionInfo, error)` |
| `GetSessionInfo` | `engine.GetSessionInfo(ctx, tenantID, sessionID)` | `ctx`, `tenantID string`, `sessionID string` | `(*SessionInfo, error)` |
| `ActiveSessionEstimate` | `engine.ActiveSessionEstimate(ctx)` | `ctx` | `(int, error)` |
| `Health` | `engine.Health(ctx)` | `ctx` | `HealthStatus` (`RedisAvailable`, `RedisLatency`) |
| `GetLoginAttempts` | `engine.GetLoginAttempts(ctx, identifier)` | `ctx`, `identifier string` | `(int, error)` |

## 6) Important Input Types Used by Methods

### CreateAccountRequest

Used by `engine.CreateAccount(ctx, req)`.

| Field | Type | Meaning |
|---|---|---|
| `Identifier` | `string` | Required user identifier (for example email/username) |
| `Password` | `string` | Required plaintext password (engine hashes with Argon2) |
| `Role` | `string` | Optional; if empty, defaults to `cfg.Account.DefaultRole` |

### MetricsConfig

Used by `goAuth.NewMetrics(cfg)`.

| Field | Type | Meaning |
|---|---|---|
| `Enabled` | `bool` | Enable/disable metrics collection |
| `EnableLatencyHistograms` | `bool` | Enable/disable operation latency histograms |

### LoginResult

Returned by `LoginWithResult`, `ConfirmLoginMFA`, and `ConfirmLoginMFAWithType`.

| Field | Type | Meaning |
|---|---|---|
| `AccessToken` | `string` | Populated on successful login completion |
| `RefreshToken` | `string` | Populated on successful login completion |
| `MFARequired` | `bool` | True when second factor is required |
| `MFAType` | `string` | MFA type requested by flow |
| `MFASession` | `string` | Challenge ID used by MFA confirm methods |

## 7) Invocation Notes

- `Build()` fails if required dependencies are missing (Redis, permissions, roles, user provider).
- If `cfg.Audit.Enabled` is true, you must call `WithAuditSink(...)` before `Build()`.
- Use `ValidateAccess` for default-mode validation; use `Validate` when you need a per-route override.
- Use `WithTenantID` on context in multi-tenant deployments to avoid default-tenant behavior.
- Always call `engine.Close()` on shutdown to flush and close audit dispatching.
