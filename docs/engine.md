# Module: Engine

## Purpose

The `Engine` is the runtime API surface of goAuth. It orchestrates all authentication, authorization, session management, MFA, password reset, email verification, and account operations. All public methods are safe for concurrent use after initialization via `Builder.Build()`.

## Primitives

### Builder / Factory

| Primitive | Signature | Description |
|-----------|-----------|-------------|
| `New()` | `func New() *Builder` | Create a new builder |
| `WithConfig` | `(b *Builder) WithConfig(cfg Config) *Builder` | Override full config |
| `WithRedis` | `(b *Builder) WithRedis(client redis.UniversalClient) *Builder` | Set Redis client |
| `WithPermissions` | `(b *Builder) WithPermissions(perms []string) *Builder` | Register permission names |
| `WithRoles` | `(b *Builder) WithRoles(r map[string][]string) *Builder` | Map roles → permissions |
| `WithUserProvider` | `(b *Builder) WithUserProvider(up UserProvider) *Builder` | Set user persistence |
| `WithAuditSink` | `(b *Builder) WithAuditSink(sink AuditSink) *Builder` | Set audit sink |
| `Build()` | `(b *Builder) Build() (*Engine, error)` | Validate config, freeze registry, start background workers |

### Authentication

| Primitive | Signature | Returns |
|-----------|-----------|---------|
| `Login` | `(ctx, username, password string)` | `(accessToken, refreshToken string, err error)` |
| `LoginWithResult` | `(ctx, username, password string)` | `(*LoginResult, error)` — includes MFA challenge info |
| `LoginWithTOTP` | `(ctx, username, password, totpCode string)` | `(accessToken, refreshToken string, err error)` |
| `LoginWithBackupCode` | `(ctx, username, password, backupCode string)` | `(accessToken, refreshToken string, err error)` |
| `ConfirmLoginMFA` | `(ctx, challengeID, code string)` | `(*LoginResult, error)` |
| `Refresh` | `(ctx, refreshToken string)` | `(newAccess, newRefresh string, err error)` |

### Validation

| Primitive | Signature | Returns |
|-----------|-----------|---------|
| `ValidateAccess` | `(ctx, tokenStr string)` | `(*AuthResult, error)` |
| `Validate` | `(ctx, tokenStr string, routeMode RouteMode)` | `(*AuthResult, error)` — per-route mode override |
| `HasPermission` | `(mask interface{}, perm string)` | `bool` |

### Logout

| Primitive | Signature |
|-----------|-----------|
| `Logout` | `(ctx, sessionID string) error` |
| `LogoutByAccessToken` | `(ctx, tokenStr string) error` |
| `LogoutAll` | `(ctx, userID string) error` |
| `InvalidateUserSessions` | `(ctx, userID string) error` |

### Errors (sentinel)

Key errors: `ErrInvalidCredentials`, `ErrLoginRateLimited`, `ErrUnauthorized`, `ErrRefreshReuse`, `ErrAccountDisabled`, `ErrTOTPRequired`, `ErrMFALoginRequired`.

See [errors.go](../errors.go) for the full list (40+ sentinel errors).

## Strategies

| Strategy | Config Knob | Description |
|----------|------------|-------------|
| JWT-Only validation | `ValidationMode = ModeJWTOnly` | Token-only, no Redis call |
| Hybrid validation | `ValidationMode = ModeHybrid` | JWT + optional Redis session check |
| Strict validation | `ValidationMode = ModeStrict` | JWT + mandatory Redis session check |
| Per-route override | `RouteMode` param on `Validate()` | Override global mode for specific routes |

## Examples

### Minimal

```go
engine, err := goAuth.New().
    WithRedis(rdb).
    WithPermissions([]string{"user.read", "user.write"}).
    WithRoles(map[string][]string{"admin": {"user.read", "user.write"}}).
    WithUserProvider(myProvider{}).
    Build()
if err != nil {
    log.Fatal(err)
}
defer engine.Close()

access, refresh, err := engine.Login(ctx, "alice@example.com", "password")
```

### With MFA

```go
result, err := engine.LoginWithResult(ctx, "alice@example.com", "password")
if result.MFARequired {
    // Prompt user for TOTP code, then:
    finalResult, err := engine.ConfirmLoginMFA(ctx, result.MFASession, totpCode)
}
```

## Security Notes

- `Close()` must be called to flush pending audit events and release resources.
- All sensitive comparisons use constant-time operations.
- Rate limiting protects login, refresh, account creation, password reset, and email verification.
- Refresh token reuse triggers automatic session invalidation (replay detection).

## Performance Notes

- JWT-only validation avoids Redis entirely (~microsecond latency).
- Strict validation adds one Redis GET per request.
- Refresh rotation uses a single Lua script (1 Redis round-trip).
- Permission checks are bitwise operations on fixed-size masks (no allocations).

## Edge Cases & Gotchas

- `Login()` returns `ErrMFALoginRequired` when TOTP is enabled — callers must handle the MFA flow.
- `Refresh()` permanently invalidates the session if a replayed (old) refresh token is detected.
- Context must carry tenant ID via `WithTenantID(ctx, id)` for multi-tenant deployments.
- `ValidateAccess()` always uses the engine's global `ValidationMode`; use `Validate()` for per-route overrides.

## Architecture

The `Engine` is the top-level orchestrator. It holds references to all internal subsystems (JWT manager, session store, rate limiters, audit dispatcher, metrics collector, permission registry, role manager, TOTP manager, and flow functions). All subsystems are initialized and frozen at `Build()` time; the engine is immutable after construction.

```
Builder.Build()
  ├─ Config validation + lint
  ├─ Permission registry freeze
  ├─ Role manager freeze
  ├─ JWT manager construction
  ├─ Session store construction
  ├─ Rate limiter construction
  ├─ Domain limiters (TOTP, backup, email, password-reset, account, lockout)
  ├─ Audit dispatcher start
  └─ Return *Engine (immutable)
```

All public `Engine` methods delegate to flow functions in `internal/flows/` which receive a dependency struct. This keeps the engine layer thin and the flow logic testable in isolation.

## Flow Ownership

| Flow | Entry Point | Internal Module |
|------|-------------|------------------|
| Login (no MFA) | `Engine.Login`, `Engine.LoginWithResult` | `internal/flows/login.go` → `RunLoginWithResult` |
| Login (with MFA) | `Engine.LoginWithTOTP`, `Engine.LoginWithBackupCode` | `internal/flows/login.go` |
| Confirm MFA Login | `Engine.ConfirmLoginMFA` | `internal/flows/login.go` → `RunConfirmLoginMFAWithType` |
| Refresh Rotation | `Engine.Refresh` | `internal/flows/refresh.go` → `RunRefresh` |
| Validate | `Engine.ValidateAccess`, `Engine.Validate` | `internal/flows/validate.go` → `RunValidate` |
| Logout | `Engine.Logout`, `Engine.LogoutAll` | `internal/flows/logout.go` |
| Password Change | `Engine.ChangePassword` | `internal/flows/password.go` |
| Password Reset | `Engine.RequestPasswordReset`, `Engine.ConfirmPasswordReset` | `internal/flows/password_reset.go` |
| Email Verification | `Engine.RequestEmailVerification`, `Engine.ConfirmEmailVerification` | `internal/flows/email_verification.go` |
| TOTP Management | `Engine.GenerateTOTPSetup`, `Engine.ConfirmTOTPSetup` | `internal/flows/totp.go` |
| Account Status | `Engine.DisableAccount`, `Engine.EnableAccount` | `internal/flows/account_status.go` |
| Introspection | `Engine.Health`, `Engine.ListActiveSessions` | `internal/flows/introspection.go` |

## Testing Evidence

| Category | File | Notes |
|----------|------|-------|
| Login & Auth | `engine_account_test.go` | Account creation, login, credential validation |
| MFA Login | `engine_mfa_login_test.go` | Challenge flow, confirm, timeout, attempts |
| TOTP | `engine_totp_test.go` | Setup, confirm, disable |
| Backup Codes | `engine_backup_codes_test.go` | Generate, consume, regenerate |
| Password Change | `engine_change_password_test.go` | Old password verify, reuse, policy |
| Password Reset | `engine_password_reset_test.go` | Request, confirm, strategies, MFA |
| Email Verification | `engine_email_verification_test.go` | Request, confirm, enumeration resistance |
| Session Hardening | `engine_session_hardening_test.go` | Version drift, strict mode |
| Device Binding | `engine_device_binding_test.go` | IP/UA detect and enforce |
| Account Status | `engine_account_status_test.go` | Disable, lock, enable, delete |
| Auto Lockout | `engine_auto_lockout_test.go` | Lockout threshold, reset |
| Introspection | `engine_introspection_test.go` | Session counts, health |
| Validation Modes | `validation_mode_test.go` | JWT-Only, Hybrid, Strict, per-route |
| Refresh Concurrency | `refresh_concurrency_test.go` | Concurrent rotation, replay |
| Security Invariants | `security_invariants_test.go` | Cross-cutting security properties |
| Benchmarks | `auth_bench_test.go` | Login, refresh, validate latency |
| Config | `config_test.go`, `config_lint_test.go`, `config_hardening_test.go` | Validation, lint, presets |
| Integration | `test/public_api_test.go`, `test/engine_delegate_test.go` | Full-stack integration |

## Migration Notes

- **v1 → v2**: `Login()` now returns `ErrMFALoginRequired` instead of a partial token when TOTP is enabled. Callers must handle the MFA flow explicitly.
- **Builder pattern**: All engine construction must go through `New().With*().Build()`. Direct struct initialization is not supported.
- **`Close()` required**: Failing to call `Close()` may leak the audit dispatcher goroutine and lose buffered audit events.
- **Session schema**: The session binary encoding auto-migrates v1–v5 on read. No manual migration is needed.

## See Also

- [Flows](flows.md)
- [Configuration](config.md)
- [Architecture](architecture.md)
- [Security Model](security.md)
- [API Reference](api-reference.md)
- [Performance](performance.md)
- [JWT](jwt.md)
- [Session](session.md)
- [Middleware](middleware.md)
