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
