# goAuth

goAuth is a high-performance Go authentication guard for latency-sensitive APIs. It combines short-lived JWT access tokens with rotating opaque refresh tokens, Redis-backed session control, and fixed-size bitmask authorization.

## What it is

- Authentication engine for login, refresh, validation, and session invalidation.
- Authorization layer using precompiled role-permission bitmasks (up to 512 bits).
- Security-focused flow controls including rate limiting, MFA, password reset, and email verification.
- Middleware integrations for JWT-only, hybrid, and strict validation modes.

## Functionality Supported

Each item links to a dedicated implementation/flow document.

- [Login and session issuance](docs/functionality-login.md)
- [Access token validation and authorization](docs/functionality-validation-and-rbac.md)
- [Refresh token rotation and replay handling](docs/functionality-refresh-rotation.md)
- [Logout and session invalidation](docs/functionality-logout-and-invalidation.md)
- [MFA (TOTP + backup code) flows](docs/functionality-mfa.md)
- [Password reset lifecycle](docs/functionality-password-reset.md)
- [Email verification lifecycle](docs/functionality-email-verification.md)
- [Account status controls (disable/lock/delete)](docs/functionality-account-status.md)
- [Audit and metrics emission](docs/functionality-audit-and-metrics.md)

## Exported Primitives (Core)

For the full index, see [docs/api-reference.md](docs/api-reference.md).

### Core engine primitives

- `Builder` and `New()` for configuration and engine construction.
- `Engine` as the runtime API (login, validate, refresh, logout, account/mfa operations).
- `AuthResult`, `LoginResult`, `CreateAccountRequest`, `CreateAccountResult` for API payloads.

### Identity and provider primitives

- `UserProvider` for credential/account/MFA/back-code persistence integration.
- `UserRecord`, `CreateUserInput`, `AccountStatus` for user state modeling.

### Permission primitives

- `PermissionMask` interface for permission checks.
- Fixed-size masks in `permission`: `Mask64`, `Mask128`, `Mask256`, `Mask512`.
- `permission.Registry` and `permission.RoleManager` for build-time freeze of permission topology.

### Session and token primitives

- `session.Store` and `session.Session` for Redis-backed session state.
- `jwt.Manager` for JWT issue/verify behavior.

## Configuration Parameters

All fields are defined in [`Config`](config.go) and nested config structs. See [docs/config.md](docs/config.md) for detailed notes.

### Top-level config groups

- `JWT` (`JWTConfig`): signing method/key material, issuer/audience, TTL.
- `Session` (`SessionConfig`): session TTL and sliding expiration behavior.
- `Password` (`PasswordConfig`): hashing algorithm/cost tuning.
- `PasswordReset` (`PasswordResetConfig`): reset strategy, token/OTP policy, TTL, attempt limits.
- `EmailVerification` (`EmailVerificationConfig`): verification strategy, TTL, attempt limits.
- `Account` (`AccountConfig`): account creation/status defaults.
- `Audit` (`AuditConfig`): audit behavior/sink controls.
- `Metrics` (`MetricsConfig`): metrics enablement/histograms.
- `Security` (`SecurityConfig`): security hardening toggles and limits.
- `SessionHardening` (`SessionHardeningConfig`): max sessions/single-session/concurrency constraints.
- `DeviceBinding` (`DeviceBindingConfig`): device-level login binding checks.
- `TOTP` (`TOTPConfig`): MFA code/window/attempt policy.
- `MultiTenant` (`MultiTenantConfig`): tenant-isolation behavior.
- `Database` (`DatabaseConfig`): optional backing data dependency settings.
- `Permission` (`PermissionConfig`): max bits, root bit reservation.
- `Cache` (`CacheConfig`): cache behavior.
- `Result` (`ResultConfig`): result payload shaping.
- `ValidationMode` (`ModeJWTOnly`, `ModeHybrid`, `ModeStrict`).

## Quick Demo

```go
package main

import (
	"context"
	"log"

	goAuth "github.com/MrEthical07/goAuth"
	"github.com/redis/go-redis/v9"
)

func main() {
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})

	engine, err := goAuth.New().
		WithRedis(rdb).
		WithPermissions([]string{"user.read", "user.write"}).
		WithRoles(map[string][]string{"admin": {"user.read", "user.write"}}).
		WithUserProvider(myUserProvider{}).
		Build()
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()

	access, refresh, err := engine.Login(context.Background(), "alice@example.com", "correct horse battery staple")
	if err != nil {
		log.Fatal(err)
	}

	_, _, _ = access, refresh, err
}

type myUserProvider struct{}
```

## Documentation Map

### Core architecture docs

- [Architecture](docs/architecture.md)
- [Usage guide](docs/usage.md)
- [API reference](docs/api-reference.md)
- [Concurrency model](docs/concurrency-model.md)
- [Security model](docs/security-model.md)
- [Benchmarks summary](docs/benchmarks.md)

### Package/file-level technical docs

- [Engine internals](docs/engine.md)
- [Builder internals](docs/builder.md)
- [Configuration internals](docs/config.md)
- [Session internals](docs/store.md)
- [Permission internals](docs/registry.md)
- [JWT manager internals](docs/manager.md)
- [Middleware internals](docs/guard.md)

For exhaustive per-file documentation, browse the [`docs/`](docs) directory.
