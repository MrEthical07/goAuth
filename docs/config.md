# Configuration Reference

## Overview

The `Config` struct is the single source of truth for all goAuth Engine behavior.
Pass it via `Builder.WithConfig(cfg)` — the builder deep-copies and validates it
during `Build()`.

Three presets are provided:

| Preset               | Validation Mode | Access TTL | Refresh TTL | Notes                    |
|----------------------|-----------------|-----------|------------|--------------------------|
| `DefaultConfig()`    | Hybrid          | 5 min     | 7 days     | Ephemeral Ed25519 keys   |
| `HighSecurityConfig()` | Strict       | 5 min     | 24 hours   | iat required, device binding on |
| `HighThroughputConfig()` | Hybrid    | 15 min    | 14 days    | Relaxed refresh limits   |

## JWT (`Config.JWT`)

| Field          | Type          | Default      | Description |
|----------------|---------------|-------------|-------------|
| `AccessTTL`    | `time.Duration`| 5 min       | Lifetime of signed access tokens |
| `RefreshTTL`   | `time.Duration`| 7 days      | Lifetime of refresh tokens / sessions |
| `SigningMethod` | `string`     | `"ed25519"` | `"ed25519"`, `"hs256"`, or `"rs256"` |
| `PrivateKey`   | `[]byte`      | —           | Private signing key (Ed25519 / RSA) |
| `PublicKey`    | `[]byte`      | —           | Public verification key |
| `Issuer`       | `string`      | `""`        | JWT `iss` claim |
| `Audience`     | `string`      | `""`        | JWT `aud` claim |
| `Leeway`       | `time.Duration`| 30 s       | Clock-skew tolerance for `exp`/`nbf` |
| `RequireIAT`   | `bool`        | `false`     | Reject tokens without `iat` |
| `MaxFutureIAT` | `time.Duration`| 10 min     | Max future `iat` allowed |
| `KeyID`        | `string`      | `""`        | `kid` header for key rotation |
| `VerifyKeys`   | `map[string][]byte` | `nil` | `kid` → verification key set for zero-downtime key rotation; when set, `KeyID` is required and must name an entry. See [ops.md §9](ops.md#9-ed25519-key-rotation-runbook) |

> **See also:** [jwt.md](jwt.md)

## Session (`Config.Session`)

| Field                     | Type          | Default | Description |
|---------------------------|---------------|---------|-------------|
| `RedisPrefix`             | `string`      | `"as"`  | Redis key namespace prefix |
| `SlidingExpiration`       | `bool`        | `true`  | Extend TTL on each access |
| `AbsoluteSessionLifetime` | `time.Duration`| 7 days | Default (non-remember-me) session lifetime, together with `JWT.RefreshTTL` |
| `MaxSessionDuration`      | `time.Duration`| unset (0) | Absolute session ceiling; remember-me sessions live up to this. See below |
| `JitterEnabled`           | `bool`        | `true`  | Add random jitter to TTLs |
| `JitterRange`             | `time.Duration`| 30 s   | ±jitter window |
| `MaxSessionSize`          | `int`         | `512`   | Max encoded session bytes |
| `SessionEncoding`         | `string`      | `"binary"` | `"binary"` (v5) or `"msgpack"` |

### MaxSessionDuration

`MaxSessionDuration` is the hard ceiling beyond which no session can be created or
extended, regardless of sliding renewal. `Validate()` rejects negative values and
values between `0` and 1 minute; `0` means unset.

- **Set explicitly (> 0):** used as-is. Remember-me sessions
  (`LoginOptions.RememberMe`, see [engine.md](engine.md)) receive exactly this
  lifetime. Non-remember-me sessions keep
  `min(RefreshTTL, AbsoluteSessionLifetime)` but are additionally capped at this
  ceiling — the `max_session_duration_caps_default` lint warns when the ceiling is
  below the default lifetime.
- **Unset (0):** resolved once in `Builder.Build()` to a per-validation-mode
  default — **24 h** for `ModeStrict`, **7 days** for `ModeHybrid`/`ModeJWTOnly` —
  raised to `min(RefreshTTL, AbsoluteSessionLifetime)` when that is longer, so
  configurations that predate this field keep their exact session lifetimes.

> **See also:** [session.md](session.md)

## Password (`Config.Password`)

| Field          | Type   | Default | Description |
|----------------|--------|---------|-------------|
| `Memory`       | `uint32`| 65536  | Argon2id memory in KB |
| `Time`         | `uint32`| 3      | Argon2id iterations |
| `Parallelism`  | `uint8` | 2      | Argon2id threads |
| `SaltLength`   | `uint32`| 16     | Salt bytes |
| `KeyLength`    | `uint32`| 32     | Derived key bytes |
| `UpgradeOnLogin` | `bool`| `true` | Re-hash on login if params changed |

> **See also:** [password.md](password.md)

## Security (`Config.Security`)

| Field                          | Type          | Default       | Description |
|--------------------------------|---------------|--------------|-------------|
| `ProductionMode`               | `bool`        | `false`      | Enable production security checks |
| `EnableIPBinding`              | `bool`        | `false`      | **No-op** — never read by the engine; IP binding is controlled by `DeviceBinding.*` (lint: `security_ip_binding_noop`) |
| `EnableUserAgentBinding`       | `bool`        | `true`       | Bind sessions to User-Agent |
| `EnableLoginFailureLimiter`    | `bool`        | `true`       | Enable login-failure limiter |
| `EnableIPSignal`               | `bool`        | `false`      | **No-op** — never read by the engine (lint: `security_ip_signal_noop`) |
| `EnforceRefreshRotation`       | `bool`        | `true`       | Require token rotation on refresh |
| `EnforceRefreshReuseDetection` | `bool`        | `true`       | Invalidate session on token reuse |
| `MaxLoginAttempts`             | `int`         | 5            | Failed logins before cooldown |
| `LoginCooldownDuration`        | `time.Duration`| 15 min      | Cooldown after max login attempts |
| `StrictMode`                   | `bool`        | `false`      | Force strict validation globally |
| `RequireSecureCookies`         | `bool`        | `true`       | **No-op** — the engine never issues cookies; enforce at the HTTP layer (lint: `cookie_settings_noop`) |
| `SameSitePolicy`               | `http.SameSite`| `Strict`    | **No-op** — the engine never issues cookies; enforce at the HTTP layer (lint: `cookie_settings_noop`) |
| `CSRFProtection`               | `bool`        | `true`       | **No-op** — no CSRF machinery exists in the engine; enforce at the HTTP layer (lint: `cookie_settings_noop`) |
| `EnablePermissionVersionCheck` | `bool`        | `true`       | Check permission version on validate |
| `EnableRoleVersionCheck`       | `bool`        | `true`       | Check role version on validate |
| `EnableAccountVersionCheck`    | `bool`        | `true`       | Check account version on validate |
| `AutoLockoutEnabled`           | `bool`        | `false`      | Auto-lock after repeated failures |
| `AutoLockoutThreshold`         | `int`         | 10           | Failures before auto-lock |
| `AutoLockoutDuration`          | `time.Duration`| 30 min      | Duration of auto-lock |
| `LimiterWindowMode`            | `string`      | `""` (fixed) | Rate-limiter algorithm for all domains: `"fixed"` or `"sliding"` (removes the 2× boundary burst) |

> **See also:** [security.md](security.md), [rate_limiting.md](rate_limiting.md)

## Session Hardening (`Config.SessionHardening`)

| Field                  | Type          | Default | Description |
|------------------------|---------------|---------|-------------|
| `MaxSessionsPerUser`   | `int`         | 0 (off) | Cap active sessions per user |
| `MaxSessionsPerTenant` | `int`         | 0 (off) | Cap active sessions per tenant |
| `EnforceSingleSession` | `bool`        | `false` | Delete old sessions on new login |
| `ConcurrentLoginLimit` | `int`         | 0 (off) | Max concurrent active logins |
| `EnableReplayTracking` | `bool`        | `true`  | Track refresh-token replay |
| `MaxClockSkew`         | `time.Duration`| 30 s   | Max tolerated clock difference |

## Device Binding (`Config.DeviceBinding`)

| Field                     | Type   | Default | Description |
|---------------------------|--------|---------|-------------|
| `Enabled`                 | `bool` | `false` | Enable device binding checks |
| `EnforceIPBinding`        | `bool` | `false` | Reject on IP mismatch |
| `EnforceUserAgentBinding` | `bool` | `false` | Reject on UA mismatch |
| `DetectIPChange`          | `bool` | `false` | Emit audit event on IP change |
| `DetectUserAgentChange`   | `bool` | `false` | Emit audit event on UA change |

> **See also:** [device_binding.md](device_binding.md)

## TOTP (`Config.TOTP`)

| Field                       | Type          | Default    | Description |
|-----------------------------|---------------|-----------|-------------|
| `Enabled`                   | `bool`        | `false`   | Enable TOTP 2FA |
| `Issuer`                    | `string`      | `""`      | otpauth:// issuer label |
| `Digits`                    | `int`         | 6         | OTP digit count |
| `Period`                    | `int`         | 30        | TOTP period in seconds |
| `Algorithm`                 | `string`      | `"SHA1"`  | TOTP hash algorithm |
| `Skew`                      | `int`         | 1         | Allowed time-step skew |
| `EnforceReplayProtection`   | `bool`        | `true`    | Reject re-used TOTP codes |
| `MFALoginChallengeTTL`      | `time.Duration`| 3 min    | MFA challenge lifetime |
| `MFALoginMaxAttempts`       | `int`         | 5         | Max MFA confirm attempts |
| `BackupCodeCount`           | `int`         | 10        | Number of backup codes |
| `BackupCodeLength`          | `int`         | 10        | Backup code character length |
| `BackupCodeMaxAttempts`     | `int`         | 5         | Max backup code attempts |
| `BackupCodeCooldown`        | `time.Duration`| 10 min   | Cooldown after max backup attempts |
| `RequireForLogin`           | `bool`        | `false`   | Require TOTP on login |
| `RequireForPasswordReset`   | `bool`        | `false`   | Require TOTP for password reset |

> **See also:** [mfa.md](mfa.md)

## WebAuthn (`Config.WebAuthn`)

| Field                        | Type            | Default       | Description |
|------------------------------|-----------------|---------------|-------------|
| `Enabled`                    | `bool`          | `false`       | Enable WebAuthn/FIDO2 second factor (user provider must implement `WebAuthnCredentialProvider`) |
| `RPID`                       | `string`        | —             | Relying Party ID (effective domain). Required when enabled |
| `RPDisplayName`              | `string`        | —             | Human-readable RP name. Required when enabled |
| `RPOrigins`                  | `[]string`      | —             | Exact origins allowed to complete ceremonies. Required when enabled |
| `AttestationPreference`      | `string`        | `"none"`      | `none`, `indirect`, `direct`, or `enterprise` |
| `UserVerification`           | `string`        | `"preferred"` | `preferred`, `required`, or `discouraged` |
| `CeremonyTTL`                | `time.Duration` | 2 min         | Ceremony lifetime (10s–10m when set) |
| `RequireForLogin`            | `bool`          | `false`       | Gate login behind an assertion for users with registered credentials |
| `RejectClonedAuthenticators` | `bool`          | `true`        | Fail assertions whose signature counter regressed |

> **See also:** [webauthn.md](webauthn.md)

## Password Reset (`Config.PasswordReset`)

| Field                    | Type              | Default         | Description |
|--------------------------|-------------------|----------------|-------------|
| `Enabled`                | `bool`            | `false`        | Enable password reset flow |
| `Strategy`               | `ResetStrategyType`| `ResetToken`  | `ResetToken`, `ResetOTP`, or `ResetUUID` |
| `ResetTTL`               | `time.Duration`   | 15 min         | Challenge lifetime |
| `MaxAttempts`            | `int`             | 5              | Max confirm attempts per challenge |
| `EnableRequestLimiter`   | `bool`            | `true`         | Enable request-phase limiter |
| `EnableConfirmFailureLimiter` | `bool`      | `true`         | Enable confirm-failure limiter |
| `OTPDigits`              | `int`             | 6              | OTP digit count (OTP strategy) |

> **See also:** [password_reset.md](password_reset.md)

## Email Verification (`Config.EmailVerification`)

| Field                    | Type                    | Default             | Description |
|--------------------------|-------------------------|--------------------|----|
| `Enabled`                | `bool`                  | `false`            | Enable email verification |
| `Strategy`               | `VerificationStrategyType`| `VerificationToken`| Delivery strategy |
| `VerificationTTL`        | `time.Duration`         | 15 min             | Challenge lifetime |
| `MaxAttempts`            | `int`                   | 5                  | Max confirm attempts |
| `RequireForLogin`        | `bool`                  | `false`            | Block login for unverified accounts |
| `EnableRequestLimiter`   | `bool`                  | `true`             | Enable request-phase limiter |
| `EnableConfirmFailureLimiter` | `bool`            | `true`             | Enable confirm-failure limiter |
| `OTPDigits`              | `int`                   | 6                  | OTP digit count |

> **See also:** [email_verification.md](email_verification.md)

## Account (`Config.Account`)

| Field                          | Type          | Default  | Description |
|--------------------------------|---------------|---------|-------------|
| `Enabled`                      | `bool`        | `true`  | Enable account creation |
| `AutoLogin`                    | `bool`        | `false` | Issue tokens on creation |
| `EnableCreationLimiter`        | `bool`        | `true`  | Enable account-creation limiter |
| `DefaultRole`                  | `string`      | `""`    | Role assigned to new accounts |
| `AccountCreationMaxAttempts`   | `int`         | 5       | Rate limit attempts |
| `AccountCreationCooldown`      | `time.Duration`| 15 min | Cooldown period |

## Audit (`Config.Audit`)

| Field        | Type   | Default | Description |
|--------------|--------|---------|-------------|
| `Enabled`    | `bool` | `false` | Enable audit event dispatch |
| `BufferSize` | `int`  | 1024    | Async buffer capacity |
| `DropIfFull` | `bool` | `true`  | Drop events on overflow (vs block) |

> **See also:** [audit.md](audit.md)

## Metrics (`Config.Metrics`)

| Field                     | Type   | Default | Description |
|---------------------------|--------|---------|-------------|
| `Enabled`                 | `bool` | `false` | Enable counters |
| `EnableLatencyHistograms` | `bool` | `false` | Enable per-op histograms |

> **See also:** [metrics.md](metrics.md)

## Permission (`Config.Permission`)

| Field            | Type   | Default | Description |
|------------------|--------|---------|-------------|
| `MaxBits`        | `int`  | 64      | Bitmask width: 64, 128, 256, or 512 |
| `RootBitReserved`| `bool` | `true`  | Reserve bit 0 for super-admin |

> **See also:** [permission.md](permission.md)

## Multi-Tenant (`Config.MultiTenant`)

| Field             | Type   | Default         | Description |
|-------------------|--------|-----------------|-------------|
| `Enabled`         | `bool` | `false`         | Scopes every user lookup to the request tenant and requires the provider to implement `TenantAwareUserProvider` (`Build` fails otherwise). The single switch governing tenant enforcement — see [multi_tenancy.md](multi_tenancy.md) |
| `TenantHeader`    | `string`| `"X-Tenant-ID"`| **Deprecated, no-op** — never read by the engine or middleware; tenant scoping comes only from `WithTenantID(ctx)` (lint: `tenant_header_noop`) |
| `EnforceIsolation`| `bool` | `false`         | **Deprecated, no-op** — never gated anything; tenant enforcement is governed entirely by `Enabled` (lint: `tenant_enforce_isolation_noop`) |

## No-op sections: Cache (`Config.Cache`) and Database (`Config.Database`)

Both structs are accepted for backward compatibility but are **never read by the
engine**:

- `CacheConfig` (`LRUEnabled`, `Size`) — no in-memory session cache is
  implemented (lint: `cache_lru_noop`).
- `DatabaseConfig` — superseded by `Builder.WithRedis`, which is the only way
  Redis is wired (lint: `database_config_noop` when `Address` is set).

## Validation Mode (`Config.ValidationMode`)

| Mode       | Redis Commands | Use Case |
|------------|---------------|----------|
| `ModeJWTOnly` (1) | 0       | Stateless routes where revocation latency ≤ AccessTTL is acceptable |
| `ModeHybrid` (2)  | 0       | Engine default; behaves like JWT-only unless a route overrides to Strict |
| `ModeStrict` (3)  | 1 GET   | Immediate revocation required |

> Note: `ModeInherit` is `-1`; `ModeJWTOnly`/`ModeHybrid`/`ModeStrict` are `1`/`2`/`3`
> (the constant block assigns `iota` after the explicit `ModeInherit = -1`, so the
> zero value is **not** a valid mode). On the `Validate` hot path, `ModeHybrid`
> performs no Redis lookup by itself — it is identical to `ModeJWTOnly` unless the
> route is explicitly validated in `ModeStrict`.

## Config Validation

`Config.Validate()` is called automatically by `Builder.Build()`. It checks:

- AccessTTL > 0, RefreshTTL ≥ AccessTTL
- MaxSessionDuration ≥ 0; when set, ≥ 1 minute
- Signing keys present for Ed25519/RSA; key length ≥ 32 for HS256
- `VerifyKeys`: non-empty kids and key material; requires `KeyID`, which must name an entry; the entry under the signing kid must match the signing key (checked at `Build()`)
- Argon2 parameters within safe bounds
- Rate limiter durations > 0 when enabled
- LimiterWindowMode is `""`, `"fixed"`, or `"sliding"`
- Account.DefaultRole exists in role manager (checked by Builder)
- TOTP.Issuer non-empty when TOTP enabled
- MFA challenge TTL and attempt limits positive
- WebAuthn (when enabled): RPID/RPDisplayName/RPOrigins present, valid attestation and user-verification enums, CeremonyTTL within 10s–10m; `RequireForLogin` requires `Enabled`

## Config Linting

`Config.Lint()` returns non-fatal warnings for sub-optimal settings. Highlights:

- `access_ttl_long` (warn) — AccessTTL > 10 min widens the revocation window
- `not_production_mode` (info) — ProductionMode disabled
- `keyid_missing` (info) — Ed25519 signing without a `KeyID` (tokens carry no `kid`, complicating future key rotation)
- `max_session_duration_caps_default` (warn) — explicit MaxSessionDuration below the default session lifetime (caps all sessions)
- `max_session_duration_long` (warn) — effective session ceiling > 30 days
- `hybrid_enforcement_strict_routes_only` (info) — Hybrid mode with enforced device binding; enforcement runs only on `ModeStrict`-resolved routes
- `*_noop` codes — config knobs that are accepted but never read by the engine (see the field tables above)

The complete code list (25 codes: 8 INFO, 13 WARN, 4 HIGH) lives in
[config_lint.md](config_lint.md).

> **See also:** [config_lint.md](config_lint.md), [config-presets.md](config-presets.md)

## See Also

- [Engine](engine.md)
- [Flows](flows.md)
- [Security Model](security.md)
- [Architecture](architecture.md)
- [Config Presets](config-presets.md)
- Does not protect callers that bypass required verification sequencing.
