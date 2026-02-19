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

> **See also:** [jwt.md](jwt.md)

## Session (`Config.Session`)

| Field                     | Type          | Default | Description |
|---------------------------|---------------|---------|-------------|
| `RedisPrefix`             | `string`      | `"as"`  | Redis key namespace prefix |
| `SlidingExpiration`       | `bool`        | `true`  | Extend TTL on each access |
| `AbsoluteSessionLifetime` | `time.Duration`| 7 days | Hard session lifetime cap |
| `JitterEnabled`           | `bool`        | `true`  | Add random jitter to TTLs |
| `JitterRange`             | `time.Duration`| 30 s   | ±jitter window |
| `MaxSessionSize`          | `int`         | `512`   | Max encoded session bytes |
| `SessionEncoding`         | `string`      | `"binary"` | `"binary"` (v5) or `"msgpack"` |

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
| `EnableIPBinding`              | `bool`        | `false`      | Bind sessions to client IP |
| `EnableUserAgentBinding`       | `bool`        | `true`       | Bind sessions to User-Agent |
| `EnableIPThrottle`             | `bool`        | `false`      | Per-IP login rate limiting |
| `EnableRefreshThrottle`        | `bool`        | `true`       | Per-session refresh rate limiting |
| `EnforceRefreshRotation`       | `bool`        | `true`       | Require token rotation on refresh |
| `EnforceRefreshReuseDetection` | `bool`        | `true`       | Invalidate session on token reuse |
| `MaxLoginAttempts`             | `int`         | 5            | Failed logins before cooldown |
| `LoginCooldownDuration`        | `time.Duration`| 15 min      | Cooldown after max login attempts |
| `MaxRefreshAttempts`           | `int`         | 20           | Refresh attempts before cooldown |
| `RefreshCooldownDuration`      | `time.Duration`| 1 min       | Cooldown after max refresh attempts |
| `StrictMode`                   | `bool`        | `false`      | Force strict validation globally |
| `EnablePermissionVersionCheck` | `bool`        | `true`       | Check permission version on validate |
| `EnableRoleVersionCheck`       | `bool`        | `true`       | Check role version on validate |
| `EnableAccountVersionCheck`    | `bool`        | `true`       | Check account version on validate |
| `AutoLockoutEnabled`           | `bool`        | `false`      | Auto-lock after repeated failures |
| `AutoLockoutThreshold`         | `int`         | 10           | Failures before auto-lock |
| `AutoLockoutDuration`          | `time.Duration`| 30 min      | Duration of auto-lock |

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

## Password Reset (`Config.PasswordReset`)

| Field                    | Type              | Default         | Description |
|--------------------------|-------------------|----------------|-------------|
| `Enabled`                | `bool`            | `false`        | Enable password reset flow |
| `Strategy`               | `ResetStrategyType`| `ResetToken`  | `ResetToken`, `ResetOTP`, or `ResetUUID` |
| `ResetTTL`               | `time.Duration`   | 15 min         | Challenge lifetime |
| `MaxAttempts`            | `int`             | 5              | Max confirm attempts per challenge |
| `EnableIPThrottle`       | `bool`            | `true`         | Per-IP rate limiting |
| `EnableIdentifierThrottle` | `bool`          | `true`         | Per-identifier rate limiting |
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
| `EnableIPThrottle`       | `bool`                  | `true`             | Per-IP rate limiting |
| `EnableIdentifierThrottle` | `bool`                | `true`             | Per-identifier rate limiting |
| `OTPDigits`              | `int`                   | 6                  | OTP digit count |

> **See also:** [email_verification.md](email_verification.md)

## Account (`Config.Account`)

| Field                          | Type          | Default  | Description |
|--------------------------------|---------------|---------|-------------|
| `Enabled`                      | `bool`        | `true`  | Enable account creation |
| `AutoLogin`                    | `bool`        | `false` | Issue tokens on creation |
| `DefaultRole`                  | `string`      | `""`    | Role assigned to new accounts |
| `AccountCreationMaxAttempts`   | `int`         | 5       | Rate limit attempts |
| `AccountCreationCooldown`      | `time.Duration`| 15 min | Cooldown period |
| `EnableIPThrottle`             | `bool`        | `true`  | Per-IP rate limiting |
| `EnableIdentifierThrottle`     | `bool`        | `true`  | Per-identifier rate limiting |

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
| `Enabled`         | `bool` | `false`         | Enable tenant isolation |
| `TenantHeader`    | `string`| `"X-Tenant-ID"`| HTTP header for tenant ID |
| `EnforceIsolation`| `bool` | `true`          | Strict tenant boundary enforcement |

## Validation Mode (`Config.ValidationMode`)

| Mode       | Redis Commands | Use Case |
|------------|---------------|----------|
| `ModeJWTOnly` (0) | 0       | Stateless routes where revocation latency ≤ AccessTTL is acceptable |
| `ModeHybrid` (1)  | 0–1     | Default balanced mode |
| `ModeStrict` (2)  | 1 GET   | Immediate revocation required |

## Config Validation

`Config.Validate()` is called automatically by `Builder.Build()`. It checks:

- AccessTTL > 0, RefreshTTL ≥ AccessTTL
- Signing keys present for Ed25519/RSA; key length ≥ 32 for HS256
- Argon2 parameters within safe bounds
- Rate limiter durations > 0 when enabled
- Account.DefaultRole exists in role manager (checked by Builder)
- TOTP.Issuer non-empty when TOTP enabled
- MFA challenge TTL and attempt limits positive

## Config Linting

`Config.Lint()` returns non-fatal warnings for sub-optimal settings:

- AccessTTL > 15 min (wide revocation window)
- ProductionMode disabled (warning only)
- Missing KeyID (complicates key rotation)
- Backup code count < 5

> **See also:** [config_lint.md](config_lint.md), [config-presets.md](config-presets.md)

## See Also

- [Engine](engine.md)
- [Flows](flows.md)
- [Security Model](security.md)
- [Architecture](architecture.md)
- [Config Presets](config-presets.md)
- Does not protect callers that bypass required verification sequencing.
