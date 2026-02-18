# Configuration Presets

goAuth provides three convenience presets so new deployments can start from a
safe baseline and then override only what they need.

## Presets

### `goAuth.DefaultConfig()`

Security-oriented baseline:

- Validation mode: `ModeHybrid`
- Signing method: `ed25519` (ephemeral keypair generated per config call)
- Refresh rotation/reuse detection: enabled
- Sliding session expiration: enabled
- Account creation flow: disabled by default

Use this when you want baseline-safe defaults and plan to tune only a few
fields.

### `goAuth.HighSecurityConfig()`

Tighter posture for security-sensitive APIs:

- Validation mode: `ModeStrict`
- `Security.ProductionMode`: enabled
- JWT hardening: `RequireIAT=true`, shorter refresh/session lifetime
- Login/refresh rate limits: tighter thresholds
- Device binding: enabled with user-agent enforcement + anomaly detection

Use this when immediate revocation and strict backend verification are required.

### `goAuth.HighThroughputConfig()`

Higher sustained throughput posture while preserving security invariants:

- Validation mode: `ModeHybrid`
- `Security.ProductionMode`: enabled
- Longer access/refresh/session lifetimes to reduce churn
- Login IP throttle disabled (refresh throttle remains enabled)

Use route-level `ModeJWTOnly` for endpoints where immediate revocation is not
required and latency budget is critical.

## Overrides

Presets return a regular `Config`; fields can be overridden before passing to
`Builder.WithConfig`.

```go
cfg := goAuth.HighSecurityConfig()
cfg.JWT.AccessTTL = 3 * time.Minute
cfg.Security.MaxLoginAttempts = 2
```
