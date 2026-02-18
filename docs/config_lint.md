# Module: Config Lint

## Purpose

Static analysis of `Config` values to detect contradictions, sub-optimal settings, and security misconfigurations before engine startup.

## Primitives

### Severity Levels

```go
type LintSeverity int

const (
    LintInfo LintSeverity = iota  // Advisory
    LintWarn                       // Sub-optimal
    LintHigh                       // Contradiction / security risk
)
```

### LintWarning

```go
type LintWarning struct {
    Code     string
    Severity LintSeverity
    Message  string
}
```

### LintResult

```go
type LintResult []LintWarning

func (lr LintResult) AsError(minSeverity LintSeverity) error   // non-nil if warnings ≥ minSeverity
func (lr LintResult) BySeverity(minSeverity LintSeverity) LintResult
func (lr LintResult) Codes() []string
```

### Entry Point

```go
func (c *Config) Lint() LintResult
```

## Warning Codes

| Code | Severity | Condition |
|------|----------|-----------|
| `leeway_large` | WARN | `JWT.Leeway > 1m` |
| `access_ttl_long` | WARN | `JWT.AccessTTL > 10m` |
| `refresh_ttl_long` | INFO | `JWT.RefreshTTL > 14d` |
| `iat_not_required` | INFO | `JWT.RequireIAT == false` |
| `signing_hs256` | WARN | `JWT.SigningMethod == "hs256"` |
| `jwtonly_device_binding` | HIGH | JWT-only mode + device binding enabled |
| `jwtonly_single_session` | HIGH | JWT-only mode + single-session enforcement |
| `jwtonly_perm_version` | WARN | JWT-only mode + permission version check |
| `rate_limits_disabled` | HIGH | Both IP + refresh throttle off |
| `ip_throttle_disabled` | WARN | IP throttle off |
| `session_lifetime_long` | WARN | Absolute session lifetime > 30 days |
| `session_shorter_than_refresh` | HIGH | Session lifetime < refresh TTL |
| `not_production_mode` | INFO | Production mode not enabled |
| `audit_disabled` | WARN | Audit disabled |
| `totp_skew_wide` | WARN | TOTP skew > 1 |
| `argon2_memory_low` | WARN | Argon2 memory < 64 MB |

Summary: 3 INFO, 9 WARN, 4 HIGH.

## Examples

```go
result := cfg.Lint()

// Fail CI on any HIGH-severity issue
if err := result.AsError(goAuth.LintHigh); err != nil {
    log.Fatal(err)
}

// Log WARN and above
for _, w := range result.BySeverity(goAuth.LintWarn) {
    log.Printf("[%s] %s: %s", w.Severity, w.Code, w.Message)
}
```

## Security Notes

- `AsError(LintHigh)` is the recommended CI gate — prevents deployment of contradictory configs.
- HIGH-severity warnings indicate settings that silently break security guarantees (e.g., device binding is ignored in JWT-only mode).
