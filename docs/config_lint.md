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
| `keyid_missing` | INFO | Ed25519 signing with empty `JWT.KeyID` (tokens carry no `kid`; complicates future key rotation) |
| `jwtonly_device_binding` | HIGH | JWT-only mode + device binding enabled |
| `jwtonly_single_session` | HIGH | JWT-only mode + single-session enforcement |
| `jwtonly_perm_version` | WARN | JWT-only mode + permission version check |
| `hybrid_enforcement_strict_routes_only` | INFO | Hybrid mode + enforced device binding (enforcement runs only on Strict-resolved routes) |
| `login_failure_limiter_disabled` | HIGH | `Security.EnableLoginFailureLimiter == false` |
| `session_lifetime_long` | WARN | Absolute session lifetime > 30 days |
| `session_shorter_than_refresh` | HIGH | Session lifetime < refresh TTL |
| `max_session_duration_caps_default` | WARN | Explicit `MaxSessionDuration` below the default session lifetime (caps all sessions) |
| `max_session_duration_long` | WARN | Effective session ceiling > 30 days |
| `not_production_mode` | INFO | Production mode not enabled |
| `audit_disabled` | WARN | Audit disabled |
| `totp_skew_wide` | WARN | TOTP skew > 1 |
| `argon2_memory_low` | WARN | Argon2 memory < 64 MB |
| `security_ip_binding_noop` | WARN | `Security.EnableIPBinding` is set but never read (use `DeviceBinding.*`) |
| `security_ip_signal_noop` | WARN | `Security.EnableIPSignal` is set but never read |
| `cookie_settings_noop` | INFO | `RequireSecureCookies`/`SameSitePolicy`/`CSRFProtection` set; the engine never issues cookies |
| `cache_lru_noop` | WARN | `Cache.LRUEnabled` is set but no in-memory session cache is implemented |
| `database_config_noop` | INFO | `Database.Address` is set but `DatabaseConfig` is never read (use `Builder.WithRedis`) |
| `tenant_header_noop` | INFO | `MultiTenant.TenantHeader` is set with multi-tenancy enabled but is never read (tenant comes from `WithTenantID(ctx)`) |

Summary: 8 INFO, 13 WARN, 4 HIGH.

### No-op knob warnings

Several config fields are accepted for backward compatibility but are not read
by the engine (`Security.EnableIPBinding`, `Security.EnableIPSignal`, the
cookie/CSRF knobs, `CacheConfig`, `DatabaseConfig`, `MultiTenant.TenantHeader`).
The `*_noop` lint codes fire when such a knob is enabled so integrators do not
assume a protection is active. They will be removed or wired up in a future
major/minor release; see `docs/config.md` for per-field notes.

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
