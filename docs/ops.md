# Operational Guidance

Production-readiness checklist and recommended operational settings for goAuth.

---

## 1. Recommended TTL Values

| Setting | Recommended | Range | Rationale |
|---------|------------|-------|-----------|
| `JWT.AccessTTL` | **5 min** | 1–15 min | Short-lived tokens limit exposure window. Production mode enforces ≤ 15 min. |
| `JWT.RefreshTTL` | **7 days** | 1–30 days | Matches session lifetime. HighSecurity preset uses 24 h. |
| `Session.AbsoluteSessionLifetime` | **7 days** | 1–30 days | Should match or exceed `RefreshTTL`. |
| `TOTP.MFALoginChallengeTTL` | **3 min** | 1–5 min | MFA challenge window must be tight. |
| `PasswordReset.ResetTTL` | **15 min** | 5–15 min | OTP mode enforces ≤ 15 min. |

**Rule of thumb:** `AccessTTL` × 2 < `RefreshTTL`. This ensures silent refresh can succeed even under worst-case clock skew.

---

## 2. JWT Leeway & IAT Settings

| Setting | Default | Recommended | Why |
|---------|---------|-------------|-----|
| `JWT.Leeway` | 30 s | **10–30 s** | Compensates for clock drift between services. >2 min is rejected by `Validate()`. |
| `JWT.RequireIAT` | false | **true** (prod) | Prevents pre-dated tokens. HighSecurity preset enables this. |
| `JWT.MaxFutureIAT` | 10 min | **5–10 min** | Caps how far in the future an `iat` claim can be. |

Keep leeway as small as your infrastructure allows. NTP-synced servers can safely use 5–10 s.

---

## 3. Redis Sizing & Eviction

See [capacity.md](capacity.md) for detailed byte-level calculations.

### Quick reference

| Metric | Value |
|--------|-------|
| Session blob size | ~80–180 bytes |
| Keys per session | 1 blob + 1 SET member + shared counter |
| 100K sessions | ~30–50 MB (including indexes) |
| 1M sessions | ~300–500 MB |

### Eviction policy

**Use `noeviction`** for the goAuth Redis instance. goAuth manages TTLs explicitly; evicted sessions would cause silent auth failures without audit trails.

If you share the Redis instance with caching workloads, use a separate database number or (better) a dedicated Redis instance for auth sessions.

### Connection pool

| Setting | Recommended |
|---------|-------------|
| `MaxConnections` | 25–50 |
| `MinConnections` | 5–10 |
| `ConnMaxLifetime` | 30 min |

Scale up connections if you observe Redis latency > 1 ms under sustained load.

---

## 4. Rate Limit Recommendations

| Setting | Default | Recommended (public) | Recommended (internal) |
|---------|---------|---------------------|----------------------|
| `Security.EnableIPThrottle` | false | **true** | true |
| `Security.MaxLoginAttempts` | 5 | **3–5** | 10 |
| `Security.LoginCooldownDuration` | 15 min | **15 min** | 5 min |
| `Security.EnableRefreshThrottle` | true | **true** | true |
| `Security.MaxRefreshAttempts` | 20 | **10–20** | 60 |
| `Security.RefreshCooldownDuration` | 1 min | **1–2 min** | 1 min |

For public-facing APIs, enable IP throttling unconditionally. For internal microservices behind a gateway, you may relax login limits but keep refresh throttling active.

---

## 5. Validation Mode Selection

| Mode | When to use | Redis cost |
|------|-------------|------------|
| `ModeJWTOnly` | Read-heavy, low-sensitivity routes (dashboards, search) | 0 ops |
| `ModeHybrid` (default) | Most applications; strict on sensitive routes | 0–1 ops/request |
| `ModeStrict` | Financial, healthcare, compliance-critical apps | 1 op/request |

Use per-route overrides: `middleware.Guard(engine, goAuth.ModeStrict)` for sensitive routes, `middleware.RequireJWTOnly(engine)` for lightweight ones.

---

## 6. Deployment Checklist

- [ ] Set `Security.ProductionMode = true`
- [ ] Use Ed25519 signing (default) — avoid HS256 unless required
- [ ] Pre-generate and securely store signing keys (don't rely on ephemeral keys)
- [ ] Set `noeviction` policy on Redis
- [ ] Enable `JWT.RequireIAT = true`
- [ ] Enable `Security.EnableIPThrottle = true` for public APIs
- [ ] Configure audit sink to durable storage
- [ ] Run `Config.Lint()` at startup and log warnings
- [ ] Set up monitoring on `MetricsSnapshot()` counters
- [ ] Load-test with `cmd/goauth-loadtest` before production

---

## 7. Monitoring Keys

| Metric | Alert threshold | Meaning |
|--------|----------------|---------|
| `MetricRefreshReuseDetected` | > 0 | Possible token theft — investigate immediately |
| `MetricLoginRateLimited` | sustained high | Brute-force attempt |
| `MetricDeviceRejected` | spike | Session hijacking attempt |
| `AuditDropped()` | > 0 | Audit buffer overflow — increase `Audit.BufferSize` |

---

## 8. Config Linting

Call `Config.Lint()` at startup to catch "valid but dangerous" configurations:

```go
cfg := goAuth.DefaultConfig()
// ... customize ...
if warnings := cfg.Lint(); len(warnings) > 0 {
    for _, w := range warnings {
        log.Printf("CONFIG WARNING: %s", w)
    }
}
```

`Lint()` checks include: excessive leeway, long access TTLs, JWT-only mode with device binding, disabled rate limiting on public endpoints, and more. Unlike `Validate()`, `Lint()` never returns an error — only advisory warnings.
