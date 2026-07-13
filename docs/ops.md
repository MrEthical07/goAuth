# Operational Guidance

Production-readiness checklist and recommended operational settings for goAuth.

---

## 1. Recommended TTL Values

| Setting | Recommended | Range | Rationale |
|---------|------------|-------|-----------|
| `JWT.AccessTTL` | **5 min** | 1–15 min | Short-lived tokens limit exposure window. Production mode enforces ≤ 15 min. |
| `JWT.RefreshTTL` | **7 days** | 1–30 days | Matches session lifetime. HighSecurity preset uses 24 h. |
| `Session.AbsoluteSessionLifetime` | **7 days** | 1–30 days | Should match or exceed `RefreshTTL`. |
| `Session.MaxSessionDuration` | **unset** (mode default) | 1–30 days | Absolute session ceiling; governs remember-me. Unset resolves to 24 h (Strict) / 7 d (Hybrid, JWTOnly), never below the default lifetime. |
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
| `Security.EnableLoginFailureLimiter` | true | **true** | true |
| `Security.MaxLoginAttempts` | 5 | **3–5** | 10 |
| `Security.LoginCooldownDuration` | 15 min | **15 min** | 5 min |

For public-facing APIs, keep the login failure limiter enabled unconditionally. For internal microservices behind a gateway, you may relax login thresholds but should keep limiter enforcement on.

---

## 5. Validation Mode Selection

| Mode | When to use | Redis cost |
|------|-------------|------------|
| `ModeJWTOnly` | Read-heavy, low-sensitivity routes (dashboards, search) | 0 ops |
| `ModeHybrid` (default) | Most applications; stateless by default, strict on sensitive routes | 0 ops (Hybrid-resolved routes); 1 op on `ModeStrict` routes |
| `ModeStrict` | Financial, healthcare, compliance-critical apps | 1 op/request |

Use per-route overrides: `middleware.Guard(engine, goAuth.ModeStrict)` for sensitive routes, `middleware.RequireJWTOnly(engine)` for lightweight ones.

---

## 6. Deployment Checklist

- [ ] Set `Security.ProductionMode = true`
- [ ] Use Ed25519 signing (default) — avoid HS256 unless required
- [ ] Pre-generate and securely store signing keys (don't rely on ephemeral keys)
- [ ] Set `JWT.KeyID` + `JWT.VerifyKeys` from day one so future key rotations need no flag day (see §9)
- [ ] Set `noeviction` policy on Redis
- [ ] Enable `JWT.RequireIAT = true`
- [ ] Keep `Security.EnableLoginFailureLimiter = true` for public APIs
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

`Lint()` checks include: excessive leeway, long access TTLs, JWT-only mode with device binding, disabled login-failure limiting, and more. Unlike `Validate()`, `Lint()` never returns an error — only advisory warnings.

---

## 9. Ed25519 Key-Rotation Runbook

goAuth verifies tokens against `JWT.VerifyKeys` (a `kid → public key` map) when it is
set, so rotation is a config-driven overlap: verify old + new keys while flipping which
key signs. Each step is a config change + rolling restart — keys are immutable after
`Build()`, by design. There is no downtime and no token rejection during the overlap.

### Baseline (do this before you ever need to rotate)

Deploy every instance with an explicit key ID from day one:

```go
cfg.JWT.PrivateKey = k1Priv
cfg.JWT.PublicKey  = k1Pub
cfg.JWT.KeyID      = "k1"                       // e.g. goauth-keygen fingerprint
cfg.JWT.VerifyKeys = map[string][]byte{"k1": k1Pub}
```

Tokens now carry a `kid` header. `Config.Lint()` emits `keyid_missing` (info) when an
Ed25519 config has no `KeyID`.

### Ceremony

1. **Generate the new key.** `go run ./cmd/goauth-keygen` prints a keypair plus a
   suggested kid (a stable public-key fingerprint), or call
   `jwt.GenerateEd25519Key()` / `jwt.Ed25519KeyFingerprint()` from provisioning code.
2. **Introduce k2 as verify-only.** Roll out **all** instances with
   `VerifyKeys: {"k1": k1Pub, "k2": k2Pub}`, still signing with k1
   (`KeyID: "k1"`). Wait until every instance runs this config — an instance that
   cannot verify k2 yet must never receive a k2-signed token.
3. **Flip signing to k2.** Roll out `PrivateKey: k2Priv`, `PublicKey: k2Pub`,
   `KeyID: "k2"`, keeping `VerifyKeys: {"k1": ..., "k2": ...}`. During the rollout both
   generations mint valid tokens and every instance verifies both keys.
4. **Retire k1.** After at least `AccessTTL + Leeway` has elapsed since the last
   instance stopped signing with k1 (every k1 access token has expired), remove `"k1"`
   from `VerifyKeys`. Refresh tokens are opaque and key-independent — only the access-token
   lifetime gates retirement. From now on k1 tokens fail verification (`unknown kid`).

### Rollback

Steps 2 and 3 are independently reversible: reverting the config restores the previous
behavior because the retiring key stays in `VerifyKeys` until step 4. After step 4,
re-adding `"k1"` to `VerifyKeys` re-accepts stragglers (harmless if the key was not
compromised).

**Compromised key:** skip the overlap. Remove the compromised kid from `VerifyKeys` and
flip signing in a single deploy; in-flight tokens signed with it are rejected immediately
(by design). Clients recover via refresh, which issues tokens under the new key.

### First rotation for fleets without `kid`

Tokens minted before `KeyID` was set carry no `kid` header, and once `VerifyKeys` is
configured the parser rejects kid-less tokens. Adopt the baseline config first (set
`KeyID` + single-entry `VerifyKeys`), wait one full `AccessTTL + Leeway` for kid-less
tokens to expire, then run the ceremony above.

### Guardrails (enforced at `Build()`)

- `VerifyKeys` set with an empty `KeyID` is rejected — the engine would mint kid-less
  tokens that fail its own verification.
- `KeyID` must name an entry in `VerifyKeys`, and that entry must match the signing key
  (derived-public-key comparison), so a rotation typo cannot ship an engine that rejects
  every token it issues.
- Every `VerifyKeys` entry must be a valid Ed25519 public key (raw or PEM); kids must be
  non-empty.
