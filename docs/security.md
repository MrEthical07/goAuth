# Security Model

This document describes the security posture of goAuth: the threat model, mitigations, invariants, and scanner/baseline tooling.

For operational security settings, see [ops.md](ops.md). For configuration lint, see [config_lint.md](config_lint.md).

---

## 1. Threat Model Summary

goAuth assumes attackers may:

- **Obtain stolen access tokens** (XSS, network sniffing without TLS)
- **Replay refresh tokens** (client-side theft, MITM)
- **Brute-force credentials** (credential stuffing, dictionary attacks)
- **Send malformed authorization requests** (fuzzing, injection)
- **Enumerate accounts** (timing attacks, differential responses)
- **Hijack sessions** (IP/UA change after token theft)
- **Exploit clock skew** (pre-dated or far-future tokens)
- **Amplify resource usage** (large password DoS against Argon2)

---

## 2. Mitigations

### Authentication

| Attack | Mitigation | Invariant |
|--------|-----------|-----------|
| **Brute force** | 7-domain rate limiting + auto-lockout | Persistent failure counter across rate-limit windows |
| **Credential stuffing** | Per-IP + per-identifier throttling | `ErrLoginRateLimited` before password verify |
| **Password DoS** | `MaxPasswordBytes` (default 1024) | Reject before Argon2 |
| **Empty password oracle** | Dummy `Verify` call on empty-password path | Equalized response time |
| **User enumeration** | Fake challenges + 20–40ms random delay | Indistinguishable responses for unknown users |

### Token Security

| Attack | Mitigation | Invariant |
|--------|-----------|-----------|
| **JWT forgery** | Algorithm allowlist (Ed25519/HS256 only) | `kid` required when `VerifyKeys` configured |
| **Algorithm confusion** | Only configured algorithm accepted | Reject unexpected alg headers |
| **Clock skew exploitation** | `MaxFutureIAT` cap + `Leeway` ≤ 2 min | `ErrTokenClockSkew` on violations |
| **Stale tokens** | Version stamps (perm/role/account) in strict mode | Mismatch → session deleted |

### Session Security

| Attack | Mitigation | Invariant |
|--------|-----------|-----------|
| **Refresh replay** | Atomic Lua CAS rotation | Hash mismatch → session family destroyed |
| **Session fixation** | New session ID on every login | Unique `crypto/rand` 16-byte IDs |
| **Session hijacking** | IP + UA binding (enforce or detect) | `ErrDeviceBindingRejected` or anomaly audit |
| **Stale sessions** | Strict mode + version drift checks | Version mismatch → session deleted |

### MFA Security

| Attack | Mitigation | Invariant |
|--------|-----------|-----------|
| **TOTP brute force** | `TOTPLimiter` (configurable max attempts) | Rate-limited per user |
| **TOTP replay** | Counter tracking prevents same-step reuse | `MetricMFAReplayAttempt` on replay |
| **Backup code hijack** | Regeneration requires TOTP proof | Must verify TOTP to regenerate |
| **MFA bypass** | Challenge TTL + attempt limits | `ErrMFALoginExpired`/`AttemptsExceeded` |

### Cryptographic Guarantees

| Operation | Primitive | Property |
|-----------|----------|----------|
| Password hashing | Argon2id | Memory-hard, PHC format |
| Token signing | Ed25519 (default) | Asymmetric, no shared secret |
| TOTP codes | HMAC-SHA1/256/512 | RFC 6238 compliant |
| Secret comparison | `crypto/subtle.ConstantTimeCompare` | Timing-safe everywhere |
| Random generation | `crypto/rand` | Cryptographically secure |
| Binding hashes | SHA-256 | One-way, no plaintext stored |

---

## 3. Invariants Mapping

| # | Invariant | Enforced By | Test Coverage |
|---|-----------|------------|---------------|
| I1 | Validate must not allocate beyond Claims in JWT-only mode | `flows.RunValidate` | `auth_bench_test.go` |
| I2 | Refresh replay deletes session family | `session.Store.RotateRefreshHash` (Lua) | `refresh_concurrency_test.go` |
| I3 | Rate limiters fail open on Redis error (non-blocking) | `internal/rate`, `internal/limiters` | `engine_auto_lockout_test.go` |
| I4 | Strict mode fails closed on Redis unavailability | `flows.RunValidate` | `engine_session_hardening_test.go` |
| I5 | Permission registry frozen at Build time | `permission.Registry.Freeze` | `security_invariants_test.go` |
| I6 | Constant-time comparison on all secrets | All verify paths | `totp_rfc_test.go`, `engine_*_test.go` |
| I7 | No PII in metrics or audit payloads | Audit sanitization | `audit_test.go` |
| I8 | Account status checked before auth flow allows access | All login/validate paths | `engine_account_status_test.go` |

---

## 4. What Is NOT Mitigated

- **Client endpoint compromise** — malware with valid session context.
- **TLS enforcement** — goAuth does not terminate TLS; this must be handled externally.
- **Business-logic authorization** — permission *checks* are provided, but *defining* correct permissions is the caller's responsibility.
- **Multi-region consistency** — intentionally out of scope for v1.
- **OAuth/OIDC provider integration** — goAuth is a standalone auth engine, not an OAuth server.

---

## 5. Scanner Tooling

### gosec

```bash
bash security/run_scanners.sh
```

Runs `gosec` with exclusions from `security/gosec.excludes`:

| Exclusion | Reason |
|-----------|--------|
| G101 | False positives on constant names like `invalid_credentials` |
| G115 | High-noise integer conversion warnings in bounded code |
| G117 | Secret-pattern matches on exported fields (`AccessToken`) |

### govulncheck

```bash
govulncheck ./...
```

JSON mode with baseline enforcement. New stdlib CVEs fail the build.

### Baselines

- `security/baselines/gosec.allowlist`
- `security/baselines/govulncheck.allowlist`

All findings tracked in `SECURITY_FINDINGS.md`.

---

## 6. Security Configuration Checklist

- [ ] `Security.ProductionMode = true`
- [ ] `JWT.SigningMethod = MethodEd25519`
- [ ] `JWT.RequireIAT = true`
- [ ] `Security.EnableIPThrottle = true`
- [ ] `Security.EnableRefreshThrottle = true`
- [ ] `Security.AutoLockoutEnabled = true`
- [ ] `Audit.Enabled = true` with durable sink
- [ ] `Config.Lint()` returns no HIGH-severity warnings
- [ ] Redis uses `noeviction` policy
- [ ] TLS terminated externally (load balancer / ingress)

---

## See Also

- [ops.md](ops.md) — Deployment checklist and monitoring
- [config_lint.md](config_lint.md) — Config lint warning codes
- [config.md](config.md) — Full configuration reference
- [flows.md](flows.md) — Security invariants per flow
- [device-binding.md](device_binding.md) — IP/UA binding details
- [rate-limiting.md](rate_limiting.md) — Rate limiting architecture
- [concurrency-model.md](concurrency-model.md) — Thread-safety guarantees
- [password.md](password.md) — Argon2id parameters
