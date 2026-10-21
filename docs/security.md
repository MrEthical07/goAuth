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
| **Long-lived signing keys** | `JWTConfig.VerifyKeys` overlap rotation ([ops.md §9](ops.md#9-ed25519-key-rotation-runbook)) | Signing kid must match its verify key at `Build()`; unknown/missing `kid` rejected |

### Session Security

| Attack | Mitigation | Invariant |
|--------|-----------|-----------|
| **Refresh replay** | Atomic Lua CAS rotation | Hash mismatch → session family destroyed |
| **Session fixation** | New session ID on every login | Unique `crypto/rand` 16-byte IDs |
| **Session hijacking** | IP + UA binding (enforce or detect) | `ErrDeviceBindingRejected` or anomaly audit |
| **Stale sessions** | Strict mode + version drift checks | Version mismatch → session deleted |
| **Stale role after a role switch** | Atomic session swap; old refresh token dead immediately | Old access token rejected at once on `ModeStrict` routes only; on Hybrid/JWT-only it lives until it expires (≤ `JWT.AccessTTL`) — see [role_switching.md](role_switching.md#revocation-guarantee-per-validation-mode) |

> **Route-mode overrides are not bounded by the engine mode.** An explicit per-route
> mode (`Validate(ctx, token, ModeJWTOnly)` / `ModeHybrid`, or the corresponding
> middleware) always wins over the engine default, including on a `ModeStrict` engine —
> such routes skip Redis-backed revocation, version, status, and device checks until
> the access token expires. Route modes are chosen in code and are never influenced by
> the request, so this is a deliberate developer decision; audit route-mode overrides
> like any other authorization rule.

> **Role switching is only safe on `ModeStrict` routes.** Hybrid and JWT-only validation never read Redis, whether Redis is healthy or not, so an access token minted before a switch keeps its old mask there until it expires. Every route that gates on role or permissions must resolve to `ModeStrict`; an explicit per-route `ModeStrict` on a hybrid engine is enough. Full table and race semantics: [role_switching.md](role_switching.md).

### MFA Security

| Attack | Mitigation | Invariant |
|--------|-----------|-----------|
| **TOTP brute force** | `TOTPLimiter` (configurable max attempts) | Rate-limited per user |
| **TOTP replay** | Counter tracking prevents same-step reuse | `MetricMFAReplayAttempt` on replay |
| **Backup code hijack** | Regeneration requires TOTP proof | Must verify TOTP to regenerate |
| **MFA bypass** | Challenge TTL + attempt limits | `ErrMFALoginExpired`/`AttemptsExceeded` |

### External Identity (Google, Sign in with Apple, OIDC)

Only when `ExternalAuth` is enabled. Full treatment: [external_identity.md](external_identity.md).

| Attack | Mitigation | Invariant |
|--------|-----------|-----------|
| **Forged or tampered ID token** | Signature verified against the provider's published key set; algorithm allow-list (RS256/384/512, ES256/384; never `none` or `HS*`); the key's `kty`, `use`, `alg` and `key_ops` must agree with the token | A token that cannot be verified is never accepted; the algorithm-confusion token (HMAC keyed with the public key) is rejected |
| **Token for another app** | `iss` and `aud` must match the provider's configuration; an `aud` list needs an `azp` that is a configured client | Only configured client IDs |
| **Token replay / capture** | Required nonce (raw or SHA-256, constant-time compare), `exp`/`iat`/`nbf` against the server clock, single use recorded with `SET NX` | A token works once; a rejected token never consumes the record; the record is keyed on the signed part so a malleated signature is not a second use |
| **Account pre-hijacking** | Linking by email needs the provider's **verified** email, a local account that proved its own address (`EmailVerification` required for auto-link), and Active status; a pending account is never linked, by email or by `LinkExternalIdentity` | An unverified email is never used to link or create |
| **Cross-tenant identity** | Identity lookups and links carry the request tenant; record-tenant backstop on provider results | An identity of tenant A is unknown in tenant B |
| **Key-fetch abuse (SSRF-ish, storms)** | Keys come only from the configured https URL; redirects to non-https are refused; 1 MB cap; unknown `kid` triggers at most one refetch per `KeyRefreshMin`; failure back-off; single flight | Random key IDs cannot make the server fetch repeatedly |
| **Stale-key trust during an outage** | `KeyMaxStale` bounds how long cached keys keep verifying; lint warns above 72h | After it, `ErrExternalProviderUnavailable`; nothing is accepted unverified |
| **Junk-token flood** | Per-IP limit before verification (needs `WithClientIP`; no shared bucket without one, which anyone could exhaust), per-identity limit after | `ErrExternalLoginRateLimited`; both reset on success |
| **Timing oracle for password-less accounts** | Password login against an account with no password runs a dummy Argon2 verification and takes the wrong-password path | Same cost, error, limiter and lockout as a wrong password |
| **Token or nonce leakage** | Never written to audit events, logs or Redis keys (only a hash of the signed part) | Asserted by test over audit output, logs and keys |

What goAuth does **not** do: run the OAuth2 code exchange, store provider tokens, revoke Apple tokens on account deletion, or require a step-up before link/unlink (the application should, using `VerifyPassword` or a recent MFA).

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

## 4. Public Error Boundary

All exported `Engine` methods enforce a canonical error boundary.

- Public failures are returned as `*AuthError` only.
- Error categories are normalized to `AUTH_ABUSE`, `AUTH_STATE`, `AUTH_VALIDATION`, and `SYSTEM`.
- Wrapped/internal dependency errors are mapped to stable public sentinels.
- Unknown internal failures collapse to `SYSTEM_INTERNAL_ERROR`.
- Dependency and timeout-style failures map to `SYSTEM_UNAVAILABLE` (or domain-specific `SYSTEM_UNAVAILABLE_*`).

This hard boundary prevents leaking raw internal errors while preserving `errors.Is` compatibility for callers.

See [error-model.md](error-model.md) for the full registry and mapping behavior.

---

## 5. What Is NOT Mitigated

- **Client endpoint compromise** — malware with valid session context.
- **TLS enforcement** — goAuth does not terminate TLS; this must be handled externally.
- **Business-logic authorization** — permission *checks* are provided, but *defining* correct permissions is the caller's responsibility.
- **Multi-region consistency** — intentionally out of scope for v1.
- **OAuth server / full OAuth2 client flows** — goAuth is a standalone auth engine, not an OAuth server. It verifies OIDC ID tokens you already obtained ([external_identity.md](external_identity.md)); the authorization-code exchange, PKCE, redirects and provider token storage or revocation are out of scope.

---

## 6. Scanner Tooling

### gosec

```bash
bash security/run_scanners.sh
```

Runs `gosec` with exclusions from `security/gosec.excludes`:

| Exclusion | Reason |
|-----------|--------|
| G101 | False positives on constant names like `AUTH_INVALID_CREDENTIALS` |
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

## 7. Security Configuration Checklist

- [ ] `Security.ProductionMode = true`
- [ ] `JWT.SigningMethod = MethodEd25519`
- [ ] `JWT.RequireIAT = true`
- [ ] `Security.EnableLoginFailureLimiter = true`
- [ ] `Security.EnforceRefreshRotation = true`
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
