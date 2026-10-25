# Module: Rate Limiting

## Purpose

Multi-layer, Redis-backed rate limiting for every security-sensitive flow. Two packages cooperate:

| Package | Scope |
|---------|-------|
| `internal/rate` | Login-failure limiter (tenant + identifier scoped) |
| `internal/limiters` | Per-flow domain limiters (account, backup-code, email-verification, TOTP, password-reset, lockout) |
| `internal/window` | Shared window-counting primitive (fixed or sliding) consumed by every limiter |

## Primitives

### internal/rate — Core Limiter

```go
func New(redisClient redis.UniversalClient, cfg Config) *Limiter
```

| Method | Signature |
|--------|-----------|
| `CheckLogin` | `(ctx, tenantID, identifier string) error` |
| `IncrementLogin` | `(ctx, tenantID, identifier string) error` |
| `ResetLogin` | `(ctx, tenantID, identifier string) error` |
| `GetLoginAttempts` | `(ctx, tenantID, identifier string) (int, error)` |

**Config:**

| Field | Type |
|-------|------|
| `EnableLoginFailureLimiter` | `bool` |
| `MaxLoginAttempts` | `int` |
| `LoginCooldownDuration` | `time.Duration` |
| `WindowMode` | `window.Mode` (zero value = fixed) |

### internal/limiters — Domain Limiters

| Limiter | Constructor | Key Methods |
|---------|-------------|-------------|
| `AccountCreationLimiter` | `NewAccountCreationLimiter(redis, cfg)` | `Enforce(ctx, tenantID, identifier)` |
| `BackupCodeLimiter` | `NewBackupCodeLimiter(redis, cfg)` | `Check`, `RecordFailure`, `Reset` |
| `EmailVerificationLimiter` | `NewEmailVerificationLimiter(redis, cfg)` | `CheckRequest`, `CheckConfirm` |
| `TOTPLimiter` | `NewTOTPLimiter(redis, cfg)` | `Check`, `RecordFailure`, `Reset` |
| `PasswordResetLimiter` | `NewPasswordResetLimiter(redis, cfg)` | `CheckRequest`, `CheckConfirm`, `Cooldown()` |

All limiters are nil-safe — calling a method on a nil receiver returns `nil`.

### Per-IP login throttle

`Security.LoginIPLimiter` (`Enabled`, `MaxAttempts`, `Cooldown`; **off by default**) adds a budget per
(tenant, client IP) in front of the identifier and account budgets. The address is the one the host puts in the
context with `WithClientIP`; it is canonicalized (port and zone dropped, an IPv4-mapped IPv6 form unmapped, an
IPv6 address grouped by its /64, the unit one subscriber is normally given) and hashed into the key
(`rl:login:ip:{tenant}:{ip}`), and an attempt with no address in its context is not counted. A slot is claimed before anything else is done for the attempt, so an
address that has used up its budget cannot also burn the budgets of the identifiers it names. A login whose
password is right gives its slot back, so the count is the failures per address within `Cooldown`, and a good
login cannot be used to refill the budget of an address that is still guessing. It honors
`Security.LimiterWindowMode` and `Security.LimiterFailClosed`.

Two things the library cannot decide for you: the address is only as trustworthy as the way your proxy chain
derives it (never take it from a header the caller can set), and every user behind one NAT or proxy shares a
budget, so size `MaxAttempts` for the busiest shared address you serve. `Config.Lint()` notes
(`login_ip_limiter_disabled`, INFO) while the throttle is off.

### Policy Controls (Optional vs Failure-Based)

| Flow | Request Limiter Toggle | Failure Limiter Toggle |
|------|-------------------------|-------------------------|
| Login | n/a | `Security.EnableLoginFailureLimiter` |
| Account creation | `Account.EnableCreationLimiter` | n/a |
| Password reset | `PasswordReset.EnableRequestLimiter` | `PasswordReset.EnableConfirmFailureLimiter` |
| Email verification | `EmailVerification.EnableRequestLimiter` | `EmailVerification.EnableConfirmFailureLimiter` |
| TOTP | n/a | always-on path via `TOTP.MFALoginMaxAttempts` budget |
| Backup code | n/a | always-on path via `TOTP.BackupCodeMaxAttempts` budget |

### Errors

| Error | Source |
|-------|--------|
| `ErrRateLimited` | Core limiter |
| `ErrRedisUnavailable` | Core limiter |
| `ErrAccountRateLimited` | Account limiter |
| `ErrBackupCodeRateLimited` | Backup-code limiter |
| `ErrVerificationRateLimited` | Email limiter |
| `ErrTOTPRateLimited` | TOTP limiter |
| `ErrResetRateLimited` | Password-reset limiter |

## Strategies

Every limiter counts through the shared `internal/window` primitive, which supports two
algorithms selected engine-wide by `Security.LimiterWindowMode`:

| Algorithm | Config value | Mechanics | Boundary behavior |
|-----------|--------------|-----------|-------------------|
| Fixed window (default) | `""` or `"fixed"` | Atomic Lua: `INCR` + first-hit `PEXPIRE` on one counter key | Up to 2× the limit across a window boundary |
| Sliding window | `"sliding"` | Atomic Lua over two bucket counters (bucket length = the window); effective count = `curr + floor(prev × (window − elapsed)/window)` | Boundary burst removed (small one-sided approximation error) |

The sliding algorithm is a weighted two-bucket approximation: O(1) memory per
identifier, one script call per check/increment, no event log to inflate. Bucket keys
are `{<base key>}:s:<bucket>` (hash-tagged so both buckets share a Redis Cluster slot)
with a TTL of 2× the window. Bucket indexes derive from the application host clock —
keep hosts NTP-synced.

Redis key prefixes:

| Prefix | Scope |
|--------|-------|
| `rl:login:fail:{tenant}:{identifier}` | Login failure counter |

Domain limiters also use explicit tenant-scoped `rl:*` key namespaces. In sliding mode
the counters live in `{<key>}:s:<bucket>` sub-keys of the same namespaces.

## Security Notes

- Each domain limiter uses separate `Unavailable` errors so callers can distinguish Redis failures from policy rejections.
- Disabling login-failure limiting triggers a HIGH-severity config lint warning (`login_failure_limiter_disabled`).
- Engine runtime wrappers apply **fail-open** behavior for limiter backend failures by default, while still honoring explicit rate-limit denials. `Security.LimiterFailClosed` turns that around; see [Failing closed](#failing-closed).

### Failing closed

By default a limiter backend error (Redis down, a script error, a timeout) never
blocks a request: it is recorded as a `limiter_fail_open` audit event (and the
`MetricLimiterFailOpen` counter) and the request proceeds unthrottled. Set
`Security.LimiterFailClosed = true` to refuse instead. An explicit rate-limit
denial blocks either way; only the meaning of an outage changes.

With the flag on, every limiter *check or count* that gates a request returns a
system error (category `SYSTEM`, HTTP 503), and the request is not processed:

| Path | Error returned on a limiter outage |
|------|------------------------------------|
| `Login` family (failure check and counting), role-switch, `VerifyPassword`, `ChangePassword`, external sign-in (both buckets) | `ErrSystemUnavailable` (`SYSTEM_UNAVAILABLE`) |
| `CreateAccount`, external sign-up | `ErrAccountCreationUnavailable` |
| Email verification request and confirm | `ErrEmailVerificationUnavailable` |
| Password reset request and confirm | `ErrPasswordResetUnavailable` |
| TOTP checks and failure counting | `ErrTOTPUnavailable` |
| Backup-code checks and failure counting | `ErrBackupCodeUnavailable` |
| `RequestEmailChange` | `ErrSystemUnavailable` |

The domain-specific codes are the ones those flows already return when their
store or limiter is unavailable; they are the same category, so a client that
maps `CategorySystem` to 503 needs nothing extra. The `limiter_fail_open` event
keeps its name and gains `fail_closed=true` (and `policy=fail_closed`) metadata;
with the flag off the event is unchanged. `Config.Lint` reports
`limiter_fail_closed_outage_blocks_signin` (INFO) while it is on.

What it does not cover: a limiter *reset* after a request already succeeded only
removes counts, so a failed reset never blocks; the auto-lockout counter
(`Security.AutoLockoutEnabled`) is a separate mechanism that also tolerates a
Redis error; WebAuthn assertions have no limiter of their own. A static test
(`TestLimiterCallSitesAreClassifiedAndRouteThroughTheCentralHelper`) lists every
limiter call site and fails when a new one is not routed through the single
helper that applies this flag.

Turn it on when throttling matters more than availability: with it on, a Redis
outage blocks sign-in (it already blocks anything that needs a session store).

### Fixed-Window Boundary Burst

The default **fixed-window** algorithm allows up to **2× the configured limit** at window boundaries:

```
Window A (60s)          Window B (60s)
   ───────────────┬───────────────
                  │
          5 reqs  │  5 reqs
        (last 1s) │ (first 1s)
                  │
10 requests in 2 seconds, but each window sees only 5
```

**Impact:** An attacker can time requests at the boundary of two consecutive windows to achieve double the intended rate for a short burst. For login throttling with `MaxLoginAttempts=5` and `LoginCooldownDuration=60s`, up to 10 attempts could occur within ~2 seconds straddling the boundary.

**Removal:** set `Security.LimiterWindowMode = "sliding"`. The weighted sliding window carries the previous window's count (proportionally decayed) into the current one, so a boundary-straddling burst stays over the limit and is rejected. The regression is pinned by `TestSlidingBlocksBoundaryBurstThatFixedAdmits`.

**Mitigations in place for fixed mode:**
- Auto-lockout (when enabled) counts failures persistently across all windows — a burst still triggers lockout once the threshold is reached.
- Argon2 hashing cost limits the practical throughput of password-guessing regardless of rate limit windows.
- All rate-limited paths also emit audit events, enabling detection of boundary bursts.

## Performance Notes

- One atomic Lua script call per increment (`EVALSHA`, cached after first use); plain `GET` for fixed-mode checks.
- The first-hit `INCR`+`PEXPIRE` pair executes atomically in the script, so a crash between the two can no longer leave a counter without a TTL (permanently rate-limited identifier).
- Sliding mode reads/writes at most two counter keys per operation — O(1) memory per identifier regardless of attempt volume.

## Architecture

Rate limiting is split into three layers:

1. **Window primitive** (`internal/window`): the single counting implementation (fixed or sliding) shared by every limiter — one place for algorithm and atomicity guarantees.
2. **Core limiter** (`internal/rate`): Handles login-failure limiting with tenant+identifier counters.
3. **Domain limiters** (`internal/limiters`): Per-flow limiters for account creation, TOTP, backup codes, email verification, password reset, and lockout.

```
Engine.Login()
  ├─ rate.Limiter.CheckLogin(tenant, identifier)     ← core limiter
  │   └─ Redis GET rl:login:fail:{tenant}:{identifier}
  └─ On failure: rate.Limiter.IncrementLogin(tenant, identifier)

Engine.ConfirmTOTPSetup()
  └─ limiters.TOTPLimiter.Check(tenant, user)       ← domain limiter
       └─ Redis GET rl:totp:fail:{tenant}:{user}
```

All limiters count through the shared window primitive; `Security.LimiterWindowMode` selects the algorithm engine-wide.

## Flow Ownership

| Flow | Entry Point | Internal Module |
|------|-------------|------------------|
| Login Throttle | `Limiter.CheckLogin`, `Limiter.IncrementLogin` | `internal/rate/limiter.go` |
| Account Creation | `AccountCreationLimiter.Enforce` | `internal/limiters/account.go` |
| TOTP Attempts | `TOTPLimiter.Check`, `TOTPLimiter.RecordFailure` | `internal/limiters/totp.go` |
| Backup Code Attempts | `BackupCodeLimiter.Check`, `BackupCodeLimiter.RecordFailure` | `internal/limiters/backup.go` |
| Email Verification | `EmailVerificationLimiter.CheckRequest/CheckConfirm` | `internal/limiters/email_verification.go` |
| Password Reset | `PasswordResetLimiter.CheckRequest/CheckConfirm` | `internal/limiters/password_reset.go` |

## Testing Evidence

| Category | File | Notes |
|----------|------|-------|
| Window Primitive | `internal/window/window_test.go` | Fixed atomicity, sliding weighted counts, boundary-burst regression |
| Sliding Mode E2E | `engine_sliding_limiter_test.go` | Login-failure limiting and reset under `LimiterWindowMode: "sliding"` |
| Auto Lockout | `engine_auto_lockout_test.go` | Lockout threshold, cooldown, reset |
| Account Rate Limit | `engine_account_test.go` | Account creation throttling |
| TOTP Rate Limit | `engine_totp_test.go` | TOTP attempt limiting |
| Backup Code Limit | `engine_backup_codes_test.go` | Backup code attempt limiting |
| Password Reset Limit | `engine_password_reset_test.go` | Request and confirm throttling |
| Email Verification Limit | `engine_email_verification_test.go` | Request and confirm throttling |
| Config Lint | `config_lint_test.go` | Login-failure-limiter warnings |
| Security Invariants | `security_invariants_test.go` | Rate limiting enforcement |

## Migration Notes

- **Disabling login failure limiting**: Setting `EnableLoginFailureLimiter=false` triggers a HIGH-severity lint warning. Not recommended for production.
- **Changing cooldown durations**: Increasing `LoginCooldownDuration` takes effect on the next EXPIRE. Existing cooldown windows continue with the old TTL until they expire naturally.
- **Redis key changes**: Rate limiter keys use fixed `rl:*` prefixes. These are not configurable. Changing tenancy settings may create new key namespaces.
- **Switching `LimiterWindowMode`**: fixed and sliding counters live in different keys (`<key>` vs `{<key>}:s:<bucket>`), so flipping the mode effectively resets in-flight windows once — plan the flip outside an active attack window. Fixed mode keeps the exact pre-v0.4.0 keys and values, so upgrading in place is a no-op.

## See Also

- [Flows](flows.md)
- [Configuration](config.md)
- [Security Model](security.md)
- [Engine](engine.md)
- [Performance](performance.md)
