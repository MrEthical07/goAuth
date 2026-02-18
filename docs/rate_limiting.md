# Module: Rate Limiting

## Purpose

Multi-layer, Redis-backed rate limiting for every security-sensitive flow. Two packages cooperate:

| Package | Scope |
|---------|-------|
| `internal/rate` | Login + refresh throttles (IP + identifier) |
| `internal/limiters` | Per-flow domain limiters (account, backup-code, email-verification, TOTP, password-reset) |

## Primitives

### internal/rate — Core Limiter

```go
func New(redisClient redis.UniversalClient, cfg Config) *Limiter
```

| Method | Signature |
|--------|-----------|
| `CheckLogin` | `(ctx, username, ip string) error` |
| `IncrementLogin` | `(ctx, username, ip string) error` |
| `ResetLogin` | `(ctx, username, ip string) error` |
| `CheckRefresh` | `(ctx, sessionID string) error` |
| `IncrementRefresh` | `(ctx, sessionID string) error` |
| `GetLoginAttempts` | `(ctx, username string) (int, error)` |

**Config:**

| Field | Type |
|-------|------|
| `EnableIPThrottle` | `bool` |
| `EnableRefreshThrottle` | `bool` |
| `MaxLoginAttempts` | `int` |
| `LoginCooldownDuration` | `time.Duration` |
| `MaxRefreshAttempts` | `int` |
| `RefreshCooldownDuration` | `time.Duration` |

### internal/limiters — Domain Limiters

| Limiter | Constructor | Key Methods |
|---------|-------------|-------------|
| `AccountCreationLimiter` | `NewAccountCreationLimiter(redis, cfg)` | `Enforce(ctx, tenantID, identifier, ip)` |
| `BackupCodeLimiter` | `NewBackupCodeLimiter(redis, cfg)` | `Check`, `RecordFailure`, `Reset` |
| `EmailVerificationLimiter` | `NewEmailVerificationLimiter(redis, cfg)` | `CheckRequest`, `CheckConfirm` |
| `TOTPLimiter` | `NewTOTPLimiter(redis)` | `Check`, `RecordFailure`, `Reset` |
| `PasswordResetLimiter` | `NewPasswordResetLimiter(redis, cfg)` | `CheckRequest`, `CheckConfirm`, `Cooldown()` |

All limiters are nil-safe — calling a method on a nil receiver returns `nil`.

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

**Fixed-window counters**: `INCR` + conditional `EXPIRE` on first hit.  Redis key prefixes:

| Prefix | Scope |
|--------|-------|
| `al:` | Login per-user |
| `ali:` | Login per-IP |
| `ar:` | Refresh per-session |

Domain limiters use tenant-scoped keys via `normalizeTenantID()` (empty → `"0"`).

## Security Notes

- Each domain limiter uses separate `Unavailable` errors so callers can distinguish Redis failures from policy rejections.
- Disabling both IP and refresh throttles triggers a HIGH-severity config lint warning (`rate_limits_disabled`).

### Fixed-Window Boundary Burst

All rate limiters use **fixed-window counters** (`INCR` + `EXPIRE`). This is simple and efficient but allows up to **2× the configured limit** at window boundaries:

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

**Mitigations already in place:**
- Auto-lockout (when enabled) counts failures persistently across all windows — a burst still triggers lockout once the threshold is reached.
- Argon2 hashing cost limits the practical throughput of password-guessing regardless of rate limit windows.
- All rate-limited paths also emit audit events, enabling detection of boundary bursts.

**Future improvement:** Replace fixed-window with sliding-window log or sliding-window counter (Redis sorted sets or dual-counter approach). This is deferred because the current approach is sufficient for most deployments given the mitigations above.

## Performance Notes

- Single `INCR` round-trip per check (atomic).
- No Lua scripts — relies on Redis single-key atomicity.
