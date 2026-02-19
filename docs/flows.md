# Flow Catalog

This document describes every authentication/authorization flow in goAuth. Each flow lists the steps, participating modules, stores/limiters, enforced invariants, Redis op budget, failure modes, and a caller usage snippet.

For module-level details, see the linked module docs. For configuration, see [config.md](config.md).

---

## Table of Contents

- [Login (without MFA)](#login-without-mfa)
- [Login (with MFA)](#login-with-mfa)
- [Confirm MFA Login](#confirm-mfa-login)
- [Refresh Rotation](#refresh-rotation)
- [Validate (JWT-Only / Hybrid / Strict)](#validate)
- [Logout (Single Session)](#logout-single-session)
- [Logout by Access Token](#logout-by-access-token)
- [Logout All](#logout-all)
- [Password Change](#password-change)
- [Password Reset — Request](#password-reset-request)
- [Password Reset — Confirm](#password-reset-confirm)
- [Email Verification — Request](#email-verification-request)
- [Email Verification — Confirm](#email-verification-confirm)
- [TOTP Setup](#totp-setup)
- [TOTP Confirm Setup](#totp-confirm-setup)
- [TOTP Disable](#totp-disable)
- [Backup Codes — Generate](#backup-codes-generate)
- [Backup Codes — Consume](#backup-codes-consume)
- [Backup Codes — Regenerate](#backup-codes-regenerate)
- [Account Status Transitions](#account-status-transitions)
- [Device Binding](#device-binding)
- [Introspection Operations](#introspection-operations)

---

## Login (without MFA) {#login-without-mfa}

**Entry points:** `Engine.Login`, `Engine.LoginWithResult`

### Steps

1. Extract client IP via `WithClientIP(ctx)`.
2. **Rate-limit check** — `rate.Limiter.CheckLogin(ctx, identifier, ip)`.
3. **User lookup** — `UserProvider.GetUserByIdentifier(ctx, identifier)`. On "not found", perform dummy Argon2 verify to equalize timing, then return `ErrInvalidCredentials`.
4. **Account status check** — reject `Disabled` / `Locked` / `Deleted` accounts with appropriate sentinel errors.
5. **Email verification check** — if `RequireForLogin`, reject `PendingVerification` with `ErrAccountUnverified`.
6. **Password verify** — `password.Argon2.Verify(password, storedHash)`. On mismatch, increment login counter (`rate.Limiter.IncrementLogin`) and auto-lockout counter (`LockoutLimiter.Record`), return `ErrInvalidCredentials`.
7. **MFA check** — if TOTP is enabled for user and no inline MFA code provided, return `ErrMFALoginRequired` (or `LoginResult.MFARequired=true`).
8. **Role/mask resolution** — `RoleStore.GetRole`, `RoleManager.GetMask`.
9. **Session creation** — `session.Store.Save(ctx, session, ttl)` (Redis: SET+SADD+INCR pipeline = ~3 commands).
10. **JWT issuance** — `jwt.Manager.CreateAccess(...)`.
11. **Refresh token generation** — `internal.EncodeRefreshToken(sid, secret)`.
12. **Rate-limit reset** — `rate.Limiter.ResetLogin(ctx, identifier, ip)`.
13. **Lockout reset** — `LockoutLimiter.Reset(ctx, identifier)`.
14. **Audit emit** — `login_success` event.
15. **Metrics** — increment `MetricLoginSuccess`, `MetricSessionCreated`.

### Modules

`internal/flows/login.go` → `RunLoginWithResult` → delegates to `RunIssueLoginSessionTokens`

### Stores / Limiters

- `session.Store` (Save)
- `rate.Limiter` (CheckLogin, IncrementLogin, ResetLogin)
- `internal/limiters.LockoutLimiter` (Record, Reset)
- `UserProvider` (GetUserByIdentifier, GetRole)
- `jwt.Manager` (CreateAccess)

### Invariants

- Fail closed on unknown user (timing-equalized).
- Account status checked before password verify.
- Session created only after full credential + status validation.

### Redis Op Budget

~5–7 commands (rate check 1–2, session save 3, rate reset 1, lockout 1).

### Failure Modes

| Error | Cause |
|-------|-------|
| `ErrInvalidCredentials` | Wrong password or user not found |
| `ErrLoginRateLimited` | Too many attempts |
| `ErrAccountDisabled` | Account disabled |
| `ErrAccountLocked` | Account locked (auto or manual) |
| `ErrAccountDeleted` | Account soft-deleted |
| `ErrAccountUnverified` | Email verification required |
| `ErrMFALoginRequired` | TOTP enabled, no code provided |
| `ErrEngineNotReady` | Engine not initialized |

### Caller Usage

```go
access, refresh, err := engine.Login(ctx, "alice@example.com", "password")
if errors.Is(err, goAuth.ErrMFALoginRequired) {
    // switch to MFA flow
}
```

---

## Login (with MFA) {#login-with-mfa}

**Entry points:** `Engine.LoginWithTOTP`, `Engine.LoginWithBackupCode`

### Steps

1–6. Same as Login (without MFA).
7. **TOTP/Backup verify** — `TOTPManager.VerifyCode` or `VerifyBackupCodeInTenant`. Rate-limited via `TOTPLimiter` / `BackupCodeLimiter`.
8–15. Same as Login steps 8–15.

### Additional Failure Modes

| Error | Cause |
|-------|-------|
| `ErrTOTPInvalid` | Wrong TOTP code |
| `ErrTOTPRateLimited` | TOTP attempt limit exceeded |
| `ErrBackupCodeInvalid` | Wrong backup code |
| `ErrBackupCodeRateLimited` | Backup code attempt limit exceeded |

### Caller Usage

```go
access, refresh, err := engine.LoginWithTOTP(ctx, "alice@example.com", "password", "123456")
```

---

## Confirm MFA Login {#confirm-mfa-login}

**Entry points:** `Engine.ConfirmLoginMFA`, `Engine.ConfirmLoginMFAWithType`

### Steps

1. **Challenge lookup** — `MFALoginChallengeStore.Get(ctx, challengeID)`.
2. **Attempt check** — reject if max attempts exceeded (`ErrMFALoginAttemptsExceeded`).
3. **Expiry check** — reject if challenge TTL elapsed (`ErrMFALoginExpired`).
4. **Code verify** — TOTP or backup code depending on `mfaType`.
5. **Challenge consume** — `MFALoginChallengeStore.Delete`.
6. **Session creation** — same as Login steps 8–15.

### Modules

`internal/flows/login.go` → `RunConfirmLoginMFAWithType`

### Stores / Limiters

- `internal/stores.MFALoginChallengeStore` (Get, Delete)
- `TOTPLimiter` or `BackupCodeLimiter`
- `session.Store`, `jwt.Manager`

### Redis Op Budget

~6–8 commands (challenge GET+DELETE, TOTP limiter, session save, rate reset).

### Failure Modes

| Error | Cause |
|-------|-------|
| `ErrMFALoginExpired` | Challenge TTL elapsed |
| `ErrMFALoginAttemptsExceeded` | Too many failed attempts |
| `ErrTOTPInvalid` | Wrong code |
| `ErrMFALoginInvalid` | Malformed challenge |

### Caller Usage

```go
result, _ := engine.LoginWithResult(ctx, "alice@example.com", "password")
if result.MFARequired {
    final, err := engine.ConfirmLoginMFA(ctx, result.MFASession, "123456")
}
```

---

## Refresh Rotation {#refresh-rotation}

**Entry point:** `Engine.Refresh`

### Steps

1. **Decode refresh token** — `internal.DecodeRefreshToken(token)` → `(sessionID, secret)`.
2. **Refresh rate-limit check** — `rate.Limiter.CheckRefresh(ctx, sessionID)`.
3. **Atomic rotation** — `session.Store.RotateRefreshHash(ctx, tenantID, sessionID, SHA256(oldSecret), SHA256(newSecret))` via Lua CAS script.
4. If hash mismatch: **replay detected** — session deleted, `ErrRefreshReuse` returned, metrics/audit emitted.
5. **Account status check** — reject disabled/locked/deleted via `UserProvider.GetUserByID`.
6. **Device binding check** — `RunValidateDeviceBinding` if enabled.
7. **JWT issuance** — `jwt.Manager.CreateAccess(...)` from refreshed session data.
8. **New refresh token** — `internal.EncodeRefreshToken(sid, newSecret)`.
9. **Audit emit** — `refresh_success` or `refresh_reuse_detected`.
10. **Metrics** — increment `MetricRefreshSuccess` or `MetricRefreshReuseDetected`.

### Modules

`internal/flows/refresh.go` → `RunRefresh`

### Stores / Limiters

- `session.Store` (RotateRefreshHash — Lua script)
- `rate.Limiter` (CheckRefresh, IncrementRefresh)
- `jwt.Manager` (CreateAccess)
- `UserProvider` (GetUserByID)

### Invariants

- Rotation is atomic (Lua CAS) — no TOCTOU.
- Replay triggers session family deletion.
- Strict mode session checks applied.

### Redis Op Budget

~3–5 commands (rate check 1, Lua rotation 1–2, rate increment 1).

### Failure Modes

| Error | Cause |
|-------|-------|
| `ErrRefreshInvalid` | Malformed token |
| `ErrRefreshReuse` | Old token replayed — session destroyed |
| `ErrRefreshRateLimited` | Too many refresh attempts |
| `ErrAccountDisabled/Locked/Deleted` | Account compromised |
| `ErrDeviceBindingRejected` | IP/UA mismatch in enforce mode |

### Caller Usage

```go
newAccess, newRefresh, err := engine.Refresh(ctx, oldRefreshToken)
```

---

## Validate {#validate}

**Entry points:** `Engine.ValidateAccess`, `Engine.Validate`, middleware `Guard`/`RequireJWTOnly`/`RequireStrict`

### Steps

1. **JWT parse** — `jwt.Manager.ParseAccess(token)` → `AccessClaims`.
2. **Mode resolution** — `flows.ResolveRouteMode(engineMode, routeMode)`.
3. **JWT-Only path** (mode=1): return `AuthResult` from claims. **0 Redis ops.**
4. **Strict path** (mode=3):
   a. `session.Store.Get(ctx, tenantID, sessionID, ttl)` — 1 Redis GET (+ optional EXPIRE for sliding).
   b. **Version checks** — compare `PermissionVersion`, `RoleVersion`, `AccountVersion` between token and session. Mismatch → delete session, return `ErrUnauthorized`.
   c. **Account status check** — reject non-active status.
   d. **Device binding** — `RunValidateDeviceBinding` if enabled.
5. **Hybrid path** (mode=2): JWT-only by default; callers opt into strict per-route via `Validate(ctx, token, ModeStrict)`.
6. **Latency observation** — `metrics.Observe(MetricValidateLatency, duration)`.
7. Return `*AuthResult`.

### Modules

`internal/flows/validate.go` → `RunValidate`, `ResolveRouteMode`

### Stores / Limiters

- `jwt.Manager` (ParseAccess)
- `session.Store` (Get — strict only)
- `internal/flows/device_binding.go` (strict only)

### Invariants

- JWT-Only: zero Redis, zero allocations beyond claims.
- Strict: fail closed on Redis unavailability (`ErrStrictBackendDown`).
- Version drift deletes stale session.

### Redis Op Budget

| Mode | Redis Ops |
|------|-----------|
| JWT-Only | 0 |
| Hybrid (default) | 0 |
| Strict | 1 GET (+1 EXPIRE if sliding) |

### Failure Modes

| Error | Cause |
|-------|-------|
| `ErrUnauthorized` | Invalid/expired token, version mismatch |
| `ErrTokenClockSkew` | Token iat too far in future |
| `ErrStrictBackendDown` | Redis unavailable in strict mode |
| `ErrAccountDisabled/Locked/Deleted` | Non-active account in strict mode |
| `ErrDeviceBindingRejected` | Device mismatch in enforce mode |

### Caller Usage

```go
// Default mode
result, err := engine.ValidateAccess(ctx, token)

// Per-route strict
result, err := engine.Validate(ctx, token, goAuth.ModeStrict)

// Middleware
mux.Handle("/api", middleware.RequireStrict(engine)(handler))
```

---

## Logout (Single Session) {#logout-single-session}

**Entry points:** `Engine.Logout`, `Engine.LogoutInTenant`

### Steps

1. **Resolve tenant** from context.
2. **Session delete** — `session.Store.Delete(ctx, tenantID, sessionID)` (Lua: DEL+SREM+DECR).
3. **Audit emit** — `logout` event.
4. **Metrics** — increment `MetricLogout`.

### Redis Op Budget

~3 commands (atomic Lua delete).

### Caller Usage

```go
err := engine.Logout(ctx, tenantID, sessionID)
```

---

## Logout by Access Token {#logout-by-access-token}

**Entry point:** `Engine.LogoutByAccessToken`

### Steps

1. **JWT parse** — extract `sessionID` and `tenantID` from claims.
2. **Session delete** — same as single logout.

### Caller Usage

```go
err := engine.LogoutByAccessToken(ctx, accessToken)
```

---

## Logout All {#logout-all}

**Entry points:** `Engine.LogoutAll`, `Engine.LogoutAllInTenant`, `Engine.InvalidateUserSessions`

### Steps

1. **Resolve tenant** from context.
2. **Delete all sessions** — `session.Store.DeleteAllForUser(ctx, tenantID, userID)`.
   - Reads user's session ID set (SMEMBERS).
   - Pipeline-checks existence.
   - TxPipelined delete of each session + set + counter adjustment.
3. **Audit emit** — `logout_all` event.
4. **Metrics** — increment `MetricLogoutAll`.

### Redis Op Budget

~2N+3 commands where N = active sessions (SMEMBERS + N×EXISTS pipeline + N×DEL pipeline + counter).

### Known Limitation

`DeleteAllForUser` is not fully atomic. See [session.md](session.md#edge-cases--gotchas).

### Caller Usage

```go
err := engine.LogoutAll(ctx, userID)
```

---

## Password Change {#password-change}

**Entry point:** `Engine.ChangePassword`

### Steps

1. **User lookup** — `UserProvider.GetUserByID`.
2. **Old password verify** — `password.Argon2.Verify`.
3. **Reuse check** — reject if new password matches current hash.
4. **Policy check** — min length, max bytes.
5. **Hash new password** — `password.Argon2.Hash`.
6. **Update hash** — `UserProvider.UpdatePasswordHash`.
7. **Invalidate sessions** — `session.Store.DeleteAllForUser`.
8. **Audit emit** — `password_change_success` or `password_change_invalid_old`.
9. **Metrics** — `MetricPasswordChangeSuccess` / `MetricPasswordChangeInvalidOld` / `MetricPasswordChangeReuseRejected`.

### Failure Modes

| Error | Cause |
|-------|-------|
| `ErrInvalidCredentials` | Wrong old password |
| `ErrPasswordReuse` | New = old |
| `ErrPasswordPolicy` | Too short / too long |

### Caller Usage

```go
err := engine.ChangePassword(ctx, userID, "old-pass", "new-pass")
```

---

## Password Reset — Request {#password-reset-request}

**Entry point:** `Engine.RequestPasswordReset`

### Steps

1. **Feature check** — reject if `PasswordReset.Enabled == false`.
2. **Rate-limit check** — `PasswordResetLimiter.CheckRequest`.
3. **User lookup** — `UserProvider.GetUserByIdentifier`. On "not found", return fake challenge (enumeration resistance + timing delay).
4. **Generate challenge** — strategy-dependent (Token/OTP/UUID).
5. **Store challenge** — `PasswordResetStore.Save` with SHA-256 hashed secret, TTL, max attempts.
6. Return challenge string (`tenant:resetID:code`).
7. **Audit emit** — `password_reset_request`.
8. **Metrics** — `MetricPasswordResetRequest`.

### Redis Op Budget

~2–3 commands (limiter check, store SET).

### Caller Usage

```go
challenge, err := engine.RequestPasswordReset(ctx, "alice@example.com")
// Send code portion to user via email
```

---

## Password Reset — Confirm {#password-reset-confirm}

**Entry points:** `Engine.ConfirmPasswordReset`, `ConfirmPasswordResetWithTOTP`, `ConfirmPasswordResetWithBackupCode`, `ConfirmPasswordResetWithMFA`

### Steps

1. **Rate-limit check** — `PasswordResetLimiter.CheckConfirm`.
2. **Challenge consume** — `PasswordResetStore.Consume` (WATCH/MULTI with constant-time compare).
3. **MFA verify** (if applicable) — TOTP or backup code.
4. **Password policy** — min length, max bytes, reuse check.
5. **Hash new password** — `password.Argon2.Hash`.
6. **Update hash** — `UserProvider.UpdatePasswordHash`.
7. **Invalidate sessions** — `session.Store.DeleteAllForUser`.
8. **Audit emit** — `password_reset_confirm_success` or failure.
9. **Metrics** — `MetricPasswordResetConfirmSuccess` / `MetricPasswordResetConfirmFailure` / `MetricPasswordResetAttemptsExceeded`.

### Redis Op Budget

~4–6 commands (limiter, WATCH/MULTI consume, session invalidation).

### Caller Usage

```go
err := engine.ConfirmPasswordReset(ctx, challenge, "new-password")
```

---

## Email Verification — Request {#email-verification-request}

**Entry point:** `Engine.RequestEmailVerification`

### Steps

1. **Feature check** — reject if not enabled.
2. **Rate-limit check** — `EmailVerificationLimiter.CheckRequest`.
3. **User lookup** — on "not found" / "already active" / "non-verifiable status", return fake challenge (enumeration resistance + timing delay).
4. **Generate challenge** — strategy-dependent (Token/OTP/UUID).
5. **Store record** — `EmailVerificationStore.Save` with hashed secret, TTL, max attempts.
6. Return challenge string (`tenant:verificationID:code`).
7. **Audit emit** — `email_verification_request`.
8. **Metrics** — `MetricEmailVerificationRequest`.

### Redis Op Budget

~2–3 commands.

### Caller Usage

```go
challenge, err := engine.RequestEmailVerification(ctx, "alice@example.com")
parts := strings.SplitN(challenge, ":", 3)
sendVerificationEmail(email, parts[1], parts[2])
```

---

## Email Verification — Confirm {#email-verification-confirm}

**Entry points:** `Engine.ConfirmEmailVerification`, `Engine.ConfirmEmailVerificationCode`

### Steps

1. **Rate-limit check** — `EmailVerificationLimiter.CheckConfirm`.
2. **Challenge consume** — `EmailVerificationStore.Consume` (Lua CAS script — atomic GET→validate→DEL).
3. **Go-side constant-time compare** — defense-in-depth after Lua returns.
4. **Status update** — `UserProvider.UpdateAccountStatus(PendingVerification → Active)`.
5. **Audit emit** — `email_verification_success` or failure.
6. **Metrics** — `MetricEmailVerificationSuccess` / `_Failure` / `_AttemptsExceeded`.

### Redis Op Budget

~2–3 commands (limiter + Lua EVALSHA).

### Caller Usage

```go
// Preferred (split inputs)
err := engine.ConfirmEmailVerificationCode(ctx, verificationID, code)

// Legacy (full challenge)
err := engine.ConfirmEmailVerification(ctx, challenge)
```

---

## TOTP Setup {#totp-setup}

**Entry points:** `Engine.GenerateTOTPSetup`, `Engine.ProvisionTOTP`

### Steps

1. **Generate secret** — `crypto/rand` 20-byte secret.
2. **Build provisioning URI** — `otpauth://totp/...`.
3. **Store secret** — `UserProvider.EnableTOTP(ctx, userID, secret)`.
4. Return `TOTPSetup{SecretBase32, QRCodeURL}` or `TOTPProvision{Secret, URI}`.

### Redis Op Budget

0 (UserProvider is caller-owned).

### Caller Usage

```go
setup, err := engine.GenerateTOTPSetup(ctx, "user-123")
// Display setup.QRCodeURL as QR code
```

---

## TOTP Confirm Setup {#totp-confirm-setup}

**Entry point:** `Engine.ConfirmTOTPSetup`

### Steps

1. **Retrieve secret** — `UserProvider.GetTOTPSecret`.
2. **Verify code** — `TOTPManager.VerifyCode` (constant-time, skew-aware).
3. **Rate-limit** — `TOTPLimiter.Check`.
4. Confirm TOTP enabled for the user.

### Caller Usage

```go
err := engine.ConfirmTOTPSetup(ctx, "user-123", "123456")
```

---

## TOTP Disable {#totp-disable}

**Entry point:** `Engine.DisableTOTP`

### Steps

1. **Disable TOTP** — `UserProvider.DisableTOTP`.
2. **Invalidate sessions** — `session.Store.DeleteAllForUser`.
3. **Audit emit** — `totp_disabled`.

### Caller Usage

```go
err := engine.DisableTOTP(ctx, "user-123")
```

---

## Backup Codes — Generate {#backup-codes-generate}

**Entry point:** `Engine.GenerateBackupCodes`

### Steps

1. **Generate codes** — 10 random codes via `crypto/rand`.
2. **Hash codes** — SHA-256 each code.
3. **Store hashes** — `UserProvider.SetBackupCodes(ctx, userID, hashes)`.
4. Return plaintext codes (display once, never stored).

### Caller Usage

```go
codes, err := engine.GenerateBackupCodes(ctx, "user-123")
// Display codes to user for safekeeping
```

---

## Backup Codes — Consume {#backup-codes-consume}

**Entry points:** `Engine.VerifyBackupCode`, `Engine.VerifyBackupCodeInTenant`

### Steps

1. **Rate-limit** — `BackupCodeLimiter.Check`.
2. **Retrieve hashes** — `UserProvider.GetBackupCodes`.
3. **Constant-time compare** — `crypto/subtle.ConstantTimeCompare` against each stored hash.
4. **Consume** — `UserProvider.ConsumeBackupCode(ctx, userID, index)`.
5. **Metrics** — `MetricBackupCodeUsed` / `MetricBackupCodeFailed`.

### Caller Usage

```go
err := engine.VerifyBackupCode(ctx, "user-123", "ABCD-EFGH-1234")
```

---

## Backup Codes — Regenerate {#backup-codes-regenerate}

**Entry point:** `Engine.RegenerateBackupCodes`

### Steps

1. **TOTP proof** — `VerifyTOTP(ctx, userID, totpCode)` required to prevent hijack.
2. **Generate + store** — same as Generate flow.
3. **Metrics** — `MetricBackupCodeRegenerated`.

### Caller Usage

```go
codes, err := engine.RegenerateBackupCodes(ctx, "user-123", "123456")
```

---

## Account Status Transitions {#account-status-transitions}

**Entry points:** `Engine.DisableAccount`, `Engine.EnableAccount`, `Engine.UnlockAccount`, `Engine.LockAccount`, `Engine.DeleteAccount`

### Steps (common)

1. **Status update** — `UserProvider.UpdateAccountStatus(ctx, userID, newStatus)`.
2. **Session invalidation** — `session.Store.DeleteAllForUser` (for disable/lock/delete).
3. **Lockout reset** — `LockoutLimiter.Reset` (for enable/unlock).
4. **Audit emit** — `account_disabled`/`account_locked`/`account_deleted`/`account_enabled`.
5. **Metrics** — `MetricAccountDisabled`/`MetricAccountLocked`/`MetricAccountDeleted`.

### State Machine

```
Active ──→ Disabled     (DisableAccount)
Active ──→ Locked       (LockAccount / auto-lockout)
Active ──→ Deleted      (DeleteAccount)
Disabled → Active       (EnableAccount)
Locked ──→ Active       (EnableAccount / UnlockAccount)
Deleted ─→ Active       (EnableAccount)
PendingVerification → Active (ConfirmEmailVerification)
```

### Modules

`internal/flows/account_status.go` → `RunUpdateAccountStatusAndInvalidate`

### Caller Usage

```go
err := engine.DisableAccount(ctx, userID)
err := engine.EnableAccount(ctx, userID)
err := engine.UnlockAccount(ctx, userID)
```

---

## Device Binding {#device-binding}

**Integrated into:** Validate (strict mode), Refresh

### Steps

1. **Extract current hashes** — `HashBindingValue(clientIP)`, `HashBindingValue(userAgent)`.
2. **Compare with session** — `subtle.ConstantTimeCompare` against stored `IPHash`/`UserAgentHash`.
3. **Detect mode** — emit `EventDeviceAnomalyDetected` audit (deduplicated via `ShouldEmitDeviceAnomaly`).
4. **Enforce mode** — return `ErrDeviceBindingRejected`, increment `MetricDeviceRejected`.

### Modules

`internal/flows/device_binding.go` → `RunValidateDeviceBinding`

### Redis Op Budget

~0–1 commands (anomaly dedup INCR in detect mode only).

### Caller Usage

Device binding is transparent — set context values:

```go
ctx = goAuth.WithClientIP(ctx, r.RemoteAddr)
ctx = goAuth.WithUserAgent(ctx, r.UserAgent())
```

---

## Introspection Operations {#introspection-operations}

**Entry points:** `Engine.GetActiveSessionCount`, `Engine.ListActiveSessions`, `Engine.GetSessionInfo`, `Engine.ActiveSessionEstimate`, `Engine.Health`, `Engine.GetLoginAttempts`

### Operations

| Method | Redis Command | Budget |
|--------|--------------|--------|
| `GetActiveSessionCount` | `SCARD` | 1 op |
| `ListActiveSessions` | `SMEMBERS` + N×`GET` | 1+N ops |
| `GetSessionInfo` | `GET` | 1 op |
| `ActiveSessionEstimate` | `DBSIZE` | 1 op |
| `Health` | `PING` | 1 op |
| `GetLoginAttempts` | `GET` | 1 op |

### Modules

`internal/flows/introspection.go` → `RunGetActiveSessionCount`, `RunListActiveSessions`, etc.

### Caller Usage

```go
count, err := engine.GetActiveSessionCount(ctx, userID)
sessions, err := engine.ListActiveSessions(ctx, userID)
health := engine.Health(ctx)
```

---

## See Also

- [engine.md](engine.md) — Engine API surface
- [config.md](config.md) — Configuration reference
- [security-model.md](security-model.md) — Threat model and invariants
- [performance.md](performance.md) — Performance budgets and Redis command costs
- [ops.md](ops.md) — Operational guidance
- [examples/http-minimal](../examples/http-minimal) — Minimal integration example
