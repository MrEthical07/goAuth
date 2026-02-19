# Module: Email Verification

## Purpose

Email verification provides a secure lifecycle for verifying user email addresses via token, OTP, or UUID strategies. The module is designed with enumeration resistance, tenant isolation, and atomic store operations as first-class properties.

## API

### Request

```go
// RequestEmailVerification initiates verification and returns a challenge string.
// The challenge encodes tenant:verificationID:code (see Challenge Format below).
func (e *Engine) RequestEmailVerification(ctx context.Context, identifier string) (string, error)
```

**Returns:**

| Component        | Description                                             | Safe to log? |
|------------------|---------------------------------------------------------|--------------|
| `verificationID` | Opaque record identifier embedded inside the challenge  | Yes          |
| `code`           | Secret portion (token bytes, OTP digits, or UUID)       | **No**       |
| `tenant`         | Effective tenant ID, bound into the challenge           | Yes          |

The caller should extract the `code` and deliver it to the user (e.g. email body). The `verificationID` may be stored server-side for audit/support lookup.

### Confirm (legacy — full challenge)

```go
// ConfirmEmailVerification completes verification using the full challenge string.
// The tenant is parsed from the challenge, so cross-tenant verification works
// automatically without requiring the correct tenant in the context.
func (e *Engine) ConfirmEmailVerification(ctx context.Context, challenge string) error
```

### Confirm (preferred — verificationID + code)

```go
// ConfirmEmailVerificationCode completes verification using the verificationID
// and secret code separately. The tenant is taken from the request context.
// This is the preferred method because it avoids passing the secret code inside
// an opaque string that might be logged.
func (e *Engine) ConfirmEmailVerificationCode(ctx context.Context, verificationID, code string) error
```

**Recommendation:** Use `ConfirmEmailVerificationCode` in new code. Reserve `ConfirmEmailVerification` for backward-compatible flows where the full challenge string is already in use.

### Errors

| Error                              | Description                                    |
|------------------------------------|------------------------------------------------|
| `ErrEmailVerificationDisabled`     | Feature not enabled in config                  |
| `ErrEmailVerificationInvalid`      | Challenge expired, invalid, already used, or malformed |
| `ErrEmailVerificationRateLimited`  | Too many requests (IP or identifier throttle)  |
| `ErrEmailVerificationUnavailable`  | Backend (Redis) unavailable                    |
| `ErrEmailVerificationAttempts`     | Max attempts exceeded for this verification    |

## Challenge Format

All strategies produce a challenge string in the format:

```
tenant:verificationID:code
```

| Segment          | Description                                              |
|------------------|----------------------------------------------------------|
| `tenant`         | Effective tenant ID (user's tenant, or context tenant)   |
| `verificationID` | Random identifier for the verification record            |
| `code`           | Strategy-dependent secret (see Strategy Matrix below)    |

### Strategy Matrix

| Strategy | Config Value       | `verificationID`           | `code`                        | Attempt Limits | Notes                                    |
|----------|--------------------|----------------------------|-------------------------------|----------------|------------------------------------------|
| Token    | `VerificationToken`| base64url-encoded 16 bytes | base64url-encoded 48 bytes    | Yes            | Default. Highest entropy.                |
| OTP      | `VerificationOTP`  | base64url-encoded 16 bytes | Numeric string, N digits      | Yes            | `OTPDigits` configurable (6–10).         |
| UUID     | `VerificationUUID` | UUID v4 string             | Same UUID v4 string           | Yes            | verificationID and code are identical.   |

**Clarification on UUID strategy:** The UUID serves as *both* the record identifier and the secret code. This means the verificationID alone is sufficient to confirm — treat it as sensitive in this mode.

## Config

```go
type EmailVerificationConfig struct {
    Enabled                  bool
    Strategy                 VerificationStrategyType
    VerificationTTL          time.Duration
    MaxAttempts              int
    RequireForLogin          bool             // Block login until verified
    EnableIPThrottle         bool
    EnableIdentifierThrottle bool
    OTPDigits                int              // 6–10 digits (OTP strategy only)
}
```

## Security Properties

### Enumeration Resistance

`RequestEmailVerification` returns a **non-empty, structurally valid challenge** for all of the following cases:

| Scenario                          | Behavior                                           |
|-----------------------------------|----------------------------------------------------|
| User not found                    | Fake challenge returned (no record written)        |
| User already active               | Fake challenge returned (no record written)        |
| User in non-verifiable status     | Fake challenge returned (no record written)        |
| User pending verification         | Real challenge returned, record saved              |
| Feature disabled                  | Error returned (`ErrEmailVerificationDisabled`)    |
| Empty identifier                  | Error returned (`ErrEmailVerificationInvalid`)     |

An attacker observing only the HTTP response **cannot distinguish** whether a given identifier maps to an existing account or its verification state.

A timing delay (`SleepEnumerationDelay`) is applied on "user not found" to equalize response times with the real path.

### Tenant Binding

The challenge string encodes the **effective tenant** (the user's tenant if set, otherwise the context tenant). On confirm:

- `ConfirmEmailVerification(challenge)` — parses tenant from challenge; works correctly even if the confirming request arrives with a different context tenant.
- `ConfirmEmailVerificationCode(verificationID, code)` — uses context tenant; caller must ensure context has the correct tenant.

This means cross-tenant verification scenarios (e.g. user.TenantID differs from context tenant) are handled automatically by the legacy API and require correct context setup for the new API.

### Store Atomicity (Lua CAS)

The verification store uses a Lua script for the `Consume` operation, providing:

- **Single EVALSHA per consume** — no WATCH/MULTI retry loops.
- **Deterministic contention behavior** — under parallel attempts, exactly one caller succeeds; others receive `ErrVerificationSecretMismatch` or `ErrVerificationAttemptsExceeded`.
- **TTL preservation** — on failed attempts, the record's TTL is preserved via `PTTL`/`PX`.
- **Defense-in-depth** — a constant-time comparison in Go is performed after Lua returns, since Lua string comparison is not constant-time.

### Additional Security

- Challenge tokens are hashed (SHA-256) before storage — raw secrets never persist.
- Challenges are **single-use**: consumed and deleted on success.
- `RequireForLogin = true` blocks login with `ErrAccountUnverified` until verified.
- Rate limiting on both request and confirm paths (IP and identifier throttles).
- OTP mode enforces stricter limits in production mode.

## Examples

### Using the preferred API (recommended)

```go
// 1. Request verification
challenge, err := engine.RequestEmailVerification(ctx, "alice@example.com")
if err != nil {
    return err
}

// 2. Parse the challenge to extract verificationID and code
parts := strings.SplitN(challenge, ":", 3)
verificationID := parts[1]  // safe to log, store in DB
code := parts[2]             // SECRET — send to user's inbox, do NOT log

// 3. Send code to user via email (your transport layer)
sendVerificationEmail(user.Email, verificationID, code)

// 4. User submits verificationID + code from their email
err = engine.ConfirmEmailVerificationCode(ctx, verificationID, code)
// Account status changes from PendingVerification → Active
```

### Using the legacy API (backward compatible)

```go
challenge, err := engine.RequestEmailVerification(ctx, "alice@example.com")
// Send entire challenge to user's inbox

err = engine.ConfirmEmailVerification(ctx, challenge)
// Account status changes from PendingVerification → Active
```

## Edge Cases & Gotchas

- Challenges are single-use.
- When `RequireForLogin` is true, `CreateAccount` sets status to `AccountPendingVerification`.
- OTP mode limits are enforced more strictly in production mode.
- UUID strategy: the verificationID *is* the code — do not log it.

## Architecture

Email verification follows a two-phase flow (request + confirm) similar to password reset, backed by a Redis verification store with Lua CAS for atomic consumption.

```
Engine.RequestEmailVerification(identifier)
  ├─ EmailVerificationLimiter.CheckRequest
  ├─ UserProvider.GetUserByIdentifier
  │   ├─ Not found / already active → fake challenge (enumeration resistance)
  │   └─ Pending verification → real challenge
  ├─ Generate challenge (Token/OTP/UUID strategy)
  ├─ EmailVerificationStore.Save (SHA-256 hashed)
  └─ Return challenge string (tenant:verificationID:code)

Engine.ConfirmEmailVerificationCode(verificationID, code)
  ├─ EmailVerificationLimiter.CheckConfirm
  ├─ EmailVerificationStore.Consume (Lua CAS)
  ├─ Go-side constant-time compare (defense-in-depth)
  └─ UserProvider.UpdateAccountStatus(PendingVerification → Active)
```

## Flow Ownership

| Flow | Entry Point | Internal Module |
|------|-------------|------------------|
| Request Verification | `Engine.RequestEmailVerification` | `internal/flows/email_verification.go` → `RunRequestEmailVerification` |
| Confirm (legacy) | `Engine.ConfirmEmailVerification` | `internal/flows/email_verification.go` → `RunConfirmEmailVerification` |
| Confirm (preferred) | `Engine.ConfirmEmailVerificationCode` | `internal/flows/email_verification.go` → `RunConfirmEmailVerificationCode` |

## Testing Evidence

| Category | File | Notes |
|----------|------|-------|
| Email Verification | `engine_email_verification_test.go` | Request, confirm, strategies, rate limiting, enumeration resistance |
| Config Validation | `config_test.go` | Email verification config validation |
| Config Lint | `config_lint_test.go` | Verification-related warnings |
| Security Invariants | `security_invariants_test.go` | Enumeration resistance, status transitions |
| Store Consistency | `test/store_consistency_test.go` | Lua CAS atomicity |

## Migration Notes

- **Enabling verification**: Set `EmailVerification.Enabled = true`. When `RequireForLogin = true`, new accounts start in `PendingVerification` status and must verify before login.
- **Changing strategy**: Switching between Token/OTP/UUID invalidates all pending verification records.
- **`ConfirmEmailVerificationCode` vs `ConfirmEmailVerification`**: Prefer `ConfirmEmailVerificationCode` in new code. It avoids passing the secret inside an opaque challenge string that might be logged.
- **UUID strategy caution**: The verificationID and code are identical in UUID mode. Treat the verificationID as sensitive data.

## See Also

- [Flows](flows.md)
- [Configuration](config.md)
- [Engine](engine.md)
- [Security Model](security.md)
- [Password Reset](password_reset.md)
