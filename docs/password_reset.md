# Module: Password Reset

## Purpose

Password reset provides a secure lifecycle for resetting user passwords via token, OTP, or UUID strategies with configurable rate limiting and attempt controls.

## Primitives

| Primitive | Signature | Description |
|-----------|-----------|-------------|
| `RequestPasswordReset` | `(ctx, identifier string) (string, error)` | Initiate reset flow, returns challenge |
| `ConfirmPasswordReset` | `(ctx, challenge, newPassword string) error` | Complete reset |
| `ConfirmPasswordResetWithTOTP` | `(ctx, challenge, newPassword, totpCode string) error` | Reset + TOTP proof |
| `ConfirmPasswordResetWithBackupCode` | `(ctx, challenge, newPassword, backupCode string) error` | Reset + backup code |
| `ConfirmPasswordResetWithMFA` | `(ctx, challenge, newPassword, mfaType, mfaCode string) error` | Reset + MFA (any type) |

### Errors

| Error | Description |
|-------|-------------|
| `ErrPasswordResetDisabled` | Feature not enabled |
| `ErrPasswordResetInvalid` | Challenge expired, invalid, or already used |
| `ErrPasswordResetRateLimited` | Too many requests |
| `ErrPasswordResetAttempts` | Max confirmation attempts exceeded |
| `ErrPasswordPolicy` | New password doesn't meet policy |
| `ErrPasswordReuse` | New password same as current |

## Strategies

| Strategy | Config Value | Description |
|----------|-------------|-------------|
| Token | `ResetToken` | Cryptographic token (default) |
| OTP | `ResetOTP` | Numeric one-time password |
| UUID | `ResetUUID` | UUID-based challenge |

### Config

```go
type PasswordResetConfig struct {
  Enabled                     bool
  Strategy                    ResetStrategyType
  ResetTTL                    time.Duration    // Challenge lifetime
  MaxAttempts                 int              // Max confirmation attempts
  EnableRequestLimiter        bool
  EnableConfirmFailureLimiter bool
  OTPDigits                   int              // Digits for OTP strategy
}
```

## Examples

```go
challenge, err := engine.RequestPasswordReset(ctx, "alice@example.com")
// Send challenge to user via email/SMS

err = engine.ConfirmPasswordReset(ctx, challenge, "new-secure-password")
```

## Security Notes

- Challenge tokens are SHA-256 hashed before storage.
- Rate limiting protects both request and confirm endpoints.
- All existing sessions are invalidated after successful reset.
- Password reuse is rejected.

## Edge Cases & Gotchas

- Challenges are single-use: confirming a challenge invalidates it.
- `RequestPasswordReset` does not reveal whether the identifier exists (prevents enumeration): every branch that answers with a challenge — registered, unknown — takes at least the same randomized 20-40 ms from request entry, so the response times overlap. An identifier over `MaxIdentifierBytes` (320) is refused as `ErrPasswordResetInvalid`.
- Requests are limited per identifier as typed and per resolved account (`rl:reset:req:user:*`). A provider that matches identifiers case-insensitively would otherwise give every spelling its own budget. The account budget answers `ErrPasswordResetRateLimited` (not a fake challenge) so that your application sends no mail; with a case-insensitive provider that lets a caller trying spellings see that the account exists.
- OTP mode requires `OTPDigits ≤ 6` in production mode.
- **One valid code per account.** A new `RequestPasswordReset` supersedes the codes of earlier requests for the same user, and a completed reset supersedes every code issued before it, whoever holds them (a pointer `aprg:<tenant>:<user>` holds the newest reset ID, or a tombstone after a completion; it lives as long as `ResetTTL`). Anyone who can request a reset for an account can therefore supersede a code that is waiting for its owner (the owner gets a new mail with a working code); the per-identifier and per-account request limiters bound how often. A code issued by a v0.8.0 instance during a rolling deploy has no pointer entry and is refused if a v0.8.1 instance has since written one.

## Architecture

Password reset is a two-phase flow (request + confirm) backed by a Redis challenge store. The engine delegates to flow functions in `internal/flows/password_reset.go`.

```
Engine.RequestPasswordReset(identifier)
  ├─ PasswordResetLimiter.CheckRequest
  ├─ UserProvider.GetUserByIdentifier (fake challenge on not-found)
  ├─ Generate challenge (Token/OTP/UUID strategy)
  ├─ PasswordResetStore.Save (SHA-256 hashed)
  └─ Return challenge string

Engine.ConfirmPasswordReset(challenge, newPassword)
  ├─ PasswordResetLimiter.CheckConfirm
  ├─ PasswordResetStore.Consume (CAS + constant-time compare)
  ├─ Password policy + reuse check
  ├─ password.Argon2.Hash(newPassword)
  ├─ UserProvider.UpdatePasswordHash
  └─ session.Store.DeleteAllForUser (invalidate sessions)
```

## Flow Ownership

| Flow | Entry Point | Internal Module |
|------|-------------|------------------|
| Request Reset | `Engine.RequestPasswordReset` | `internal/flows/password_reset.go` → `RunRequestPasswordReset` |
| Confirm Reset | `Engine.ConfirmPasswordReset` | `internal/flows/password_reset.go` → `RunConfirmPasswordReset` |
| Confirm + TOTP | `Engine.ConfirmPasswordResetWithTOTP` | `internal/flows/password_reset.go` |
| Confirm + Backup | `Engine.ConfirmPasswordResetWithBackupCode` | `internal/flows/password_reset.go` |
| Confirm + MFA | `Engine.ConfirmPasswordResetWithMFA` | `internal/flows/password_reset.go` |

## Testing Evidence

| Category | File | Notes |
|----------|------|-------|
| Password Reset | `engine_password_reset_test.go` | Request, confirm, strategies, rate limiting, MFA variants |
| Config Validation | `config_test.go` | Password reset config validation |
| Config Lint | `config_lint_test.go` | Reset-related warnings |
| Security Invariants | `security_invariants_test.go` | Enumeration resistance, session invalidation |

## Migration Notes

- **Enabling password reset**: Set `PasswordReset.Enabled = true`. The feature is off by default.
- **Changing strategy**: Switching between Token/OTP/UUID invalidates all pending challenges because the code format changes.
- **TTL changes**: Reducing `ResetTTL` only affects new challenges. Existing challenges retain their original TTL.
- **MFA variants**: `ConfirmPasswordResetWithTOTP` and `ConfirmPasswordResetWithMFA` require the user to have TOTP enabled. If TOTP is not set up, use the plain `ConfirmPasswordReset`.

## See Also

- [Flows](flows.md)
- [Configuration](config.md)
- [Password](password.md)
- [MFA](mfa.md)
- [Security Model](security.md)
- [Engine](engine.md)
- [Email Verification](email_verification.md)
