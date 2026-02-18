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
    Enabled                  bool
    Strategy                 ResetStrategyType
    ResetTTL                 time.Duration    // Challenge lifetime
    MaxAttempts              int              // Max confirmation attempts
    EnableIPThrottle         bool
    EnableIdentifierThrottle bool
    OTPDigits                int              // Digits for OTP strategy
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
- `RequestPasswordReset` does not reveal whether the identifier exists (prevents enumeration).
- OTP mode requires `OTPDigits ≤ 6` in production mode.
