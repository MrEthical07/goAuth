# Module: MFA (Multi-Factor Authentication)

## Purpose

goAuth supports TOTP (Time-Based One-Time Password, RFC 6238) and backup codes as second-factor authentication mechanisms. MFA is integrated into the login flow and can be required globally or per-user.

## Primitives

### TOTP

| Primitive | Signature | Description |
|-----------|-----------|-------------|
| `GenerateTOTPSetup` | `(ctx, userID string) (*TOTPSetup, error)` | Generate TOTP secret + QR URL |
| `ProvisionTOTP` | `(ctx, userID string) (*TOTPProvision, error)` | Alternative provisioning |
| `ConfirmTOTPSetup` | `(ctx, userID, code string) error` | Verify initial code to confirm setup |
| `VerifyTOTP` | `(ctx, userID, code string) error` | Verify a TOTP code |
| `DisableTOTP` | `(ctx, userID string) error` | Remove TOTP from account |

### Backup Codes

| Primitive | Signature | Description |
|-----------|-----------|-------------|
| `GenerateBackupCodes` | `(ctx, userID string) ([]string, error)` | Generate a set of one-time codes |
| `RegenerateBackupCodes` | `(ctx, userID, totpCode string) ([]string, error)` | Regenerate (requires TOTP proof) |
| `VerifyBackupCode` | `(ctx, userID, code string) error` | Use a backup code |

### MFA Login Flow

| Primitive | Signature | Description |
|-----------|-----------|-------------|
| `LoginWithTOTP` | `(ctx, user, pass, totp string) (access, refresh, err)` | Login with TOTP in one step |
| `LoginWithBackupCode` | `(ctx, user, pass, code string) (access, refresh, err)` | Login with backup code in one step |
| `LoginWithResult` | `(ctx, user, pass string) (*LoginResult, error)` | Returns MFA challenge if required |
| `ConfirmLoginMFA` | `(ctx, challengeID, code string) (*LoginResult, error)` | Complete MFA challenge |
| `ConfirmLoginMFAWithType` | `(ctx, challengeID, code, mfaType string) (*LoginResult, error)` | Complete with explicit type |

### Return Types

```go
type TOTPSetup struct {
    SecretBase32 string  // Base32-encoded secret for authenticator apps
    QRCodeURL    string  // otpauth:// URI for QR code generation
}

type LoginResult struct {
    AccessToken  string
    RefreshToken string
    MFARequired  bool    // true if MFA step needed
    MFAType      string  // "totp" or "backup_code"
    MFASession   string  // challenge ID for ConfirmLoginMFA
}
```

## Strategies

| Strategy | Config | Description |
|----------|--------|-------------|
| TOTP (RFC 6238) | `Config.TOTP.Enabled = true` | Time-based codes, 30s period |
| Backup codes | Auto-generated | One-time recovery codes |
| Challenge flow | `LoginWithResult → ConfirmLoginMFA` | Two-step login for UIs |
| Single-step | `LoginWithTOTP` | Combined login + TOTP for APIs |

### TOTP Config

```go
type TOTPConfig struct {
    Enabled           bool
    Issuer            string  // Display name in authenticator
    Digits            int     // Code length (default 6)
    Period            int     // Time step in seconds (default 30)
    Skew              int     // Window tolerance (default 1 = ±30s)
    MaxAttempts       int     // Rate limit per window
    CooldownDuration  time.Duration
}
```

## Examples

### Setup TOTP for a user

```go
setup, err := engine.GenerateTOTPSetup(ctx, "user-123")
// Show setup.QRCodeURL to user
// User scans QR, enters code:
err = engine.ConfirmTOTPSetup(ctx, "user-123", "123456")
```

### Login with MFA challenge

```go
result, err := engine.LoginWithResult(ctx, "alice@example.com", "password")
if result.MFARequired {
    // UI prompts for TOTP code
    final, err := engine.ConfirmLoginMFA(ctx, result.MFASession, userCode)
    accessToken := final.AccessToken
}
```

## Security Notes

- TOTP secrets are 20-byte random values from `crypto/rand`.
- Code verification uses `crypto/subtle.ConstantTimeCompare`.
- Skew > 1 is warned by `Config.Lint()` (widens acceptance window).
- Backup code regeneration requires TOTP proof to prevent hijack.
- MFA challenges have TTL and attempt limits.

## Performance Notes

- TOTP verification is CPU-only (HMAC-SHA1, ~1µs).
- MFA challenge storage uses Redis with short TTL.

## Edge Cases & Gotchas

- `LoginWithResult` returns `MFARequired=true` but no error — callers must check the flag.
- Backup codes are one-time: each code can only be used once.
- `GenerateBackupCodes` replaces any existing backup codes.
- TOTP counter tracking prevents code reuse within the same time step.

## Architecture

MFA is integrated directly into the engine's login flow rather than existing as a standalone module. TOTP management methods live on the `Engine` struct, while the underlying TOTP verification uses an internal `TOTPManager` and the backup code logic delegates to `UserProvider`.

```
Login flow (MFA-aware)
  ├─ Credential verification (password)
  ├─ MFA check: is TOTP enabled for user?
  │   ├─ Yes + code provided → verify inline (LoginWithTOTP)
  │   ├─ Yes + no code → create MFA challenge (LoginWithResult)
  │   └─ No → proceed to session creation
  └─ Challenge flow: ConfirmLoginMFA → verify code → issue tokens
```

Rate limiting for TOTP and backup codes uses dedicated domain limiters (`TOTPLimiter`, `BackupCodeLimiter`) separate from the login rate limiter.

## Error Reference

| Error | Condition |
|-------|----------|
| `ErrMFALoginRequired` | TOTP enabled but no code provided in login |
| `ErrTOTPRequired` | TOTP code required for this operation |
| `ErrTOTPInvalid` | Wrong TOTP code |
| `ErrTOTPRateLimited` | TOTP attempt limit exceeded |
| `ErrTOTPNotEnabled` | TOTP not set up for user |
| `ErrBackupCodeInvalid` | Wrong backup code |
| `ErrBackupCodeRateLimited` | Backup code attempt limit exceeded |
| `ErrMFALoginExpired` | MFA challenge TTL elapsed |
| `ErrMFALoginAttemptsExceeded` | Too many failed MFA attempts |
| `ErrMFALoginInvalid` | Malformed MFA challenge |

## Flow Ownership

| Flow | Entry Point | Internal Module |
|------|-------------|------------------|
| TOTP Setup | `Engine.GenerateTOTPSetup`, `Engine.ProvisionTOTP` | `internal/flows/totp.go` |
| TOTP Confirm Setup | `Engine.ConfirmTOTPSetup` | `internal/flows/totp.go` |
| TOTP Disable | `Engine.DisableTOTP` | `internal/flows/totp.go` |
| TOTP Verify (login) | `Engine.LoginWithTOTP` | `internal/flows/login.go` |
| Backup Code Generate | `Engine.GenerateBackupCodes` | `internal/flows/backup_codes.go` |
| Backup Code Consume | `Engine.VerifyBackupCode` | `internal/flows/backup_codes.go` |
| Backup Code Regenerate | `Engine.RegenerateBackupCodes` | `internal/flows/backup_codes.go` |
| MFA Challenge | `Engine.LoginWithResult` → `Engine.ConfirmLoginMFA` | `internal/flows/login.go` |

## Testing Evidence

| Category | File | Notes |
|----------|------|-------|
| TOTP Setup & Verify | `engine_totp_test.go` | Generate, confirm, disable, verify |
| TOTP RFC Compliance | `totp_rfc_test.go` | RFC 6238 test vectors |
| MFA Login Flow | `engine_mfa_login_test.go` | Challenge, confirm, timeout, attempts |
| Backup Codes | `engine_backup_codes_test.go` | Generate, consume, regenerate, rate limit |
| Security Invariants | `security_invariants_test.go` | MFA-related security properties |

## Migration Notes

- **Enabling TOTP**: Setting `Config.TOTP.Enabled = true` does not retroactively require MFA for existing users. Users must individually set up TOTP via `GenerateTOTPSetup` + `ConfirmTOTPSetup`.
- **Skew changes**: Increasing `Skew` widens the acceptance window. Decreasing it may cause valid codes from slower users to be rejected.
- **Backup code regeneration**: `RegenerateBackupCodes` replaces all existing codes. Users must save the new codes immediately.

## See Also

- [Flows](flows.md)
- [Configuration](config.md)
- [Engine](engine.md)
- [Security Model](security.md)
- [Password](password.md)
- [Password Reset](password_reset.md)
