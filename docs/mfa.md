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
