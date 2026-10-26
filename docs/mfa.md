# Module: MFA (Multi-Factor Authentication)

## Purpose

goAuth supports TOTP (Time-Based One-Time Password, RFC 6238), backup codes, and WebAuthn/FIDO2 (see [webauthn.md](webauthn.md)) as second-factor authentication mechanisms. MFA is integrated into the login flow and can be required globally or per-user.

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
| `GenerateBackupCodes` | `(ctx, userID string) ([]string, error)` | Generate the first set of one-time codes. Needs an enabled authenticator (`ErrTOTPNotConfigured` otherwise) and works without a TOTP code **only within 10 minutes of a successful `ConfirmTOTPSetup`**, once; any other time, or when codes already exist, it returns `ErrBackupCodeRegenerationRequiresTOTP` |
| `RegenerateBackupCodes` | `(ctx, userID, totpCode string) ([]string, error)` | Replace the set (requires a TOTP code; `ErrTOTPNotConfigured` for a user without an enabled authenticator) |
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
    MFARequired  bool     // true if MFA step needed
    MFAType      string   // preferred factor: "webauthn" or "totp"
    MFASession   string   // challenge ID for ConfirmLoginMFA
    MFATypes     []string // every factor the user can answer with
}
```

`ConfirmLoginMFAWithType` accepts `"totp"`, `"backup"`, or `"webauthn"` (the code
argument carries the raw assertion response JSON for webauthn — see
[webauthn.md](webauthn.md)). When a user has both WebAuthn credentials and TOTP,
`MFATypes` lists both and `MFAType` prefers `"webauthn"` (phishing-resistant first).

### Session profiles

With [session profiles](session.md#session-profiles) configured, the profile is resolved at the password step (an explicit `WithSessionProfile`, else the remember-me mapping, else the default) and stored with the challenge, so it **survives the MFA step**: the session issued by `ConfirmLoginMFA` / `ConfirmLoginMFAWithType` (or by `LoginWithTOTP` / `LoginWithBackupCode`, which do both steps) gets the stored profile. The challenge record is **v3**, the v2 layout plus a length-prefixed profile name; with no profiles configured it is still written as v2, byte for byte.

- **The stored profile wins.** A confirm that names no profile, or the same one, issues the stored profile.
- **A confirm naming a different profile** fails with `ErrSessionProfileConflict`. The challenge is **not consumed** and no attempt is counted, so the same challenge still works with the right profile (or none). The check runs before any factor is verified.
- A challenge created before profiles were configured carries none and is resolved like a fresh login at confirm; one whose profile has since been removed fails with `ErrUnknownSessionProfile` and is left to expire.

### Step-up for role switching

When `Config.RoleSwitch.StepUp` is configured, a session issued after a successful second factor (`ConfirmLoginMFA`, `ConfirmLoginMFAWithType` with `totp`/`backup`/`webauthn`, `LoginWithTOTP`, `LoginWithBackupCode`) records an MFA assurance beside the session, and `Engine.SwitchRole` can use it to satisfy a `RequireMFA` policy without asking again. A switch can also take an inline `totp` or `backup_code` proof; a user who has no TOTP enrolled never satisfies a policy with a made-up code. WebAuthn as an *inline* factor is a planned follow-up; a fresh WebAuthn login satisfies the policy. See [role_switching.md](role_switching.md#step-up).

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

`GenerateTOTPSetup`/`ProvisionTOTP` refuse to run while the user already has
TOTP enabled, returning `ErrTOTPAlreadyEnabled` instead of generating and
persisting a new secret. There is no in-place rotation: to replace an
enabled secret, call `DisableTOTP` first, then `GenerateTOTPSetup` /
`ProvisionTOTP` + `ConfirmTOTPSetup` again. A setup that was started but
never confirmed (`Enabled == false`) is not affected — re-running setup in
that state still succeeds and replaces the unconfirmed secret.

### Login with MFA challenge

```go
result, err := engine.LoginWithResult(ctx, "alice@example.com", "password")
if result.MFARequired {
    // UI prompts for TOTP code
    final, err := engine.ConfirmLoginMFA(ctx, result.MFASession, userCode)
    accessToken := final.AccessToken
}
```

A remember-me login (`LoginWithOptions` with `LoginOptions{RememberMe: true}`)
stores the flag with the MFA challenge, so the session issued by
`ConfirmLoginMFA` is durable without any change to the confirm call — see
[session.md](session.md#session-lifetimes--remember-me).

## Security Notes

- TOTP secrets are 20-byte random values from `crypto/rand`.
- Code verification uses `crypto/subtle.ConstantTimeCompare`.
- Skew > 1 is warned by `Config.Lint()` (widens acceptance window).
- Backup codes are a recovery artifact of an enabled authenticator. They are neither generated nor regenerated for a user without one, and a backup code is accepted as a second factor (login, role-switch step-up) only for a user who has one.
- Backup code regeneration requires TOTP proof to prevent hijack. The first set can be generated without it only in the 10 minutes after `ConfirmTOTPSetup` (a single-use marker, `abg:<tenant>:<user>`); a session holder cannot mint codes for themselves later.
- `DisableTOTP` removes the user's backup codes, so a set minted for one authenticator never works for the next.
- MFA challenges have TTL and attempt limits. The per-challenge cap (`TOTP.MFALoginMaxAttempts`) is claimed with one script *before* the factor is evaluated, so parallel confirmations cannot evaluate more codes than the cap allows.
- TOTP guesses at MFA login also draw on the **per-account TOTP budget** that `VerifyTOTP` uses (`TOTP.MFALoginMaxAttempts` per `TOTP.VerifyAttemptCooldown`), so minting a new challenge for every five guesses does not reset the limit. When the budget is spent the challenge is destroyed and `ErrTOTPRateLimited` is returned, and a right code is refused too until the window passes; a right code clears the budget.
- Every code check (TOTP, backup code, step-up) claims its attempt before the code is evaluated; see [rate_limiting.md](rate_limiting.md#reserve-before-you-verify).

## Performance Notes

- TOTP verification is CPU-only (HMAC-SHA1, ~1µs).
- MFA challenge storage uses Redis with short TTL.

## Edge Cases & Gotchas

- `LoginWithResult` returns `MFARequired=true` but no error — callers must check the flag.
- Backup codes are one-time: each code can only be used once.
- `GenerateBackupCodes` never replaces existing codes: it returns `ErrBackupCodeRegenerationRequiresTOTP` while any exist. `RegenerateBackupCodes` (with a TOTP code) replaces them. A user who enrolled before upgrading to v0.8.1 and has no codes generates them with `RegenerateBackupCodes`.
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
| `ErrTOTPFeatureDisabled` | TOTP/backup-code functionality is disabled in config |
| `ErrTOTPRequired` | TOTP code required for this operation |
| `ErrTOTPInvalid` | Wrong TOTP code |
| `ErrTOTPRateLimited` | TOTP attempt limit exceeded |
| `ErrTOTPNotConfigured` | TOTP not set up for user |
| `ErrTOTPAlreadyEnabled` | `GenerateTOTPSetup`/`ProvisionTOTP` called while TOTP is already enabled; disable then re-setup to rotate |
| `ErrTOTPUnavailable` | TOTP backend/limiter unavailable |
| `ErrBackupCodeInvalid` | Wrong backup code |
| `ErrBackupCodeRateLimited` | Backup code attempt limit exceeded |
| `ErrBackupCodeUnavailable` | Backup code backend/limiter unavailable |
| `ErrBackupCodesNotConfigured` | Backup codes are not configured for the user |
| `ErrBackupCodeRegenerationRequiresTOTP` | Regenerating backup codes requires successful TOTP verification |
| `ErrMFALoginExpired` | MFA challenge TTL elapsed |
| `ErrMFALoginAttemptsExceeded` | Too many failed MFA attempts |
| `ErrMFALoginReplay` | MFA challenge replay detected |
| `ErrMFALoginUnavailable` | MFA challenge backend unavailable |
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

- **v0.5.1**: `GenerateTOTPSetup`/`ProvisionTOTP` now return `ErrTOTPAlreadyEnabled` instead of silently replacing an active secret. See [migrations.md](migrations.md#v051-migration-notes-non-breaking).
- **Enabling TOTP**: Setting `Config.TOTP.Enabled = true` does not retroactively require MFA for existing users. Users must individually set up TOTP via `GenerateTOTPSetup` + `ConfirmTOTPSetup`.
- **Skew changes**: Increasing `Skew` widens the acceptance window. Decreasing it may cause valid codes from slower users to be rejected.
- **Backup code regeneration**: `RegenerateBackupCodes` replaces all existing codes. Users must save the new codes immediately.
- **Session profiles (v0.8.0)**: the MFA challenge record becomes v3 (carries the profile) only while profiles are configured; v3 records cannot be read by v0.7.0, so finish a rolling deploy first. See [migrations.md](migrations.md#v080-migration-notes-non-breaking).
- **Role-switch step-up (v0.7.0)**: opt-in via `Config.RoleSwitch`; with it unused nothing about MFA login changes. See [migrations.md](migrations.md#v070-migration-notes-non-breaking).

## See Also

- [Flows](flows.md)
- [Configuration](config.md)
- [Engine](engine.md)
- [Security Model](security.md)
- [Password](password.md)
- [Password Reset](password_reset.md)
- [Role Switching](role_switching.md)
