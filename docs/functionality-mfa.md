# MFA (TOTP + Backup Code)

## What it does

Supports setup, confirmation, enforcement, and recovery via backup codes.

## Main entry points

- `Engine.GenerateTOTPSetup`
- `Engine.ConfirmTOTPSetup`
- `Engine.DisableTOTP`
- `Engine.LoginWithTOTP`
- `Engine.LoginWithBackupCode`
- `Engine.GenerateBackupCodes`

## Flow

MFA setup generation → user secret persistence via `UserProvider` → verification of TOTP challenge with skew window and anti-reuse counter tracking → MFA session completion and final token issuance.

Backup codes are hashed and consumed one-time.

Setup is refused with `ErrTOTPAlreadyEnabled` while TOTP is already enabled
for the user; there is no in-place rotation. To replace an active secret,
call `DisableTOTP` first, then setup + confirm again.

## Security behavior

- TOTP attempts are rate-limited.
- Reused or invalid backup codes are rejected.
- Re-enrollment while TOTP is already enabled is refused (`ErrTOTPAlreadyEnabled`), preventing a caller from silently overwriting an active secret.
