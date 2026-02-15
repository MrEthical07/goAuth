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

## Security behavior

- TOTP attempts are rate-limited.
- Reused or invalid backup codes are rejected.
