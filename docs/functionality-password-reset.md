# Password Reset Lifecycle

## What it does

Implements reset request and confirmation using strategy-controlled artifacts (token/OTP/UUID).

## Main entry points

- `Engine.RequestPasswordReset`
- `Engine.ConfirmPasswordReset`

## Flow

request identity → reset limiter check → create reset artifact and store metadata in Redis → deliver artifact through application channel → confirm artifact + new password policy check → hash update via `UserProvider.UpdatePasswordHash` → invalidate existing sessions.

## Security behavior

- Confirmation is rate-limited and expiry-bound.
- Reset artifacts are one-time use.
