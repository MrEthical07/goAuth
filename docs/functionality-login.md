# Login and Session Issuance

## What it does

Authenticates an identifier/password, applies rate limits and account status checks, then issues:

1. JWT access token (short-lived)
2. Opaque refresh token (rotating)
3. Redis session record keyed by SID

## Main entry points

- `Engine.Login`
- `Engine.LoginWithResult`
- `Engine.LoginWithTOTP`
- `Engine.LoginWithBackupCode`

## Flow

`Login*` → limiter checks → `UserProvider.GetUserByIdentifier` → password verify (argon2) → role/mask resolution → session save (`session.Store.Save`) → access token sign (`jwt.Manager`) → refresh token generation.

## Security behavior

- Invalid credentials and limiter breaches fail closed.
- MFA-required accounts return MFA continuation state unless an MFA method is provided.
- Session and refresh state are persisted server-side for replay control.

## Performance notes

- Avoids DB lookups in validation hot path after session issuance.
- Uses fixed-size permission masks and bounded token/session structures.
