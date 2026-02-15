# Refresh Token Rotation and Replay Handling

## What it does

Consumes a refresh token, rotates refresh secret material, and issues fresh access/refresh tokens.

## Main entry points

- `Engine.Refresh`
- refresh token helpers in `refresh/`
- `session.Store.RotateRefreshHash`

## Flow

refresh parse (`SID||SECRET`) → session lookup by SID → constant-time hash comparison of `SHA256(SECRET)` with stored hash → issue new secret and access token → atomically update stored refresh hash.

## Replay detection

If secret mismatch/reuse is detected, the session is invalidated immediately.

## Security behavior

- Refresh tokens are opaque and URL-safe base64 encoded.
- Rotation is mandatory; JWT refresh tokens are not used.
