# Logout and Session Invalidation

## What it does

Invalidates active sessions at various scopes.

## Main entry points

- `Engine.Logout`
- `Engine.LogoutInTenant`
- `Engine.LogoutByAccessToken`
- `Engine.LogoutAll`
- `Engine.LogoutAllInTenant`
- `Engine.InvalidateUserSessions`

## Flow

request context/token identifies session/user scope → targeted Redis deletion(s) → audit/metrics emission.

## Security behavior

- Scope-aware invalidation supports per-session and global user revocation.
- Deletions are best-effort; failures return errors so callers can retry or alert.
