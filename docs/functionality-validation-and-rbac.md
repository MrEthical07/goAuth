# Access Token Validation and RBAC

## What it does

Verifies access tokens and enforces route-level authorization using precompiled bitmasks.

## Main entry points

- `Engine.ValidateAccess`
- `Engine.Validate`
- `Engine.HasPermission`
- middleware adapters in `middleware/`

## Flow

Bearer token parse → JWT signature/claims validation → mode-specific backend checks:

- `ModeJWTOnly`: token-only checks.
- `ModeHybrid`: token-only (stateless, zero Redis) for routes resolved to Hybrid;
  individual routes opt into `ModeStrict` (Redis-backed checks) or `ModeJWTOnly`
  via the `Validate` route mode or middleware. An explicit route mode always wins
  over the engine default.
- `ModeStrict`: Redis/session check for every request.

Then permission bit checks are evaluated with O(1) mask operations.

## Security behavior

- Strict mode fails closed on backend validation failures.
- Permission bits are assigned/frozen at build-time; no runtime remapping.

## Performance notes

- Fixed-size masks (`64/128/256/512`) avoid dynamic growth.
- Hot path remains DB-free.
- Permission/role lookup maps are read lock-free after `Build()` freezes registry and role manager state.
