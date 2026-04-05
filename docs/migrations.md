# Migrations

## v0.3.0 Migration Guide (Breaking)

This release introduces breaking config, limiter, and error-model changes.

### 1. Update Configuration Fields

Apply the following renames/removals:

| Old field | New field | Notes |
|-----------|-----------|-------|
| `Security.EnableIPThrottle` | `Security.EnableLoginFailureLimiter` | Login abuse gate changed from IP-oriented naming to failure-limiter naming. |
| `Security.EnableRefreshThrottle` | removed | Refresh throttle path removed in v0.3.0. |
| `Security.MaxRefreshAttempts` | removed | No replacement. |
| `Security.RefreshCooldownDuration` | removed | No replacement. |
| `PasswordReset.EnableIPThrottle` | `PasswordReset.EnableRequestLimiter` | Request-phase limiter toggle. |
| `PasswordReset.EnableIdentifierThrottle` | `PasswordReset.EnableConfirmFailureLimiter` | Confirm-failure limiter toggle. |
| `EmailVerification.EnableIPThrottle` | `EmailVerification.EnableRequestLimiter` | Request-phase limiter toggle. |
| `EmailVerification.EnableIdentifierThrottle` | `EmailVerification.EnableConfirmFailureLimiter` | Confirm-failure limiter toggle. |
| `Account.EnableIPThrottle` | `Account.EnableCreationLimiter` | Account creation limiter toggle. |
| `Account.EnableIdentifierThrottle` | removed | Covered by `EnableCreationLimiter`. |

Validation behavior is stricter for enabled reset/verification flows:

- `PasswordReset.EnableRequestLimiter` and `PasswordReset.EnableConfirmFailureLimiter` must both be `true` when password reset is enabled.
- `EmailVerification.EnableRequestLimiter` and `EmailVerification.EnableConfirmFailureLimiter` must both be `true` when email verification is enabled.

### 2. Error Handling Migration

Public engine failures now normalize to `*AuthError`.

- Continue using `errors.Is(err, goAuth.ErrXxx)` for stable sentinel checks.
- Add `errors.As(err, &ae)` when you need structured `Category` + `Code`.
- `ErrRefreshRateLimited` is removed; refresh rate limiting is no longer part of the public contract.

Recommended boundary check pattern:

```go
var ae *goAuth.AuthError
if err != nil && errors.As(err, &ae) {
	// ae.Category, ae.Code
}
```

### 3. Limiter Behavior and Keyspace

Limiter keys now use tenant-scoped `rl:*` namespaces.

Common examples:

- `rl:login:fail:{tenant}:{identifier}`
- `rl:account:req:{tenant}:{identifier}`
- `rl:reset:req:{tenant}:{identifier}`
- `rl:reset:confirm:fail:{tenant}:{resetID}`
- `rl:verify:req:{tenant}:{identifier}`
- `rl:verify:confirm:fail:{tenant}:{verificationID}`
- `rl:totp:fail:{tenant}:{userID}`
- `rl:backup:fail:{tenant}:{userID}`

Legacy limiter keys are safe to leave in Redis because they are short-lived counters, but can be removed during maintenance windows if desired.

### 4. Runtime Policy Change (Fail-Open Wrappers)

Limiter backend outages now follow fail-open wrappers in runtime flow wiring:

- Explicit limiter denials still block requests.
- Limiter backend failures are audited and metered, then execution continues.

If your deployment expected fail-closed limiter behavior for backend outages, enforce that policy externally (gateway/WAF/rate-limit proxy) before rollout.

---

## Session Schema Migration Notes

goAuth stores Redis session blobs with an embedded schema byte (`Session.SchemaVersion`).

### Current behavior

- Current schema version: `5` (`session.CurrentSchemaVersion`)
- Unknown/future schema versions: fail closed with a clear decode error
- Legacy supported versions (`1-4`): decoded safely and migrated on read

### Read-time migration strategy

When a legacy session is read successfully:

1. It is decoded into the current `Session` model.
2. The store rewrites the same key using current schema encoding.
3. Existing Redis TTL is preserved (`PTTL` -> `SET ... PX`).

This allows rolling upgrades without forced global logout.

### Upgrade guidance

1. Deploy new library version.
2. Keep mixed traffic running; active sessions migrate naturally on access.
3. Monitor decode errors for unsupported schema versions.
4. If unsupported versions appear, treat as fail-closed and investigate source.

### Future schema changes

For future session layout changes:

1. Bump `session.CurrentSchemaVersion`.
2. Extend `Decode` to parse prior supported versions.
3. Keep migration-on-read for at least one major cycle.
4. Add/extend tests in `session/schema_version_test.go`.
