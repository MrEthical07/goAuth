# Migrations

## v0.6.1 Migration Notes (Non-Breaking)

No action needed. v0.6.1 is a drop-in replacement for v0.6.0: no exported
API or config changed, and single-tenant deployments
(`MultiTenant.Enabled = false`) behave exactly as before.

With `MultiTenant.Enabled = true`, `VerifyBackupCode`,
`VerifyBackupCodeInTenant`, `ListWebAuthnCredentials`, and
`RemoveWebAuthnCredential` now resolve the user within the request's tenant
(the explicit `tenantID` for `VerifyBackupCodeInTenant`) before touching the
provider. If you expose these methods over HTTP, a user id from another
tenant now yields `ErrUserNotFound` (map it the way you already map
`ErrUserNotFound` from `ChangePassword` or the TOTP methods) instead of
whatever your provider happened to return. Same-tenant calls are unchanged.

## v0.6.0 Migration Notes (Non-Breaking)

v0.6.0 upgrades `github.com/go-webauthn/webauthn` from v0.17.4 to v0.18.2,
adds a rate limiter to `ChangePassword`'s old-password check plus the new
`VerifyPassword` method, and raises goAuth's minimum Go version. No goAuth
public signature was removed or changed; `gorelease -base=v0.5.1` reports no
incompatible changes. It is a minor bump rather than a patch because of the
Go version floor and the new exported method.

### Action required: raise your Go toolchain to 1.27+

From v0.6.0, goAuth supports the current Go major release only (Go 1.27)
and will raise its minimum again whenever a new Go major ships. This is a
maintainer policy choice, not a technical requirement of the go-webauthn
upgrade itself (which needs only Go 1.26.0). If your project builds with an
older toolchain, upgrade it before taking this release.

### Action required if you expose ChangePassword errors over HTTP

`ChangePassword`'s old-password check (and the new `VerifyPassword`) can now
return `ErrPasswordVerifyRateLimited` (`AUTH_PASSWORD_VERIFY_RATE_LIMITED`)
after repeated verification failures for the same user, using your existing
`Security.MaxLoginAttempts` / `Security.LoginCooldownDuration` thresholds —
no new config field to set. Like every other `AUTH_*_LIMITED` code, map it
to `429 Too Many Requests` if your HTTP layer doesn't already fall through
to the generic abuse-category mapping. This never triggers account
auto-lockout.

### No action needed if you don't use WebAuthn

If `Config.WebAuthn.Enabled` is false, the go-webauthn upgrade changes
nothing observable for you beyond the Go version floor above.

### No action needed if you do use WebAuthn

- **Credentials your users have already registered keep working.** Proven
  against fixtures captured from an actual v0.17.4 ceremony — see the
  changelog's rolling-deploy notes.
- **A rolling deploy across this upgrade is not expected to break
  in-flight ceremonies, in either direction.** goAuth requests no WebAuthn
  extensions and pins `ExtensionsUnsolicitedOutputPolicyIgnore`, so a
  ceremony begun on an old instance and finished on a new one decodes and
  completes normally — and the reverse (begun on a new instance, finished
  on an old one, the rollback case) does too, proven directly rather than
  assumed. This is a stronger guarantee than go-webauthn's own upgrade
  guide describes for the general case, specific to goAuth never
  requesting extensions or binding a ceremony to one origin.
- **`BeginWebAuthnRegistration`/`BeginWebAuthnLogin` output is unchanged**
  apart from the always-random per-ceremony challenge — including the
  algorithm list (`pubKeyCredParams`): go-webauthn v0.18's new
  post-quantum algorithms are opt-in only, and goAuth doesn't opt in.

### Optional: adopt `VerifyPassword`

If you re-implement a "confirm your password" check before a sensitive
action (removing a security key, disabling MFA, deleting an account),
`Engine.VerifyPassword(ctx, userID, password) error` does the same
tenant-scoped lookup and Argon2 check `ChangePassword` uses, with no state
change, sharing its new rate limiter. Nothing changes if you don't call it.

### Worth knowing

- If `Config.WebAuthn.RPID` is an IP address or otherwise not a valid
  domain string (for example, a Docker container IP used in local
  development), `Build()` now fails immediately with a readable message
  instead of the ceremony failing later at the client. Use `localhost` for
  local development against this library.
- A WebAuthn response whose `id` and `rawId` disagree, or that omits
  `rawId`, is now rejected. No legitimate client produces such a response;
  this closes a gap rather than tightening anything a real authenticator
  could trip.

## v0.5.1 Migration Notes (Non-Breaking)

No action needed. v0.5.1 is a drop-in replacement for v0.5.0: no public
signature changed, and the only new exported names are the sentinel
`ErrTOTPAlreadyEnabled` and the error code `AUTH_TOTP_ALREADY_ENABLED`.

The one observable behavior change: calling `GenerateTOTPSetup` /
`ProvisionTOTP` for a user who already has TOTP enabled now returns
`ErrTOTPAlreadyEnabled` instead of silently generating and persisting a
replacement secret (see the Security entry in the changelog). If your
integration ever called setup again for an already-enrolled user expecting
it to rotate the secret, switch that call to `DisableTOTP` followed by
`GenerateTOTPSetup`/`ProvisionTOTP` + `ConfirmTOTPSetup`. Setup for a user
who has never enrolled, or who started but never confirmed a previous setup,
behaves exactly as before.

Consumers who expose TOTP setup over HTTP should map `ErrTOTPAlreadyEnabled`
(`AUTH_TOTP_ALREADY_ENABLED`) to `409 Conflict`.

## v0.5.0 Migration Notes (Non-Breaking)

v0.5.0 is additive: no config fields were renamed or removed, no public
signatures changed, and one optional interface was added. Every behavior
change is gated on `MultiTenant.Enabled`, which defaults to `false` and is not
set by any shipped preset.

### Single-tenant deployments: no action needed

If `MultiTenant.Enabled` is false — the default — nothing changes. User lookup
stays tenant-blind, reset and verification records bind exactly as before, and
your existing `UserProvider` needs no new methods. Upgrade and move on.

### Multi-tenant deployments: required work

If you run more than one tenant, v0.5.0 fixes three cross-tenant
vulnerabilities (see the Security section of the changelog), and opting in is
required to get them:

1. **Implement `TenantAwareUserProvider`** on your existing provider —
   `GetUserByIdentifierInTenant` and `GetUserByIDInTenant`, both scoping the
   query to the given `tenant_id` in the database and returning not-found for
   records in other tenants.
2. **Populate `UserRecord.TenantID`** correctly on every returned record.
3. **Attach the tenant to every request context** with `WithTenantID`.
4. **Set `MultiTenant.Enabled = true`.** `Builder.Build()` fails with a clear
   message if step 1 was missed, so a misconfiguration cannot start.

See [multi_tenancy.md](multi_tenancy.md) for the full contract and examples.

### Caveats when turning multi-tenancy on

- **In-flight reset and verification links.** Records now bind to the
  request's tenant rather than the resolved user's. Where those differed,
  links issued before the switch may not resolve afterwards. Drain the reset
  and verification TTL window first, or accept that affected users
  re-request.
- **Cross-tenant user ids are now rejected.** Administrative calls that pass a
  bare `userID` (change password, account status transitions, backup codes,
  TOTP, WebAuthn) resolve within the context tenant only. Any caller relying
  on acting across tenants with a single context must set the correct tenant
  per call.
- **Deprecation warnings.** `MultiTenant.EnforceIsolation` and
  `MultiTenant.TenantHeader` are no-ops and now warn when set;
  `Account.AllowDuplicateIdentifierAcrossTenants` is documented as a
  provider-owned contract. No field was removed — clearing them is optional
  and changes nothing.

## v0.4.0 Migration Notes (Non-Breaking)

v0.4.0 is additive: no config fields were renamed or removed and no public
signatures changed. Existing configurations resolve to identical session
lifetimes. Three behavior changes are worth reviewing:

1. **Expired-token logout now succeeds.** `LogoutByAccessToken` with an
   expired-but-authentic access token destroys the session and returns nil
   instead of `ErrTokenInvalid`. Callers that branched on `ErrTokenInvalid`
   for expired tokens during logout should treat nil as the success it is.
   Forged/invalid tokens are still rejected.
2. **Explicit `ModeHybrid` route overrides are now valid.**
   `Validate(ctx, token, ModeHybrid)` and `middleware.Guard(engine,
   ModeHybrid)` previously failed every request with `ErrInvalidRouteMode`;
   they now validate statelessly. An explicit route mode always wins over the
   engine mode — audit route wiring so no route unintentionally downgrades a
   Strict engine (see [security.md](security.md)).
3. **Rolling-deploy caveat.** MFA login challenges written by v0.4.0 use a
   v2 record; binaries older than v0.4.0 cannot decode them during the
   (≤ 3 minute) challenge TTL window of a mixed-version deploy. Deploy all
   instances before relying on new MFA challenges, or accept a brief window
   of failed MFA confirmations on old instances.

Optional opt-ins added in v0.4.0 (no action needed to keep current behavior):
`Session.MaxSessionDuration` + `LoginOptions.RememberMe`,
`Security.LimiterWindowMode = "sliding"`, `JWT.VerifyKeys` key rotation, and
`Config.WebAuthn`. Switching `LimiterWindowMode` to `"sliding"` effectively
resets in-flight rate-limit windows (counters move to new bucket keys).

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
| `PasswordReset.EnableIPThrottle` | `PasswordReset.EnableRequestLimiter` | New field is request-phase specific. Legacy password-reset throttles were not phase-specific, so when migrating an enabled flow, you must enable both `EnableRequestLimiter` and `EnableConfirmFailureLimiter` if either legacy throttle had been enabled. |
| `PasswordReset.EnableIdentifierThrottle` | `PasswordReset.EnableConfirmFailureLimiter` | New field is confirm-failure-phase specific. Legacy password-reset throttles were not phase-specific, so when migrating an enabled flow, you must enable both `EnableRequestLimiter` and `EnableConfirmFailureLimiter` if either legacy throttle had been enabled. |
| `EmailVerification.EnableIPThrottle` | `EmailVerification.EnableRequestLimiter` | New field is request-phase specific. Legacy email-verification throttles were not phase-specific, so when migrating an enabled flow, you must enable both `EnableRequestLimiter` and `EnableConfirmFailureLimiter` if either legacy throttle had been enabled. |
| `EmailVerification.EnableIdentifierThrottle` | `EmailVerification.EnableConfirmFailureLimiter` | New field is confirm-failure-phase specific. Legacy email-verification throttles were not phase-specific, so when migrating an enabled flow, you must enable both `EnableRequestLimiter` and `EnableConfirmFailureLimiter` if either legacy throttle had been enabled. |
| `Account.EnableIPThrottle` | `Account.EnableCreationLimiter` | Account creation limiter toggle. |
| `Account.EnableIdentifierThrottle` | removed | Covered by `EnableCreationLimiter`. |

Validation behavior is stricter for enabled reset/verification flows:

- `PasswordReset.EnableRequestLimiter` and `PasswordReset.EnableConfirmFailureLimiter` must both be `true` when password reset is enabled; do not treat the legacy throttle fields as separate per-phase opt-ins during migration.
- `EmailVerification.EnableRequestLimiter` and `EmailVerification.EnableConfirmFailureLimiter` must both be `true` when email verification is enabled; do not treat the legacy throttle fields as separate per-phase opt-ins during migration.

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

Where all dynamic segments (`{tenant}`, `{identifier}`, `{userID}`, `{resetID}`, `{verificationID}`, etc.) are SHA-256 hashed and hex-encoded, so keys have a fixed-length, collision-free format regardless of the input value.

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
