# Module: Role Switching

## Purpose

An account can hold more than one role (a teacher who is also an
administrator, a support agent who can act as a customer admin). Role
switching lets one authenticated session change which role it is acting as,
without logging in again, and without the new role ever being asserted by the
client.

`Engine.SwitchRole` replaces the caller's session with a new one that carries
the target role and its permission mask, and returns a fresh token pair. The
provider decides whether the account may hold the role; goAuth decides
everything else: that the session is genuine, that the proof the target role
demands has been given, and that the swap is atomic.

The feature is off by default. With it off, behavior is byte-for-byte what it
was before it existed: the same session bytes in Redis, the same access-token
claims, the same errors, audit events and metrics, and no extra Redis or
provider calls.

> **Read [the revocation table](#revocation-guarantee-per-validation-mode)
> before enabling this.** Role switching is only safe on routes validated in
> `ModeStrict`. Every route that gates on role or permissions must resolve to
> `ModeStrict`.

## Quick start

```go
cfg := goAuth.DefaultConfig()
cfg.RoleSwitch.Enabled = true
cfg.RoleSwitch.StepUp = map[string]goAuth.RoleStepUpPolicy{
    "admin": {RequireMFA: true},
}

engine, err := goAuth.New().
    WithConfig(cfg).
    WithRedis(rdb).
    WithPermissions(perms).
    WithRoles(roles).
    WithUserProvider(provider). // must implement goAuth.RoleSwitchProvider
    Build()

res, err := engine.SwitchRole(ctx, refreshToken, "admin", goAuth.RoleSwitchOptions{})
```

## Configuration

`Config.RoleSwitch` (zero value = disabled):

| Field | Meaning |
|-------|---------|
| `Enabled` | Turns the feature on. When `false`, `SwitchRole` returns `ErrRoleSwitchDisabled` and changes nothing. |
| `StepUp` | Map of **target role** to `RoleStepUpPolicy`. A target role with no entry needs no proof beyond the provider's permission. Keys must be registered roles. |
| `MaxAttempts` | Switch attempts one session may make within `Cooldown`. Zero selects the default of **10**. |
| `Cooldown` | Rate-limit window. Zero selects the default of **15 minutes**. |

`RoleStepUpPolicy`:

| Field | Meaning |
|-------|---------|
| `RequireMFA` | The session must hold a second-factor assurance (see [Step-up](#step-up)). |
| `MaxAge` | When `> 0`, how recent the proof must be. With `RequireMFA`, the age of the second-factor assurance. Without it, "recent authentication": the newer of the session's creation time and its last proof must be within `MaxAge`. Zero means no age limit. |

Validation (all build errors):

- `StepUp` keys must be registered roles.
- `MaxAge`, `MaxAttempts` and `Cooldown` must be `>= 0`.
- `RequireMFA` on any role requires `TOTP.Enabled` or `WebAuthn.Enabled`.
- `RoleSwitch.Enabled` requires the user provider to implement
  `RoleSwitchProvider` (below).

Lint: enabling `RoleSwitch` with `ValidationMode` `ModeJWTOnly` or
`ModeHybrid` produces the info-level warning `role_switch_stateless_validation`,
pointing at the revocation table below. The config presets are unchanged.

## The provider contract

```go
type RoleSwitchProvider interface {
    // CanAssumeRole reports whether userID, in tenantID, currently holds role.
    // It MUST return true for the account's primary role as well as any
    // other role it holds. goAuth always passes the tenant it resolved
    // itself, never a caller-supplied one.
    CanAssumeRole(ctx context.Context, tenantID, userID, role string) (bool, error)
}
```

It is an optional capability detected by type assertion at `Builder.Build()`,
exactly like `WebAuthnCredentialProvider` and `TenantAwareUserProvider`.
Enabling role switching without it fails the build:

```
RoleSwitch is enabled but the user provider does not implement RoleSwitchProvider
```

**It must return `true` for the primary role.** goAuth calls it in two places:

1. when a session switches into a role, and
2. on every refresh while role switching is enabled, to confirm the role the
   session currently carries is still held (see [Refresh](#refresh-semantics)).
   That includes sessions that never switched, whose role is the primary one.

A provider that answers `false` for the primary role therefore ends every
session at its next refresh.

Return `(false, nil)` for an unknown user or an unheld role. Return an error
only for a backend failure; goAuth reports that as `ErrSystemUnavailable`
without changing anything.

The same split applies to the account lookup `SwitchRole` performs
(`GetUserByID` / `GetUserByIDInTenant`): **return `goAuth.ErrUserNotFound` for a
missing user** and any other error for a backend failure. Only `ErrUserNotFound`
(including goAuth's own tenant-mismatch backstop, which already returns it)
means the account is gone and is reported as `ErrSessionNotFound`. A provider
that returns a plain error for a missing user is indistinguishable from an
outage and gets `ErrSystemUnavailable`.

**Why a yes/no check and not an `AllowedRoles(userID) []string` list.** There
is nothing to enumerate and no list to keep consistent with the role registry;
the provider answers the one question goAuth has. The same call serves both
the switch and the refresh re-check, where a list would have to be fetched and
searched every time.

## API

```go
type RoleSwitchOptions struct {
    MFAType  string // optional inline step-up: "totp" or "backup_code"
    MFACode  string
    Password string // satisfies a recent-authentication policy
}

type RoleSwitchResult struct {
    AccessToken, RefreshToken string
    Role                      string
    StepUpRequired            bool     // only together with ErrStepUpRequired
    StepUpFactors             []string // e.g. ["totp","backup_code"] or ["password"]
}

func (e *Engine) SwitchRole(ctx context.Context, refreshToken, targetRole string, opts RoleSwitchOptions) (*RoleSwitchResult, error)
```

- The session is identified by the **refresh token**, the same proof
  `Refresh` uses. Spending it makes a switch single-use.
- The **tenant comes from the request context** (`WithTenantID`), like
  `Refresh`. There is deliberately no tenant-explicit variant: `Refresh` has
  none, and a caller-supplied tenant would contradict the design.
- The result is non-nil only on success, or alongside `ErrStepUpRequired`.
  Every other failure returns `nil` and an `*AuthError`.
- The new session keeps the old session's `CreatedAt` and `ExpiresAt`, so
  repeated switches never extend a session past its absolute lifetime or
  `MaxSessionDuration`. This holds for remember-me sessions too.
- Other sessions of the same user are never touched.
- A switch does not run login-time `SessionHardening` checks: the user's
  session count and the tenant counter are unchanged (one out, one in).

## Algorithm

All failures leave the old session untouched unless stated.

1. Disabled → `ErrRoleSwitchDisabled`.
2. Decode the refresh token. Failure → `ErrRefreshInvalid`, as `Refresh` does.
3. Reserve a limiter slot keyed by (request tenant, decoded session ID),
   atomically and before any provider, Argon2 or session work. Wrong-tenant
   and unknown sessions consume slots too. Limited → `ErrRoleSwitchRateLimited`
   and the provider is never called. The limiter honors
   `Security.LimiterWindowMode` and fails open on Redis errors, like the
   other limiters.
4. Load the session read-only from the **request** tenant.
   - Missing → `ErrSessionNotFound`. Expired → the same handling as `Refresh`
     (the session is deleted, `ErrSessionNotFound`).
   - The presented secret is compared in constant time with the session's
     refresh hash. On a mismatch the existing rotation script is invoked with
     the presented hash, so it atomically deletes the session exactly as
     `Refresh` does; the result is `ErrRefreshReuse`, with the same metrics,
     replay tracking and `refresh_reuse_detected` audit event, plus
     `role_switch_failed` with reason `reuse_detected`.
   - Device binding is validated against the request when enabled, the same
     way strict validation does (`ErrDeviceBindingRejected`; the session is
     kept).
5. Target equals the session's current role → `ErrRoleSwitchSameRole`. It is
   an error, not a no-op.
6. Target is not a registered role → `ErrRoleNotAllowed`. The provider is not
   called and the role's absence is not revealed.
7. Resolve the account through the tenant-scoped lookup with the **session's**
   tenant. `ErrUserNotFound`, or a record from another tenant (a provider that
   ignores the tenant predicate) → `ErrSessionNotFound`. Any other lookup error
   is a provider failure → `ErrSystemUnavailable` (503, reason `unavailable`);
   the session is not deleted and the same refresh token works on retry, like
   the refresh role re-check. A non-active account
   status deletes the session and returns the status error; a
   pending-verification account is handled as `Refresh` does.
8. `CanAssumeRole(sessionTenant, userID, targetRole)`: `false` →
   `ErrRoleNotAllowed`; an error → `ErrSystemUnavailable`, nothing changes.
9. [Step-up](#step-up) check for the target role. Unsatisfied →
   `ErrStepUpRequired`, nothing switches.
10. Build the new session: a fresh session ID and refresh secret; same user
    and tenant; the target role and its mask; permission, role and account
    versions from the freshly resolved account (account version `0` becomes
    `1`, as at login); status from the account; IP and User-Agent hashes
    copied; `CreatedAt` and `ExpiresAt` **copied**.
11. One atomic Lua script swaps the sessions. It re-reads the old session and
    applies exactly the rotation script's checks in the same order (missing,
    expired, refresh-hash mismatch, remaining TTL), with the same side
    effects on the failing branches. Then it refuses to overwrite a live
    session: a replacement ID that is already in use (`session.ErrSessionIDInUse`,
    impossible for the random IDs `SwitchRole` generates) changes nothing and is
    reported as `ErrSystemUnavailable`. Only when every check passes does it delete
    the old session, write the new one with the old session's **remaining
    absolute lifetime**, swap the user-index entry, and move or write the
    assurance key. There is no separate "conflict" outcome: a switch that
    loses a race behaves exactly like a second refresh that loses it.
12. Issue the access token from the new session and encode the refresh token
    (both built before the swap, so a failure cannot strand the caller),
    emit `role_switched`, and reset the limiter.

The only in-place writers of a live session blob elsewhere in goAuth are
refresh-hash rotation and schema migration. Rotation is a script and so is
atomic with the swap. Schema migration (a one-time upgrade of pre-v5 session
blobs on read) used to rewrite the blob with a plain `SET` after a separate
read; it now uses `SET ... XX`, so it can no longer recreate a session that a
switch, logout or reuse revocation deleted in between.

## Refresh semantics

- **A switched role survives refresh.** Refresh never reads the provider for
  the role; it rotates the refresh hash and issues the access token from the
  stored session.
- **Re-check (only while role switching is enabled).** Before rotating, the
  engine reads the session read-only and, **only if it exists, has not
  expired and the presented token matches**, calls
  `CanAssumeRole(sessionTenant, userID, session.Role)`.
  - `false`: the session is **deleted**, the refresh-failure audit
    (`refresh_invalid`) is emitted with reason `role_revoked`, and `Refresh`
    returns `ErrRoleNotAllowed`. The session ends; there is no fallback to the
    primary role.
  - provider error: nothing is rotated and nothing is deleted; `Refresh`
    returns `ErrSystemUnavailable` (audit reason `role_check_unavailable`).
    The same refresh token still works on retry.
  - In every other case (session missing, expired, or token mismatching) the
    re-check is skipped and the normal rotation runs unchanged, so reuse
    detection and deletion behave exactly as without role switching.
- **Cost.** One extra Redis `GET` and **one provider call per refresh** while
  enabled, covering primary-role sessions too. Validation still makes **zero**
  provider calls, in every mode.
- When role switching is disabled the refresh path is untouched: no extra
  reads, no provider calls.

## Step-up

`StepUp[targetRole]` demands proof before a session may take that role.

**Assurance.** A session's proof is stored *outside* the session blob, in the
Redis key `asa:<tenant>:<sessionID>` (value: MFA time, MFA method, last-proof
time), so session bytes never change. Its TTL is the session's remaining
absolute lifetime. It is written **only** when `StepUp` is non-empty:

- on every path that issues a session after a successful second factor:
  `ConfirmLoginMFA`, `ConfirmLoginMFAWithType` (TOTP, backup code, WebAuthn),
  `LoginWithTOTP` and `LoginWithBackupCode`;
- on a successful inline step-up.

The swap script moves it to the new session ID. An assurance left behind by a
logout simply expires by its TTL. With no `StepUp` configured no `asa:` key is
ever written.

**Sessions created before step-up was configured have no assurance.** A
`RequireMFA` policy asks them for an inline proof (or a fresh MFA login).

**Policies.**

| Policy | Satisfied by |
|--------|--------------|
| `{RequireMFA: true}` | an MFA assurance, of any age |
| `{RequireMFA: true, MaxAge: d}` | an MFA assurance newer than `d` |
| `{MaxAge: d}` | "recent authentication": the newest of the session's creation time, its MFA assurance and its last password proof is within `d` |
| `{}` | always |

**Inline factors.** Supply them in `RoleSwitchOptions` when the session does
not already satisfy the policy.

- `MFAType: "totp"` or `"backup_code"` with `MFACode`. The failures are the
  existing errors (`ErrTOTPInvalid`, `ErrBackupCodeInvalid`, ...) and count in
  their own limiters. Backup codes use the tenant-scoped path. A user who has
  no TOTP configured gets `ErrTOTPNotConfigured`; an unenrolled factor is
  never accepted as proof. A success records a new assurance at the current
  time, which the new session carries, so later switches within the policy
  need no further proof.
- `Password`, for a recent-authentication policy only
  (`RequireMFA: false`, `MaxAge > 0`). It goes through the `VerifyPassword`
  path and its limiter (`ErrInvalidCredentials`, `ErrPasswordVerifyRateLimited`).
  It records recent authentication, never an MFA assurance, and keeps any MFA
  assurance the session already held.
- Anything else (unknown type, a type without a code, a password for an MFA
  policy) does not satisfy the policy.

When the proof is missing the result is `ErrStepUpRequired` with
`StepUpRequired: true` and `StepUpFactors` listing the inline factors the user
**actually has**: `["totp","backup_code"]` (TOTP enabled, unused backup codes
present), `["totp"]`, `["password"]` for a recent-authentication policy, or an
empty slice when only a fresh MFA login can satisfy the policy.

**Out of scope: WebAuthn as an inline step-up factor.** A session created by
a fresh WebAuthn MFA login carries an assurance and satisfies `RequireMFA`,
but a WebAuthn ceremony cannot be supplied inline to `SwitchRole`. Inline
WebAuthn is a planned follow-up.

All checks that can fail for reasons unrelated to the proof (same role,
unknown role, the provider's answer) run first, so a proof is never consumed
for a switch that could not have succeeded.

## Revocation guarantee per validation mode

What happens to the **old** tokens after a successful switch:

| | Old refresh token | Old access token |
|---|---|---|
| Any mode | **Dead immediately.** Presenting it gives `ErrSessionNotFound` (the old session ID no longer exists). It does **not** trigger reuse handling, because there is no session left to revoke. | see below |
| Route resolves to **`ModeStrict`** | | **Rejected on its next use** (`ErrSessionNotFound`). If Redis is down, strict rejects *every* token (fail closed). |
| Route resolves to **`ModeHybrid`**, Redis healthy | | **Still accepted until it expires.** The result carries the **old** mask and `Role` is empty (hybrid never sets it). Hybrid never reads Redis. |
| Route resolves to **`ModeHybrid`**, Redis failing | | **Identical to healthy hybrid.** There is no fallback path; hybrid never touches Redis. |
| Route resolves to **`ModeJWTOnly`** | | **Identical to hybrid.** |

Worst-case exposure on hybrid and JWT-only routes is the remaining access
token lifetime, at most `JWT.AccessTTL`. After that every mode rejects it.

**Conclusion.** Role switching is only safe on routes validated with
**`ModeStrict`**. Any route that gates on role or permissions must resolve to
`ModeStrict`. An explicit per-route `ModeStrict` on a hybrid engine is
sufficient; the engine default does not matter. Hybrid is not sufficient,
whether Redis is healthy or not.

The access token carries no role claim: the role lives in the session, and the
token carries the mask. `RoleVersion` stays consistent: the new session and
token carry the provider's current `RoleVersion`, and the version check
compares claim to session. Nothing can be resurrected: the old session is
deleted atomically and the new session ID is random. No public `RoleVersion`
bump is added.

These guarantees are pinned by tests, one per row.

## Race and reuse semantics

goAuth's replay protection is unchanged. These are the exact outcomes:

- **Refresh, then a switch presenting the pre-refresh (already rotated)
  token:** reuse. The session is deleted, the switch returns `ErrRefreshReuse`,
  and the client is logged out of that session.
- **A switch, then a refresh presenting the pre-switch token:**
  `ErrSessionNotFound` (the old session no longer exists). The client must use
  the tokens the switch returned.
- **A truly concurrent switch and refresh with the same token:** exactly one
  wins the compare-and-swap. The loser sees a mismatch: the session is
  deleted as reuse (`ErrRefreshReuse`) if the refresh won first, or it is
  not-found (`ErrSessionNotFound`) if the switch won first. There is never a
  second live session and no orphan index entry.
- **Two concurrent switches with the same token:** exactly one wins; the other
  gets `ErrSessionNotFound`.

Clients must serialize refresh and switch per session (single-flight) and
always use the most recently returned refresh token.

## Rate limiting

Switch attempts are limited per (tenant, session) with `MaxAttempts` per
`Cooldown` (defaults 10 / 15 minutes), using the shared window primitive (so
`Security.LimiterWindowMode` applies). The slot is claimed atomically before
any provider, Argon2 or session work, so a burst cannot exceed the limit.
Every attempt that reaches the limiter counts, including wrong-tenant and
unknown sessions. A successful switch resets the counter. Redis errors fail
open (`limiter_fail_open` audit event).

## Audit events

| Event | When |
|-------|------|
| `role_switched` | A switch succeeded. User, tenant, new session ID; metadata `from_role`, `to_role`, `old_session_id`, `new_session_id`, and `step_up` (`totp`, `backup_code`, `password` or `session_assurance`) when the target role had a policy. |
| `role_switch_failed` | A switch failed; `metadata.reason` is one of the values below, and `Error` carries the audit error code. |
| `refresh_reuse_detected` | Additionally, when a switch presents a reused refresh token (the same event `Refresh` emits). |
| `refresh_invalid` (reason `role_revoked`) | `Refresh` found the session's role revoked and ended the session. |
| `refresh_invalid` (reason `role_check_unavailable`) | The refresh re-check could not reach the provider. |

`role_switch_failed` reasons:

| Reason | Cause |
|--------|-------|
| `disabled` | `RoleSwitch.Enabled` is false |
| `invalid_session` | undecodable token, missing/expired/unknown session, an account the provider reports as `ErrUserNotFound` or a foreign-tenant account, or a device-binding rejection |
| `reuse_detected` | the presented token was not the session's current one |
| `same_role` | target equals the current role |
| `not_allowed` | unregistered target role, or the provider said no |
| `step_up_required` | the policy is unsatisfied, or an inline proof failed |
| `rate_limited` | the attempt budget is exhausted |
| `account_status` | the account is disabled, locked, deleted or pending verification |
| `unavailable` | the provider (`CanAssumeRole` or the account lookup), Redis or token issuance failed |

No metric IDs were added. A switch books the existing limiter-check metric,
and reuse books the same three metrics as `Refresh` (`refresh_reuse_detected`,
`replay_detected`, `session_invalidated`). Metrics output is unchanged when
the feature is unused.

## Errors and HTTP mapping

| Error | Code | Category | Suggested status |
|-------|------|----------|------------------|
| `ErrRoleSwitchDisabled` | `AUTH_ROLE_SWITCH_DISABLED` | `AUTH_STATE` | `403` (or `404` if you do not expose the route when disabled) |
| `ErrRoleNotAllowed` | `AUTH_ROLE_NOT_ALLOWED` | `AUTH_STATE` | `403` |
| `ErrStepUpRequired` | `AUTH_STEP_UP_REQUIRED` | `AUTH_STATE` | `403`, with `StepUpFactors` in the body |
| `ErrRoleSwitchSameRole` | `AUTH_ROLE_SWITCH_SAME_ROLE` | `AUTH_VALIDATION` | `409` |
| `ErrRoleSwitchRateLimited` | `AUTH_ROLE_SWITCH_RATE_LIMITED` | `AUTH_ABUSE` | `429` |
| `ErrRefreshReuse` | `AUTH_REFRESH_REUSE_DETECTED` | `AUTH_ABUSE` | `401` (the session is gone; log in again) |
| `ErrSessionNotFound` | `AUTH_SESSION_EXPIRED` | `AUTH_STATE` | `401` |
| `ErrRefreshInvalid` | `AUTH_REFRESH_INVALID` | `AUTH_VALIDATION` | `401` |
| `ErrSystemUnavailable` | `SYSTEM_UNAVAILABLE` | `SYSTEM` | `503` (provider, account-lookup or Redis failure; the session is untouched, retry with the same token) |

Decode, not-found, expired and reuse cases return **exactly** the errors
`Refresh` returns for them; no new sentinels were added for them. Inline
step-up failures return the existing factor errors (`ErrTOTPInvalid`,
`ErrTOTPRateLimited`, `ErrTOTPNotConfigured`, `ErrBackupCodeInvalid`,
`ErrInvalidCredentials`, `ErrPasswordVerifyRateLimited`, ...). `Refresh`
additionally returns `ErrRoleNotAllowed` when the re-check finds the
session's role revoked.

For the switch endpoint a reused token is mapped to `401` rather than the
generic `429` suggested for abuse codes in [error-model.md](error-model.md):
the client's session no longer exists, which is what a `401` tells it.

## Recommended client flow

1. Keep exactly one in-flight refresh-or-switch per session (single-flight).
   Queue other callers behind it.
2. After every successful refresh or switch, **store the returned token pair
   immediately** and discard the old one.
3. Call `SwitchRole` with the stored refresh token; on success use the
   returned pair. On `ErrStepUpRequired`, prompt for one of `StepUpFactors`
   and call again with the proof; the refresh token was not spent.
4. If an in-flight request fails with `401` while a refresh or switch was
   running, **re-read the stored tokens and retry once only if they changed**.
   Do not retry with the token you started with: presenting a pre-refresh
   token after a refresh is refresh-token reuse and ends the session.
5. Route every endpoint that gates on role or permissions through `ModeStrict`
   (see the [table](#revocation-guarantee-per-validation-mode)).

## Operational notes

- Redis keys added: `asa:<tenant>:<sessionID>` (only with `StepUp`
  configured) and `rl:roleswitch:<tenant>:<sessionID>` (the limiter).
- The swap script, like the existing rotation script, touches keys in more
  than one hash slot, so it needs a single-node or non-sharded deployment.
- A switch costs one `GET` (read), one limiter script, the provider call(s) it needs (`CanAssumeRole`, plus the account lookup), one swap script, and one extra `GET` for the assurance when the target role has a step-up policy.

## Related

- [flows.md](flows.md), [session.md](session.md), [mfa.md](mfa.md)
- [multi_tenancy.md](multi_tenancy.md) — the tenant is read from the context
  with `WithTenantID` and can be read back with `TenantIDFromContext`
- [error-model.md](error-model.md), [audit.md](audit.md), [config.md](config.md)
