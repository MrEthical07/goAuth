# Module: Email Change

## Purpose

Let a signed-in user move their account to a new email address, proving they control it first. Opt-in (`Config.EmailChange`); with it off the engine behaves exactly as it did before the feature existed: no new Redis keys, no extra calls on any other path.

goAuth does not send mail. It issues a challenge, you deliver the code to the **new** address, and the user (or your confirm endpoint) hands it back.

```
signed-in user ── step-up ──▶ RequestEmailChange(userID, newEmail) ──▶ { VerificationID, Code }
                                                                           │ you send Code to the NEW address
user opens the link / types the code ──▶ ConfirmEmailChange(VerificationID, Code, opts)
                                              │  ▶ result.OldEmail: you SHOULD notify the old address
```

## API

```go
func (e *Engine) RequestEmailChange(ctx, userID, newEmail string) (*EmailChangeRequest, error)
func (e *Engine) ConfirmEmailChange(ctx, verificationID, code string, opts ConfirmEmailChangeOptions) (*EmailChangeResult, error)
func (e *Engine) CancelEmailChange(ctx, userID string) error

type EmailChangeRequest struct{ VerificationID, Code string }
type ConfirmEmailChangeOptions struct{ KeepSessionID string }
type EmailChangeResult struct{ UserID, OldEmail, NewEmail string; SessionsRevoked bool }
```

`userID` for Request and Cancel comes from the session, never from the request body. `VerificationID` is `<tenant>:<id>`: it carries the tenant, is safe to log, and may be handed to the browser. `Code` is a secret: send it to the new address, never log it. goAuth never writes it to the audit trail or its own logs.

### Request

1. Refused with `ErrEmailChangeDisabled` unless `EmailChange.Enabled`.
2. Rate limited per `(tenant, user)`: `RequestMaxAttempts` per `RequestCooldown` (default 5 per hour), honoring `Security.LimiterWindowMode` and `Security.LimiterFailClosed`. A denial is `ErrEmailChangeRateLimited`.
3. The user is resolved through the tenant-scoped lookup with the record-tenant backstop. Only `ErrUserNotFound` means "not found"; any other provider error is a 503.
4. The account must be **Active**. Pending, disabled, locked and deleted accounts get the matching status error (`ErrAccountUnverified`, `ErrAccountDisabled`, `ErrAccountLocked`, `ErrAccountDeleted`).
5. `newEmail` is trimmed and must be a bare address (no display name, angle brackets, whitespace or control characters, at most 254 bytes) and must differ, case-insensitively, from the current identifier: `ErrEmailChangeInvalid` otherwise. This is stricter than account creation, which only requires a non-empty identifier, because a code is about to be mailed to it.
6. **Whether `newEmail` already has an account is not checked**, so the call cannot be used to enumerate accounts: the result, the audit trail and the Redis footprint are the same for a taken and a free address. Uniqueness is enforced at confirm.
7. One change is pending per user: a new request replaces the old challenge.
8. The challenge record holds the tenant, the user, the **old** and **new** identifiers, the account's `AccountVersion` at request time, the attempt count and the code's hash. It lives for `VerificationTTL`.

### Confirm

1. The code is compared in constant time; each wrong attempt is counted, and the challenge is deleted when `MaxAttempts` run out. An unknown, expired or foreign challenge is `ErrEmailChangeInvalid`. The challenge belongs to the tenant its id carries; with multi-tenancy on, a caller whose context names a different tenant cannot use it.
2. The challenge is **one use**: a correct code deletes it. Any failure after that (stale, in use, status, provider outage) needs a new request.
3. The account is loaded again. It must still be Active, still at the `AccountVersion` the request saw and still have the identifier the request replaced; otherwise `ErrEmailChangeStale` ("something changed the account, start again").
4. The provider's `UpdateIdentifier` installs the new identifier with a compare-and-set (see below):
   - `ErrProviderDuplicateIdentifier` becomes **`ErrEmailInUse`**. Saying so is safe: the caller has just proved they own that address.
   - `ErrEmailChangeStale` passes through.
   - Any other error is a 503 (`ErrSystemUnavailable`).
5. Sessions: unless `KeepOtherSessions`, every session of the user is revoked **except** `opts.KeepSessionID`, when that is a live session of the same user and tenant (otherwise it is ignored and everything is revoked). The kept session stays in the user's index and in the tenant count; revoked sessions' MFA-proof keys go with them. If the change succeeded but the sessions could not be revoked, you get both the result and `ErrSessionInvalidationFailed`: the address did change, so notify and retry `LogoutAll`.
6. `EmailChangeResult.OldEmail` is the address that was replaced. **Your application SHOULD notify it**: it is the only way a previous owner (or the real owner of a hijacked account) learns the account moved.

### Cancel

`CancelEmailChange` deletes the user's pending challenge. It is idempotent and succeeds when nothing is pending.

## The provider contract

```go
type EmailChangeProvider interface {
    UpdateIdentifier(ctx context.Context, tenantID, userID, oldIdentifier, newIdentifier string) error
}
```

Optional capability, detected by type assertion at `Build` and required when `EmailChange.Enabled` (the build fails otherwise). It is tenant-scoped and must:

- **Compare-and-set**: set the identifier to `newIdentifier` only if it is currently `oldIdentifier`, atomically (one `UPDATE … WHERE id = ? AND tenant = ? AND identifier = ?`). Return `ErrEmailChangeStale` when it is not.
- **Enforce uniqueness** within the tenant, and return `ErrProviderDuplicateIdentifier` for a taken address. goAuth cannot enforce it: it does not query across accounts. Decide your collation (case-insensitive uniqueness is recommended; the identifier check in the engine for "same as current" is case-insensitive).
- **Bump `AccountVersion`** in the same statement.
- Return `ErrUserNotFound` when the user does not exist in the tenant.
- **Not touch external identity links.** They are keyed by `(provider, subject)`, not by email.

```sql
UPDATE users
   SET identifier = $4, account_version = account_version + 1
 WHERE tenant_id = $1 AND id = $2 AND identifier = $3;
-- 0 rows: re-read to tell "stale" from "not found"; a unique violation is a duplicate
```

## Interactions

| With | What happens |
|------|--------------|
| **External identities** | Links stay. A link is `(provider, subject)`, so signing in through it keeps working and keeps resolving to the same account. With `ExternalAuth.AutoLinkVerifiedEmail`, later auto-links match the **new** identifier (which was just proved) and no longer the old one; the old address becomes a free address. |
| **Password-less accounts** | They can change their email. The code mailed to the new address proves the new address, but nothing proves the *current user* is who they say: the application must step them up before calling `RequestEmailChange` (below). |
| **Pending email-verification challenges** for the old address | Refused after a change: `ConfirmEmailVerification*` returns `ErrEmailVerificationInvalid`. |
| **Password-reset challenges** issued to the old address | Refused after a change: `ConfirmPasswordReset*` returns `ErrPasswordResetInvalid`. |
| **`AccountVersion`** | The provider bumps it. It makes a *pending email change* stale if anything else changes the account in between. |
| **Sessions** | See Confirm, step 5. Strict validation is unaffected for kept sessions: sessions carry their own copy of the version. |

### How old challenges are invalidated

A reset or verification record holds only its user, secret hash, expiry, attempts and strategy: no identifier and no account version. The `AccountVersion` bump therefore does **not** stop an old reset code (a test pins this). With `EmailChange` enabled, a confirmed change writes a per-user marker (`aeci:<tenant>:<user>`, the change time) before the provider call and again right after it commits (so a code requested for the old address while the call ran is refused too; a failure of the second write is only logged), and the reset and verification confirm paths read it after consuming a record: a record whose issue time (its expiry minus the configured TTL) is at or before the marker is refused as invalid. The marker lives for the longer of the two TTLs plus an hour. It costs one `GET` on those two confirm paths while the feature is on, and nothing while it is off. Consequences: a code requested within the same second as the change is also refused (ask again); changing a TTL in the configuration shifts the computed issue time of codes already issued by the difference; a marker that cannot be read refuses the challenge (a 503) rather than guess.

## Step-up before you call it

goAuth does not enforce a re-authentication, and a stolen session should not be able to point the account at an attacker's address. Require a step-up for the **current user** in the same request that calls `RequestEmailChange` (and before link/unlink of external identities):

| The user has | Ask for |
|--------------|---------|
| A password | `Engine.VerifyPassword(ctx, userID, password)` |
| No password, but TOTP or backup codes | `Engine.VerifyTOTP(ctx, userID, code)` or `Engine.VerifyBackupCode(ctx, userID, code)` |
| No password and no second factor | A fresh external sign-in: a new ID token with a new nonce through `LoginWithExternalIdentity`; call `ValidateAccess` on the access token it returns and require `AuthResult.UserID` to equal the current user; `Logout` the session it created if you do not want it |

goAuth has no public "recent MFA" accessor (the assurance it keeps per session serves role-switch step-up only), so keep your own timestamp when you verify a factor. Do not use the new address's code as the step-up: it proves the new address, not the person. See also [external_identity.md](external_identity.md#link-unlink-list).

## Configuration

`Config.EmailChange` (zero value = disabled):

| Field | Default | Meaning |
|-------|---------|---------|
| `Enabled` | `false` | Turns the three methods on. Requires `EmailChangeProvider`. |
| `Strategy` | `VerificationToken` | Code format, the email-verification strategies (`VerificationToken`, `VerificationUUID`, `VerificationOTP`). The zero value is the same default as `EmailVerification`. |
| `OTPDigits` | 6 | Code length in OTP mode, 6 to 10. |
| `VerificationTTL` | 15m | Challenge lifetime, 1m to 24h; at most 15m in OTP mode. |
| `MaxAttempts` | 5 | Confirm attempts per challenge, at most 65535; at most 5 in OTP mode. |
| `RequestMaxAttempts` | 5 | Requests per user per `RequestCooldown`. |
| `RequestCooldown` | 1h | Window for `RequestMaxAttempts`. |
| `KeepOtherSessions` | `false` | When `false`, a confirmed change revokes every session except `KeepSessionID`. Lint `email_change_keeps_other_sessions` (INFO) when on. |

`Build` fails when `Enabled` and the user provider does not implement `EmailChangeProvider`, or a bound is violated.

## Errors

| Sentinel | Code | Category | Suggested HTTP |
|----------|------|----------|----------------|
| `ErrEmailChangeDisabled` | `AUTH_EMAIL_CHANGE_DISABLED` | state | 403 |
| `ErrEmailChangeInvalid` | `AUTH_EMAIL_CHANGE_INVALID` | validation | 400 |
| `ErrEmailChangeStale` | `AUTH_EMAIL_CHANGE_STALE` | state | 409 |
| `ErrEmailInUse` | `AUTH_EMAIL_IN_USE` | state | 409 |
| `ErrEmailChangeRateLimited` | `AUTH_EMAIL_CHANGE_RATE_LIMITED` | abuse | 429 |

Account status failures use the existing status errors, and a provider or Redis outage is `ErrSystemUnavailable` (503).

## Audit

| Event | `metadata` |
|-------|-----------|
| `email_change_requested` | `old_email`, `new_email`, both masked (`j***@example.com`); never the code |
| `email_change_confirmed` | `old_email`, `new_email` (masked), `sessions_revoked` |
| `email_change_failure` | `stage` (`request`, `confirm` or `cancel`), `reason` |

Failure reasons: `disabled`, `user_not_found`, `status`, `invalid_email`, `same_email`, `rate_limited`, `invalid`, `expired`, `attempts`, `stale`, `in_use`, `unavailable`. With `Security.LimiterFailClosed` a limiter outage on a request is `unavailable`.

## Redis keys

Only while enabled: `aec:<tenant>:<id>` (challenge), `aecp:<tenant>:<user>` (the user's pending id), `aeci:<tenant>:<user>` (identifier-change marker), `rl:emailchange:<tenant>:<user>` (request limiter). Rolling back is `EmailChange.Enabled = false`; the keys expire by TTL.

## Related

- [email_verification.md](email_verification.md), [password_reset.md](password_reset.md), [external_identity.md](external_identity.md)
- [session.md](session.md) — `DeleteAllForUserExcept`
- [rate_limiting.md](rate_limiting.md#failing-closed)
