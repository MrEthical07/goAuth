# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.7.0] - 2026-10-04

Minor release (SemVer): additive only. `gorelease -base=v0.6.2` reports **no
incompatible changes** (everything it lists is `added`) and suggests v0.7.0.
Nothing is removed or altered: no exported signature changed, `Config` only
gained a field, and the new provider capabilities are optional interfaces
detected by type assertion. **With the new features unused (the defaults),
behavior is byte-for-byte what it was in v0.6.2:** the same session bytes in
Redis (`session/golden_bytes_test.go` passes unmodified), the same
access-token claims, the same errors, audit events and metrics output, and no
extra Redis or provider calls. This was checked by running one scenario
(login, refresh, hybrid/JWT-only/strict validation, a reused refresh token and a
malformed one) against the v0.6.2 tag and against this release with role
switching off: identical Redis command sequences, claim sets, errors, audit
events and metric counters, now pinned by `TestRoleSwitchDisabledMatchesV062`.

`gorelease -base=v0.6.2` (compatible changes only):

```
# github.com/MrEthical07/goAuth
(*Engine).SwitchRole, Config.RoleSwitch, RoleSwitchConfig, RoleStepUpPolicy,
RoleSwitchOptions, RoleSwitchResult, RoleSwitchProvider,
TenantAwarePasswordUpdater, TenantIDFromContext,
ErrRoleSwitchDisabled, ErrRoleNotAllowed, ErrRoleSwitchSameRole,
ErrStepUpRequired, ErrRoleSwitchRateLimited and their five Code* constants: added

# github.com/MrEthical07/goAuth/session
(*Store).SwapSession, (*Store).Peek, (*Store).SaveAssurance, (*Store).GetAssurance,
Assurance, EncodeAssurance, DecodeAssurance, ErrAssuranceCorrupt: added

# summary
Suggested version: v0.7.0
```

### Added

- **Session role switching: `Engine.SwitchRole(ctx, refreshToken, targetRole,
  opts) (*RoleSwitchResult, error)`.** One authenticated session can change
  which of the account's roles it acts as, without logging in again. The
  session is identified by its refresh token (single-use, the same proof
  `Refresh` uses) and the tenant comes from the request context. The provider
  decides whether the account may hold the role; goAuth swaps the session
  atomically, keeping the old session's `CreatedAt`/`ExpiresAt` so switching
  can never extend a session past its absolute lifetime or
  `MaxSessionDuration`. Other sessions of the user are untouched and login-time
  `SessionHardening` is not re-run. The result is non-nil only on success or
  alongside `ErrStepUpRequired`. Off by default; see
  [docs/role_switching.md](docs/role_switching.md).
  - `Config.RoleSwitch` (`Enabled`, `StepUp`, `MaxAttempts`, `Cooldown`),
    deep-copied by `WithConfig`, validated by `Validate`/`Build`, with a
    `role_switch_stateless_validation` lint (info) for `ModeJWTOnly`/`ModeHybrid`.
    Presets are unchanged.
  - `RoleSwitchProvider` — optional `UserProvider` capability,
    `CanAssumeRole(ctx, tenantID, userID, role) (bool, error)`. It must return
    true for the account's primary role. A yes/no check was chosen over an
    allowed-roles list: nothing to enumerate, and one call serves both the
    switch and the refresh re-check. `Build` fails when `RoleSwitch.Enabled`
    and the provider lacks it.
  - Step-up policies per target role (`RoleStepUpPolicy{RequireMFA, MaxAge}`),
    satisfied by an MFA assurance recorded at login, or inline with a TOTP or
    backup code, or (recent-authentication policies) the password through the
    `VerifyPassword` path and its limiter. The assurance is stored outside the
    session blob in `asa:<tenant>:<sessionID>` (written only when `StepUp` is
    set), so session bytes never change. WebAuthn as an inline factor is a
    follow-up; a fresh WebAuthn login does satisfy a `RequireMFA` policy.
  - A per-session attempt limiter (`rl:roleswitch:*`, default 10 per 15 minutes,
    atomic reserve before any provider, Argon2 or session work, fails open).
  - Five new sentinels with codes, categories, mapping and audit codes:
    `ErrRoleSwitchDisabled`, `ErrRoleNotAllowed` (`AUTH_STATE`),
    `ErrRoleSwitchSameRole` (`AUTH_VALIDATION`), `ErrStepUpRequired`
    (`AUTH_STATE`), `ErrRoleSwitchRateLimited` (`AUTH_ABUSE`). Decode,
    not-found, expired and reuse outcomes return exactly the errors `Refresh`
    returns (`ErrRefreshInvalid`, `ErrSessionNotFound`, `ErrRefreshReuse`).
  - Audit events `role_switched` and `role_switch_failed` (reasons `disabled`,
    `invalid_session`, `reuse_detected`, `same_role`, `not_allowed`,
    `step_up_required`, `rate_limited`, `account_status`, `unavailable`).
    No metric IDs were added.
  - `session.Store.SwapSession` (one Lua script re-applying the rotation
    script's checks in the same order, then swapping the sessions, index entry
    and assurance), `Peek`, `SaveAssurance`/`GetAssurance` and the `Assurance`
    type. The existing scripts are unchanged. `SwapSession` refuses a
    replacement session ID that is empty, equal to the old one, or already held by
    a live session (`session.ErrSessionIDInUse`, checked after every
    rotate-equivalent check and before the first write, so nothing changes and a
    stale refresh hash still gets the reuse outcome); `SwitchRole` always uses a
    fresh random ID and reports that case as `ErrSystemUnavailable`.
- **`TenantAwarePasswordUpdater`** — optional `UserProvider` capability,
  `UpdatePasswordHashInTenant(ctx, tenantID, userID, newHash)`. With
  `MultiTenant.Enabled` and a provider that implements it, `ChangePassword`,
  the password-reset confirm flow and rehash-on-login call it, with the tenant
  goAuth resolved, instead of the by-ID `UpdatePasswordHash`. Otherwise
  behavior and error mapping are exactly as before.
- **`TenantIDFromContext(ctx) (string, bool)`** — reads back the tenant attached
  with `WithTenantID`; `("", false)` when none is attached, never the internal
  default `"0"` (an explicitly attached `"0"` is returned as `"0", true`).
- Tests: per-mode revocation of the pre-switch access token (strict,
  hybrid with Redis healthy and down, JWT-only, after `AccessTTL`), refresh/switch
  reuse and race semantics (concurrent goroutines, run repeatedly), cross-tenant
  and tenant-blind-provider cases, limiter, step-up, audit reasons, the swap
  script against the rotation script's failure handling, and Redis
  compatibility tests for the swap script (`TestRedisCompat_SwapSession*`).

### Changed

- **When `RoleSwitch.Enabled` is true, `Refresh` re-checks the session's role
  before rotating.** If the session exists, is unexpired and the presented token
  matches, the engine calls `CanAssumeRole(sessionTenant, userID,
  session.Role)`. `false` deletes the session (audit `refresh_invalid`, reason
  `role_revoked`) and returns `ErrRoleNotAllowed`: the session ends, with no
  fallback to the primary role. A provider error neither rotates nor deletes and
  returns `ErrSystemUnavailable`, so the same token works on retry. Missing,
  expired and mismatching sessions skip the re-check, so reuse detection is
  unchanged. This costs one extra Redis read and **one provider call per
  refresh**, covering primary-role sessions too (so the provider must answer
  true for the primary role); validation still makes no provider calls. With
  the feature off `Refresh` is untouched.
- When `RoleSwitch.StepUp` is non-empty, MFA logins (`ConfirmLoginMFA`,
  `ConfirmLoginMFAWithType`, `LoginWithTOTP`, `LoginWithBackupCode`) record a
  session assurance with one extra Redis write. With `StepUp` empty nothing is
  written.
- `Refresh`'s reuse handling (the three reuse metrics, the audit event and replay
  tracking) was factored into helpers shared with `SwitchRole`; `Refresh`'s
  observable behavior is unchanged.
- Documentation: new `docs/role_switching.md`; updates to `config.md`,
  `error-model.md`, `api-reference.md`, `goAuth-methods.md`, `session.md`,
  `mfa.md`, `multi_tenancy.md`, `flows.md`, `security.md`, `migrations.md` and the
  lint reference (now 28 codes: 10 INFO, 14 WARN, 4 HIGH).
- New root source file `engine_roleswitch.go` (the per-subsystem pattern of
  `engine_webauthn.go`); the root source whitelist in
  `.github/workflows/go-race.yml` was updated.

### Fixed

- **Session schema migration could recreate a deleted session.** Reading a
  pre-v5 session blob and rewriting it as v5 was a read followed by a plain
  `SET`. A session deleted in between (logout, refresh-reuse revocation, or now a
  role switch) could be written back with its old refresh hash, un-revoking it.
  The rewrite now uses `SET ... XX`, so it only ever updates a key that still
  exists. Only sessions written under an older schema were ever exposed.

### Security

- **Role switching is only safe on routes validated with `ModeStrict`.** After a
  switch the old refresh token is dead at once in every mode, and a strict route
  rejects the old access token on its next use. On **`ModeHybrid` and
  `ModeJWTOnly` routes the pre-switch access token is still accepted, with its old
  mask and an empty `Role`, until it expires** (worst case `JWT.AccessTTL`).
  Hybrid never reads Redis, so this holds whether Redis is healthy or not; there
  is no fallback path. Any route that gates on role or permissions must resolve
  to `ModeStrict`; an explicit per-route `ModeStrict` override on a hybrid engine
  is sufficient. The full table is in `docs/role_switching.md`, linked from
  `flows.md` and `security.md`, and the `role_switch_stateless_validation` lint
  flags the configuration.
- **Replay protection is not weakened.** A switch presenting a stale refresh
  token is refresh-token reuse: the session is deleted by the existing rotation
  script and the existing metrics, audit event and replay tracking fire.
  Concurrent switch and refresh with the same token has exactly one winner; the
  loser is reuse-with-deletion (refresh won first) or not-found (switch won
  first), never a second live session.
- Inline step-up never treats an unenrolled factor as proof: the shared TOTP
  verifier returns success for a user who has no TOTP (it is meant for optional
  sensitive-action prompts), which would have made any code a valid proof here,
  so the engine checks enrollment first (`ErrTOTPNotConfigured`).
- Tenant handling: the session is read from the request tenant, the account is
  resolved with the session's tenant (a foreign-tenant record from a tenant-blind
  provider is rejected), and the provider is only ever called with the session's
  own tenant. Wrong-tenant attempts consume limiter slots.
- `TenantAwarePasswordUpdater` closes the by-ID password-write gap for
  multi-tenant deployments whose providers can scope the write (opt-in).

## [0.6.2] - 2026-09-30

Patch release (SemVer): a drop-in replacement for v0.6.0 and v0.6.1. No exported API
changed (nothing added, removed, or altered), there are no config changes,
and single-tenant deployments (`MultiTenant.Enabled = false`, the default)
are unaffected: same errors, same audit events, same metrics, and no new
provider calls.

### Security

- **Three public methods skipped the tenant-scoped user lookup under
  `MultiTenant.Enabled = true`.** The v0.5.0 guarantee is that every
  id-keyed path resolves the user within the request's tenant before
  touching the provider. `VerifyBackupCode` / `VerifyBackupCodeInTenant`,
  `ListWebAuthnCredentials`, and `RemoveWebAuthnCredential` handed the
  caller's `userID` straight to the provider (`ConsumeBackupCode`,
  `GetWebAuthnCredentials`, `RemoveWebAuthnCredential`) without resolving
  it. A `UserProvider` whose SQL does not scope by tenant, which the
  documented contract allows because goAuth's lookup is where tenant
  enforcement lives, could therefore have a user id from another tenant
  have its backup code consumed, its WebAuthn credentials listed, or its
  credentials removed. All three now resolve the user through the
  tenant-scoped lookup, including the record-tenant backstop, and fail
  closed before any provider call. This completes the v0.5.0 guarantee. It
  affects `MultiTenant.Enabled = true` deployments only.
  - For backup codes the resolution runs after the limiter check and before
    the code is canonicalized or consumed. A failed resolution records a
    limiter failure (so cross-tenant probing is rate-limited like wrong
    codes) and emits the existing `backup_code_failed` audit event with
    `reason: "user_not_found"`. The limiter is keyed by (tenant, user), so
    probing with a foreign id cannot lock the real owner out.
  - No account-status check was added to `VerifyBackupCode`: its sibling
    `VerifyTOTP` does not check status either, so status handling is
    unchanged.
  - An audit of every other exported `Engine` method that takes a `userID`
    found no further gaps: each either resolves through the tenant-scoped
    lookup or is keyed only by tenant-partitioned Redis state.

### Fixed

- `VerifyBackupCode`, `VerifyBackupCodeInTenant`, `ListWebAuthnCredentials`,
  and `RemoveWebAuthnCredential` now return `ErrUserNotFound` in
  multi-tenant mode when `userID` does not belong to the request's tenant
  (or to the explicit `tenantID` argument of `VerifyBackupCodeInTenant`),
  matching the user-not-found row for backup codes and WebAuthn in
  `docs/multi_tenancy.md`. Previously the call reached the provider and its
  result depended on the provider's own scoping.
- In multi-tenant mode the MFA-login and password-reset flows, which verify
  backup codes through `VerifyBackupCodeInTenant`, now make one additional
  in-tenant user lookup per backup-code attempt. Their outcomes are
  unchanged.

---

## [0.6.1] - 2026-09-30

Tagged in error on the v0.6.0 commit; contains no changes and is retracted in
`go.mod`. Use v0.6.2.

---

## [0.6.0] - 2026-09-28

Minor release (SemVer): `gorelease -base=v0.5.1` reports no incompatible
changes. Two things push this above a patch: goAuth now targets **Go 1.27
only** (a maintainer policy choice — see Changed — not something
go-webauthn v0.18.2 itself requires, which needs only Go 1.26.0), and one
new exported method (`VerifyPassword`) plus one new sentinel/error code were
added. Every other consumer-visible difference is upstream behavior (a
go-webauthn v0.18 tightening) that no legitimate client or caller could
have depended on.

### Security

- **`ChangePassword`'s old-password check had no attempt limiting.**
  `Engine.ChangePassword` verified the caller-supplied old password with
  Argon2 and, on a mismatch, only incremented a metric and emitted an audit
  event — nothing limited repeated attempts. A caller holding only a stolen
  access token could guess the account password without limit, at roughly
  200 ms of Argon2 CPU per guess and no other cost. Fixed by a dedicated
  `PasswordVerifyLimiter` (its own `rl:pwdverify:*` Redis namespace, reusing
  `Security.MaxLoginAttempts` / `Security.LoginCooldownDuration`), which
  atomically *reserves* each attempt (a single Redis `INCR`) before Argon2
  runs, rather than checking a read-only count and only recording after a
  failed verification: a check-then-verify split leaves a race where an
  arbitrarily large *concurrent* burst can all observe a count below the
  limit before any of them records an attempt, spending unbounded Argon2 CPU
  regardless of the configured limit. The atomic reservation caps the number
  of verifications that ever run at exactly `MaxLoginAttempts`, however many
  requests arrive concurrently (`TestVerifyPasswordConcurrentBurstBoundedByMaxAttempts`).
  It never triggers account auto-lockout, so exhausting it cannot be used to
  lock the real owner out of login. See Added.

### Added

- `Engine.VerifyPassword(ctx, userID, password) error` — a step-up
  primitive for consumers who need to confirm a password before a sensitive
  action (removing a security key, disabling MFA, deleting an account)
  without re-implementing verification. No state change; shares
  `ChangePassword`'s tenant-scoped lookup and its new rate limiter; reveals
  no more about account existence than `ChangePassword` already does.
- `ErrPasswordVerifyRateLimited` (`AUTH_PASSWORD_VERIFY_RATE_LIMITED`,
  `CategoryAuthAbuse`) — returned by `ChangePassword` and `VerifyPassword`
  when the password-verify limiter is exceeded. Maps to `429 Too Many
  Requests` under the existing `AUTH_*_LIMITED` HTTP guidance.
- `Config.Validate` now rejects a `WebAuthn.RPID` that isn't a valid domain
  string (an IP address, empty/hyphen-bounded labels, non-ASCII characters)
  with a readable message, so `Build()` fails fast instead of the engine
  surfacing a go-webauthn library error the first time a ceremony starts.
  Uses `protocol.ValidateRPID`, the exact function go-webauthn v0.18 itself
  runs, so there is no drift between the two checks.
- `testdata/webauthn_v0.17/gen` — the go-webauthn v0.17.4 fixture generator
  used to prove the v0.17→v0.18 compatibility claims below, committed as
  its own Go module (pinned to `go-webauthn v0.17.4` +
  `descope/virtualwebauthn v1.0.5`) so v0.17.4 never enters goAuth's own
  module graph. `make webauthn-compat` runs both compatibility directions.
- Golden-byte tests (`session`, `internal/stores`, `internal/audit`) proving
  every Redis record goAuth writes, and the JSON its audit sink emits, are
  byte-for-byte identical under Go 1.27.1 to what v0.5.1 (Go 1.26.5)
  produced for the same fields.

### Changed

- **goAuth now targets the current Go major release only (Go 1.27), and
  will raise its minimum whenever a new Go major ships.** This is a
  maintainer policy decision, not a technical requirement of this release —
  go-webauthn v0.18.2 itself needs only Go 1.26.0. `go.mod`'s `go` directive
  is `1.27.0` (`toolchain go1.27.1`). See Migration Notes for what this
  means for consumers on an older toolchain.
- `github.com/go-webauthn/webauthn` v0.17.4 → v0.18.2. Hygiene, not a
  security fix: there is no known advisory against v0.17.4 in the Go
  vulnerability database or GHSA at the time of writing.
- `newWebAuthnRP` pins `ExtensionsUnsolicitedOutputPolicy:
  protocol.UnsolicitedOutputPolicyIgnore`. go-webauthn v0.18 defaults to
  *rejecting* a ceremony whose client volunteers an extension output the
  Relying Party never requested. goAuth requests no WebAuthn extensions,
  and a real browser or password manager can return one unprompted, so the
  new default would fail real logins; pinning `Ignore` reproduces v0.17.4's
  behavior, which performed no such check at all.
  `TestWebAuthnV017SessionRejectsUnsolicitedOutputWithoutIgnorePolicy`
  documents what would happen without the pin.
- go-webauthn v0.18's default credential-parameter list
  (`CredentialParametersDefault`, what `BeginRegistration` uses unless a
  caller opts into a different list) is unchanged by Go 1.27 — the new
  post-quantum ML-DSA algorithms are gated behind a *separate*,
  library-provided opt-in (`CredentialParametersPQCRecommendedL3`, itself
  gated on a `go1.27` build tag) that goAuth does not call. Confirmed both
  by re-running `TestWebAuthnOptionsJSONUnchangedAcrossUpgrade` under Go
  1.27.1 (still passes, `pubKeyCredParams` unchanged) and by reading
  go-webauthn's source. No pin was needed.
- TOTP re-enrollment refusal (`ErrTOTPAlreadyEnabled`, added in v0.5.1) no
  longer increments the `TOTPFailure` metric. That metric is a brute-force
  signal; a refused re-enroll is a policy rejection, not a failed code. The
  audit event and its distinct `totp_already_enabled` code are unchanged.
- `golang.org/x/crypto` v0.54.0 → v0.57.0 and `golang.org/x/sys` v0.47.0 →
  v0.48.0 (transitive, pulled in by go-webauthn v0.18.2).

### Dependencies

Direct:
- `github.com/go-webauthn/webauthn` v0.17.4 → v0.18.2

Transitive (all pulled in by the above; none newly introduced beyond what
v0.5.1 already carried transitively through v0.17.4, except where noted):
- `github.com/go-webauthn/x` v0.2.6 → v0.3.1
- `github.com/fxamacker/cbor/v2` v2.9.2 → v2.9.4
- `golang.org/x/crypto` v0.54.0 → v0.57.0
- `golang.org/x/sys` v0.47.0 → v0.48.0
- `github.com/go-viper/mapstructure/v2`, `github.com/tinylib/msgp`,
  `github.com/philhofer/fwd`, `github.com/google/go-tpm` were already
  indirect dependencies under v0.5.1 (via go-webauthn v0.17.4) and are
  unchanged in version.

### Notes: rolling-deploy compatibility

Both upgrade direction (v0.5.x → v0.6.0) and rollback direction (v0.6.0 →
v0.5.x) were tested against real ceremony data, not assumed:

- **Upgrade (v0.17.4-written ceremony, finished under v0.18.2):** succeeds
  cleanly — no failure, bounded or otherwise —
  `TestWebAuthnV017SessionDecodesAndFinishesUnderV018`.
- **Rollback (v0.18.2-written ceremony, finished under v0.17.4):** also
  succeeds cleanly. A `SessionData` record written by v0.18.2 for goAuth's
  own (no-extensions, no-origin-binding) configuration carries no
  `extensions`, `origin`, or `authorizeUVInitialization` keys, so it
  decodes under v0.17.4's `SessionData` exactly as a native v0.17.4 record
  would — proven by `testdata/webauthn_v0.17/gen -verify-reverse`
  (`make webauthn-compat` runs both directions).
- Redis records for sessions, MFA login challenges, password-reset and
  email-verification records, and WebAuthn ceremony envelopes are all
  encoded with `encoding/binary` (fixed-width big-endian, length-prefixed
  strings) — never `encoding/json` — so Go 1.27's `encoding/json` v2
  backend cannot affect their wire format. Proven byte-for-byte identical
  to v0.5.1 (Go 1.26.5) output, not just assumed from the encoding choice.
- The one JSON path in a stored record — go-webauthn's own `SessionData`
  blob inside the WebAuthn ceremony envelope — was also spot-checked
  directly: its `json.Marshal` output for the same go-webauthn v0.18.2
  dependency is byte-for-byte identical between Go 1.26.5 and Go 1.27.1.

## [0.5.1] - 2026-09-28

Patch release (SemVer): no public signature changed. One new sentinel
(`ErrTOTPAlreadyEnabled`) and one new error code
(`AUTH_TOTP_ALREADY_ENABLED`) were added; every other exported name is
unchanged. `go get github.com/MrEthical07/goAuth@v0.5.1` is a drop-in
replacement for v0.5.0.

### Security

- **TOTP re-enrollment silently replaced an active secret.**
  `GenerateTOTPSetup`/`ProvisionTOTP` never checked whether the user already
  had TOTP enabled before generating a new secret and calling
  `UserProvider.EnableTOTP` unconditionally. Depending on how the provider
  tracks enabled/verified state, this had two possible outcomes, neither
  correct: if the provider kept the account "enabled" through the call, the
  new, never-confirmed secret went live immediately — locking the real user
  out of their authenticator app and handing the new secret (in the setup
  response) to whoever called setup, including a caller holding only a
  stolen access token, defeating MFA for anyone who also knew the password.
  If the provider instead reset to "unverified" on the call, TOTP was
  silently downgraded to disabled until someone confirmed the new secret.
  goAuth never documented a "rotate TOTP while enabled" flow — the
  documented path is `DisableTOTP` followed by `GenerateTOTPSetup` +
  `ConfirmTOTPSetup` — so no correct consumer flow depended on the old
  behavior.

### Added

- `ErrTOTPAlreadyEnabled` (`AUTH_TOTP_ALREADY_ENABLED`, `CategoryAuthState`) —
  returned by `GenerateTOTPSetup`/`ProvisionTOTP` when the user already has
  TOTP enabled.

### Changed

- `GenerateTOTPSetup`/`ProvisionTOTP` now refuse to run while TOTP is already
  enabled for the user (`record.Enabled && len(record.Secret) > 0`, the same
  predicate the login flow uses), returning `ErrTOTPAlreadyEnabled` instead
  of generating and persisting a replacement secret. No secret is generated,
  `EnableTOTP` is not called, and no `TOTPSetupRequested` audit event is
  emitted on the rejected path. Re-running setup after a setup that was
  started but never confirmed (`Enabled == false`) is unaffected and still
  succeeds, replacing the unconfirmed secret — losing the QR code before
  confirming still recovers the same way it always has. The rotation path
  for an enabled user is unchanged: `DisableTOTP` then setup + confirm again.
  If `UserProvider.GetTOTPSecret` returns an error (for example a provider
  that returns `sql.ErrNoRows` rather than a nil record for a user who has
  never set up TOTP) the guard proceeds exactly as v0.5.0 did — this is
  deliberate, and no weaker than v0.5.0, which never checked at all.
  `ConfirmTOTPSetup`, `VerifyTOTP`, `DisableTOTP`, backup codes, MFA login,
  and password-reset-with-TOTP are unchanged.

## [0.5.0] - 2026-08-12

Minor release (SemVer): additive. One new optional interface, no changed
public signatures, no removed or renamed config fields. Every behavior change
is gated on `MultiTenant.Enabled`, which defaults to `false` and is not set by
any shipped preset — deployments that do not opt in behave exactly as they did
in v0.4.0.

### Security

All three fixes below apply only when `MultiTenant.Enabled = true`. They are
live vulnerabilities for any deployment running more than one tenant; the
`Enabled = false` path was never affected.

- **Cross-tenant account takeover via password reset (unauthenticated).** The
  password-reset request path resolved the identifier tenant-blind and then
  stored the reset record under the **resolved user's** tenant rather than the
  request's. A reset requested under tenant B for an address belonging to
  tenant A wrote a valid, redeemable reset record into tenant A's keyspace,
  which the confirm path honored. Reachable by anyone who could reach the
  reset endpoint and guess an email address. The lookup is now scoped to the
  request's tenant and the record is always stored under it.
- **Cross-tenant credential attack on login.** Login resolved the user
  tenant-blind and never compared the resolved user's tenant to the request's.
  Valid tenant-A credentials presented against tenant-B's context
  authenticated, yielding a token cryptographically stamped tenant B while
  carrying tenant A's user id and role. Login now resolves within the request's
  tenant and rejects a mismatch with the same generic invalid-credentials error
  as a wrong password.
- **Cross-tenant email verification.** Same shape as the reset hole: a
  tenant-blind lookup plus record binding to the resolved user's tenant. Now
  scoped and bound to the request's tenant.

Enumeration resistance is preserved on every path: a cross-tenant identifier
is indistinguishable from a nonexistent one in response shape, error value,
and timing posture. Rejections are recorded in the audit trail with
`reason: "tenant_mismatch"` against the context tenant. **Audit events must
not be surfaced to tenant users** — the stream distinguishes cases the
response deliberately does not.

### Added

- `TenantAwareUserProvider` — optional capability interface with
  context-taking, tenant-scoped variants of both user lookups
  (`GetUserByIdentifierInTenant`, `GetUserByIDInTenant`). Detected by type
  assertion at `Builder.Build()`, the same mechanism as
  `WebAuthnCredentialProvider`. The existing `UserProvider` interface is
  unchanged and existing implementations continue to compile.
- Fail-fast build validation: `Builder.Build()` now fails when
  `MultiTenant.Enabled` is set and the user provider does not implement
  `TenantAwareUserProvider`. A silent fallback to tenant-blind lookup in a
  multi-tenant deployment must be impossible to configure. Safe for existing
  consumers, who default to `Enabled = false`.
- `docs/multi_tenancy.md` — tenant model, provider contract with
  implementation guidance, enforced paths, enumeration-resistance notes, and
  adoption steps.
- New lint warnings: `tenant_enforce_isolation_noop` and
  `account_duplicate_identifier_provider_owned`.

### Changed

- With `MultiTenant.Enabled = true`, every user lookup — including the
  authenticated id-keyed paths (change password, account status transitions,
  backup codes, TOTP provisioning, WebAuthn ceremonies) — is scoped to the
  request's tenant. Previously these resolved across all tenants, so a user id
  from another tenant was honored. With `Enabled = false` they remain
  tenant-blind.
- `MultiTenant.EnforceIsolation` no longer defaults to `true` in
  `defaultConfig()`. The field is unread, so this changes no behavior; it
  previously implied an enforcement the engine never performed and would now
  emit a deprecation warning for every default config.

### Fixed

- Email-verification confirm no longer consumes a valid link when the
  request context's tenant is absent or differs from the tenant embedded in
  the challenge. `ConfirmEmailVerification` is documented as the
  cross-tenant entry point — the challenge carries its own tenant, and the
  record is loaded and consumed under that tenant — but the user lookup and
  the status transition were scoped to the context tenant, so a divergent
  context deleted the record and then failed to resolve the user. Both now
  use the tenant the record was loaded under. Affects
  `MultiTenant.Enabled = true` only.
- Tenant-scoped ID lookups now verify the returned record's `TenantID`
  against the requested tenant and fail closed as not-found on mismatch. A
  provider that satisfies `TenantAwareUserProvider` without honouring the
  tenant predicate would otherwise hand the id-keyed paths (change password,
  account status, backup codes, TOTP, WebAuthn) a foreign-tenant record that
  callers go on to mutate. The identifier paths already had this backstop.
- Bumped `go.opentelemetry.io/otel` and its `metric`, `trace`, `sdk`, and
  `sdk/metric` modules from v1.43.0 to v1.44.0, clearing advisory
  GO-2026-5158 (baggage parsing no longer caps raw header length). goAuth
  does not call the affected code — `govulncheck` reports zero reachable
  vulnerabilities on v1.43.0 — so this is a hygiene upgrade rather than an
  exploitable fix. Unrelated to the tenant work in this release.

### Deprecated

No fields removed; all continue to be accepted.

- `MultiTenant.EnforceIsolation` — no-op that never gated anything. Tenant
  enforcement is governed entirely by `MultiTenant.Enabled`.
- `MultiTenant.TenantHeader` — no-op. The engine is transport-agnostic and
  will not read HTTP headers; extract the tenant in your HTTP layer and attach
  it with `WithTenantID`.
- `Account.AllowDuplicateIdentifierAcrossTenants` — documented as a
  provider-owned contract. goAuth never queries across tenants and so cannot
  enforce global identifier uniqueness; only the provider's schema can.

---

## [0.4.0] - 2026-07-14

Minor release (SemVer): every public API change is additive — new config
fields, new methods, new optional interfaces — with no breaking signature or
config changes. The two observable behavior changes (expired-token logout now
succeeds; explicit `ModeHybrid` route overrides no longer error) are fixes
that align behavior with the documented intent, called out under **Changed**
and **Fixed** with migration notes in `docs/migrations.md`.

### Added

- Remember-me and configurable durable sessions:
	- `Config.Session.MaxSessionDuration` — absolute session ceiling beyond which no session can be created or extended, regardless of sliding renewal. Unset (0) resolves at `Builder.Build()` to a per-validation-mode default (24 h for `ModeStrict`, 7 days for `ModeHybrid`/`ModeJWTOnly`), raised to the effective default session lifetime (`min(RefreshTTL, AbsoluteSessionLifetime)`) when that is longer, so existing configurations keep their exact session lifetimes. Validated at build time (0 or ≥ 1 minute).
	- `LoginOptions` and `Engine.LoginWithOptions` — per-login remember-me flag; remember-me sessions are created with the `MaxSessionDuration` lifetime, default logins keep the existing shorter lifetime. Existing `Login`/`LoginWithResult`/`LoginWithTOTP`/`LoginWithBackupCode` signatures are unchanged and behave as remember-me = false.
	- `CreateAccountRequest.RememberMe` — additive field; applies the durable lifetime to `AutoLogin` sessions.
	- Remember-me survives the MFA hop: the flag is persisted with the MFA login challenge (record version 2, backward-compatible decode of v1 records) and honored by `ConfirmLoginMFA`/`ConfirmLoginMFAWithType` without signature changes.
	- New lint warnings: `max_session_duration_caps_default` (explicit ceiling below the default session lifetime caps all sessions) and `max_session_duration_long` (effective ceiling > 30 days).
- Hybrid validation mode aligned with its intended per-route design:
	- `middleware.RequireHybrid` — shorthand for `Guard(engine, ModeHybrid)`, parallel to `RequireJWTOnly`/`RequireStrict`.
	- New advisory lint `hybrid_enforcement_strict_routes_only` (info) — Hybrid mode with enforced device binding; enforcement runs only on routes resolved to `ModeStrict`.
- Sliding-window rate limiting (opt-in): `Security.LimiterWindowMode = "sliding"` switches every limiter domain (login failure, lockout, account creation, TOTP, backup codes, password reset, email verification) to a weighted two-bucket sliding-window counter, removing the fixed-window 2× boundary-burst weakness. Defaults to the existing fixed-window behavior (`""`/`"fixed"`); validated at build time. All limiters now count through a single shared window primitive (`internal/window`).
- WebAuthn / FIDO2 second-factor support (security keys, platform authenticators, passkeys as a second factor):
	- `Config.WebAuthn` — relying-party settings (`RPID`, `RPDisplayName`, `RPOrigins`), attestation (default `"none"`) and user-verification preferences, `CeremonyTTL`, `RequireForLogin`, and `RejectClonedAuthenticators`; validated at build time.
	- `WebAuthnCredentialProvider` — optional capability interface detected on the `UserProvider` via type assertion at `Builder.Build()`; existing `UserProvider` implementations are unaffected, and enabling WebAuthn without the capability fails the build. Credentials persist through goAuth-owned `WebAuthnCredential` records (no library types in the public API).
	- Registration ceremonies: `Engine.BeginWebAuthnRegistration` / `FinishWebAuthnRegistration`, plus `ListWebAuthnCredentials` / `RemoveWebAuthnCredential`. The engine exchanges raw CredentialCreation/CredentialRequest JSON with the caller and stays transport-agnostic.
	- Login integration: with `WebAuthn.RequireForLogin`, users holding registered credentials get an MFA challenge answered via `Engine.BeginWebAuthnLogin` + the existing `ConfirmLoginMFAWithType(..., "webauthn")` — no signature changes. `LoginResult` gains an additive `MFATypes []string`; `MFAType` prefers `"webauthn"` over `"totp"` when both are available (TOTP-only deployments see identical behavior). Remember-me survives the WebAuthn hop.
	- Security posture: ceremony sessions are single-use (atomic `GETDEL`, new `awn:` Redis keys) and TTL-bounded; origin/RPID enforced per config; signature-counter regression fails the login with `ErrWebAuthnCloneDetected` and destroys the challenge; failed assertions consume MFA challenge attempts like wrong TOTP codes, while ceremony-expired failures do not (no verification happened).
	- New sentinels: `ErrWebAuthnDisabled`, `ErrWebAuthnInvalid`, `ErrWebAuthnCeremonyExpired`, `ErrWebAuthnCloneDetected`, `ErrWebAuthnCredentialNotFound`, `ErrWebAuthnUnavailable`.
	- New dependency: `github.com/go-webauthn/webauthn` (ceremony verification); tests use `github.com/descope/virtualwebauthn` (test-only authenticator emulator).
- Ed25519 key-rotation tooling:
	- `Config.JWT.VerifyKeys` (`kid` → verification key map) — exposes the jwt layer's existing multi-key verification on the engine config, enabling zero-downtime signing-key rotation via a verify-overlap ceremony (documented step-by-step in `docs/ops.md`). Build-time guardrails: `VerifyKeys` requires a `KeyID` naming one of its entries, and the entry under the signing kid must match the signing key — misconfigurations that would reject every self-issued token cannot build.
	- `jwt.GenerateEd25519Key` and `jwt.Ed25519KeyFingerprint` helpers, plus a `cmd/goauth-keygen` CLI (keypair generation in raw-base64 or PEM, `-fingerprint` for kid derivation from existing public keys).
	- New lint `keyid_missing` (info) — Ed25519 signing without a `KeyID`; setting one from day one avoids a flag day on the first rotation.
- Lint warnings for no-op config knobs — several fields are accepted (and validated) but never read by the engine; `Config.Lint()` now says so instead of letting integrators believe a protection is active: `security_ip_binding_noop` (warn), `security_ip_signal_noop` (warn), `cache_lru_noop` (warn), `cookie_settings_noop` (info), `database_config_noop` (info), `tenant_header_noop` (info). The fields themselves are unchanged (backward compatible); doc comments and `docs/config.md` now mark each one **no-op**.

### Changed

- The store-level sliding-renewal clamp now uses the resolved `MaxSessionDuration` ceiling instead of the default session lifetime; per-session expiry is carried entirely by the session's stored `ExpiresAt` (written once at creation, as before). Existing sessions are unaffected.
- `LogoutByAccessToken` now succeeds for expired-but-authentic access tokens: the token's session (if any) is destroyed and nil is returned, instead of failing with `ErrTokenInvalid`. Signature, algorithm, kid, issuer, audience, not-before, and iat checks are still enforced (new `jwt.Manager.ParseAccessAllowExpired`, wired only into the logout flow — `Validate`/`Refresh` keep the strict parser). Expired-token logouts carry `expired_token: "true"` audit metadata. Callers that matched on `ErrTokenInvalid` when logging out expired sessions will now receive nil.
- Hybrid validation semantics are now an explicit, documented contract: routes resolved to `ModeHybrid` (inherited or explicit) validate statelessly — signature, claims, and clock-skew checks with zero Redis — and individual routes opt into `ModeStrict` (session-backed revocation/version/status/device checks) or `ModeJWTOnly` per call. This matches the existing runtime behavior of inherited Hybrid; documentation that implied an opportunistic session lookup ("Redis lookup used when available") has been corrected.

### Fixed

- Login timing oracle on unknown identifiers: the user-not-found path now performs the same dummy Argon2 verification as the wrong-password path, closing a username-enumeration side channel.
- Limiter increments are now atomic (single Lua script instead of `INCR` followed by `EXPIRE`): a crash between the two commands could previously leave a counter key without a TTL, rate-limiting that identifier until manual cleanup.
- Explicit `ModeHybrid` route overrides (e.g. `middleware.Guard(engine, ModeHybrid)`, `Validate(ctx, token, ModeHybrid)`) no longer fail with `ErrInvalidRouteMode`; they resolve to the stateless Hybrid path. An explicit route mode always wins over the engine default. The `ValidationMode` zero value remains invalid (`ModeJWTOnly` is `1`).

### Dependencies

- Added `github.com/go-webauthn/webauthn` (WebAuthn ceremony verification) and its transitive dependencies; test-only `github.com/descope/virtualwebauthn`.
- Bumped `golang.org/x/crypto` to v0.54.0 and pinned the `go1.26.5` toolchain to clear known stdlib advisories (GO-2026-4970, GO-2026-5856) in the security scanner gate. No OIDC/OAuth2 dependencies were added (SSO is deferred).

### Notes

- Mixed-version rollout: MFA login challenges written by this version use record v2; binaries older than this version cannot decode them during the (≤ 3 minute) challenge TTL window of a rolling deploy.
- Security caveat: an explicit per-route validation mode always overrides the engine mode — a route validated with `ModeJWTOnly` or `ModeHybrid` skips session-backed checks even on a `ModeStrict` engine. Audit route wiring when adopting per-route modes (see `docs/security.md`).
- Deferred to a future cycle: SSO / OIDC + OAuth2 social login (see `docs/roadmap.md`).

---

## [0.3.0] - 2026-04-06

### Breaking

- Public engine failures are now normalized to a canonical `*AuthError` boundary; raw internal/store/limiter/session errors are no longer returned from exported `Engine` methods.
- Removed refresh-throttle configuration and behavior (`Security.EnableRefreshThrottle`, `Security.MaxRefreshAttempts`, `Security.RefreshCooldownDuration`) and retired refresh rate-limit signaling from the public surface.
- Renamed config fields for abuse controls:
	- `Security.EnableIPThrottle` -> `Security.EnableLoginFailureLimiter`
	- `PasswordReset.EnableIPThrottle` / `PasswordReset.EnableIdentifierThrottle` -> `PasswordReset.EnableRequestLimiter` / `PasswordReset.EnableConfirmFailureLimiter`
	- `EmailVerification.EnableIPThrottle` / `EmailVerification.EnableIdentifierThrottle` -> `EmailVerification.EnableRequestLimiter` / `EmailVerification.EnableConfirmFailureLimiter`
	- `Account.EnableIPThrottle` / `Account.EnableIdentifierThrottle` -> `Account.EnableCreationLimiter`
- Limiter keyspace moved to tenant-scoped `rl:*` prefixes; legacy limiter keys are not reused.

### Added

- Canonical public error model:
	- `AuthError` with stable `Category` and `Code`
	- Full `AuthCode` registry
	- `NewAuthError` and `WrapAuthError`
	- Boundary mapper (`mapToAuthError`) and canonical fallbacks (`ErrSystemInternal`, `ErrSystemUnavailable`)
- CI guardrails for error-boundary regressions:
	- Static boundary scanner (`engine_error_boundary_static_test.go`)
	- Runtime boundary contract tests (`engine_error_boundary_runtime_test.go`)
- New observability counters for limiter behavior and lockout:
	- `MetricLimiterCheck`
	- `MetricLimiterTrigger`
	- `MetricLimiterFailOpen`
	- `MetricLockoutTrigger`
- New error-model documentation (`docs/error-model.md`).

### Changed

- Login limiter now uses tenant+identifier scoping and no longer depends on IP pairing.
- Password reset and email verification abuse controls are split into explicit request-phase and confirm-failure limiter paths.
- Limiter backend failures in runtime flow wrappers now follow fail-open policy with audit + metric signals (`limiter_fail_open`) while preserving explicit limiter denials.
- Security report and docs now reflect `EnableLoginFailureLimiter` as the login abuse-control gate.

### Removed

- `ErrRefreshRateLimited` and `MetricRefreshRateLimited` from the public model.
- Refresh-throttle flow path and associated refresh rate-limit audit branch.

### Docs

- Updated API, config, flow, security, operations, and rate-limiting docs to align with v0.3.0 semantics.
- Added boundary enforcement policy details under the error-model documentation.

### Tests

- Migrated limiter and config tests to new semantics and keyspace.
- Added static + runtime tests that hard-fail CI on boundary contract drift.
- Targeted guardrail run passes: `go test ./... -run "TestEngineErrorBoundaryStatic|TestEngineErrorBoundaryRuntime"`.

---

## [0.2.1] - 2026-03-31

### Changed

- Permission registry and role manager read helpers now elide read locks after `Build()` freeze, while keeping write-path locking intact.
- `Engine.HasPermission` behavior and API remain unchanged, but now benefit from lock-free frozen permission lookup paths.

### Performance

- Reduced CPU overhead in hot RBAC lookup paths by removing post-freeze read-lock contention from permission and role lookups.
- Added focused benchmarks for permission helper paths: registry bit lookup and end-to-end `HasPermission`.

### Docs

- Updated permission, RBAC validation, API reference, methods guide, and performance docs to reflect frozen lock-free lookup behavior and updated benchmark coverage.

### Tests

- Added benchmark coverage for permission lookup helpers and validated existing auth flow behavior without API changes.

---

## [0.2.0] - 2026-03-16

### Added

- String tenant IDs end-to-end in JWT claims and validation, including backward-compatible parsing for legacy numeric `tid` claims.
- `AuditSinkErrors()` engine metric plus Prometheus / OpenTelemetry export for audit sink write failures.
- `SlogAuditSink` / `NewSlogAuditSink(...)` for forwarding audit events into existing `slog` pipelines.

### Changed

- TOTP direct verification attempt limits now use `TOTP.MFALoginMaxAttempts` so setup confirmation and direct verify share the MFA budget.
- Audit-enabled builds now fail fast when no audit sink is configured instead of silently discarding events.
- Audit docs, metrics docs, API reference, JWT docs, and roadmap were updated to match the current behavior.

### Fixed

- Backup-code audit coverage now records invalid-format, rate-limited, generation, and regeneration failures consistently.
- JSON audit writer sinks now count encoding / write failures instead of swallowing them invisibly.
- JWT-only / hybrid claim-derived auth results now preserve string tenant IDs correctly.

### Tests

- Added regression coverage for TOTP limiter wiring, legacy numeric tenant claim parsing, JWT-only tenant round-tripping, audit sink misconfiguration, slog sink output, sink error counting, and backup-code audit failures.
- `go test ./...` passes with the new coverage.

---

## [0.1.0] - 2026-02-19

### Added

- **Core engine** - `Engine` with `Builder` pattern for configuration, Redis wiring, and permission/role registration.
- **Authentication flows** - `Login`, `LoginWithResult`, `LoginWithTOTP`, `LoginWithBackupCode`, `ConfirmLoginMFA`, `ConfirmLoginMFAWithType`.
- **Token management** - JWT access tokens (Ed25519/HS256) with `ValidateAccess`, `Validate`, `HasPermission`.
- **Refresh rotation** - `Refresh` with atomic Lua CAS, replay detection, and session family destruction.
- **Logout** - `Logout`, `LogoutInTenant`, `LogoutByAccessToken`, `LogoutAll`, `LogoutAllInTenant`, `InvalidateUserSessions`.
- **Password management** - `ChangePassword` with reuse detection; Argon2id hashing via `password` package.
- **Password reset** - `RequestPasswordReset`, `ConfirmPasswordReset`, `ConfirmPasswordResetWithTOTP/BackupCode/MFA` with Token/OTP/UUID strategies.
- **Email verification** - `RequestEmailVerification`, `ConfirmEmailVerification`, `ConfirmEmailVerificationCode` with enumeration resistance and Lua CAS consumption.
- **MFA (TOTP + backup codes)** - `GenerateTOTPSetup`, `ProvisionTOTP`, `ConfirmTOTPSetup`, `VerifyTOTP`, `DisableTOTP`, `GenerateBackupCodes`, `RegenerateBackupCodes`, `VerifyBackupCode`.
- **Account management** - `CreateAccount`, `DisableAccount`, `EnableAccount`, `UnlockAccount`, `LockAccount`, `DeleteAccount`.
- **Automatic account lockout** - Persistent failure counter with configurable threshold and duration.
- **Session management** - Binary-encoded sessions (schema v5) with sliding expiration, jitter, and read-time migration (v1-v5).
- **Permission system** - 64/128/256/512-bit bitmasks, frozen registry, role-to-mask compilation.
- **Middleware** - `Guard`, `RequireJWTOnly`, `RequireStrict`, `AuthResultFromContext`.
- **Rate limiting** - 7-domain fixed-window limiters (login, refresh, account creation, TOTP, backup codes, password reset, email verification).
- **Device binding** - IP/UA hash enforcement or anomaly detection modes.
- **Audit system** - Async dispatcher with `ChannelSink`, `JSONWriterSink`, `NoOpSink`; drop-if-full mode.
- **Metrics** - 44 counters + 1 histogram, lock-free cache-line-padded; Prometheus and OpenTelemetry exporters.
- **Introspection** - `GetActiveSessionCount`, `ListActiveSessions`, `GetSessionInfo`, `ActiveSessionEstimate`, `Health`, `GetLoginAttempts`.
- **Configuration** - `DefaultConfig`, `HighSecurityConfig`, `HighThroughputConfig` presets; `Validate()` and `Lint()` with 16 warning codes.
- **Multi-tenancy** - Tenant-scoped sessions, counters, and rate limits.
- **Context helpers** - `WithClientIP`, `WithTenantID`, `WithUserAgent`.
- **Max password length** - `MaxPasswordBytes` (default 1024) applied before Argon2.
- **RequireIAT enforcement** - Explicit nil-check for `iat` claim when `RequireIAT=true`.

### Security

- Constant-time comparison on all secret paths (passwords, TOTP, reset tokens, verification codes, backup codes).
- Enumeration resistance for password reset and email verification (fake challenges + timing delay).
- Empty password timing oracle eliminated.
- Permission version drift triggers session deletion (alignment with role/account version behavior).
- Device binding uses SHA-256 hashes - no plaintext IPs stored.
- All rate limiters fail open on Redis unavailability (availability over correctness for rate limits).
- Strict validation mode fails closed on Redis unavailability.

### Documentation

- Full module documentation for all 14 subsystems.
- Flow catalog documenting all authentication/authorization workflows.
- Configuration reference with presets and lint rules.
- Architecture, security model, concurrency model, and capacity planning guides.
- Performance budgets with CI regression gates.
- Operational guidance with deployment checklist.
- Minimal HTTP example with 4 endpoints.

### Tests

- 266 tests across 9 packages, all passing.
- Race detector clean (`go test -race ./...`).
- 4 fuzz targets (refresh token, JWT parse, permission codec, refresh session).
- Redis 7-alpine integration tests via Docker Compose.
- 13 benchmarks covering metrics, validation, and export paths.

---

[0.3.0]: https://github.com/MrEthical07/goAuth/releases/tag/v0.3.0
[0.2.1]: https://github.com/MrEthical07/goAuth/releases/tag/v0.2.1
[0.2.0]: https://github.com/MrEthical07/goAuth/releases/tag/v0.2.0
[0.1.0]: https://github.com/MrEthical07/goAuth/releases/tag/v0.1.0
[Unreleased]: https://github.com/MrEthical07/goAuth/compare/v0.3.0...HEAD
