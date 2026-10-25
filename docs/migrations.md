# Migrations

## v0.8.0 Migration Notes (Non-Breaking)

**No action needed unless you adopt session profiles or external sign-in.** v0.8.0 is additive: no
exported signature changed and everything `gorelease -base=v0.7.0` lists is an
addition (`Config` gained `SessionProfiles` and `ExternalAuth` fields; `SessionConfig` itself is
unchanged). With profiles unused (the default) behavior is byte-for-byte what
it was in v0.7.0: the same session bytes in Redis (`session/golden_bytes_test.go`
passes unmodified), the same MFA challenge bytes, the same Redis commands for
login, refresh, validate and logout, the same token claims and lifetimes, errors,
audit events and metrics. `TestSessionProfilesUnusedMatchesV070` pins this: its
expected values were captured by running the same scenario against the v0.7.0
tag.

**Exception: the security fixes from the pre-release audit** (below) deliberately
change the limiter traffic and a few results, and the unchanged-when-unused
transcripts were updated for exactly those lines.

### Security fixes from the audit: what changes with nothing enabled

Applications that enable nothing new see these differences (the CHANGELOG lists
each with its finding ID):

- **Login limiter traffic.** A login claims its identifier budget with one
  script before the password is verified (it used to read the counter), also
  claims the resolved account's budget (`rl:login:user:*`), and clears both when
  the password is right. The attempt that used to be the first refused
  (`MaxLoginAttempts + 1`) is still refused with `ErrLoginRateLimited`, but it is
  now refused *before* its password is evaluated: a correct password sent after
  `MaxLoginAttempts` wrong ones is rejected instead of accepted.
- **Auto-lockout** (only if you turned it on): the attempt that reaches the
  threshold locks the account but is answered `ErrInvalidCredentials`, like every
  other wrong password; `ErrAccountLocked` appears once the right password is
  given. Only an Active account is counted or locked; a Disabled, Deleted or
  PendingVerification account keeps its status. A login completed through MFA
  clears the failure counter, as a password-only login does.
- **MFA login.** TOTP guesses at the confirmation count against the per-account
  TOTP budget that `VerifyTOTP` uses (`TOTP.MFALoginMaxAttempts` per
  `TOTP.VerifyAttemptCooldown`, default 5 per minute), across challenges; when
  it is spent the challenge is destroyed and `ErrTOTPRateLimited` is returned. A
  right code clears the budget. The per-challenge cap still answers
  `ErrMFALoginAttemptsExceeded` on the last wrong code of a challenge.
- **Input caps.** Login refuses an identifier over `MaxIdentifierBytes` (320) or
  a password over 1024 bytes with `ErrInvalidCredentials` before any lookup.
  Password-reset requests, email-verification requests and account creation
  refuse an over-length identifier as an invalid request (`ErrPasswordResetInvalid`,
  `ErrEmailVerificationInvalid`, `ErrAccountCreationInvalid`). Audit events copy at
  most 320 bytes of an unauthenticated identifier.
- **Reset and verification requests** answer after a randomized 20-40 ms floor on
  every branch (they used to do so only for unknown identifiers), so a registered
  address is no longer the fast answer.
- **Limiter keys of the password-reset, email-verification and account-creation
  limiters are hashed** (SHA-256 of the tenant and the identifier or ID): their
  counters start from zero on upgrade, which is harmless (they expire within a
  window). The old keys expire on their own.
- `Build` hashes one throwaway password with your Argon2 settings (the dummy
  verification hash), which takes one hash time at startup.
- `Config.Lint()` gains `login_ip_limiter_disabled` (INFO, raised for every
  config that has not enabled the new per-IP throttle) and `auto_lockout_duration_noop`
  (WARN, `AutoLockoutEnabled` with a non-zero `AutoLockoutDuration`). If you gate
  startup on lint output at INFO or WARN, expect the new codes.

### Optional: per-IP login throttle

Set `Security.LoginIPLimiter = LoginIPLimiterConfig{Enabled: true, MaxAttempts: 20, Cooldown: 15 * time.Minute}`
and attach the client address with `WithClientIP`. The address must come from your
own proxy chain; users behind one NAT share a budget. See
[rate_limiting.md](rate_limiting.md#per-ip-login-throttle).

### Optional: adopt session profiles

[Session profiles](session.md#session-profiles) give different clients different
session lifetimes: a fixed lifetime (for example a web app, 15 days from login) or
a renewing one (for example a mobile app, 90 days of inactivity renewed by each
refresh, up to a 365-day ceiling), plus an optional per-profile access-token TTL.

1. **Finish any rolling deploy first.** A session created under a profile is
   stored as schema **v6**, and an MFA challenge created under one as record
   **v3**; v0.7.0 binaries cannot read either. Roll every instance to v0.8.0
   *before* configuring profiles, or an older instance that meets such a record
   fails on it. Sessions created without a profile are still v5 and stay readable
   by v0.7.0.
2. **Define the profiles** in `Config.SessionProfiles.Profiles` and set
   `DefaultProfile` (required once any profile exists):

   ```go
   cfg.SessionProfiles.Profiles = map[string]goAuth.SessionProfile{
       "web":    {AbsoluteLifetime: 15 * 24 * time.Hour},
       "mobile": {IdleTimeout: 90 * 24 * time.Hour, AbsoluteLifetime: 365 * 24 * time.Hour, RenewOnUse: true},
   }
   cfg.SessionProfiles.DefaultProfile = "web"
   ```

   `Build` validates the table (see [config.md](config.md#session-profiles-configsessionprofiles));
   in `ProductionMode` it also caps a profile's access TTL at 15 minutes, a fixed
   ceiling at 30 days and a renewing idle window at 90 days. Run `cfg.Lint()` and
   read the `session_profile_*` findings.
3. **Pick the profile server-side** and attach it to the context of every login:
   `ctx = goAuth.WithSessionProfile(ctx, "mobile")`. Decide it from your own
   routing or from the authenticated API client, never from a header or body field
   the end user controls. Existing call sites that name no profile get the default.
4. **Map remember-me, if you use it.** With profiles configured,
   `LoginOptions{RememberMe: true}` is no longer the silent "durable session up to
   `MaxSessionDuration`" it was. Either set `SessionProfiles.RememberMeProfile` (for
   example `"mobile"`) so remember-me selects that profile, or stop sending
   `RememberMe` and name the profile instead. `RememberMe` with no
   `RememberMeProfile`, or together with `WithSessionProfile`, fails with
   `ErrSessionProfileConflict` instead of guessing. Without profiles remember-me
   is unchanged.
5. **Map the two new errors** in your HTTP layer: `ErrUnknownSessionProfile`
   (`AUTH_UNKNOWN_SESSION_PROFILE`, a server-side bug, 400) and
   `ErrSessionProfileConflict` (`AUTH_SESSION_PROFILE_CONFLICT`, 409). Both are
   returned before any password is verified or limiter touched.
6. **Know what existing sessions do.** Sessions issued before you enable profiles
   stay legacy (v5) and keep their lifetime and sliding behavior until they
   expire; only new logins get profiles. `AbsoluteSessionLifetime` and
   `MaxSessionDuration` no longer apply to a session created under a profile.
7. **Operate profiles as live configuration.** The policy is resolved from the
   config each time a session is refreshed, switched or read strictly. Shortening a
   profile's ceiling shortens existing sessions; lengthening never extends one;
   **removing or renaming a profile ends its sessions** at their next use
   (audited as `profile_unknown`), as does switching profiles off entirely. Keep a
   retired profile until its sessions have drained.
8. **Renewal and Hybrid.** A refresh always renews a renewing profile. `RenewOnUse`
   renews on `ModeStrict` reads only; on Hybrid and JWT-only routes, which never
   read the session, mobile sessions stay alive by refreshing.

New surface, all additive: `WithSessionProfile` / `SessionProfileFromContext`,
`SessionProfile`, `SessionProfilesConfig` and the `Config.SessionProfiles` field
(`Profiles`, `DefaultProfile`, `RememberMeProfile`), `ErrUnknownSessionProfile` /
`ErrSessionProfileConflict`, `SessionInfo.Profile` / `IdleExpiresAt`,
`jwt.Manager.CreateAccessWithTTL`, and in `session`: `Session.Profile`,
`ProfilePolicy`, `Store.WithProfiles` / `NewSessionLifetime`. A new
`session_invalid` audit event is emitted only with profiles configured.

### Optional: adopt external sign-in (Google, Sign in with Apple, OIDC)

**No action unless you enable `Config.ExternalAuth`.** With it off (the default)
behavior is byte-for-byte what it was before the feature: the same Redis commands
for login, refresh, validate, logout, `VerifyPassword` and `ChangePassword`, the
same audit events and metrics, no new keys, no network call.
`TestExternalAuthUnusedMatchesMain` pins this; its expected transcript was
captured by running the same scenario against the commit the feature branched
from.

To adopt it (see [external_identity.md](external_identity.md)):

1. **Add the schema.** A table with a unique `(tenant_id, provider, subject)`
   (example in the guide). Existing users need no migration.
2. **Implement `ExternalIdentityProvider`** on your `UserProvider`:
   `GetUserByExternalIdentity` (return `ErrUserNotFound` when none; your
   by-identifier lookups must likewise return `ErrUserNotFound` for a missing
   user, since any other error is treated as a failure),
   `CreateUserWithExternalIdentity` (user and link in one transaction;
   `ErrProviderDuplicateIdentifier` / `ErrExternalIdentityInUse` on a conflict),
   `LinkExternalIdentity`, `UnlinkExternalIdentity`, `ListExternalIdentities`.
   `Build` fails with `ExternalAuth.Enabled` and a provider that lacks them.
3. **Allow an empty `PasswordHash`.** External sign-up creates accounts with
   none. goAuth treats `""` as "no password" everywhere (see below); make sure
   your column allows it and your own code does not assume a hash.
4. **Configure providers** with every client ID that can obtain a token for your
   users (Google web/iOS/Android IDs; Apple Services ID and bundle ID).
5. **Issue a nonce per sign-in** from your server and pass it as
   `ExternalLoginOptions.Nonce`; pass `WithClientIP(ctx, ip)` so the per-IP limit
   works.
6. **Decide on linking.** `AutoLinkVerifiedEmail` requires
   `EmailVerification.Enabled` (`Build` fails otherwise: without it, pre-hijacking
   is possible), and it trusts an Active account to have a verified email. If
   you already have accounts that were never verified (created before
   verification was on, imported, or created Active by an admin), mark them
   `PendingVerification` first, or leave auto-linking off. Without it, tell users who hit `ErrExternalAccountLinkRequired`
   to sign in and link from settings, behind a step-up of your own.
7. **Optionally** call `Engine.WarmExternalKeys` at startup, and pass your own
   client with `Builder.WithHTTPClient` (proxy, egress policy).

Behavior changes that apply **even if you never enable external sign-in** and
only matter for accounts with an empty `PasswordHash` (which could not log in
before either):

- Password login against such an account now runs a dummy Argon2 verification
  (it used to fail instantly on the unparsable empty hash) and is audited with
  reason `password_not_set` instead of `password_mismatch`; it still returns
  `ErrInvalidCredentials` and counts toward the login limiter and auto-lockout.
- `ChangePassword` and `VerifyPassword` return the new `ErrPasswordNotSet`
  (`AUTH_PASSWORD_NOT_SET`, suggested HTTP 409) instead of
  `ErrInvalidCredentials` for such an account.
- A recent-authentication role-switch step-up no longer lists `"password"` as a
  factor for such an account.

Accounts that have a password are unaffected.

New surface, all additive: `Config.ExternalAuth` (`ExternalAuthConfig`,
`ExternalProviderConfig`, `ExternalKind*`), `Engine.LoginWithExternalIdentity` /
`LinkExternalIdentity` / `UnlinkExternalIdentity` / `ListExternalIdentities` /
`WarmExternalKeys`, `Builder.WithHTTPClient`, `ExternalIdentity`,
`ExternalIdentityProvider`, `ExternalLoginOptions`, `LoginResult.NewAccount` /
`LinkedIdentity`, and the sentinels `ErrExternalAuthDisabled`,
`ErrExternalProviderUnknown`, `ErrExternalTokenInvalid`,
`ErrExternalTokenReplayed`, `ErrExternalProviderUnavailable`,
`ErrExternalEmailUnverified`, `ErrExternalAccountNotFound`,
`ErrExternalAccountLinkRequired`, `ErrExternalLinkRequiresVerification`,
`ErrExternalIdentityInUse`, `ErrLastLoginMethod`, `ErrPasswordNotSet`,
`ErrExternalLoginRateLimited`. New Redis keys appear only when enabled:
`axt:<provider>:<hash>` (single-use records, expiring with the token) and
`rl:extlogin:*` (limiter counters).

### Rolling back external sign-in

Set `ExternalAuth.Enabled` to `false` (or downgrade). Sessions already issued stay
valid; users who signed up through a provider have no password and can set one
through password reset. The link table is yours and is not touched; the Redis
keys expire on their own.

### Rolling back session profiles

Downgrading to v0.7.0 after profiles were in use leaves v6 sessions and v3
challenges that v0.7.0 cannot decode. Sessions end (users sign in again);
nothing corrupts. To roll back cleanly, remove the profile configuration first
(on v0.8.0 that ends the profile sessions at their next use) and let challenges
(three minutes) drain.

## v0.7.0 Migration Notes (Non-Breaking)

No action needed unless you adopt the features. v0.7.0 is additive: no exported
signature changed, `gorelease -base=v0.6.2` reports no incompatible changes, and
with the new features unused (the defaults) behavior is byte-for-byte what it was
in v0.6.2: the same session bytes in Redis, the same access-token claims, the
same errors, audit events and metrics, and no extra Redis or provider calls.

### Optional: adopt role switching

1. Implement `RoleSwitchProvider.CanAssumeRole(ctx, tenantID, userID, role) (bool, error)`
   on your user provider. It **must return true for the account's primary role**
   as well as any other role it holds (it is also used by the refresh re-check).
   Scope it by `tenantID`. Make sure your `GetUserByID` / `GetUserByIDInTenant`
   return `goAuth.ErrUserNotFound` for a missing user: `SwitchRole` treats only
   that as "session not found" (401) and every other lookup error as a provider
   outage (`ErrSystemUnavailable`, 503, session untouched).
2. Set `Config.RoleSwitch.Enabled = true`. Optionally add step-up policies, for
   example `StepUp["admin"] = RoleStepUpPolicy{RequireMFA: true}`. `Build` fails if
   the provider lacks the capability, a `StepUp` key is not a registered role, or
   `RequireMFA` is used with neither TOTP nor WebAuthn enabled.
3. **Route every endpoint that gates on role or permissions through `ModeStrict`.**
   A per-route `ModeStrict` override on a hybrid engine is enough. On Hybrid and
   JWT-only routes an access token minted before a switch stays valid, with its old
   mask, until it expires. See the [per-mode revocation table](role_switching.md#revocation-guarantee-per-validation-mode).
4. Call `engine.SwitchRole(ctx, refreshToken, targetRole, goAuth.RoleSwitchOptions{})`
   from your HTTP layer, with the tenant on the context as for `Refresh`. Map the
   new errors: `ErrRoleNotAllowed`, `ErrStepUpRequired` and `ErrRoleSwitchDisabled`
   to 403 (return `StepUpFactors` for step-up), `ErrRoleSwitchSameRole` to 409,
   `ErrRoleSwitchRateLimited` to 429, `ErrRefreshReuse`/`ErrSessionNotFound` to 401.
5. Make clients serialize refresh and switch per session (single-flight), always
   store the most recently returned tokens, and retry an in-flight 401 only after
   re-reading the stored tokens. Presenting a pre-refresh token to `SwitchRole` is
   refresh-token reuse and ends the session.

What changes once `RoleSwitch.Enabled` is true, whether or not anyone switches:
`Refresh` first re-checks the session's role (one extra Redis read and **one
provider call per refresh**, primary-role sessions included); a revoked role ends
the session with `ErrRoleNotAllowed` and a provider outage returns
`ErrSystemUnavailable` without consuming the refresh token. Validation makes no
provider calls. If `StepUp` is non-empty, MFA logins also write an `asa:` Redis key
per session (sessions created before you configured step-up have none).

### Optional: `TenantAwarePasswordUpdater`

With `MultiTenant.Enabled`, implement
`UpdatePasswordHashInTenant(ctx, tenantID, userID, newHash) error` on your provider
and `ChangePassword`, password-reset confirm and rehash-on-login will call it, with
the tenant goAuth resolved, instead of the tenant-blind `UpdatePasswordHash`. Not
implementing it changes nothing.

### Optional: `TenantIDFromContext`

`goAuth.TenantIDFromContext(ctx) (string, bool)` reads back the tenant attached with
`WithTenantID`; it returns `("", false)` when none is attached and never invents the
default tenant `"0"`.

### Fixed: schema migration could resurrect a deleted session

The one-time rewrite of a pre-v5 session blob read the session and then wrote it
back with a plain `SET`. A session deleted in between (logout, reuse revocation, a
role switch) could be recreated with its old refresh hash. The rewrite now uses
`SET ... XX`. This only ever mattered for sessions written by goAuth versions older
than the v5 schema.

## v0.6.2 Migration Notes (Non-Breaking)

No action needed. v0.6.2 is a drop-in replacement for v0.6.0 and v0.6.1: no
exported API or config changed, and single-tenant deployments
(`MultiTenant.Enabled = false`) behave exactly as before.

v0.6.1 is retracted: it was tagged in error on the v0.6.0 commit and does not
contain this fix. Upgrade straight to v0.6.2.

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

If your deployment expects fail-closed limiter behavior for backend outages, set `Security.LimiterFailClosed = true` (v0.8.0; see [rate_limiting.md](rate_limiting.md#failing-closed)) or enforce that policy externally (gateway/WAF/rate-limit proxy).

---

## Session Schema Migration Notes

goAuth stores Redis session blobs with an embedded schema byte (`Session.SchemaVersion`).

### Current behavior

- Current schema version: `5` (`session.CurrentSchemaVersion`); sessions created under a session profile use the separate version `6` (`session.ProfileSchemaVersion`), written only for them
- Unknown/future schema versions: fail closed with a clear decode error
- Legacy supported versions (`1-4`): decoded safely and migrated on read, up to `5` and never beyond: migration never converts v5 into v6 and never rewrites a v6 record

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
