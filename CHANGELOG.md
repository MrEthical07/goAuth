# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.8.1] - 2026-10-27

**Security release. Upgrading from v0.8.0 is recommended, and v0.8.0 is retracted**
(`retract v0.8.0` in `go.mod`: MFA-login TOTP guessing was not limited per account;
fixed in v0.8.1). It contains the fixes for the second security audit of v0.8.0
(findings `R2-xx`), delivered as three pull requests. No exported signature changed:
`gorelease -base=v0.8.0` reports only compatible changes, and every capability the
fixes add is optional (new interfaces are detected by type assertion, new
configuration keeps today's behavior unless a line below says otherwise).
v0.8.0 and v0.8.1 can share a Redis during a rolling deploy; no stored format
changed (read the notes under part 2 for what the revocation fence covers while
both versions run).

### Behavior changes when upgrading from v0.8.0

What an application that enables nothing new sees, old → new, with the finding that
causes it. The same changes are explained, with their reasons, in the three parts
below and in `docs/migrations.md`.

*Login and brute force (part 1)*

- A correct password sent after `MaxLoginAttempts` wrong ones: accepted → refused with
  `ErrLoginRateLimited`, before the password is evaluated. (R2-05)
- Auto-lockout, if enabled: the attempt that reaches the threshold is answered
  `ErrAccountLocked` → `ErrInvalidCredentials` (the lock is still applied); wrong
  passwords rewrote a Disabled, Deleted or PendingVerification account to Locked →
  they leave its status alone. (R2-14, R2-16)
- MFA login: wrong TOTP codes were counted only inside the disposable challenge →
  also against the per-account TOTP budget `VerifyTOTP` uses (5 per minute by default),
  across challenges; the fifth wrong code destroys the challenge and answers
  `ErrTOTPRateLimited`. (R2-01)
- `RequestPasswordReset`, `RequestEmailVerification`, `CreateAccount`: an over-length
  identifier (more than 320 bytes) was looked up and hashed → an invalid request; a
  registered identifier answered faster than an unknown one → every branch takes the
  same randomized 20–40 ms; a request refused only by the per-account budget answers
  the rate-limit error. Their limiter keys became digests, so their counters restart
  at zero. (R2-19, R2-23, R2-04, R2-21)
- Login: an identifier over 320 bytes or a password over the hasher's limit was
  evaluated → refused with `ErrInvalidCredentials` before any lookup. `Build` hashes one
  throwaway password with your Argon2 settings. (R2-23, R2-18)

*Sessions and revocation (part 2)*

- Login read the account once → reads it a second time by ID (one extra
  `GetUserByID` per login), and a login that raced a password change, a disable or a
  logout-all is refused (`ErrInvalidCredentials` or the status error) or retried once
  instead of storing a session. (R2-08)
- MFA login: the session caps were checked at the password step only → also at the
  confirmation (`ErrSessionLimitExceeded`); single-session mode ended the other
  sessions at the password step → when the new session is stored; a confirmation after
  a revocation since the password step: accepted → `ErrMFALoginInvalid`. (R2-27, R2-28, R2-08)
- Rehash on login ran before the login was known to succeed and overwrote a newer
  password → runs after the session is issued and skips a hash that changed. (R2-07)
- `DisableAccount`, `LockAccount`, `DeleteAccount` skipped revocation when the user
  already had that status → revoke on every call. (R2-12)
- Password change and reset, TOTP changes, email change and blocking statuses revoked in
  one tenant → in the request's tenant and the provider record's. (R2-09)
- Refresh with enforced device binding ignored it → `ErrDeviceBindingRejected`. (R2-17)
- Email verification could re-enable a blocked account → it activates only a pending
  one. (R2-13)
- Strict `Validate` was documented as noticing role and permission changes → the
  documentation now says it compares the token with the session only; opt in to
  `Security.RecheckUserOnRefresh` or call `InvalidateUserSessions`. (R2-11)

*MFA artifacts, recovery and configuration (part 3)*

- `GenerateBackupCodes` worked for any caller whose user had no codes on file →
  needs an enabled authenticator and works without a TOTP code only in the 10 minutes
  after a successful `ConfirmTOTPSetup`, once; otherwise
  `ErrBackupCodeRegenerationRequiresTOTP`. `RegenerateBackupCodes` for a user
  without TOTP succeeded → `ErrTOTPNotConfigured`. A backup code counts as a factor
  (login, role-switch step-up) only for a user with an enabled authenticator. (R2-02)
- `DisableTOTP` left the user's backup codes on file → removes them.
- `EmailChange.Strategy = VerificationUUID` built → `Build` returns an error. (R2-03)
- Each `RequestPasswordReset` left the earlier codes valid, and a completed reset left
  the others valid → only the newest code is valid and a completed reset invalidates
  every outstanding one. (R2-25)
- A staged email change survived password reset, password change and `LogoutAll` →
  every successful revocation of all of a user's sessions cancels it (audit event
  `email_change_cancelled`, reason `recovery`). (R2-26)
- The MFA confirmation accepted any factor the user had enrolled → only a factor the
  challenge advertised (a backup code is the fallback of TOTP).
- `Security.EnableUserAgentBinding` defaulted to true and did nothing → defaults to
  false, is deprecated, and `Config.Lint()` warns when it is set.
- `Config.Lint()` also raises `login_ip_limiter_disabled` and `refresh_user_recheck_off`
  (both INFO) for every config that has not enabled those options. Redis traffic:
  see the Redis keys listed in each part.

### If you use…

- **`EmailChange` with `Strategy: VerificationUUID`**: `Build` now fails. In that
  strategy the code mailed to the new address was the id part of the
  `VerificationID` you may hand to the browser. Use `VerificationToken` (the default) or
  `VerificationOTP`; challenges already pending are discarded by the change of strategy
  (the user requests a new one).
- **`GenerateBackupCodes` outside the 10 minutes after `ConfirmTOTPSetup`** (for
  example a "show my backup codes" button in account settings, or a first generation
  for a user who enrolled before upgrading): it now returns
  `ErrBackupCodeRegenerationRequiresTOTP`. Call it right after `ConfirmTOTPSetup`, or
  ask the user for a TOTP code and call `RegenerateBackupCodes(ctx, userID, totpCode)`.
- Optional, no action needed: `PasswordHashCASUpdater`, `AccountStatusCASUpdater`
  and `Security.RecheckUserOnRefresh` (see `docs/migrations.md`).

### Security fixes (audit)

The security audit of v0.8.0 (run 2, `R2-xx` below) is fixed in three pull
requests, shipped together as v0.8.1. **Part 1 of 3: limiters, brute force and
enumeration** (R2-01, R2-04, R2-05, R2-06, R2-10, R2-14, R2-15, R2-16, R2-18,
R2-19, R2-21, R2-22, R2-23 and the audit's needs-validation record on unbounded
identifiers). **Part 2 of 3: session lifecycle and revocation** follows part 1
below, and **part 3 of 3: MFA artifacts, recovery and docs** follows part 2.

These are security fixes, so the unchanged-when-unused baselines moved where a
fix required it; `session/golden_bytes_test.go` is untouched and no session
or challenge format changed. The list of behavior changes for an application
that enables nothing new is under **Behavior changes** below.

#### Fixed

- **R2-01 (high): TOTP guesses at MFA login are bounded per account.**
  `ConfirmLoginMFA` counted wrong codes only inside the disposable challenge, and
  a correct password mints a fresh one every time. The confirmation now claims an
  attempt of the per-account TOTP budget that `VerifyTOTP` uses before the code is
  evaluated, clears it on a right code, and when it is spent destroys the
  challenge and returns `ErrTOTPRateLimited`. The per-challenge counter stays as a
  second bound.
- **R2-05, R2-10, R2-24: the check-then-record limiters now reserve first.** The
  login failure limiter, the TOTP limiter (`VerifyTOTP`, `ConfirmTOTPSetup`, the
  inline step-up check used by backup-code regeneration, password-reset MFA and
  role switching), the backup-code limiter (including the one behind MFA login) and
  the MFA challenge's attempt counter claim the attempt with one script
  (`Window.Reserve`; the challenge uses a script over the record's attempt field,
  replacing an optimistic transaction that gave up after four conflicts without
  counting) *before* the password or code is evaluated, so a concurrent burst
  evaluates at most the budget. A claim is given back only when the attempt was not
  a guess (a replayed code, a provider error, an expired WebAuthn ceremony).
- **R2-04: budgets keyed by the identifier as typed no longer multiply with
  spellings.** A second budget keyed by the resolved (tenant, user) is claimed after
  the lookup (login) or when the identifier resolves (password-reset and
  email-verification requests). goAuth still does not canonicalize identifiers.
  A login refused only by the account budget is answered `ErrInvalidCredentials`
  after the dummy verification so it is not an existence oracle; a request refused by
  it is answered with the rate-limit error (that is what stops the mail), which with
  a case-insensitive provider tells a caller trying spellings that the account
  exists. See `docs/rate_limiting.md`.
- **R2-21: limiter keys never carry caller input.** The password-reset,
  email-verification and account-creation limiter keys use SHA-256 digests of the
  tenant and the identifier or ID, as the login key does. Their counters start from
  zero on upgrade (`docs/migrations.md`).
- **R2-23 and the unbounded-identifier record: input caps.** Login refuses an
  identifier over `MaxIdentifierBytes` (320) or a password over the hasher's limit
  before the limiter, the lookup or any hashing, on one cheap path (`ErrInvalidCredentials`)
  that does the same work whether or not the account exists; an over-length password
  used to skip Argon2 for an existing account only. Reset requests, verification
  requests and account creation refuse an over-length identifier as an invalid
  request, and identifiers copied into audit metadata are truncated to the cap.
- **R2-18: the dummy verification costs what a real one costs.** `Build` hashes a
  random password once with the engine's hasher and every dummy verification (unknown
  identifier, empty password, an account without a password, `VerifyPassword` and
  `ChangePassword` on one) uses that hash instead of a constant of fixed cost.
- **R2-19: one response-time floor for every branch** of `RequestPasswordReset` and
  `RequestEmailVerification`: a randomized 20-40 ms measured from request entry,
  applied to the registered, unknown, inactive and already-verified branches.
- **R2-14: auto-lockout is not an existence oracle.** The attempt that reaches the
  threshold, and every wrong password after it, is answered `ErrInvalidCredentials`; the
  lock is still applied and audited, and `ErrAccountLocked` appears once the right
  password is given.
- **R2-16: auto-lockout leaves other statuses alone.** Only an Active account is
  counted or locked, so wrong passwords no longer rewrite a Disabled, Deleted or
  PendingVerification account to Locked.
- **R2-22: a login completed through MFA clears the auto-lockout counter**, as a
  password-only login does.
- **R2-15: `AutoLockoutDuration` is documented as what it is.** It sizes the
  window failures are counted in; an auto-locked account stays Locked until
  `UnlockAccount` or `EnableAccount`. Automatic unlocking is not built here (it is
  on the roadmap). New lint warning `auto_lockout_duration_noop`.

#### Added

- **`Security.LoginIPLimiter`** (R2-06; `LoginIPLimiterConfig{Enabled, MaxAttempts,
  Cooldown}`, **off by default**; defaults 20 per 15 minutes once enabled): a budget
  per (tenant, canonical client IP from `WithClientIP`), claimed before anything
  else is done for a login, given back when the password is right, skipped when the
  context has no address, honoring `LimiterWindowMode` and `LimiterFailClosed`.
  IPv6 addresses are grouped by /64. The address must come from your own proxy
  chain, and users behind one NAT share a budget (`docs/rate_limiting.md`). The
  documentation promised per-IP throttling that did not exist; it now says it is
  opt-in. New lint note `login_ip_limiter_disabled` (INFO). The lint reference is
  now 37 codes (15 INFO, 18 WARN, 4 HIGH).
- `MaxIdentifierBytes` (320), `password.Argon2.MaxPasswordBytes()`.
- New Redis keys (all counters with the limiter window as TTL): `rl:login:user:*`,
  `rl:reset:req:user:*`, `rl:verify:req:user:*` and, only when the per-IP throttle is
  on, `rl:login:ip:*`. The login, reset, verification and account-creation keys carry
  digests, not identifiers.
- Real-Redis `TestRedisCompat` coverage for the reserve, release and
  MFA-challenge attempt scripts.

#### Behavior changes (nothing new enabled)

- Login: a correct password sent after `MaxLoginAttempts` wrong ones is now refused
  with `ErrLoginRateLimited` (it used to be evaluated and accepted); the wrong
  attempts are refused at the same attempt number as before. (R2-05)
- Auto-lockout, if enabled: the threshold attempt is answered `ErrInvalidCredentials`
  instead of `ErrAccountLocked`; Disabled, Deleted and PendingVerification accounts keep
  their status. (R2-14, R2-16)
- MFA login: a fifth wrong TOTP code within a minute across challenges answers
  `ErrTOTPRateLimited` and destroys the challenge; `VerifyTOTP` failures share that
  budget. (R2-01)
- `RequestPasswordReset`, `RequestEmailVerification`: an over-length identifier is an
  invalid request, a registered identifier now takes the same 20-40 ms as an unknown
  one, and with a case-insensitive provider the account budget can answer the
  rate-limit error to another spelling. `CreateAccount` refuses an identifier over
  320 bytes. (R2-19, R2-23, R2-04)
- Redis traffic of a login: the limiter `GET` becomes a reserve script, the failure
  script is gone, and a right password issues `DEL` for the identifier and account
  budgets; counters of the reset, verification and account-creation limiters restart
  at zero on upgrade. `Build` performs one extra Argon2 hash. (R2-05, R2-04, R2-21,
  R2-18)
- `Config.Lint()` raises `login_ip_limiter_disabled` (INFO) for every config that has not
  enabled the per-IP throttle.

#### Notes

- The sequential limits are unchanged; what changed is that a refused attempt is
  refused before its secret is evaluated and that the budget cannot be exceeded by
  parallel requests. The regression tests fail on the branch the audit was run against
  (the TOTP ones need a one-line test seam there) and pass here.
- Dummy-verification timing now matches a real verification only for accounts whose
  stored hash was made under the current Argon2 settings; hashes that predate a cost
  change stay distinguishable until their owner logs in and the hash is upgraded.
- Auto-lockout's lock itself is a provider write that the attempt crossing the
  threshold performs and a wrong password does not; that difference in work is not
  equalized.

### Security fixes (audit), part 2 of 3: session lifecycle and revocation

R2-07, R2-08, R2-09, R2-11, R2-12, R2-13, R2-17, R2-20, R2-27, R2-28, R2-29, plus
three follow-ups found while reviewing these fixes (marked below).

#### Fixed

- **R2-08 (high): a login can no longer store a session after a revocation that
  it raced.** Every delete-all (password change or reset, account disable, TOTP
  change, email change, `LogoutAll`, `InvalidateUserSessions`) now also bumps a
  per-user revocation epoch (`aue:<tenant>:<user>`, kept for at least 24 hours). Password
  login, MFA confirmation, external sign-in and auto-login read the epoch before
  they read the account, and the session is stored by one script that refuses
  when the epoch moved. On a refusal the account is read once more: a blocking
  status is returned as that status's error, a password hash that is no longer the
  one that was verified or an account version that moved (a factor enrolled, a
  role or status changed) is `ErrInvalidCredentials`, and an unrelated logout-all
  retries once under the new epoch. The MFA confirmation is fenced with the epoch
  the password step ran under (stored next to the challenge, `amc:<id>:ep`), so a
  revocation between the two steps refuses the confirmation (`ErrMFALoginInvalid`)
  instead of being read as the epoch to issue under (follow-up, found in review).
  Residual window: auto-login after `CreateAccount` reads the epoch right after
  the account is created.
- **R2-27 (high): the session caps cannot be exceeded by parallel logins.** The
  per-user, concurrent-login and tenant caps are checked inside the script that
  stores the session, and they are checked again at the MFA confirmation, which
  used to store as many sessions as there were challenges. A tenant counter that
  drifted upwards is reconciled by a compare-and-set against the value read
  before the scan, so a session saved during the scan stays counted (follow-up,
  found in review); the password step no longer writes the scan back
  (follow-up).
- **R2-28: single-session mode no longer ends the account's sessions at the
  password step.** With MFA required the other sessions were ended before the
  second factor was proven. The password step only checks the caps; the other
  sessions are ended by the script that stores the new one, after everything
  else passed.
- **R2-29: the tenant session estimate counts only the tenant's own keys.** The
  scan pattern is glob-escaped and only keys whose remainder is a session ID are
  counted, so tenants `a` and `a:b`, or a tenant ID containing `* ? [ ]`, no
  longer count against each other.
- **R2-09: revocation reaches the sessions it is meant to.** Password change,
  password reset, TOTP enable and disable, email change and a blocking account
  status revoke in the request's tenant and, when it differs, the provider
  record's. One helper decides; a static test keeps call sites from choosing a
  tenant themselves.
- **R2-12: a retried disable, lock or delete revokes.** A blocking target status
  always runs the revocation, also when the stored status already equals it and
  also when the provider did not advance the account version.
- **R2-11 (opt-in): `Security.RecheckUserOnRefresh`.** Refresh re-reads the user
  through the tenant-scoped lookup and ends the session if the permission, role
  or account version differs from the session's copy or the status is blocking
  (`ErrSessionNotFound` or the status error); an unreachable provider is
  `ErrSystemUnavailable` and nothing is rotated. The docs said the version
  stamps detect a change in the user record; they only compare the token with
  the session. They now say so, and that without the flag the application must
  call `InvalidateUserSessions` on any role, permission or status change. New
  lint note `refresh_user_recheck_off` (INFO).
- **R2-17: Refresh applies enforced device binding.** In enforce mode (IP or
  user agent) Refresh reads the session without changing it and, if the presented
  token is its current one, applies the check Validate and role switching use
  before rotating. A mismatch is `ErrDeviceBindingRejected` and rotates nothing;
  a store outage while reading the session is `ErrSystemUnavailable` (follow-up,
  found in review). Off and detect-only modes read nothing extra.
- **R2-20: migrating a legacy session blob cannot undo a refresh rotation.** The
  rewrite of a pre-v5 blob is one script that compares the stored bytes with the
  bytes that were read and writes, keeping the TTL, only if they match.
- **R2-07: the rehash-on-login upgrade cannot overwrite a newer password.**
  Optional `PasswordHashCASUpdater` (below); without it the user is re-read right
  before the write and the upgrade is skipped unless the hash is still the verified
  one (narrows the window, does not close it). The upgrade runs after the session
  is issued or the MFA challenge created, so a login refused later upgrades
  nothing.
- **R2-13: email verification activates only a pending account.** Optional
  `AccountStatusCASUpdater` (below) for the pending-to-active write; without it
  the account is read again right before the write and only a pending one is
  activated. A disable, lock or delete that landed meanwhile is returned as that
  status's error and left alone.

#### Added

- Optional provider capabilities, detected by type assertion at `Build`:
  `PasswordHashCASUpdater{CompareAndSwapPasswordHash(ctx, tenantID, userID,
  expectedOldHash, newHash string) (applied bool, err error)}` and
  `AccountStatusCASUpdater{UpdateAccountStatusIf(ctx, tenantID, userID string,
  expected, next AccountStatus) (applied bool, err error)}`.
- `Security.RecheckUserOnRefresh` (default `false`).
- `session`: `Store.RevocationEpoch`, `Store.SaveFenced`, `SaveLimits`,
  `ErrSessionFenced`, `ErrUserSessionLimit`, `ErrTenantSessionLimit`.
- New Redis keys: `aue:<tenant>:<user>` (revocation epoch; integer; 24 hours,
  refreshed on every bump; written by every delete-all), and `amc:<challenge>:ep`
  (the epoch the password step ran under; the challenge's TTL; written when an
  MFA challenge is created, deleted with it). The session record, the MFA
  challenge record and every other stored format are unchanged
  (`session/golden_bytes_test.go` and `internal/stores/golden_bytes_test.go` are
  untouched).
- Lint code `refresh_user_recheck_off` (INFO); the reference is now 38 codes (16
  INFO, 18 WARN, 4 HIGH).
- Real-Redis `TestRedisCompat` coverage for the fenced save, the epoch bump, the
  legacy-schema migration, the tenant-counter reconciliation and the MFA
  challenge epoch.

#### Behavior changes (nothing new enabled)

- **Login**: after the identifier lookup the account is read once more by ID (the
  epoch is read first), so a provider sees one extra `GetUserByID` per login; the
  session is stored by one script (the caps are enforced inside it) instead of a
  count, a `SET` and a counter increment; a login that raced a password change,
  a disable or an unrelated logout-all is refused (`ErrInvalidCredentials`, or
  the status error) or retried once instead of storing a session. (R2-08)
- **MFA login**: the session caps are enforced at the confirmation
  (`ErrSessionLimitExceeded`, `ErrTenantSessionLimitExceeded`); the password step
  does not end sessions in single-session mode; a confirmation after a
  revocation since the password step is `ErrMFALoginInvalid`. (R2-27, R2-28, R2-08)
- **Rehash on login** runs after the session is issued (or the MFA challenge is
  created): a login refused by the session cap, device binding or an MFA outage
  no longer upgrades the hash, and a hash that changed since it was verified is
  not replaced. (R2-07)
- **Account status**: `DisableAccount`, `LockAccount` and `DeleteAccount` revoke
  the user's sessions on every call, including one whose target status the user
  already has. (R2-12)
- **Revocation** after a password change or reset, a TOTP change, an email change
  or a blocking status also covers the request's tenant when the provider record
  carries another. (R2-09)
- **Refresh** with `DeviceBinding.EnforceIPBinding` or
  `EnforceUserAgentBinding`: a request from another address or agent gets
  `ErrDeviceBindingRejected`. (R2-17)
- **Email verification**: the account is read again right before the status
  write, and a blocked account is returned as its status error. (R2-13)
- The revocation epoch is kept for `max(24h, TOTP.MFALoginChallengeTTL + 1h)` after the
  last revocation, computed once at `Build`, so an MFA challenge, which is fenced with
  the epoch of its password step, never outlives the evidence of a revocation made
  after it was issued. `Build` accepts any challenge TTL. (R2-08)
- `Config.Lint()` raises `refresh_user_recheck_off` (INFO) for every config that
  has not enabled the user re-read.
- Redis traffic: a login adds a `GET aue:*`; every delete-all adds an `INCR` and
  `PEXPIRE` inside its script; an MFA login adds a `SET` and a `GET` of the
  challenge's `:ep` companion and a `DEL` with the challenge.

#### Notes

- The fence protects against revocations done by instances that bump the epoch
  (v0.8.1); during a rolling deploy a revocation made by a v0.8.0 instance does
  not move it.
- The compare-and-set that reconciles the tenant counter compares the counter's
  value, so a save and a delete that cancel out during one scan can still leave a
  count off by the operations that overlapped it; the counter has always been an
  estimate that sessions expiring on their own pull away from the truth.
- The password-hash and status compare-and-set capabilities narrow, and with a
  provider that implements them close, the windows described above. Without them
  the re-read leaves a gap between the read and the write.
- The regression tests fail on the branch the audit was run against and pass
  here; the tests that need a new option or interface compile there against a
  stub of it.

### Security fixes (audit), part 3 of 3: MFA artifacts, recovery and docs

R2-02, R2-03, R2-25, R2-26, the backup codes that survived `DisableTOTP`, the MFA
confirmation that accepted an unadvertised factor, and the documentation the audit
found wrong. Also folds in one change from the review of part 2 (the revocation
epoch's life).

#### Fixed

- **R2-02 (medium): a session holder could mint backup codes and use them as a
  second factor.** `GenerateBackupCodes` needed no proof and no enrolled factor, and
  the `backup_code` step-up did not require an enabled TOTP record the way the `totp`
  branch does. Backup codes are now a recovery artifact of an enabled authenticator:
  the step-up and the login accept them only for a user who has one; Generate and
  Regenerate return `ErrTOTPNotConfigured` for a user who does not (Regenerate used to
  succeed for them); Generate works without a TOTP code only in the 10 minutes after
  `ConfirmTOTPSetup`, once (a tenant-scoped, single-use marker that a revocation of the
  user's sessions also invalidates); otherwise it returns
  `ErrBackupCodeRegenerationRequiresTOTP`. A user who enrolled before upgrading and
  has no codes uses `RegenerateBackupCodes` with a TOTP code.
- **`DisableTOTP` removes the user's backup codes** (and the pending marker): a set
  minted for one authenticator no longer works for the next. A failure to clear is
  returned as `ErrTOTPUnavailable` after the sessions have been revoked, and audited.
- **R2-03: the change-email Code no longer equals the VerificationID.** `Build` rejects
  `EmailChange.Strategy = VerificationUUID` with an error that names `VerificationToken`
  and `VerificationOTP`. A test checks that for each allowed strategy the Code cannot be
  read from the VerificationID.
- **R2-25: one valid reset code per account.** A per-(tenant, user) pointer names the
  newest reset record: a new `RequestPasswordReset` supersedes the codes of earlier
  requests (after its own record is stored, so a failed request leaves the user's code
  alone), and a completed reset supersedes every code issued before it. Anyone who can
  request a reset can supersede a waiting code; the request limiters bound that and the
  owner gets a new mail.
- **R2-26: recovery cancels a staged email change.** Every successful revocation of all
  of a user's sessions (password reset or change, `LogoutAll`, `LogoutAllInTenant`,
  `InvalidateUserSessions`, and the flows that end with one) cancels the user's pending
  email change while `EmailChange` is enabled, in the request's tenant, the caller's and
  the user's own. It is audited as `email_change_cancelled` (reason `recovery`); a
  failure neither fails the revocation nor goes unnoticed (logged, and
  `email_change_failure` with stage `cancel`, reason `recovery`), and the challenge then
  expires with its TTL.
- **The MFA confirmation accepts only a factor the challenge advertised.** The password
  step stores the factors it offered next to the challenge (its record is unchanged, so
  the golden-bytes tests are untouched); any other type is a wrong answer. A challenge
  from an earlier version accepts any enrolled factor, as before.
- **The revocation epoch is kept for `max(24h, TOTP.MFALoginChallengeTTL + 1h)`**, so
  `Build` accepts any challenge TTL (part 2 had rejected more than 12 hours).
- **Documentation corrected:** `docs/mfa.md` no longer says `GenerateBackupCodes`
  replaces codes; `docs/email_change.md` no longer suggests the VerificationID may
  reveal the Code; password-reset confirmation does not check password reuse (the docs
  said it did; the check is not added); `Security.EnableUserAgentBinding` was never read
  (see Added).

#### Added

- Redis keys: `abg:<tenant>:<user>` (the first-generation marker: 10 minutes, written by
  `ConfirmTOTPSetup`, consumed by `GenerateBackupCodes`, removed by `DisableTOTP`);
  `aprg:<tenant>:<user>` (the newest reset ID, or a tombstone after a completed reset;
  `PasswordReset.ResetTTL`, written by `RequestPasswordReset` and by a completed
  reset). The value of `amc:<challenge>:ep` is now `<epoch>:<factors>`.
- Audit event `email_change_cancelled`.
- Lint code `security_user_agent_binding_noop` (WARN); the reference is now 39 codes
  (16 INFO, 19 WARN, 4 HIGH). `Security.EnableUserAgentBinding` is deprecated and now
  defaults to false.
- `session.DefaultRevocationEpochTTL` and `Store.WithRevocationEpochTTL`.
- `go.mod`: `retract v0.8.0`.

#### Behavior changes (nothing new enabled)

Listed above under "Behavior changes when upgrading from v0.8.0" (part 3).

#### Notes

- The regression tests fail on the branch the audit was run against and pass here; the
  tests that need a new option, constant or method compile there against a stub of it.
- Backup codes minted by an earlier version for an account without TOTP stay on file
  but prove nothing until the user enrols an authenticator; `DisableTOTP` removes them.
- A reset code issued by a v0.8.0 instance while a v0.8.1 instance already wrote the
  pointer for that user is refused; the user requests another.

---

## [0.8.0] - 2026-10-25

Minor release (SemVer), delivered as three pull requests. **Part 1 (per-client session profiles) is additive; part 2 (external identity) follows it below.**
Nothing is removed and no exported signature changed: `Config` gained one
field, `SessionProfiles`, and `SessionConfig` is byte-for-byte what it was (it
stays comparable with `==`; the profile table lives in its own top-level field
because `Config` is already not comparable). `gorelease -base=v0.7.0` reports
only compatible changes. **With profiles unused (the default), behavior is
byte-for-byte what it was in v0.7.0:** the same session bytes in Redis
(`session/golden_bytes_test.go` passes unmodified), the same MFA challenge bytes, the same Redis command
sequence for login, refresh, validate and logout, the same token claims and
lifetimes, errors, audit events and metrics. This was checked by running one
scenario (every session-creating path, refresh, reuse, validation in all three
modes, a role switch, both logouts and an MFA login) against the v0.7.0 tag and
against this branch with no profile configured, and is now pinned by
`TestSessionProfilesUnusedMatchesV070`.

`gorelease -base=v0.7.0`:

```
# github.com/MrEthical07/goAuth
## compatible changes
Config.SessionProfiles, SessionProfilesConfig, SessionProfile,
WithSessionProfile, SessionProfileFromContext,
ErrUnknownSessionProfile, ErrSessionProfileConflict and their two Code* constants,
SessionInfo.Profile, SessionInfo.IdleExpiresAt: added

# github.com/MrEthical07/goAuth/jwt
(*Manager).CreateAccessWithTTL: added

# github.com/MrEthical07/goAuth/session
(*Store).WithProfiles, (*Store).NewSessionLifetime, (*Store).HasProfiles,
(*Store).Profile, ProfilePolicy, Session.Profile, Session.IdleExpiresAt,
UnboundedExpiresAt, ProfileSchemaVersion, MaxProfileNameLen, ErrProfileUnknown,
ErrSessionExpired, EndedProfileName: added

# github.com/MrEthical07/goAuth/examples/session-profiles
package added

# summary
Suggested version: v0.8.0
```

### Added

- **Per-client session profiles.** A profile is a named session lifetime and
  access-token policy, so one engine can serve a web app (fixed: ends 15 days
  after login), a mobile app (renewing: a 90-day inactivity window renewed by
  every successful refresh, up to a 365-day ceiling) and other clients with
  their own policy. Configure `Config.SessionProfiles`
  (`SessionProfilesConfig`: `Profiles map[string]SessionProfile`,
  `DefaultProfile` and optionally `RememberMeProfile`); a `SessionProfile` has `AccessTTL`, `IdleTimeout`
  (`0` = fixed, `> 0` = renewing), `AbsoluteLifetime` (a hard ceiling from
  login), `AllowUnbounded` and `RenewOnUse`. The zero value (no profiles) is
  v0.7.0.
- **`WithSessionProfile(ctx, name)` and `SessionProfileFromContext(ctx)`**,
  beside `WithTenantID`. The profile applies to every path that creates a
  session (`Login`, `LoginWithResult`, `LoginWithOptions`, `LoginWithTOTP`,
  `LoginWithBackupCode`, `ConfirmLoginMFA`, `ConfirmLoginMFAWithType`,
  `CreateAccount` with auto-login). No profile on the context means the
  `DefaultProfile`; `RememberMe` maps to `RememberMeProfile`. The profile is
  resolved before any limiter is read, password verified or provider called.
  Choose it from trusted server-side signals, never from request input.
- **`ErrUnknownSessionProfile` (`AUTH_UNKNOWN_SESSION_PROFILE`) and
  `ErrSessionProfileConflict` (`AUTH_SESSION_PROFILE_CONFLICT`)**, both
  validation errors. Conflict covers `RememberMe` together with an explicit
  profile, `RememberMe` with no `RememberMeProfile`, and an MFA confirm naming a
  different profile than its challenge (the challenge is left unconsumed).
- **Expiry mechanics enforced atomically in Redis.** The refresh script keeps
  every existing check and its order, then resolves a profile session's policy
  from the live configuration and renews a renewing profile's window to
  `min(IdleTimeout +/- jitter, ceiling - now)` in the same Lua call as the
  compare-and-swap; a fixed profile keeps its TTL. A role switch is a use
  and renews the window, never past the ceiling. A `ModeStrict` read renews it
  only with `RenewOnUse` and never applies the legacy sliding reset to a
  profile session. Profiles are resolved from the current configuration:
  shortening a ceiling shortens existing sessions, lengthening never extends
  one, and removing a profile ends its sessions at their next use.
- **Session schema v6**, written only for sessions created under a profile: the
  unchanged v5 layout plus a length-prefixed profile name after `ExpiresAt`.
  `CurrentSchemaVersion` stays 5, legacy sessions stay v5 forever, and
  migration never converts v5 into v6 or rewrites a v6 record. Both Lua copies of
  the blob parser read v6.
- **MFA challenge record v3**, written only when a profile was resolved: v2
  plus a length-prefixed profile name, so the profile survives the MFA step. A
  challenge without a profile is still v2, byte for byte. The decoder accepts
  v1-v3.
- **`jwt.Manager.CreateAccessWithTTL`**, an additive method issuing an access
  token with its own lifetime (a profile's `AccessTTL`). `CreateAccess` is
  unchanged; only `exp` differs.
- **Observability.** `SessionInfo` gains `Profile` and `IdleExpiresAt`. With
  profiles configured the audit events `login_success`, `mfa_success`,
  `refresh_success`, `refresh_invalid`, `logout_session` and `role_switched`
  carry `metadata.profile`; a refresh of a removed profile is `refresh_invalid`
  with reason `profile_unknown`, and a strict read that ends a profile session
  emits the new `session_invalid` event (reason `expired` or `profile_unknown`).
  No metric IDs were added.
- **Config validation and lint.** `Build` rejects a missing or undefined
  default, malformed names (`[a-z0-9_-]`, at most 32), negative durations, a
  missing ceiling without `AllowUnbounded`, `RenewOnUse` without an idle window
  and an idle window longer than the ceiling. `ProductionMode` additionally
  requires, per profile, an effective access TTL of at most 15 minutes, a fixed
  ceiling of at most 30 days, and a renewing idle window of at most 90 days
  with a bounded ceiling unless `AllowUnbounded`. New lint codes:
  `session_profile_ceiling_long` (warn), `session_profile_unbounded` (warn),
  `session_profile_renew_on_use_stateless` (info) and
  `session_profile_removal_ends_sessions` (info); the lint reference is now 32
  codes (12 INFO, 16 WARN, 4 HIGH).
- New `session` API: `Session.Profile`, `Session.IdleExpiresAt`,
  `ProfilePolicy`, `Store.WithProfiles`, `Store.NewSessionLifetime`,
  `Store.HasProfiles`, `Store.Profile`, `UnboundedExpiresAt`,
  `ProfileSchemaVersion`, `MaxProfileNameLen`, `ErrProfileUnknown`,
  `ErrSessionExpired` and `EndedProfileName`.
- `examples/session-profiles`, a runnable walkthrough (built in CI next to
  `http-minimal`), and real-Redis `TestRedisCompat` coverage for the profile
  scripts.

### Changed

- With profiles configured, `RememberMe` no longer silently selects
  `MaxSessionDuration`: it selects `SessionProfiles.RememberMeProfile`, or fails with
  `ErrSessionProfileConflict` when none is set. Without profiles remember-me is
  unchanged.
- A session created under a profile is governed by that profile alone:
  `AbsoluteSessionLifetime`, `MaxSessionDuration` and `SlidingExpiration` do
  not apply to it (its strict-read renewal is `RenewOnUse`).
- The refresh and swap Lua scripts changed (their SHA1 differs) because they
  must parse v6 and apply profile rules. For a legacy session they take the old
  path unchanged, and with no profile table the script arguments, and so the
  commands sent to Redis, are the legacy ones.
- `AllowUnbounded` is accepted only on a renewing profile (`IdleTimeout > 0`)
  and is exclusive with `AbsoluteLifetime`: a fixed profile with no ceiling
  would never expire, and the combination is rejected at `Build`.
- Documentation: `session.md` (a full "Session profiles" section), `config.md`,
  `config_lint.md`, `api-reference.md`, `goAuth-methods.md`, `mfa.md`,
  `multi_tenancy.md`, `introspection.md`, `audit.md`, `role_switching.md`,
  `jwt.md`, `error-model.md` and `migrations.md`.
- New root source file `engine_sessionprofile.go` (the per-subsystem pattern of
  `engine_roleswitch.go`); the root source whitelist in
  `.github/workflows/go-race.yml` was updated.

### Notes: rolling-deploy compatibility

- **v6 sessions and v3 MFA challenge records cannot be read by v0.7.0.** A
  v0.7.0 instance that meets one rejects it (sessions end; users sign in again;
  nothing is corrupted). **Finish the deploy to v0.8.0 before enabling
  profiles.** Sessions and challenges created without a profile are v5 and v2
  and stay readable by v0.7.0 in both directions.
- Removing or renaming a profile, or switching profiles off, ends the sessions
  issued under it at their next use; this is also the way to roll profiles back.
- Part 1 of 3 (this section). Third-party sign-in is part 2 (below); the
  change-email, atomic `DeleteAllForUser`, opt-in fail-closed limiter and
  role-switch MFA-proof cleanup work is part 3. The release tag follows the
  third.

### Part 2 of 3: third-party sign-in (Google, Sign in with Apple, OIDC)

Additive. Nothing is removed and no exported signature changed: `Config` gained
one field, `ExternalAuth`, a new top-level struct (no map or slice was added to
an existing comparable struct), the `Engine` and `Builder` gained methods, and the
user provider gained an **optional** capability interface detected by type
assertion. **With `ExternalAuth` off (the default), behavior is byte-for-byte
what it was before this part:** the same Redis commands for login, refresh,
validate, logout, `VerifyPassword` and `ChangePassword`, the same audit events
and metrics, no new keys and no network call, pinned by
`TestExternalAuthUnusedMatchesMain` (expected values captured by running the same
scenario on the commit this part branched from) next to the unchanged
`TestSessionProfilesUnusedMatchesV070` and golden tests. No new module
dependency: verification uses the standard library and
`github.com/golang-jwt/jwt/v5`, already required.

The one change that can be seen without enabling it is deliberate hardening of
**accounts with an empty `PasswordHash`**, which only the new feature creates
(see Changed).

`gorelease -base=v0.7.0` (the whole v0.8.0 diff so far, parts 1 and 2):

```
# github.com/MrEthical07/goAuth
## compatible changes
(*Builder).WithHTTPClient: added
(*Engine).LinkExternalIdentity: added
(*Engine).ListExternalIdentities: added
(*Engine).LoginWithExternalIdentity: added
(*Engine).UnlinkExternalIdentity: added
(*Engine).WarmExternalKeys: added
CodeAuthExternalAccountNotFound: added
CodeAuthExternalDisabled: added
CodeAuthExternalEmailUnverified: added
CodeAuthExternalIdentityInUse: added
CodeAuthExternalLinkRequired: added
CodeAuthExternalLinkRequiresVerify: added
CodeAuthExternalLoginRateLimited: added
CodeAuthExternalProviderUnknown: added
CodeAuthExternalTokenInvalid: added
CodeAuthExternalTokenReplayed: added
CodeAuthLastLoginMethod: added
CodeAuthPasswordNotSet: added
CodeAuthSessionProfileConflict: added
CodeAuthUnknownSessionProfile: added
CodeSystemUnavailableExternalProvider: added
Config.ExternalAuth: added
Config.SessionProfiles: added
ErrExternalAccountLinkRequired: added
ErrExternalAccountNotFound: added
ErrExternalAuthDisabled: added
ErrExternalEmailUnverified: added
ErrExternalIdentityInUse: added
ErrExternalLinkRequiresVerification: added
ErrExternalLoginRateLimited: added
ErrExternalProviderUnavailable: added
ErrExternalProviderUnknown: added
ErrExternalTokenInvalid: added
ErrExternalTokenReplayed: added
ErrLastLoginMethod: added
ErrPasswordNotSet: added
ErrSessionProfileConflict: added
ErrUnknownSessionProfile: added
ExternalAuthConfig: added
ExternalIdentity: added
ExternalIdentityProvider: added
ExternalKindApple: added
ExternalKindGoogle: added
ExternalKindOIDC: added
ExternalLoginOptions: added
ExternalProviderConfig: added
LoginResult.LinkedIdentity: added
LoginResult.NewAccount: added
SessionInfo.IdleExpiresAt: added
SessionInfo.Profile: added
SessionProfile: added
SessionProfileFromContext: added
SessionProfilesConfig: added
WithSessionProfile: added

# github.com/MrEthical07/goAuth/examples/external-identity
## compatible changes
package added

# github.com/MrEthical07/goAuth/examples/session-profiles
## compatible changes
package added

# github.com/MrEthical07/goAuth/jwt
## compatible changes
(*Manager).CreateAccessWithTTL: added

# github.com/MrEthical07/goAuth/session
## compatible changes
(*Store).HasProfiles: added
(*Store).NewSessionLifetime: added
(*Store).Profile: added
(*Store).WithProfiles: added
EndedProfileName: added
ErrProfileUnknown: added
ErrSessionExpired: added
MaxProfileNameLen: added
ProfilePolicy: added
ProfileSchemaVersion: added
Session.IdleExpiresAt: added
Session.Profile: added
UnboundedExpiresAt: added

# summary
v0.8.0 is a valid semantic version for this release.
```

#### Added

- **`Engine.LoginWithExternalIdentity(ctx, provider, idToken, ExternalLoginOptions)`.**
  Verifies an OIDC ID token the application already obtained, resolves, links or
  creates the account, and continues exactly like a password login (account
  status, session hardening, MFA decision and challenge, session issuance, audit
  and metrics) through a shared login tail extracted from the password flow.
  `LoginResult` gains `NewAccount` and `LinkedIdentity`. The OAuth2 code
  exchange, PKCE, redirects and discovery are out of scope (roadmap phase 2).
- **Token verification** (new `internal/oidc`): size cap (16 KB), algorithm
  allow-list (RS256/384/512, ES256/384; never `none` or `HS*`), key selected by
  `kid` with `kty`/`use`/`alg`/`key_ops` consistent with the token, issuer,
  audience (a list needs a configured `azp`), `exp`/`iat`/`nbf` against the
  server clock with a leeway, a required nonce (raw or lowercase hex SHA-256,
  constant-time), subject, Google hosted domain, `email_verified` /
  `is_private_email` as bool or string, and single use recorded with `SET NX` as
  `axt:<provider>:<hash of the signed part>`.
- **Key cache** with `Cache-Control` max-age clamped to `[KeyRefreshMin, 24h]`,
  single-flight fetch, at most one refetch per `KeyRefreshMin` for an unknown
  `kid`, a failure back-off, last-good keys served for `KeyMaxStale` during an
  outage and then `ErrExternalProviderUnavailable` (never an unverified token),
  a 1 MB cap, https-only URLs and redirects. Nothing is fetched at `Build`;
  `Engine.WarmExternalKeys` is an optional warm-up; `Builder.WithHTTPClient`
  injects the client (default 5s timeout).
- **Account resolution:** linked identity; else a *verified* email matched through
  the tenant-scoped lookup, auto-linked only for an Active account when
  `AutoLinkVerifiedEmail` is on (which `Build` requires
  `EmailVerification.Enabled` for, closing account pre-hijacking), refused for a
  pending account (`ErrExternalLinkRequiresVerification`), for auto-link off
  (`ErrExternalAccountLinkRequired`) or with the account's own status error;
  else `AllowSignup` creates a password-less Active account atomically with its
  link, under the account-creation limiter; a concurrent first sign-up re-runs
  the resolution once. An unverified or missing email is never used.
- **`LinkExternalIdentity`, `UnlinkExternalIdentity`, `ListExternalIdentities`.**
  Link verifies the token like a sign-in, is idempotent for the same user,
  refuses an account pending verification and another user's identity.
  Unlink refuses the last way in of a password-less account
  (`ErrLastLoginMethod`).
- **`ExternalIdentityProvider`**, the optional `UserProvider` capability
  (tenant-scoped; unique `(tenant, provider, subject)`; atomic create-and-link),
  with the record-tenant backstop applied to its lookups.
- **Rate limiting:** a new `rl:extlogin:*` domain on `internal/window`, honouring
  `LimiterWindowMode`, atomic reserve, failing open: per client IP before
  verification (skipped without an IP, because a shared bucket would let anyone
  lock out the provider) and per identity after; reset on success.
- **Config and lint:** `Config.ExternalAuth` (`ExternalAuthConfig`,
  `ExternalProviderConfig`, `ExternalKindGoogle|Apple|OIDC`) with validation (including that no
  two providers share an issuer and a client ID, and `KeyMaxStale >= KeyRefreshMin`) and
  deep copy in `cloneConfig`; lint codes `external_signup_passwordless` (info),
  `external_key_max_stale_long` (warn, above 72h) and
  `external_autolink_trusts_active_status` (info: auto-link treats an Active
  account as email-verified, which legacy accounts may not be); the lint
  reference is now 35 codes
  (14 INFO, 17 WARN, 4 HIGH).
- **Errors:** `ErrExternalAuthDisabled` (403), `ErrExternalProviderUnknown` (400),
  `ErrExternalTokenInvalid` (401), `ErrExternalTokenReplayed` (401),
  `ErrExternalProviderUnavailable` (503), `ErrExternalEmailUnverified` (403),
  `ErrExternalAccountNotFound` (404), `ErrExternalAccountLinkRequired` (409),
  `ErrExternalLinkRequiresVerification` (409), `ErrExternalIdentityInUse` (409),
  `ErrLastLoginMethod` (409), `ErrPasswordNotSet` (409) and
  `ErrExternalLoginRateLimited` (429), each with an `AuthCode`, category and
  error-boundary mapping.
- **Audit:** `external_login_success`, `external_login_failure` (fixed
  `reason`), `external_identity_linked`, `external_identity_unlinked`,
  `external_identity_link_failure`, and `account_creation_success` with
  `method=external`. The ID token and nonce are never written to audit or logs. No
  metric IDs were added.
- `examples/external-identity`, a runnable walkthrough with a local test identity
  provider (built in CI), and `docs/external_identity.md`.

#### Changed

- **Accounts with no password** (`PasswordHash == ""`) are now handled
  deliberately. Password login against one runs a dummy Argon2 verification and
  takes the wrong-password path (same limiter, auto-lockout and
  `ErrInvalidCredentials`; audit reason `password_not_set`) instead of failing
  instantly on the unparsable hash, which would have been a timing oracle once
  such accounts exist. `ChangePassword` and `VerifyPassword` return
  `ErrPasswordNotSet` after a dummy verification and still count toward the
  password-verify limiter. A recent-authentication role-switch step-up no longer
  offers `"password"` to them. Password reset still sets a first password.
  Behavior for accounts that have a password is unchanged.
- `RunLoginWithResult` ends in a shared `runCompleteLogin` (moved verbatim); the
  raw-error budget in `engine_error_boundary_static_test.go` moved with it
  (`RunLoginWithResult` 3 to 0, new `RunCompleteLogin` 3).
- Documentation: new `external_identity.md`; `config.md`, `config_lint.md`,
  `api-reference.md`, `goAuth-methods.md`, `error-model.md`, `multi_tenancy.md`,
  `security.md`, `password.md`, `audit.md`, `migrations.md`, `roadmap.md`
  (SSO phase 1 done, phase 2 planned), `index.md` and the README.
- New root source file `engine_external.go`; the root source whitelist in
  `.github/workflows/go-race.yml` was updated, and CI now builds
  `examples/external-identity`.

#### Notes

- Redis keys appear only when enabled: `axt:*` (single-use records) and
  `rl:extlogin:*`. Rolling back is `ExternalAuth.Enabled = false`.
- Applications must handle what goAuth cannot: Apple token revocation on account
  deletion and Apple server-to-server notifications (see the checklist in
  `docs/external_identity.md`), and a step-up before link and unlink.
- Parts 1 and 2 of 3. Part 3 (change-email, atomic `DeleteAllForUser`, opt-in
  fail-closed limiters, role-switch MFA-proof cleanup) follows below. The release
  tag follows it.

### Part 3 of 3: change-email, atomic logout-all and hardening

Additive, with two documented improvements to existing behavior (the atomic
logout-all and the MFA-proof key cleanup below). No exported signature changed
and no module dependency was added: `Config` gained `EmailChange`,
`SecurityConfig` one bool, the user provider one **optional** capability, and
`session.Store` one method. **With every new feature off (the default), behavior
is what it was before this part**, apart from those two improvements:
`TestSessionProfilesUnusedMatchesV070` and `TestExternalAuthUnusedMatchesMain`
still pin the Redis commands, bytes, errors, audit events and metrics of login,
refresh, validation, password verification and change, and both logouts, with
only their "logout all" block updated for the script, and the golden-bytes tests
pass unmodified. `gorelease -base=v0.7.0` reports only compatible changes.

#### Changed

- **`session.Store.DeleteAllForUser` is atomic.** It was several round trips
  (read the user's session set, read the tenant counter, check which sessions
  exist, then delete): a session created in between survived "logout everywhere"
  and the counter could drift. It is now one Lua script that deletes every
  session of the user that exists (and its `asa:` MFA-proof key), lowers the
  tenant counter by the number it actually deleted (never below zero, key removed
  at zero) and clears the user's session set. The exported signature is
  unchanged, `Engine.LogoutAll`, `LogoutAllInTenant`, `ChangePassword`, password
  reset and the account-status methods all use it, and
  `session.Store.DeleteAllForUserExcept` is new for callers that must keep one
  session. Like the existing rotation and swap scripts it touches keys in more
  than one hash slot (single-node or non-sharded Redis). The only change to the
  unchanged-when-unused baselines is their "logout all" block: the old
  SMEMBERS/GET/EXISTS/MULTI/DEL sequence is now one script call.

- **Role-switch MFA-proof keys (`asa:<tenant>:<sessionID>`) are removed with
  their session.** Logout, logout-all, refresh-token reuse, session expiry and a
  removed or expired session profile used to leave the key to age out by its TTL.
  Every path that deletes a session now deletes the key in the same script
  (`deleteSessionScript`, the rotation script's five delete branches, the swap
  script's failure branches, `DeleteAllForUser`). The scripts' keys and arguments
  are unchanged; the key is derived from the tenant counter key inside the
  script, so the baselines are unaffected.

#### Added

- **Change email.** `Engine.RequestEmailChange`, `ConfirmEmailChange` and
  `CancelEmailChange`, behind `Config.EmailChange` (zero value = disabled; with
  it off nothing changes and no key is created). The user provider gains an
  **optional** capability, `EmailChangeProvider.UpdateIdentifier`, a
  tenant-scoped compare-and-set on the old identifier that bumps
  `AccountVersion`; it is detected at `Build` and required when the feature is
  on. A request stores a challenge bound to the user, the old and new
  identifiers and the account version, rate limited per user, with a code (token,
  UUID or OTP) the application mails to the NEW address. It does not check
  whether the new address is taken, so it cannot be used to find out which
  addresses have accounts; confirm enforces uniqueness (`ErrEmailInUse`), a
  changed account (`ErrEmailChangeStale`), the status and the code (constant
  time, attempts counted, one use). Unless `KeepOtherSessions`, every session of
  the user is revoked except the one named in `ConfirmEmailChangeOptions`. The
  result carries the old address: notify it. External identity links are not
  touched. Five sentinels: `ErrEmailChangeDisabled` (403),
  `ErrEmailChangeInvalid` (400), `ErrEmailChangeStale` (409), `ErrEmailInUse`
  (409), `ErrEmailChangeRateLimited` (429); audit events `email_change_requested`,
  `email_change_confirmed`, `email_change_failure` (addresses masked, never the
  code). Lint: `email_change_keeps_other_sessions` (INFO). See
  `docs/email_change.md`. `.github/workflows/go-race.yml`'s root-source
  whitelist gained `engine_emailchange.go`.
- **A confirmed email change refuses every password-reset and
  email-verification challenge issued before it.** Those records hold no
  identifier and no account version, so the `AccountVersion` bump alone did not
  stop an old reset code from working after the address moved. With `EmailChange`
  enabled a per-user marker is written before the provider call and again once it
  commits, and read (one `GET`) on the two confirm paths; with it off nothing is
  read or written.
- **`Security.LimiterFailClosed`** (default `false`). A limiter backend error
  is still recorded as a `limiter_fail_open` audit event and the request still
  proceeds unthrottled by default. With the flag on, every limiter check or
  count that gates a request (login, password verification, TOTP, backup codes,
  role switch, account creation, email verification, password reset, external
  sign-in and sign-up) refuses it with a system error (503) instead. One helper,
  `Engine.limiterOutage`, makes the decision for every call site; a static test
  lists them all. The event keeps its name and gains `fail_closed=true`
  metadata when the flag is on. Lint: `limiter_fail_closed_outage_blocks_signin`
  (INFO). With the flag off, behavior is unchanged. Limiter resets after a
  success never block, and the auto-lockout counter is not covered.

#### Fixed

- `LinkExternalIdentity`, `UnlinkExternalIdentity` and `ListExternalIdentities`
  read every error from the signed-in user's lookup as "account not found". Only
  `ErrUserNotFound` (from the provider or the tenant-mismatch backstop) means
  that now; any other provider error is reported as `ErrSystemUnavailable`
  (503), so a database blip no longer tells a client to sign the user out.
  The link-failure audit reason for it is `lookup_failed`.
- `UnlinkExternalIdentity` audits its failures as
  `external_identity_unlink_failure` with the reason `disabled`,
  `user_not_found`, `account_status`, `last_login_method` or `unavailable`, as
  link failures already were. Nothing is added to the success path.
- `TestSessionProfilesUnusedMatchesV070` flaked about once in 55 runs: its
  argument printer read a random 32-byte refresh hash that started with the byte 2
  as an MFA challenge record. A test-only change; 36 of 2000 runs failed before
  it and none after.

#### Notes

- Rolling deploys: nothing is migrated. The new Lua scripts load on first use, a
  v0.8.0 instance and an earlier one can share a Redis (the old
  `DeleteAllForUser` is simply not atomic), and the email-change keys (`aec:*`,
  `aecp:*`, `aeci:*`, `rl:emailchange:*`) appear only while the feature is on and
  expire by TTL, so rolling it back is `EmailChange.Enabled = false`.
- Like the rotation and swap scripts, the atomic `DeleteAllForUser` touches keys
  in more than one hash slot, so it needs a single-node or non-sharded Redis.
- `Security.LimiterFailClosed` does not cover limiter *resets*, the auto-lockout
  counter or WebAuthn assertions (which have no limiter of their own).
- The application must step the current user up before `RequestEmailChange` and
  should notify `EmailChangeResult.OldEmail`; see `docs/email_change.md`.
- `Engine.ConfirmEmailChange` can return its result together with
  `ErrSessionInvalidationFailed` when the address changed but the other sessions
  could not be revoked.

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
    During a switch only `ErrUserNotFound` from the account lookup (which includes
    the tenant-mismatch backstop) means the session is gone; any other lookup
    error is a provider outage and returns `ErrSystemUnavailable` with the session
    untouched, so the same refresh token works on retry. Return
    `goAuth.ErrUserNotFound` for a missing user from `GetUserByID` /
    `GetUserByIDInTenant`.
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
