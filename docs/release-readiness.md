# Release Readiness Assessment

## v0.8.1 (security release)

Date: 2026-10-31
Release Target: v0.8.1
Status: Ready for release once the pull request for the Dressin G-4 requests (part 4) is merged and CI is green on `main`. The tag is created by the maintainer; nothing in the pull requests creates, moves or deletes one.

### Summary

v0.8.1 is the fix release for the second security audit of v0.8.0 (findings `R2-xx`),
delivered as three pull requests: part 1 limiters, brute force and enumeration (#30),
part 2 session lifecycle and revocation (#31), part 3 MFA artifacts, recovery and
docs (#32), plus part 4, the four changes requested by the first adopter (G-4: a test
clock, email change for an unverified account, the change-email boundary fix and a
two-step external sign-up). **v0.8.0 is retracted** (`retract v0.8.0` in `go.mod`: MFA-login TOTP
guessing was not limited per account). Upgrading from v0.8.0 is recommended; the
CHANGELOG `[0.8.1]` section lists the behavior changes old → new and the two changes
that can need action (`EmailChange.Strategy: VerificationUUID` is rejected by `Build`;
`GenerateBackupCodes` works without a TOTP code only in the ten minutes after
`ConfirmTOTPSetup`).

### Compatibility & rollout

- `gorelease -base=v0.8.0` reports only compatible changes (it suggests v0.9.0 because
  the API grew; the release is a patch release because every addition is optional and no
  signature changed).
- No new module dependencies; no stored format changed (the session and MFA challenge
  records and their golden-bytes tests are untouched).
- New Redis keys, all expiring by TTL: `aue:<tenant>:<user>` (revocation epoch),
  `amc:<challenge>:ep` (epoch and advertised factors of an MFA challenge),
  `abg:<tenant>:<user>` (first backup-code generation, 10 minutes),
  `aprg:<tenant>:<user>` (newest password-reset code), plus the limiter keys of part 1.
  Part 4 adds `aevg:<tenant>:<user>` (newest verification code, or a tombstone),
  `aecu:<tenant>:<id>` (an email change requested by a pending account) and, only with
  `DeferSignup`, `axs:<tenant>:<sha256(handle)>` (needs Redis 6.2 for `GETDEL`). The
  time-based `aeci:<tenant>:<user>` marker stays as the fallback for records with no
  pointer (issued by older instances).
- **Rolling deploy.** v0.8.0 and v0.8.1 instances can share a Redis. The revocation
  fence covers revocations made by v0.8.1 instances only; a reset code issued by a
  v0.8.0 instance may be refused once a v0.8.1 instance wrote the user's pointer; an
  MFA challenge issued by a v0.8.0 instance behaves as it did.
- **Provider contract.** By-ID lookups (`GetUserByID`, `GetUserByIDInTenant`) must return
  `ErrUserNotFound` for a missing user; any other error is treated as an outage.
- Optional provider capabilities, detected at `Build`: `PasswordHashCASUpdater`,
  `AccountStatusCASUpdater`. Optional option: `Security.RecheckUserOnRefresh`.

### Verification gates

Run on the part 3 branch (Windows, Go 1.27):

| Gate | Result |
|------|--------|
| `gofmt -l .`, `goimports -l .` | no output |
| `go build ./...`, `go vet ./...`, `go vet -tags=integration ./...` | pass |
| `go test ./... -count=1` | pass |
| `go test -tags=integration ./test/...` (miniredis, and Redis 7.0.15 through `REDIS_ADDR`) | pass |
| staticcheck (`-checks=all,-ST1000,-ST1003,-ST1005,-U1000`) | no findings |
| `security/run_scanners.sh` (Go 1.27.3) | baseline passed |
| `gorelease -base=v0.8.0` | only compatible changes |
| `security/run_perf_sanity.sh` | `ns/op` of `BenchmarkRefresh` is above the recorded baseline locally exactly as on `main` on the same machine (the baseline was recorded on other hardware); a same-machine A/B of Login, Login+MFA, Refresh, Validate, Logout and LogoutAll is in the pull request |

`go test -race ./...` is enforced by the `go-race` CI workflow (Ubuntu and macOS);
local race builds are unavailable on the release machine.

### Release checklist

- [x] Parts 1 and 2 merged (#30, #31)
- [x] Part 3 implemented with tests and docs
- [x] Part 4 (G-4) implemented with tests and docs; CHANGELOG `[0.8.1]` carries the security-review summary and the known residuals
- [x] CHANGELOG `[0.8.1]` dated, with the combined behavior changes and migration notes
- [x] `go.mod` retracts v0.8.0
- [x] Local gate passes
- [ ] Part 4 pull request merged to `main`, `go-race` and CodeQL green on `main`
- [ ] Annotated tag `v0.8.1` created after merge (maintainer); the retraction takes effect once it is published

---

## v0.8.0

Date: 2026-10-22
Release Target: v0.8.0
Status: Ready for release once the pull request for part 3 is merged and CI is green on `main`

---

## Summary

v0.8.0 is a backward-compatible minor release delivered as three pull requests:

1. **Per-client session profiles** (#26): named session lifetimes and
   access-token policies (a fixed web session, a renewing mobile one), a session
   blob schema v6 and an MFA challenge record v3 that exist only while profiles
   are used.
2. **External identity** (#27): `LoginWithExternalIdentity` and link, unlink and
   list for Google, Sign in with Apple and generic OIDC ID tokens, behind the
   optional `ExternalIdentityProvider` capability, with password-less account
   hardening.
3. **Change-email, atomic logout-all and hardening** (this release's last
   pull request): `RequestEmailChange` / `ConfirmEmailChange` /
   `CancelEmailChange` behind the optional `EmailChangeProvider` capability; an
   atomic `DeleteAllForUser` (and `DeleteAllForUserExcept`); role-switch
   MFA-proof keys deleted with their session; opt-in `Security.LimiterFailClosed`;
   and small fixes from the part 2 review.

Every public API change is additive. With every new feature off (the default),
behavior is what it was in v0.7.0, apart from two documented improvements in
part 3 (the atomic logout-all and the MFA-proof key cleanup).

---

## Scope (v0.8.0)

- Session profiles, `WithSessionProfile`, per-profile ceilings and idle
  windows, `SessionInfo.Profile` / `IdleExpiresAt`.
- External sign-in, `ExternalAuth` config, key cache, replay protection,
  identity linking and auto-link, `ErrPasswordNotSet` for password-less accounts,
  `external_identity_unlink_failure`.
- Change email with proof of the new address, five sentinels, three audit events,
  and refusal of password-reset and email-verification codes issued before the
  change.
- `session.Store.DeleteAllForUser` as one Lua script, `DeleteAllForUserExcept`,
  and the `asa:` proof key removed on every session-deleting path.
- `Security.LimiterFailClosed` with one deciding helper and a static call-site
  audit.
- The `TestSessionProfilesUnusedMatchesV070` flake fixed (test-only).

---

## Compatibility & migration notes

- `gorelease -base=v0.7.0` reports only compatible changes (new methods,
  fields, types, sentinels and codes; no signature changed).
- No new module dependencies.
- Behavior changes callers may observe, both in part 3:
  - `DeleteAllForUser` is atomic. Its Redis commands changed from a multi-command
    sequence to one script call; the result is the same, without the race.
  - A session's `asa:<tenant>:<id>` key is deleted with the session (it used to
    age out by TTL).
- Rolling deploys: profiles create v6 sessions and v3 challenges that v0.7.0
  cannot read; finish the deploy before enabling profiles. Part 3 migrates
  nothing; its keys appear only while a feature is on.
- The session scripts (rotation, swap, atomic logout-all) touch keys in more than
  one hash slot and need a single-node or non-sharded Redis, as before.
- `LimiterFailClosed` does not cover limiter resets, the auto-lockout counter or
  WebAuthn (which has no limiter).
- Applications must step the current user up before `RequestEmailChange`, link
  and unlink, and should notify `EmailChangeResult.OldEmail`
  (`docs/email_change.md`, `docs/external_identity.md`).

---

## Verification Gates

Run on the part 3 branch (Windows, Go 1.27):

| Gate | Result |
|------|--------|
| `gofmt -l .`, `goimports -l .` | no output |
| `go build ./...`, `go vet ./...`, `go vet -tags=integration ./...` | pass |
| `go test ./... -count=1` | pass |
| `go test -tags=integration ./test/...` (miniredis, and Redis 7.0.15 through `REDIS_ADDR`) | pass |
| staticcheck (`-checks=all,-ST1000,-ST1003,-ST1005,-U1000`) | no findings |
| `security/run_scanners.sh` (Go 1.27.3) | baseline passed (gosec=3, govulncheck=1) |
| `gorelease -base=v0.7.0` | only compatible changes |
| `security/run_perf_sanity.sh` | fails on `ns/op` locally exactly as it does on `main` on the same machine (baseline recorded on other hardware); a same-machine A/B of Login, Refresh and Validate shows no significant difference |

`go test -race ./...` is enforced by the `go-race` CI workflow (Ubuntu and
macOS); local race builds are unavailable on the release machine. It runs for
pull requests and for pushes to `main`.

### Boundary and unchanged-when-unused guardrails

`TestEngineErrorBoundaryStatic*`, `TestSessionProfilesUnusedMatchesV070` and
`TestExternalAuthUnusedMatchesMain` (only their "logout all" block changed, for
the script), `TestLimiterCallSitesAreClassifiedAndRouteThroughTheCentralHelper`,
and the golden-bytes tests (unmodified).

---

## Release Checklist

- [x] Parts 1 and 2 merged (#26, #27)
- [x] Part 3 implemented with tests and docs
- [x] CHANGELOG `[0.8.0]` dated, with migration notes
- [x] Behavior changes and rollout caveats documented
- [x] Local gate passes
- [ ] Part 3 pull request merged to `main`, `go-race` and CodeQL green on `main`
- [ ] Annotated tag `v0.8.0` created after merge (maintainer)
