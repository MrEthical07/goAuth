# Release Readiness Assessment

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
