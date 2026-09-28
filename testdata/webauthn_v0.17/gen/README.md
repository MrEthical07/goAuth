# WebAuthn v0.17.4 fixture generator

Captures the `testdata/webauthn_v0.17/*.json` fixtures from a real
`go-webauthn` v0.17.4 + `descope/virtualwebauthn` v1.0.5 ceremony, and checks
whether a ceremony written by the *current* go-webauthn version (v0.18.2)
still decodes and finishes under v0.17.4.

This is a **separate Go module** pinned to `go-webauthn v0.17.4`, so that
version never enters goAuth's own module graph. It exists purely to prove
compatibility; it is not part of the library or its build.

## Regenerating the v0.17.4 fixtures

```sh
cd testdata/webauthn_v0.17/gen
go run . -out ..
```

This overwrites `testdata/webauthn_v0.17/*.json` with a fresh ceremony
(a new random challenge and credential each run — the point is the JSON
*shape*, not byte-for-byte identity with the previous fixtures). Commit the
result if you intend to update the golden fixtures.

## Reverse rolling-deploy check

The main module's `TestWebAuthnV017*` tests already prove the **forward**
direction: a ceremony started under v0.17.4 decodes and finishes under
v0.18.2 (upgrading from v0.5.x to v0.6.0 mid-deploy is safe).

To check the **reverse** direction — rolling *back* from v0.6.0 to v0.5.x —
regenerate the v0.18-side fixtures from the main module, then verify them
here:

```sh
# From the repo root, with the main module's go-webauthn at v0.18.2:
go test -run TestGenerateReverseRollingDeployFixtures -update .

# Then, from this directory:
cd testdata/webauthn_v0.17/gen
go run . -verify-reverse ../../webauthn_v0.18
```

`-verify-reverse` reports two lines: whether the v0.18-written `SessionData`
decodes under v0.17.4 (`REVERSE DECODE`), and whether the registration
ceremony then finishes (`REVERSE FINISH`). A non-zero exit means one of them
failed.

Or run both directions in one step from the repo root:

```sh
make webauthn-compat
```
