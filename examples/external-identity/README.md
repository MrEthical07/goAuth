# examples/external-identity

A scripted walkthrough of goAuth **external sign-in**: verifying a Google (or
Sign in with Apple) ID token your application already obtained, then
creating, finding or linking the account and issuing a normal goAuth session.

It needs no network: a local test identity provider (a TLS key server and a
token signer, see `localIdP`) stands in for Google, and
[miniredis](https://github.com/alicebob/miniredis) stands in for Redis.

## Run

```bash
go run ./examples/external-identity
```

## What it shows

1. A first sign-in with an identity nobody has seen creates a **password-less**
   account (`AllowSignup`), linked in the same step.
2. The same person returning is found by the link alone; no email is needed
   (Sign in with Apple omits it after the first sign-in).
3. An ID token is accepted **once**: replaying it fails with
   `ErrExternalTokenReplayed`.
4. A verified Google email that matches an existing **password** account does
   not log in as that account (`ErrExternalAccountLinkRequired`). Taking it over
   would let anyone who pre-registered the address hijack it; see
   [docs/external_identity.md](../../docs/external_identity.md#why-auto-linking-needs-local-email-verification).
5. The legitimate path: sign in with the password, confirm it with
   `VerifyPassword` (the recommended step-up), then `LinkExternalIdentity`.
6. What a password-less account cannot do: `VerifyPassword` and
   `ChangePassword` fail with `ErrPasswordNotSet`, and its only identity
   cannot be unlinked (`ErrLastLoginMethod`).

The `users` type is a minimal in-memory `UserProvider` that also implements
`ExternalIdentityProvider`; in a real service the three identity methods sit on
a table with a unique index on `(tenant_id, provider, subject)`.

In production, leave `JWKSURL` out of the provider config (Google's and
Apple's published keys are the defaults) and issue the nonce from your server
(see `newNonce`).
