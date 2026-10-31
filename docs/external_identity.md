# External Identity (Google, Sign in with Apple, OIDC)

goAuth can sign a user in with an **OpenID Connect ID token your application
already obtained** from Google, Sign in with Apple or another OIDC provider. It
verifies the token, finds or links or creates the account, and then issues a
normal goAuth session through the same path a password login takes.

```go
res, err := engine.LoginWithExternalIdentity(ctx, "google", idToken, goAuth.ExternalLoginOptions{
    Nonce: nonceYourServerIssued,
})
```

- **Off by default.** `Config.ExternalAuth` has a zero value of "disabled", and a
  disabled engine behaves exactly as it did before the feature existed (see
  [migrations.md](migrations.md#v080-migration-notes-non-breaking)).
- **No new dependencies.** Verification uses the standard library and
  `github.com/golang-jwt/jwt/v5`.

## Scope

In scope: verifying an ID token you hand over, and the account lifecycle around
it (resolve, link, create, unlink, list).

Out of scope, and deliberately so:

- The OAuth2 authorization-code exchange and PKCE, redirects and callbacks, and
  provider discovery (`.well-known`). Your application (or the provider's SDK)
  does the redirect dance and gets the ID token; goAuth does not run it. These
  are the planned "phase 2" in the [roadmap](roadmap.md).
- Storing or refreshing provider access/refresh tokens. goAuth never sees them.
- **Revoking Apple tokens when an account is deleted.** App Store rules require
  it and only your application holds the credentials to do it; see the
  [Apple checklist](#apple-compliance-checklist).

Where the token comes from: Google Identity Services on the web, the Google
Sign-In SDKs on iOS and Android, the Sign in with Apple SDK or JS, or any OIDC
provider's implicit/hybrid flow.

## Configuration

```go
cfg := goAuth.DefaultConfig()
cfg.Account.Enabled = true              // needed for AllowSignup
cfg.Account.DefaultRole = "member"
cfg.ExternalAuth = goAuth.ExternalAuthConfig{
    Enabled: true,
    Providers: map[string]goAuth.ExternalProviderConfig{
        "google": {
            Kind: goAuth.ExternalKindGoogle,
            ClientIDs: []string{
                "1234-web.apps.googleusercontent.com",     // web
                "1234-ios.apps.googleusercontent.com",     // iOS
                "1234-android.apps.googleusercontent.com", // Android
            },
        },
        "apple": {
            Kind: goAuth.ExternalKindApple,
            ClientIDs: []string{
                "com.example.web", // Services ID (Sign in with Apple JS)
                "com.example.app", // bundle ID (native)
            },
        },
    },
    AllowSignup: true,
}

engine, err := goAuth.New().
    WithConfig(cfg).
    WithRedis(rdb).
    WithUserProvider(users). // must also implement ExternalIdentityProvider
    // ...
    Build()
```

Two providers may not share an issuer and a client ID (`Build` fails): the
single-use record of a token is kept per provider name, so a token valid under
both would be usable once under each. List each client ID under one provider.

The provider name (`"google"`, `"apple"`; `[a-z0-9_-]`, 1 to 32 characters) is
what you pass to the API and what is stored with each link. It does not have to
equal the kind: you can name two OIDC providers `"corp-sso"` and `"partner"`.

### `ExternalAuthConfig`

| Field | Default | Meaning |
|-------|---------|---------|
| `Enabled` | `false` | Turns the feature on. `Build` then requires at least one provider and a user provider implementing `ExternalIdentityProvider` |
| `Providers` | none | Name to settings, below |
| `AutoLinkVerifiedEmail` | `false` | Link an identity to the local account whose identifier is the provider's verified email. **Requires `EmailVerification.Enabled`** |
| `AllowSignup` | `false` | Create a password-less account for an identity that matches nothing. Requires `Account.Enabled` |
| `MaxAttempts` | `0` (= 10) | Sign-in attempts per source and per identity within `Cooldown` |
| `Cooldown` | `0` (= 15m) | Rate-limit window |
| `ClockLeeway` | `0` (= 60s) | Tolerance for `exp`, `iat`, `nbf`; maximum 5m |
| `KeyRefreshMin` | `0` (= 5m) | Minimum interval between key-set fetches per provider, and the shortest cache lifetime honoured; 1s to 24h |
| `KeyMaxStale` | `0` (= 24h) | How long the last good key set may keep verifying while the provider is unreachable; at least `KeyRefreshMin` (5m when unset), up to 30d (lint warns above 72h) |
| `SignupTicketTTL` | `0` (= 10m) | How long the handle of a [two-step sign-up](#two-step-sign-up) is accepted; 1m to 1h. Only used with `ExternalLoginOptions.DeferSignup` |

### `ExternalProviderConfig`

| Field | Meaning |
|-------|---------|
| `Kind` | `"google"`, `"apple"` or `"oidc"` |
| `ClientIDs` | Accepted audiences. **Required.** Every client that can obtain a token for your users: Google web, iOS and Android client IDs; Apple Services ID and bundle ID |
| `Issuer` | Expected `iss`. Defaulted for google and apple; required for oidc; must be an https URL |
| `JWKSURL` | Where signing keys are published. Defaulted for google and apple; required for oidc; **must be https** |
| `AllowedHostedDomains` | google only. When set, the token's `hd` claim must match one of them (restrict to a Google Workspace domain) |
| `Algorithms` | oidc only. From `RS256`, `RS384`, `RS512`, `ES256`, `ES384`; default `RS256`. `none` and `HS*` are never accepted |

### Provider defaults

| Kind | Issuer(s) | Keys | Algorithm |
|------|-----------|------|-----------|
| `google` | `https://accounts.google.com` (and the spelling `accounts.google.com`, which Google also uses) | `https://www.googleapis.com/oauth2/v3/certs` | `RS256` |
| `apple` | `https://appleid.apple.com` | `https://appleid.apple.com/auth/keys` | `RS256` |

These come from the providers' OpenID Connect discovery documents
(`https://accounts.google.com/.well-known/openid-configuration`,
`https://appleid.apple.com/.well-known/openid-configuration`) and Google's
[OpenID Connect documentation](https://developers.google.com/identity/openid-connect/openid-connect).
Overriding `JWKSURL` is for tests and unusual deployments; it still must be
https.

### The builder

- `WithHTTPClient(*http.Client)` sets the client used to fetch keys. The default
  has a 5-second timeout. Only https URLs are requested and a redirect to a
  non-https URL is refused whatever the client's own policy says.
- **Nothing is fetched at `Build`.** Keys are fetched on first use. Call
  `Engine.WarmExternalKeys(ctx)` at startup if you want a wrong URL or a blocked
  egress to fail fast; it is optional and a failure leaves the engine usable.

## The nonce contract

The nonce ties an ID token to one sign-in attempt on your side, so a token
captured from one place cannot be replayed into another.

1. Your server generates a fresh random nonce per sign-in attempt and remembers
   it (for example in a short-lived pre-login cookie or server session).
2. The client includes it in its request to the provider.
3. The provider puts it in the token's `nonce` claim.
4. You pass the **raw** nonce as `ExternalLoginOptions.Nonce`.

goAuth accepts the token when its `nonce` claim equals the raw nonce **or equals
the lowercase hexadecimal SHA-256 of it**. The second form is the common Sign in
with Apple native pattern (the app sends the hash to Apple and keeps the raw
value). Both comparisons are constant-time. An empty nonce is always refused,
and a token without a `nonce` claim never verifies.

The nonce must be single-use on your side too. goAuth additionally refuses to
accept the same token twice (below).

## What is verified

In this order; each failure returns `ErrExternalTokenInvalid` unless noted, with
the reason kept out of the response:

1. **Size and structure.** At most 16 KB; three parts; an allow-listed `alg`
   (never `none`, never `HS*`); a non-empty `kid`; no `crit` header; strict
   base64url.
2. **Signature**, with the key the `kid` names. Only keys whose `kty`, `use`,
   `alg` and `key_ops` agree with the token are used. This is what stops the
   classic "sign with HMAC using the RSA public key as the secret" attack.
3. **Issuer** equals the configured issuer.
4. **Audience** contains a configured client ID. If `aud` lists more than one
   entry, `azp` must be present and be a configured client ID.
5. **Times**, against the server clock with `ClockLeeway`: `exp` in the future,
   `iat` not in the future, `nbf` (if present) not in the future. `exp` and
   `iat` are required, and an `exp` more than 24 hours away is refused.
6. **Nonce**, as above.
7. **Subject** present and at most 255 characters.
8. **Hosted domain** (google, when `AllowedHostedDomains` is set).
9. **Claims.** `email` is trimmed (case is the provider's: goAuth does not
   lowercase it, so normalize in your `UserProvider` if your identifiers are
   case-insensitive). `email_verified` and `is_private_email` are accepted as a
   boolean or as the strings `"true"`/`"false"` (Apple sends strings).
10. **Single use.** The token is recorded with `SET NX` under
    `axt:<provider>:<sha256 hex>` for its remaining validity plus the leeway
    (never longer than about 24 hours, at least one second). A second use fails
    with `ErrExternalTokenReplayed`. The record is written last, so a token that
    fails any other check never uses up its single use, and it is keyed on the
    signed part of the token (header and payload), so re-encoding or malleating
    the signature does not produce a second use.

Nothing from a token or nonce is written to an audit event or a log.

### The key cache

Keys are cached per provider.

- **Lifetime.** The response's `Cache-Control: max-age` is honoured, clamped to
  `[KeyRefreshMin, 24h]`; with none, one hour.
- **Single flight.** N concurrent first sign-ins cause one fetch.
- **Unknown `kid`.** At most one refetch per `KeyRefreshMin`; otherwise the
  token is simply invalid. Tokens naming random key IDs cannot cause a fetch
  storm.
- **Failures.** A failed fetch is not retried inside the request (the next
  attempt waits a short back-off, at most 15 seconds, so an outage costs one
  request per interval, not one per sign-in). The last good key set keeps
  verifying for `KeyMaxStale` after it was fetched. After that, or when no key
  set was ever fetched, sign-in fails with `ErrExternalProviderUnavailable`
  (HTTP 503). **A token that cannot be verified is never accepted.**
- **Bad responses.** The body is capped at 1 MB, must be https, and a response
  without a usable key never replaces a good key set. A `kid` that appears twice
  in a set is ambiguous and is not used.

## Account resolution

After verification:

| # | Situation | Result |
|---|-----------|--------|
| 1 | The identity `(provider, sub)` is linked to an account | Sign in as that account. The email is not needed or consulted |
| 2 | Not linked; no email, or the email is not verified | `ErrExternalEmailUnverified`. An unverified email is never used to link or create |
| 3 | Not linked; verified email matches a local account that is **Active**, `AutoLinkVerifiedEmail` on | Link, sign in (`LinkedIdentity = true`) |
| 4 | ... matches an account that is **pending verification** | `ErrExternalLinkRequiresVerification`, nothing linked |
| 5 | ... matches a Disabled, Locked or Deleted account | That account's status error, exactly as a password login returns it; nothing linked |
| 6 | ... matches an Active account, `AutoLinkVerifiedEmail` off | `ErrExternalAccountLinkRequired`, nothing linked. Tell the user to sign in another way and link from settings |
| 7 | Verified email matches nothing, `AllowSignup` on | Create a password-less Active account with `Account.DefaultRole`, linked atomically (`NewAccount = true`) |
| 8 | Verified email matches nothing, `AllowSignup` off | `ErrExternalAccountNotFound` |

Row 1 also applies to Sign in with Apple's later sign-ins, which may omit the
email entirely.

A concurrent first sign-in of the same person makes the user provider report a
duplicate (`ErrProviderDuplicateIdentifier` or `ErrExternalIdentityInUse`); goAuth
runs the resolution **once more**, which finds what the winner created, so two
simultaneous first sign-ins produce one account. A conflict that persists is
reported (`ErrAccountExists` or `ErrExternalIdentityInUse`).

From the resolved account the sign-in continues exactly like a password login:
account status, device-binding requirements, session hardening, the MFA
decision and challenge, session issuance, audit and metrics.

### Why auto-linking needs local email verification

Linking by email is the most dangerous convenience in federated sign-in. The
attack ("pre-hijacking"):

1. The attacker registers locally with the **victim's** email address and a
   password the attacker knows. With no email verification the account is
   immediately usable.
2. Later the victim signs in with Google, whose verified email matches that
   account. If goAuth linked it, the victim now uses the attacker's account, and
   the attacker's password still works.

`AutoLinkVerifiedEmail` therefore requires `EmailVerification.Enabled`
(`Build` fails otherwise): only an account that *proved* its address can be
linked by it, and an account still pending verification is refused (row 4) even
with the knob on. Where you cannot or do not want email verification, leave
auto-linking off and let signed-in users link from settings.

**Auto-link trusts the status.** goAuth has no per-account "email verified" flag: it treats an **Active** account as one whose address was verified. That is true for every account created while `EmailVerification` was enabled, and false for accounts created before it was (or imported, or created Active by an admin): such an account may have been registered by someone who never owned the address. Before turning auto-linking on in an existing deployment, mark those accounts `PendingVerification` (or leave auto-linking off); lint reports `external_autolink_trusts_active_status` as a reminder.

The same reasoning applies to `LinkExternalIdentity`: an account pending email
verification cannot be linked (`ErrExternalLinkRequiresVerification`), because
whoever registered the address could otherwise keep a way into the account
after its real owner verifies it. If your application re-establishes ownership
of an account (an email change, or a password reset after suspected takeover),
consider also unlinking its external identities.

## Two-step sign-up

Row 7 of the table above creates the account inside `LoginWithExternalIdentity`. An
application that must run its own step between "the token is verified and the
identity has no account" and "the account exists" (an age check, a terms
acceptance, a waitlist) cannot: the sign-up either happens in that call or the call
fails after the single-use token is spent. With `ExternalLoginOptions.DeferSignup`
the sign-in stops at row 7 and hands back a ticket; the application runs its step
and then completes or cancels it.

```go
type ExternalSignupTicket struct {
    Handle         string    // opaque, single use; a secret, never log it
    Provider       string
    Subject        string
    Email          string
    EmailVerified  bool
    IsPrivateEmail bool
    DisplayName    string    // as passed to step one
    ExpiresAt      time.Time
}
// LoginResult.ExternalSignup *ExternalSignupTicket // non-nil: no account yet, no tokens

type ExternalSignupOptions struct{ DisplayName string; RememberMe bool }
func (e *Engine) CompleteExternalSignup(ctx, handle string, opts ExternalSignupOptions) (*LoginResult, error)
func (e *Engine) CancelExternalSignup(ctx, handle string) error
```

```
client            your server                         goAuth                              Redis / provider
  │ ID token + nonce │                                    │
  │─────────────────▶│ LoginWithExternalIdentity          │
  │                  │   (DeferSignup: true)              │ verify token, spend it
  │                  │───────────────────────────────────▶│ identity unknown, AllowSignup on:
  │                  │                                    │   create nothing; SET axs:<tenant>:<sha256(handle)>
  │                  │◀───────────────────────────────────│ LoginResult{ExternalSignup: ticket}, nil
  │                  │ your step: age check, terms ...    │
  │                  │   refused: CancelExternalSignup ──▶│ DEL axs:...            (nothing else to undo)
  │                  │   accepted: CompleteExternalSignup▶│ resolve the session profile
  │                  │                                    │ GETDEL axs:... (single use, tenant-bound)
  │                  │                                    │ resolve the identity again, no token
  │                  │                                    │ account-creation limiter, create + link
  │                  │◀───────────────────────────────────│ shared login tail: session, audit, NewAccount=true
  │◀─────────────────│ tokens                             │
```

**Step one** is identical to today up to the point where the resolution would create
an account (a verified email, no link, no local account, `AllowSignup` on). There it
creates nothing: no account, no link, no session and no account-creation limiter
slot. It stores the verified identity (provider, subject, email and flags, display
name, tenant) under `axs:<tenant>:<sha256(handle)>` for `SignupTicketTTL`, returns
the 32 random bytes of the handle (base64url) and audits `external_signup_deferred`
(provider only). The ID token's single-use record is spent exactly as before; the
handle replaces it. Every other branch is unchanged even with `DeferSignup`: a
linked identity signs in, auto-link links, and a pending-verification match, a
link-required match, an unverified email and a refusal to sign up all keep their
errors. `DeferSignup` needs `AllowSignup`: without it an identity with no account is
`ErrExternalAccountNotFound`, as always. The external sign-in limiters apply to step
one as they do today.

**Step two** (`CompleteExternalSignup`):

1. resolves the session profile first, as every session path does (an unknown profile
   is refused before the handle is touched, so it does not spend it);
2. consumes the handle atomically with `GETDEL`. It is bound to the context's tenant:
   a handle used under another tenant is simply not found, and does not burn the
   owner's. A missing, used or expired handle is `ErrExternalSignupInvalid`;
3. resolves the stored identity again, **with no token**: if the identity is linked
   now, `ErrExternalIdentityInUse`; if a local account now holds the email,
   `ErrExternalAccountLinkRequired` (the identity is never auto-linked here, whatever
   `AutoLinkVerifiedEmail` says); otherwise it creates the account;
4. runs the account-creation limiter and `CreateUserWithExternalIdentity` exactly as
   the one-call sign-up does (the same input fields, duplicate handling with one
   retry after a concurrent duplicate, metrics and `account_creation_success` with
   `method=external`);
5. finishes through the shared login tail (account status, session hardening, the MFA
   decision, the fenced session issue, the profile, `external_login_success` with
   `new_account=true`) and returns `NewAccount: true`. A new account has no second
   factor, so no MFA is asked for;
6. `opts.DisplayName`, when non-empty, replaces the step-one name (capped at 256
   bytes like step one); `opts.RememberMe` and the session profile are those of step
   two, not remembered from step one.

**The handle is consumed even if a later step fails** (a limiter refusal, the
provider being down). The application restarts the sign-up from a new ID token. This
is deliberate: a handle that survived a failure could be retried by whoever holds it.

`CancelExternalSignup` deletes the handle and is idempotent; an unknown, used or
expired handle is not an error. Nothing was created in step one, so there is nothing
else to undo.

**Security.** The handle is a bearer secret: whoever holds it can create the account
for that identity. It is never written to the audit trail, a log line or an error;
only its SHA-256 names the Redis key (so a dump of Redis cannot be replayed);
`ExternalSignupTicket` prints and logs with the handle redacted. Keep it out of URLs
and of your own logs, and send it only to the client that has to come back. It needs
no constant-time comparison: it is looked up by hash.

**The age-check use case.** An application that must refuse sign-ups from users under
a threshold, and must store nothing about a refused person, calls
`LoginWithExternalIdentity` with `DeferSignup`, shows its own form for the date of
birth, and then either calls `CompleteExternalSignup` (the account is created only
now) or `CancelExternalSignup` and tells the user. A refusal leaves no account, no
link and no row of the application's own; the ticket expires in at most
`SignupTicketTTL` anyway. The date of birth never reaches goAuth.

Redis keys: `axs:<tenant>:<hex sha256 of the handle>` (JSON record, `SignupTicketTTL`),
written by step one, read and deleted by `GETDEL` in step two, deleted by Cancel.
`GETDEL` needs Redis 6.2 or later.

## Password-less accounts

An account created by external sign-up has `PasswordHash == ""`. Every password
path treats that deliberately:

- **Password login** against it runs a dummy Argon2 verification, counts toward
  the login limiter and auto-lockout like a wrong password, and returns
  `ErrInvalidCredentials`. It costs and behaves the same as a wrong password or
  an unknown identifier. The audit reason is `password_not_set`.
- **`ChangePassword` and `VerifyPassword`** return `ErrPasswordNotSet`
  (HTTP 409), after a dummy verification, and still count toward the
  password-verify limiter.
- **Role-switch step-up** does not offer `"password"` as a factor to it.
- **Password reset is allowed and sets a first password.** After that the
  account behaves like any other, and its last external identity may be
  unlinked.

None of this changes anything for accounts that have a password.

## Link, unlink, list

The caller is the **authenticated user**; take `userID` from the session, never
from the request.

```go
// Settings page: "Connect Google". The client obtained an ID token with a nonce
// your server issued.
identity, err := engine.LinkExternalIdentity(ctx, userID, "google", idToken, nonce)

identities, err := engine.ListExternalIdentities(ctx, userID)

err = engine.UnlinkExternalIdentity(ctx, userID, "google", subject)
```

- **Link** verifies the token exactly like a sign-in (nonce, single use, the same
  rate limits). Because the user is already authenticated it does not need
  `email_verified`; `EmailVerified` is stored as reported. Linking an identity
  already linked to this user succeeds without change; one linked to another
  user is `ErrExternalIdentityInUse`. An account pending email verification is
  refused (`ErrExternalLinkRequiresVerification`).
- **Unlink** refuses with `ErrLastLoginMethod` when the account has **no
  password** and this is its only linked identity. Unlinking something that is
  not linked succeeds. A link to a provider you have since removed from the
  config can still be unlinked. Two concurrent unlinks of an account's last two
  identities can each see the other still present; if that matters, enforce it
  in your provider's transaction.
- **Step-up.** goAuth does not enforce one, but your application should require
  one before link and unlink (and before [changing the account
  email](email_change.md)). A stolen session should not be able to attach an
  attacker's Google account. What to ask for depends on what the user has:

  | The user has | Ask for |
  |--------------|---------|
  | A password | `Engine.VerifyPassword(ctx, userID, password)` (rate limited, never locks the account) |
  | No password, but TOTP or backup codes | `Engine.VerifyTOTP(ctx, userID, code)` or `Engine.VerifyBackupCode(ctx, userID, code)`: a fresh, rate-limited proof of a second factor |
  | No password and no second factor | A **fresh external sign-in**: have the client obtain a new ID token with a new nonce and call `LoginWithExternalIdentity`; then call `ValidateAccess` on the access token it returns and require `AuthResult.UserID` to equal the current user, and `Logout` the session it created (its ID is in the refresh token) if you do not want it |

  Notes. goAuth has no public "recent MFA" accessor: the assurance it records
  for a session serves role-switch step-up only, and a WebAuthn assertion exists
  only inside the MFA login ceremony, so neither can gate link or unlink
  directly; keep your own timestamp when you verify a factor. Whatever you
  choose, take `userID` from the session, never from the request, and require
  the proof for the CURRENT user in the same request that calls `Link…`,
  `Unlink…` or `RequestEmailChange`.

## Apple compliance checklist

Sign in with Apple has requirements that are the application's, not the
library's:

- [ ] **Private relay emails.** `is_private_email` is true for
  `@privaterelay.appleid.com` addresses. They are real, verified, and stable per
  app, but mail only reaches them if you register your sending domain with
  Apple. `ExternalIdentity.IsPrivateEmail` carries the flag.
- [ ] **The name is sent once.** Apple gives the user's name to the *client*
  only on the first authorization, never in the ID token. Capture it then and
  pass it as `ExternalLoginOptions.DisplayName`; goAuth hands it to
  `CreateUserWithExternalIdentity`.
- [ ] **Account deletion.** If your app lets users delete their account, you
  must revoke the user's Apple tokens (Apple's REST API, with your client
  secret) as part of it. goAuth stores no Apple tokens and cannot do this.
- [ ] **Server-to-server notifications.** Apple notifies you when a user changes
  their email forwarding preference, deletes their app account, or revokes
  consent. Handle that endpoint in your application. After a revoke or delete,
  unlink the identity (and delete the account if appropriate).
- [ ] **Client IDs.** List the Services ID (web) and the bundle ID (native) in
  `ClientIDs`; a token minted for one is rejected unless it is listed.
- [ ] **Native nonce.** Send the SHA-256 of your raw nonce to Apple, pass the
  raw one to goAuth.

## Multi-tenancy

`ExternalIdentityProvider` methods are all scoped to the tenant the engine takes
from the request context (`WithTenantID`; the default tenant `"0"` otherwise). An
identity linked in tenant A is not found in tenant B.

- Email lookup uses the tenant-scoped identifier lookup, with the same
  record-tenant backstop as password login.
- `GetUserByExternalIdentity` results get the backstop too: when multi-tenancy is
  enabled, a record whose `TenantID` is not the request tenant is treated as not
  found and a warning is logged, so a provider that forgets its tenant predicate
  cannot hand out another tenant's account.
- External sign-up with multi-tenancy enabled requires an explicit tenant on the
  context (`ErrAccountCreationInvalid` otherwise), like `CreateAccount`.

See [multi_tenancy.md](multi_tenancy.md).

## Session profiles and MFA

- The session profile is chosen **before any work**, as for every login: from
  `WithSessionProfile(ctx, name)` and `ExternalLoginOptions.RememberMe` with the
  same rules and errors (`ErrUnknownSessionProfile`,
  `ErrSessionProfileConflict`). A refused profile makes no limiter, key fetch or
  provider call and does not use up the token. See
  [session.md](session.md#session-profiles).
- **MFA.** If the account has a required second factor, the result is
  `MFARequired` with an `MFASession`, no tokens, and `ConfirmLoginMFA` completes
  it unchanged, with the profile carried by the challenge.

## Rate limiting

Two stages, both with the atomic reserve pattern and the same budget
(`MaxAttempts` per `Cooldown`), honouring `Security.LimiterWindowMode`:

1. **Before verification, per client IP** (`rl:extlogin:ip:<tenant>:<ip>`). Pass
   the IP with `WithClientIP`. **Without an IP this stage is skipped**: a bucket
   shared by every request without one could be exhausted by anyone, locking out
   every user of the provider. Behind a proxy, set the IP only from a header you
   trust.
2. **After verification, per identity** (`rl:extlogin:sub:<tenant>:<provider>:<sub>`).
   Counts sign-ins that fail to resolve (link required, not found, and so on).

Both reset on a successful sign-in. Over the limit, the call fails with
`ErrExternalLoginRateLimited`. The limiters fail open on a Redis error (a
`limiter_fail_open` audit event), like the others, unless
`Security.LimiterFailClosed` is on (a 503, audit reason `limiter_unavailable`). Sign-up additionally goes
through the account-creation limiter when `Account.EnableCreationLimiter` is on.

## Audit

| Event | When | Metadata |
|-------|------|----------|
| `external_login_success` | The external identity resolved and the login tail succeeded (a session was issued, or an MFA challenge) | `provider`, `new_account`, `linked`, `mfa_required`, `profile` (when profiles are on) |
| `external_login_failure` | Anything before the shared tail failed | `provider`, `reason` |
| `account_creation_success` | A sign-up created an account (also in step two of a two-step sign-up) | `identifier`, `role`, `method=external`, `provider` |
| `external_signup_deferred` | A sign-in with `DeferSignup` stopped at account creation and returned a ticket | `provider` only (never the handle or the token) |
| `external_identity_linked` | A link was made | `provider`, `via` (`verified_email` or `link`) |
| `external_identity_unlinked` | A link was removed | `provider` |
| `external_identity_link_failure` | `LinkExternalIdentity` failed | `provider`, `reason` |

`external_login_failure` reasons: `disabled`, `provider_unknown`, `session_profile`,
`token_invalid`, `token_replayed`, `provider_unavailable`, `store_unavailable`,
`rate_limited`, `email_unverified`, `link_required`, `link_requires_verification`,
`account_not_found`, `account_status`, `signup_rate_limited`, `signup_failed`,
`account_exists`, `identity_in_use`, `lookup_failed`, `signup_ticket_invalid` and `signup_defer_failed` (step one or two of a two-step sign-up).

The part of a sign-in after the identity is resolved is the password login's own
code, so its events are the usual ones: `login_success` (with the session ID),
`mfa_required`, and `login_failure` / `mfa_failure` for session hardening, device
binding, pending verification (`RequireForLogin`) and MFA problems. A successful
external sign-in therefore emits both `login_success` and
`external_login_success`. Failure metrics use the existing counters
(`MetricLoginFailure`, `MetricLoginRateLimited`, `MetricAccountCreation*`); no
metric IDs were added.

## The user provider contract

Implement `ExternalIdentityProvider` on your `UserProvider`. It is detected at
`Build`.

```go
type ExternalIdentityProvider interface {
    GetUserByExternalIdentity(ctx context.Context, tenantID, provider, subject string) (UserRecord, error)
    CreateUserWithExternalIdentity(ctx context.Context, input CreateUserInput, identity ExternalIdentity) (UserRecord, error)
    LinkExternalIdentity(ctx context.Context, tenantID, userID string, identity ExternalIdentity) error
    UnlinkExternalIdentity(ctx context.Context, tenantID, userID, provider, subject string) error
    ListExternalIdentities(ctx context.Context, tenantID, userID string) ([]ExternalIdentity, error)
}
```

- Your **`GetUserByIdentifier` / `GetUserByIdentifierInTenant` must return `ErrUserNotFound` for a missing user** (they are used to match the provider's email). Any other error is treated as a failure (HTTP 503) and never as "no such account", so an outage cannot lead to an account being created.
- `GetUserByExternalIdentity` returns `ErrUserNotFound` when there is none. Any
  other error is treated as a backend failure (HTTP 503), never as "not found".
- `CreateUserWithExternalIdentity` creates the user (`input.PasswordHash == ""`)
  **and** the link in one transaction. It returns `ErrProviderDuplicateIdentifier`
  for an identifier clash and `ErrExternalIdentityInUse` if the identity is
  already linked.
- `LinkExternalIdentity` returns `ErrExternalIdentityInUse` if the identity is
  linked to a *different* user and succeeds if it is already linked to this one.
- `UnlinkExternalIdentity` of a missing link is not an error.

Schema: `(tenant_id, provider, subject)` is **unique**, which is what makes the
concurrent-sign-up retry safe. One identity belongs to at most one account per
tenant; one account may hold several identities. For example:

```sql
CREATE TABLE external_identities (
    tenant_id       text        NOT NULL,
    provider        text        NOT NULL,
    subject         text        NOT NULL,
    user_id         text        NOT NULL REFERENCES users (id),
    email           text        NOT NULL DEFAULT '',
    email_verified  boolean     NOT NULL DEFAULT false,
    is_private_email boolean    NOT NULL DEFAULT false,
    display_name    text        NOT NULL DEFAULT '',
    linked_at       timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, provider, subject)
);
CREATE INDEX external_identities_user ON external_identities (tenant_id, user_id);
```

A password-less user's `UserRecord.PasswordHash` must be the empty string (goAuth
only tests for `""`; map a NULL column to it). Store the email for display
only; once the link exists the account is found by `(provider, subject)`.

## HTTP mapping

| Error | Code | Suggested status |
|-------|------|------------------|
| `ErrExternalAuthDisabled` | `AUTH_EXTERNAL_DISABLED` | 403 |
| `ErrExternalProviderUnknown` | `AUTH_EXTERNAL_PROVIDER_UNKNOWN` | 400 |
| `ErrExternalTokenInvalid` | `AUTH_EXTERNAL_TOKEN_INVALID` | 401 |
| `ErrExternalTokenReplayed` | `AUTH_EXTERNAL_TOKEN_REPLAYED` | 401 |
| `ErrExternalProviderUnavailable` | `SYSTEM_UNAVAILABLE_EXTERNAL_PROVIDER` | 503 |
| `ErrExternalEmailUnverified` | `AUTH_EXTERNAL_EMAIL_UNVERIFIED` | 403 |
| `ErrExternalAccountNotFound` | `AUTH_EXTERNAL_ACCOUNT_NOT_FOUND` | 404 |
| `ErrExternalAccountLinkRequired` | `AUTH_EXTERNAL_LINK_REQUIRED` | 409 |
| `ErrExternalLinkRequiresVerification` | `AUTH_EXTERNAL_LINK_REQUIRES_VERIFICATION` | 409 |
| `ErrExternalIdentityInUse` | `AUTH_EXTERNAL_IDENTITY_IN_USE` | 409 |
| `ErrExternalSignupInvalid` | `AUTH_EXTERNAL_SIGNUP_INVALID` | 400 |
| `ErrLastLoginMethod` | `AUTH_LAST_LOGIN_METHOD` | 409 |
| `ErrPasswordNotSet` | `AUTH_PASSWORD_NOT_SET` | 409 |
| `ErrExternalLoginRateLimited` | `AUTH_EXTERNAL_LOGIN_RATE_LIMITED` | 429 |

Why **404** and not 401 for `ErrExternalAccountNotFound`: the caller has just
proved, with a verified token, that they own the identity, so telling them "no
account exists for it" reveals nothing about anyone else, and it is actionable
(offer sign-up). A 401 would trip generic "session expired, log in again"
handling in clients and send them in a loop. Applications that prefer to hide it
can map it to 401 themselves; the code is stable.

Why **400** and not 401 for `ErrExternalSignupInvalid`: it is the same class as
`AUTH_RESET_INVALID`, `AUTH_VERIFICATION_INVALID` and `AUTH_EMAIL_CHANGE_INVALID`, a
single-use challenge that is unknown, used or expired. The caller is not failing to
authenticate; there is nothing to refresh, so a 401 would send a client into a
"log in again" loop for what is really "restart the sign-up".

Status errors of a linked or matched account keep their usual codes
(`AUTH_ACCOUNT_DISABLED` and friends, 403).

## Operations

- Redis holds the single-use records (`axt:*`, a few dozen bytes each, expiring
  with the token) and the limiter counters (`rl:extlogin:*`).
- Egress: servers need https access to the key URLs (and your proxy, if any,
  configured in the client passed to `WithHTTPClient`).
- Clock: ID tokens are checked against the server clock; keep hosts NTP-synced.
  `ClockLeeway` absorbs small skew.
- Key rotation at the provider needs no action: a new `kid` triggers one
  refetch (at most once per `KeyRefreshMin`).

## See also

- [config.md](config.md), [config_lint.md](config_lint.md)
- [multi_tenancy.md](multi_tenancy.md), [session.md](session.md#session-profiles), [mfa.md](mfa.md)
- [password.md](password.md), [security.md](security.md)
- [error-model.md](error-model.md)
- [examples/external-identity](../examples/external-identity)
