# Module: WebAuthn / FIDO2

## Purpose

WebAuthn support adds phishing-resistant, hardware-backed second-factor authentication
(security keys, platform authenticators, passkeys used as a second factor) alongside TOTP
and backup codes. The engine runs the registration (attestation) and login (assertion)
ceremonies server-side; the caller shuttles raw JSON between the engine and the browser's
`navigator.credentials` API. This cycle ships WebAuthn as a **second factor**; the stored
credential model retains the flags needed for a future passwordless mode.

## Configuration (`Config.WebAuthn`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Enabled` | `bool` | `false` | Turns the WebAuthn surface on |
| `RPID` | `string` | — | Relying Party ID (effective domain, e.g. `"example.com"`). Required |
| `RPDisplayName` | `string` | — | Human-readable RP name shown by authenticators. Required |
| `RPOrigins` | `[]string` | — | Exact origins allowed to complete ceremonies. Required |
| `AttestationPreference` | `string` | `"none"` | `none`/`indirect`/`direct`/`enterprise` |
| `UserVerification` | `string` | `"preferred"` | `preferred`/`required`/`discouraged` |
| `CeremonyTTL` | `time.Duration` | 2 min | Lifetime of a begun ceremony (10s–10m when set) |
| `RequireForLogin` | `bool` | `false` | Gate login behind an assertion for users with credentials |
| `RejectClonedAuthenticators` | `bool` | `true` | Fail assertions whose signature counter regressed |

Validation happens at `Builder.Build()`; enabling WebAuthn without the provider
capability (below) fails the build.

## Provider capability

Credential storage is an **optional capability interface** — `UserProvider` itself is
unchanged, so existing integrations keep compiling:

```go
type WebAuthnCredentialProvider interface {
    GetWebAuthnCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error)
    AddWebAuthnCredential(ctx context.Context, userID string, credential WebAuthnCredential) error
    UpdateWebAuthnCredentialSignCount(ctx context.Context, userID string, credentialID []byte, signCount uint32) error
    RemoveWebAuthnCredential(ctx context.Context, userID string, credentialID []byte) error
}
```

Implement it on the same type as your `UserProvider`; `Build()` detects it via type
assertion when `WebAuthn.Enabled` is set. `WebAuthnCredential` is goAuth's own struct —
providers never import WebAuthn library types. Persist `CredentialID` and `PublicKey`
byte-exact, and store the flag fields faithfully: backup-eligibility is compared on every
assertion, and `SignCount` drives cloned-authenticator detection.

## Ceremonies

### Registration (enrolling an authenticator)

```go
// 1. Caller authenticates the user, then begins the ceremony:
challenge, err := engine.BeginWebAuthnRegistration(ctx, userID)
// -> send challenge.OptionsJSON to the browser: navigator.credentials.create(...)
// -> keep challenge.CeremonyID (e.g. in the client or your session)

// 2. Browser returns the attestation response JSON:
credential, err := engine.FinishWebAuthnRegistration(ctx, userID, challenge.CeremonyID, responseJSON)
```

Management: `engine.ListWebAuthnCredentials(ctx, userID)` and
`engine.RemoveWebAuthnCredential(ctx, userID, credentialID)`.

### Login (second factor)

With `RequireForLogin` enabled, a login by a user who has registered credentials returns
an MFA challenge instead of tokens. `LoginResult.MFATypes` lists every factor the user
can answer with; `MFAType` is the preferred one (`"webauthn"` when available —
phishing-resistant first, then `"totp"`).

```go
result, _ := engine.LoginWithResult(ctx, username, password)
if result.MFARequired && result.MFAType == "webauthn" {
    optionsJSON, _ := engine.BeginWebAuthnLogin(ctx, result.MFASession)
    // -> navigator.credentials.get(...) in the browser
    // -> post the assertion response JSON back:
    tokens, err := engine.ConfirmLoginMFAWithType(ctx, result.MFASession, string(assertionJSON), "webauthn")
}
```

A user listed with multiple factors may confirm with any of them (`"totp"`, `"backup"`,
`"webauthn"`). Remember-me set at step 1 survives the WebAuthn hop exactly as it does for
TOTP.

## Security Notes

- **Ceremonies are single-use**: the server-side session (challenge, allowed credential
  IDs) is consumed atomically on finish — success or failure — so responses cannot be
  replayed. A consumed or never-begun ceremony fails with `ErrWebAuthnCeremonyExpired`.
- **Origin and RPID** from the config are enforced on every response; assertions minted
  for another origin fail verification.
- **Cloned-authenticator detection**: a signature-counter regression fails the login with
  `ErrWebAuthnCloneDetected` (when `RejectClonedAuthenticators`) and destroys the MFA
  challenge — it is treated as a compromise signal, not a typo.
- **Attempt limiting**: failed assertions consume MFA challenge attempts exactly like
  wrong TOTP codes. Ceremony-expired failures do *not* consume attempts (no verification
  happened); they tell the client to call `BeginWebAuthnLogin` again.
- **Fail closed**: enabling WebAuthn without the provider capability or required config
  fails `Build()`; backend errors surface as `ErrWebAuthnUnavailable`, never as success.
- Attestation defaults to `"none"` — verify-and-store of attestation chains is out of
  scope unless you opt into a stronger conveyance preference.

## Redis Keys

| Key | Content | TTL |
|-----|---------|-----|
| `awn:<ceremonyID>` | Pending ceremony session (binary v1: purpose, user, tenant, library session JSON) | `CeremonyTTL` |

Login ceremonies are keyed by the MFA challenge ID; registration ceremonies get a random
ceremony ID. Sessions are read with `GETDEL` (atomic single use).

## Error Reference

| Error | Condition |
|-------|-----------|
| `ErrWebAuthnDisabled` | Surface called while `WebAuthn.Enabled` is false |
| `ErrWebAuthnInvalid` | Attestation/assertion failed verification (or malformed JSON) |
| `ErrWebAuthnCeremonyExpired` | Ceremony session missing, expired, consumed, or bound to another user |
| `ErrWebAuthnCloneDetected` | Assertion signature counter regressed |
| `ErrWebAuthnCredentialNotFound` | Removing/asserting with no matching credential |
| `ErrWebAuthnUnavailable` | Ceremony store or credential provider unreachable |
| `ErrMFALoginInvalid` / `ErrMFALoginAttemptsExceeded` | Login-path failures (shared with TOTP) |

## Flow Ownership

| Flow | Entry Point | Internal Module |
|------|-------------|-----------------|
| Registration | `Engine.BeginWebAuthnRegistration` / `FinishWebAuthnRegistration` | `internal/flows/webauthn.go` |
| Login assertion | `Engine.BeginWebAuthnLogin` + `Engine.ConfirmLoginMFAWithType("webauthn")` | `internal/flows/webauthn.go` + `internal/flows/login.go` |
| Ceremony sessions | — | `internal/stores/webauthn_session.go` |
| Credential storage | `WebAuthnCredentialProvider` (caller-implemented) | — |

## Testing Evidence

| Category | File | Notes |
|----------|------|-------|
| End-to-end ceremonies | `engine_webauthn_test.go` | Virtual authenticator: register → MFA login → strict validate |
| Attack cases | `engine_webauthn_test.go` | Wrong origin, replayed ceremony, sign-count regression, mismatched user |
| Session store | `internal/stores/webauthn_session_test.go` | Single-use consume, TTL expiry, corrupt records |
| Config validation | `config_webauthn_test.go` | Required fields, enums, TTL bounds, clone immutability |

## Dependencies

`github.com/go-webauthn/webauthn` performs all CBOR/COSE parsing and ceremony
verification (the first heavyweight dependency in goAuth; attestation left at `"none"`
keeps its TPM/x509 verification paths unused). Tests emulate authenticators with
`github.com/descope/virtualwebauthn` (test-only).

## See Also

- [MFA](mfa.md)
- [Flows](flows.md)
- [Configuration](config.md)
- [Security Model](security.md)
- [Engine](engine.md)
