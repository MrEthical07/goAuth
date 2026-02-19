# Module: JWT

## Purpose

The `jwt` package manages access-token issuance and verification using configured signing keys and strict validation semantics suitable for low-latency authentication paths.

## Primitives

| Primitive | Signature | Description |
|-----------|-----------|-------------|
| `NewManager` | `func NewManager(cfg Config) (*Manager, error)` | Create a validated JWT manager |
| `CreateAccess` | `(uid, tid, sid, mask, permV, roleV, acctV string, flags...) (string, error)` | Issue a signed access token |
| `ParseAccess` | `(tokenStr string) (*AccessClaims, error)` | Verify and parse an access token |

### Config

```go
type Config struct {
    AccessTTL     time.Duration   // Token lifetime (e.g. 5m)
    SigningMethod  SigningMethod   // MethodEd25519 or MethodHS256
    PrivateKey    []byte          // Signing key material
    PublicKey     []byte          // Verification key material
    Issuer        string          // "iss" claim
    Audience      string          // "aud" claim
    Leeway        time.Duration   // Clock skew tolerance (max 2m)
    RequireIAT    bool            // Require "iat" claim
    MaxFutureIAT  time.Duration   // Max allowed future iat (default 10m)
    KeyID         string          // "kid" header
    VerifyKeys    map[string][]byte // Multi-key verification set
}
```

### AccessClaims

```go
type AccessClaims struct {
    UID            string `json:"uid"`
    TID            uint32 `json:"tid,omitempty"`
    SID            string `json:"sid"`
    Mask           []byte `json:"mask,omitempty"`
    PermVersion    uint32 `json:"pv,omitempty"`
    RoleVersion    uint32 `json:"rv,omitempty"`
    AccountVersion uint32 `json:"av,omitempty"`
    jwt.RegisteredClaims
}
```

## Strategies

| Strategy | Config | Description |
|----------|--------|-------------|
| Ed25519 (default) | `SigningMethod: MethodEd25519` | Asymmetric, recommended for production |
| HS256 | `SigningMethod: MethodHS256` | Symmetric, requires shared secret |
| Key rotation | `VerifyKeys` map + `KeyID` | Multiple verification keys for zero-downtime rotation |

## Examples

### Create and verify a token

```go
mgr, err := jwt.NewManager(jwt.Config{
    AccessTTL:    5 * time.Minute,
    SigningMethod: jwt.MethodEd25519,
    PrivateKey:   privKey,
    PublicKey:    pubKey,
    Issuer:       "my-service",
    KeyID:        "k1",
    VerifyKeys:   map[string][]byte{"k1": pubKey},
})

token, err := mgr.CreateAccess("user-123", 1, "session-abc", maskBytes, 1, 1, 1, true, true, true, true, false)
claims, err := mgr.ParseAccess(token)
```

### Key rotation

```go
// Add new key to VerifyKeys before rotating signing key.
// Both old and new keys will verify during the transition window.
cfg.VerifyKeys = map[string][]byte{
    "k1": oldPubKey,  // still accepted
    "k2": newPubKey,  // new signing key
}
cfg.KeyID = "k2"
cfg.PrivateKey = newPrivKey
cfg.PublicKey = newPubKey
```

## Security Notes

- Ed25519 is strongly recommended over HS256 (asymmetric, no shared secret exposure).
- `MaxFutureIAT` prevents acceptance of tokens with far-future `iat` claims.
- `Leeway` is capped at 2 minutes to prevent excessive clock drift tolerance.
- Missing `kid` header causes rejection when `VerifyKeys` is configured.

## Performance Notes

- Ed25519 verification is ~50µs (CPU-bound, no allocations beyond the claim struct).
- Token parsing is the hot path for JWT-only validation mode.
- No Redis calls — purely CPU-bound.

## Edge Cases & Gotchas

- `VerifyKeys` must include the current `KeyID` — validation fails if the signing kid is not in the verify set.
- Root accounts get a forced 2-minute max TTL regardless of `AccessTTL` setting.
- `ParseAccess` returns `ErrTokenInvalid` for expired tokens (check `token clock skew exceeded` for clock issues).

## Architecture

The `jwt` package is a self-contained module with no Redis dependency. It is instantiated by `Builder.Build()` and injected into the engine as the sole token issuer/verifier.

```
jwt.NewManager(cfg)
  ├─ Config validation (key sizes, TTL, signing method)
  ├─ Key parsing (Ed25519 or HS256)
  ├─ VerifyKeys map initialization
  └─ Return *Manager (immutable after construction)
```

`CreateAccess` is called by login and refresh flows. `ParseAccess` is the hot path for every validation request in all modes (JWT-Only, Hybrid, Strict).

## Error Reference

| Error | Condition |
|-------|----------|
| `ErrTokenInvalid` | Token expired, malformed, or signature invalid |
| `ErrTokenClockSkew` | Token `iat` claim is too far in the future |
| `ErrJWTConfig` | Invalid JWT configuration (bad keys, unsupported method) |
| `ErrUnauthorized` | Generic authorization failure (wraps token errors) |

## Flow Ownership

| Flow | Entry Point | Internal Module |
|------|-------------|------------------|
| Token Issuance | `jwt.Manager.CreateAccess` | Called by `internal/flows/login.go`, `internal/flows/refresh.go` |
| Token Verification | `jwt.Manager.ParseAccess` | Called by `internal/flows/validate.go` |
| Key Rotation | Config-driven (`VerifyKeys` map) | No dedicated flow — config change + restart |

## Testing Evidence

| Category | File | Notes |
|----------|------|-------|
| Manager Hardening | `jwt/manager_hardening_test.go` | Key validation, TTL caps, edge cases |
| Fuzz Testing | `jwt/fuzz_parse_test.go` | Random input parsing robustness |
| Integration | `test/jwt_integration_test.go` | End-to-end token create/parse |
| Validation Modes | `validation_mode_test.go` | JWT-Only mode exercises ParseAccess |
| Benchmarks | `auth_bench_test.go` | Token creation and parsing latency |

## Migration Notes

- **Key rotation**: Add the new public key to `VerifyKeys` before switching `KeyID` and `PrivateKey`. Both keys will verify during the transition window.
- **Ed25519 → HS256**: Not recommended. If switching signing methods, all existing tokens become invalid immediately.
- **TTL changes**: Reducing `AccessTTL` only affects newly issued tokens. Existing tokens remain valid until their original expiry.

## See Also

- [Flows](flows.md)
- [Configuration](config.md)
- [Security Model](security.md)
- [Engine](engine.md)
- [Middleware](middleware.md)
- [Session](session.md)
