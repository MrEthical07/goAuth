# examples/http-minimal

Minimal HTTP integration that demonstrates the goAuth "golden path":

```
POST /login     →  obtain access + refresh tokens
POST /refresh   →  rotate tokens (cookie-based)
POST /logout    →  destroy session
GET  /protected →  middleware-guarded route
```

## Run

```bash
go run ./examples/http-minimal
```

No external Redis required — uses [miniredis](https://github.com/alicebob/miniredis) in-process.

## Try it

```bash
# Login (add "remember":true for a durable session capped by
# Config.Session.MaxSessionDuration)
curl -s -X POST http://localhost:8080/login \
  -d '{"username":"alice@example.com","password":"correct-horse","remember":true}' \
  -c cookies.txt

# Access a protected route
TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -d '{"username":"alice@example.com","password":"correct-horse"}' | jq -r .access_token)

curl -s http://localhost:8080/protected \
  -H "Authorization: Bearer $TOKEN"

# Refresh
curl -s -X POST http://localhost:8080/refresh -b cookies.txt -c cookies.txt

# Logout
curl -s -X POST http://localhost:8080/logout \
  -H "Authorization: Bearer $TOKEN"
```

## Integration in your project

1. Replace `stubProvider` with your real database-backed `UserProvider`.
2. Generate Ed25519 keys with `go run ./cmd/goauth-keygen` (or use
   `goAuth.DefaultConfig()`, which generates ephemeral keys). Set `JWT.KeyID`
   and `JWT.VerifyKeys` from day one so the key-rotation ceremony in
   [docs/ops.md](../../docs/ops.md) works without a flag day.
3. Point `redis.NewClient` at your real Redis instance.
4. Copy the handler patterns and middleware wiring into your router
   (`middleware.RequireJWTOnly` / `RequireHybrid` / `RequireStrict` for
   per-route validation modes).
5. For WebAuthn/FIDO2 second factor, implement `WebAuthnCredentialProvider`
   on your provider and enable `Config.WebAuthn` — see
   [docs/webauthn.md](../../docs/webauthn.md).

See [docs/api-reference.md](../../docs/api-reference.md) for the full API surface.
