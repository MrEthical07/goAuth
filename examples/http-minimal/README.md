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
# Login
curl -s -X POST http://localhost:8080/login \
  -d '{"username":"alice@example.com","password":"correct-horse"}' \
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
2. Generate Ed25519 keys or use `goAuth.DefaultConfig()` (generates ephemeral keys).
3. Point `redis.NewClient` at your real Redis instance.
4. Copy the handler patterns and middleware wiring into your router.

See [docs/api-reference.md](../../docs/api-reference.md) for the full API surface.
