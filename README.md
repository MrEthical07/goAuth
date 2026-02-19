# goAuth

Low-latency authentication engine for Go: JWT access tokens + Redis-backed sessions + rotating refresh tokens + bitmask RBAC.

[![Go Tests](https://img.shields.io/badge/tests-266%20passing-brightgreen)]()
[![Go Version](https://img.shields.io/badge/go-1.24%2B-blue)]()
[![Race Detector](https://img.shields.io/badge/race%20detector-clean-brightgreen)]()

---

## Features

- **Three validation modes** — JWT-only (0 Redis ops), Hybrid, Strict (instant revocation)
- **Refresh token rotation** — atomic Lua CAS with replay detection
- **MFA** — TOTP (RFC 6238) + backup codes with rate limiting
- **Password management** — Argon2id hashing, reset (Token/OTP/UUID strategies), change with reuse detection
- **Email verification** — enumeration-resistant with Lua CAS consumption
- **Permission system** — 64/128/256/512-bit frozen bitmasks, O(1) checks
- **Rate limiting** — 7-domain fixed-window limiters + auto-lockout
- **Device binding** — IP/UA fingerprint enforcement or anomaly detection
- **Audit + Metrics** — 44 counters, latency histogram, Prometheus + OpenTelemetry exporters
- **Multi-tenancy** — tenant-scoped sessions, counters, and rate limits

## Quickstart

```go
package main

import (
    "context"
    "fmt"
    "log"

    goAuth "github.com/MrEthical07/goAuth"
    "github.com/redis/go-redis/v9"
)

func main() {
    rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})

    engine, err := goAuth.New().
        WithRedis(rdb).
        WithPermissions([]string{"user.read", "user.write"}).
        WithRoles(map[string][]string{
            "admin": {"user.read", "user.write"},
        }).
        WithUserProvider(myProvider{}).
        Build()
    if err != nil {
        log.Fatal(err)
    }
    defer engine.Close()

    // Login
    access, refresh, err := engine.Login(context.Background(), "alice@example.com", "password")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Access:", access[:20]+"...")

    // Validate
    result, err := engine.ValidateAccess(context.Background(), access)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("UserID:", result.UserID)

    // Refresh
    newAccess, newRefresh, err := engine.Refresh(context.Background(), refresh)
    _ = newAccess
    _ = newRefresh
}
```

See [examples/http-minimal](examples/http-minimal) for a complete HTTP server with login, refresh, logout, and protected routes.

## Installation

```bash
go get github.com/MrEthical07/goAuth
```

**Requirements:** Go 1.24+, Redis 6+

## Validation Modes

| Mode | Redis Ops | Use Case |
|------|-----------|----------|
| `ModeJWTOnly` | 0 | Stateless microservices, dashboards |
| `ModeHybrid` | 0–1 | Most applications (default) |
| `ModeStrict` | 1 | Financial, healthcare, compliance |

```go
// Per-route mode with middleware
mux.Handle("/api/read", middleware.RequireJWTOnly(engine)(readHandler))
mux.Handle("/api/admin", middleware.RequireStrict(engine)(adminHandler))
```

## Configuration

```go
// Start from a preset
cfg := goAuth.HighSecurityConfig()
cfg.JWT.AccessTTL = 3 * time.Minute

// Lint for misconfigurations
if err := cfg.Lint().AsError(goAuth.LintHigh); err != nil {
    log.Fatal(err)
}
```

Three presets: `DefaultConfig()`, `HighSecurityConfig()`, `HighThroughputConfig()`. See [docs/config.md](docs/config.md).

## Documentation

| Document | Description |
|----------|-------------|
| [docs/index.md](docs/index.md) | Documentation hub |
| [docs/flows.md](docs/flows.md) | All auth flows with step lists |
| [docs/api-reference.md](docs/api-reference.md) | Full API reference |
| [docs/architecture.md](docs/architecture.md) | System design |
| [docs/security.md](docs/security.md) | Threat model and mitigations |
| [docs/performance.md](docs/performance.md) | Benchmarks and budgets |
| [docs/ops.md](docs/ops.md) | Deployment and monitoring |
| [docs/config.md](docs/config.md) | Configuration reference |
| [docs/roadmap.md](docs/roadmap.md) | Future plans |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Testing

```bash
# All tests
go test ./...

# With race detector
go test -race ./...

# Integration tests (requires Redis)
docker compose -f docker-compose.test.yml up -d
go test -tags=integration ./test/...

# Benchmarks
go test -run '^$' -bench . -benchmem ./...
```

266 tests, 4 fuzz targets, 13 benchmarks. Race-detector clean.

## License

See [LICENSE](LICENSE) for details.
