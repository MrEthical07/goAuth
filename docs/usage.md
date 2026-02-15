# Usage Guide

## Minimal setup

```go
package main

import (
    "context"
    "log"

    goAuth "github.com/MrEthical07/goAuth"
    "github.com/redis/go-redis/v9"
)

func main() {
    rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})

    engine, err := goAuth.New().
        WithRedis(rdb).
        WithPermissions([]string{"user.read", "user.write"}).
        WithRoles(map[string][]string{"admin": {"user.read", "user.write"}}).
        WithUserProvider(myUserProvider{}).
        Build()
    if err != nil { log.Fatal(err) }
    defer engine.Close()

    _, _, _ = engine.Login(context.Background(), "alice@example.com", "correct horse battery staple")
}

type myUserProvider struct{}
```

## Production recommendations

- Keep default hybrid validation unless strict consistency is mandatory.
- Use Ed25519 keys and short access-token TTLs.
- Enable rate limiting and audit sinks.
- Keep Redis highly available and low-latency.

## Error handling pattern

- Treat returned errors as policy decisions (`invalid credentials`, `rate limited`, `MFA required`).
- Avoid exposing internal error details to clients.
- Emit telemetry/audit with request correlation IDs.

## Concurrency expectations

- Build engine once and reuse globally.
- Do not mutate Builder from multiple goroutines.
- Ensure custom providers and sinks are goroutine-safe.
