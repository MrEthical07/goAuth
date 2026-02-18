# Module: Introspection

## Purpose

Read-only queries for session state, active-session counts, login-attempt counters, and Redis health. All operations are purely observational — they never mutate state.

## Primitives

### Engine Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `GetActiveSessionCount` | `(ctx, userID string) (int, error)` | Exact count via Redis SET cardinality |
| `ListActiveSessions` | `(ctx, userID string) ([]SessionInfo, error)` | Decode all active sessions |
| `GetSessionInfo` | `(ctx, tenantID, sessionID string) (*SessionInfo, error)` | Single session lookup |
| `ActiveSessionEstimate` | `(ctx) (int, error)` | Approximate global count via `DBSIZE` |
| `Health` | `(ctx) HealthStatus` | Redis `PING` with latency |
| `GetLoginAttempts` | `(ctx, identifier string) (int, error)` | Current failed-login counter |

### HealthStatus

```go
type HealthStatus struct {
    RedisAvailable bool
    RedisLatency   time.Duration
}
```

### SessionInfo

Returned by `ListActiveSessions` and `GetSessionInfo`. Converted from internal `*session.Session` via `toSessionInfo()`.

## Internal Flow Functions

Each public method delegates to a flow function in `internal/flows/introspection.go`:

| Flow | Purpose |
|------|---------|
| `RunGetActiveSessionCount` | Tenant-scoped session count |
| `RunListActiveSessions` | Batch read + decode sessions |
| `RunGetSessionInfo` | Single session fetch |
| `RunActiveSessionEstimate` | Global estimate |
| `RunHealth` | Redis ping + latency |
| `RunGetLoginAttempts` | Rate-limiter counter |

### Dependencies

Flow functions receive an `IntrospectionDeps` struct containing:

- `SessionStore` — Redis session store (read-only methods: `ActiveSessionCount`, `ActiveSessionIDs`, `GetManyReadOnly`, `GetReadOnly`, `EstimateActiveSessions`, `Ping`)
- `RateLimiter` — `GetLoginAttempts` method
- `MultiTenantEnabled` — tenant resolution flag
- Tenant-ID extractors from context
- Sentinel errors for unauthorized, not-ready, etc.

## Security Notes

- `ListActiveSessions` uses `GetManyReadOnly` — no session mutations.
- Tenant isolation enforced: all queries scope by `tenantID` extracted from context.

## Performance Notes

- `ActiveSessionEstimate` uses Redis `DBSIZE` (O(1)) — suitable for dashboards.
- `ListActiveSessions` is O(n) in sessions — use `ActiveSessionEstimate` for monitoring.
