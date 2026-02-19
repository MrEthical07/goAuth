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

## Architecture

Introspection methods are read-only wrappers over the session store and rate limiter. Each public `Engine` method delegates to a flow function in `internal/flows/introspection.go` that receives an `IntrospectionDeps` struct, keeping the engine layer thin.

```
Engine.ListActiveSessions(ctx, userID)
  └─ flows.RunListActiveSessions(ctx, deps)
       ├─ SessionStore.ActiveSessionIDs (SMEMBERS)
       ├─ SessionStore.GetManyReadOnly (pipeline GET)
       └─ Convert []session.Session → []SessionInfo
```

No introspection method mutates state. All reads use `GetReadOnly` or equivalent non-extending methods.

## Configuration

Introspection does not have dedicated configuration. Behavior is controlled by:

| Setting | Effect on Introspection |
|---------|------------------------|
| `MultiTenant.Enabled` | Scopes all queries by tenant ID from context |
| `Session.SlidingExpiration` | `GetReadOnly` avoids extending TTL (introspection is read-only) |
| `RateLimiting.*` | `GetLoginAttempts` reads from the rate limiter's counters |

## Error Reference

| Error | Condition |
|-------|----------|
| `ErrEngineNotReady` | Engine not initialized |
| `ErrUnauthorized` | Missing tenant context in multi-tenant mode |
| `ErrRedisUnavailable` | Redis connection failure |
| `ErrSessionNotFound` | `GetSessionInfo` with nonexistent session ID |

## Flow Ownership

| Flow | Entry Point | Internal Module |
|------|-------------|------------------|
| Active Session Count | `Engine.GetActiveSessionCount` | `internal/flows/introspection.go` → `RunGetActiveSessionCount` |
| List Active Sessions | `Engine.ListActiveSessions` | `internal/flows/introspection.go` → `RunListActiveSessions` |
| Session Info | `Engine.GetSessionInfo` | `internal/flows/introspection.go` → `RunGetSessionInfo` |
| Session Estimate | `Engine.ActiveSessionEstimate` | `internal/flows/introspection.go` → `RunActiveSessionEstimate` |
| Health Check | `Engine.Health` | `internal/flows/introspection.go` → `RunHealth` |
| Login Attempts | `Engine.GetLoginAttempts` | `internal/flows/introspection.go` → `RunGetLoginAttempts` |

## Testing Evidence

| Category | File | Notes |
|----------|------|-------|
| Introspection API | `engine_introspection_test.go` | All six methods, error paths |
| Redis Compat | `test/redis_compat_test.go` | Redis version compatibility |
| Store Consistency | `test/store_consistency_test.go` | Read-only consistency |
| Integration | `test/public_api_test.go` | Introspection through public API |

## Migration Notes

- **Multi-tenant activation**: Enabling `MultiTenant.Enabled` requires all introspection calls to carry tenant context. Calls without tenant context return `ErrUnauthorized`.
- **`ListActiveSessions` scaling**: This method is O(n) in active sessions per user. For users with many concurrent sessions, prefer `GetActiveSessionCount` for counts and `GetSessionInfo` for individual lookups.

## See Also

- [Flows](flows.md)
- [Configuration](config.md)
- [Session](session.md)
- [Engine](engine.md)
- [Metrics](metrics.md)
