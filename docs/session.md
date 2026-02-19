# Module: Session

## Purpose

The `session` package provides Redis-backed session persistence and compact binary session encoding for authentication hot paths. It handles session CRUD, refresh token rotation (via Lua scripts), tenant session counting, sliding expiration, and replay anomaly tracking.

## Primitives

### Store

| Primitive | Signature | Description |
|-----------|-----------|-------------|
| `NewStore` | `func NewStore(redis UniversalClient, prefix string, sliding bool, jitterEnabled bool, jitterRange time.Duration) *Store` | Create a session store |
| `Save` | `(ctx, sess *Session, ttl) error` | Persist a session to Redis (pipeline: SET+SADD+INCR) |
| `Get` | `(ctx, tenantID, sessionID string, ttl) (*Session, error)` | Read + optional sliding expiry extension |
| `GetReadOnly` | `(ctx, tenantID, sessionID string) (*Session, error)` | Read without extending TTL |
| `Delete` | `(ctx, tenantID, sessionID string) error` | Idempotent session deletion |
| `DeleteAllForUser` | `(ctx, tenantID, userID string) error` | Remove all sessions for a user |
| `RotateRefreshHash` | `(ctx, tenantID, sessionID string, old, new [32]byte) (*Session, error)` | Atomic Lua rotation |
| `TenantSessionCount` | `(ctx, tenantID string) (int, error)` | Current session count for tenant |
| `ActiveSessionCount` | `(ctx, tenantID, userID string) (int, error)` | User's active session count |
| `ActiveSessionIDs` | `(ctx, tenantID, userID string) ([]string, error)` | List user's session IDs |
| `TrackReplayAnomaly` | `(ctx, sessionID string, ttl) error` | Increment replay counter |
| `Ping` | `(ctx) (time.Duration, error)` | Redis health check |

### Session Model

```go
type Session struct {
    SchemaVersion     uint8
    SessionID         string
    UserID            string
    TenantID          string
    Role              string
    Mask              interface{}    // permission.Mask64/128/256/512
    PermissionVersion uint32
    RoleVersion       uint32
    AccountVersion    uint32
    Status            uint8
    RefreshHash       [32]byte
    IPHash            [32]byte
    UserAgentHash     [32]byte
    CreatedAt         int64
    ExpiresAt         int64
}
```

### Binary Encoding (v5)

`Encode(s *Session) ([]byte, error)` / `Decode(data []byte) (*Session, error)`

Wire format: `[version][userID_len][userID][tenantID_len][tenantID][role_len][role][permV][roleV][acctV][status][mask_len][mask][refreshHash][ipHash][uaHash][createdAt][expiresAt]`

Supports decoding v1–v5 with forward migration (missing fields get safe defaults).

### Errors

| Error | Description |
|-------|-------------|
| `ErrRefreshHashMismatch` | Replay detected — old refresh token reused |
| `ErrRedisUnavailable` | Redis connection failure |
| `ErrRefreshSessionNotFound` | Session ID not in Redis |
| `ErrRefreshSessionExpired` | Session TTL elapsed |
| `ErrRefreshSessionCorrupt` | Decode failure on stored data |

## Strategies

| Feature | Config Knob | Description |
|---------|------------|-------------|
| Sliding expiry | `SessionConfig.SlidingExpiration` | Extend TTL on each read |
| Jitter | `SessionConfig.JitterEnabled` + `JitterRange` | Randomize TTL to avoid thundering herd |
| Binary encoding | Default (`SessionConfig.SessionEncoding = "binary"`) | Compact wire format |

## Examples

### Direct store usage

```go
store := session.NewStore(redisClient, "myapp:sess", true, false, 0)

// Save
err := store.Save(ctx, sess, 24*time.Hour)

// Read (extends TTL if sliding)
got, err := store.Get(ctx, "tenant-0", "sid-abc", 24*time.Hour)

// Rotate refresh
rotated, err := store.RotateRefreshHash(ctx, "tenant-0", "sid-abc", oldHash, newHash)
```

## Security Notes

- Refresh rotation is atomic (Lua script) — no TOCTOU race between read and write.
- Hash mismatch triggers automatic session deletion (replay detection).
- All hashes are SHA-256 of the raw secret — secrets are never stored.

## Performance Notes

- `Save` uses a Redis pipeline (SET+SADD+INCR in one round-trip).
- `RotateRefreshHash` is a single Lua EVALSHA (1 round-trip after script cache warm).
- Binary encoding is ~10x smaller than JSON and avoids reflection.

## Edge Cases & Gotchas

- **`DeleteAllForUser` is not fully atomic.** It reads the user's session set, checks existence via pipeline, then deletes via `TxPipelined`. A session created between the read and delete phases will not be captured. The race window is extremely narrow and the stray session will expire naturally or be caught by a subsequent call. For stronger guarantees, call `DeleteAllForUser` twice or follow up with a counter reconciliation.
- First Lua call may use 2 commands (EVALSHA miss + EVAL fallback); subsequent calls are 1.
- `Delete` is idempotent — deleting a non-existent session succeeds silently.
- Counter can never go negative (Lua script clamps at 0).
- Session schema migration happens transparently on `Decode` — v1–v4 sessions are read-compatible.

## Architecture

The session store is a Redis-backed persistence layer with no application-level caching. All operations go directly to Redis via single commands, pipelines, or Lua scripts.

```
session.NewStore(redis, prefix, sliding, jitter, jitterRange)
  ├─ Key scheme: {prefix}:s:{tenantID}:{sessionID}  (session data)
  │              {prefix}:u:{tenantID}:{userID}      (session ID set)
  │              {prefix}:c:{tenantID}               (tenant counter)
  ├─ Binary codec: Encode/Decode (v5 schema, backward-compatible v1–v4)
  └─ Lua scripts: RotateRefreshHash (CAS), Delete (DEL+SREM+DECR)
```

The store is injected into the engine and consumed by login, refresh, validate, logout, and introspection flows.

## Flow Ownership

| Flow | Entry Point | Internal Module |
|------|-------------|------------------|
| Session Save | `Store.Save` | Called by `internal/flows/login.go` |
| Session Read | `Store.Get`, `Store.GetReadOnly` | Called by `internal/flows/validate.go`, `internal/flows/introspection.go` |
| Refresh Rotation | `Store.RotateRefreshHash` | Called by `internal/flows/refresh.go` |
| Session Delete | `Store.Delete`, `Store.DeleteAllForUser` | Called by `internal/flows/logout.go`, `internal/flows/account_status.go` |
| Replay Tracking | `Store.TrackReplayAnomaly` | Called by `internal/flows/refresh.go` |

## Testing Evidence

| Category | File | Notes |
|----------|------|-------|
| Schema Versioning | `session/schema_version_test.go` | Encode/decode v1–v5, migration |
| Fuzz Testing | `session/fuzz_decode_test.go` | Random binary input decoding |
| Delete Idempotency | `session/store_delete_idempotent_test.go` | Double-delete safety |
| Counter Invariant | `session/store_counter_never_negative_test.go` | Counter floor at zero |
| Session Hardening | `engine_session_hardening_test.go` | Version drift, strict validation |
| Refresh Concurrency | `refresh_concurrency_test.go` | Concurrent rotation races |
| Refresh Fuzz | `internal/fuzz_refresh_test.go` | Token encode/decode fuzzing |
| Store Consistency | `test/store_consistency_test.go` | Save/Get round-trip |
| Redis Budget | `test/redis_budget_test.go` | Command count verification |

## Migration Notes

- **Session schema v5**: New fields (`AccountVersion`, `Status`) are auto-populated with safe defaults when decoding older schemas. No manual migration needed.
- **Sliding expiration**: Enabling sliding expiration on an existing deployment extends session lifetimes on next read. Disable and re-enable carefully if strict TTL enforcement is required.
- **Prefix changes**: Changing the Redis key prefix creates a new namespace. Old sessions become orphaned and expire naturally.

## See Also

- [Flows](flows.md)
- [Configuration](config.md)
- [Engine](engine.md)
- [Security Model](security.md)
- [Performance](performance.md)
- [JWT](jwt.md)
- [Introspection](introspection.md)
- [Device Binding](device_binding.md)
