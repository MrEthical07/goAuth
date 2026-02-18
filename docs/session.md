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
