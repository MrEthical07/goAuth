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
| `DeleteAllForUser` | `(ctx, tenantID, userID string) error` | Remove all sessions for a user (and their MFA-proof keys) in one atomic Lua script |
| `RevocationEpoch` | `(ctx, tenantID, userID string) (int64, error)` | The user's revocation epoch: bumped by every `DeleteAllForUser`/`DeleteAllForUserExcept`, kept an hour |
| `SaveFenced` | `(ctx, sess *Session, ttl time.Duration, epoch int64, limits SaveLimits) error` | `Save` that is refused (`ErrSessionFenced`) if the epoch moved since it was read, and enforces the per-user, concurrent-login and tenant caps and the single-session purge in the same script |
| `DeleteAllForUserExcept` | `(ctx, tenantID, userID, keepSessionID string) (int, error)` | `DeleteAllForUser` that leaves one session stored, indexed and counted; reports how many it removed |
| `RotateRefreshHash` | `(ctx, tenantID, sessionID string, old, new [32]byte) (*Session, error)` | Atomic Lua rotation |
| `SwapSession` | `(ctx, tenantID, oldSessionID string, presented [32]byte, next *Session, assurance *Assurance) error` | Atomic Lua swap of one session for another (role switch); same checks and failure side effects as rotation |
| `WithProfiles` | `(profiles map[string]ProfilePolicy) *Store` | Install the session profile table (call before the store is shared); the engine does this at Build |
| `NewSessionLifetime` | `(name string, now time.Time) (expiresAt int64, ttl time.Duration, err error)` | The ceiling and initial key TTL for a new session under a profile |
| `HasProfiles` / `Profile` | `() bool` / `(name string) (ProfilePolicy, bool)` | Inspect the installed table |
| `Peek` | `(ctx, tenantID, sessionID string) (*Session, error)` | Raw read: no expiry filter, no schema migration, no write |
| `SaveAssurance` / `GetAssurance` | `(ctx, tenantID, sessionID string, ...)` | Step-up assurance, stored beside (not inside) the session |
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
    Profile           string // "" = legacy (v5); non-empty = session profile (v6)
    IdleExpiresAt     int64  // read-only views only; never encoded
}
```

### What the version stamps detect

A session stores the user's `PermissionVersion`, `RoleVersion` and `AccountVersion` as they were when the session was created, and the access token carries the same three numbers. Strict `Validate` compares the token's stamps with the session's. Both were copied from the same place at the same moment, so the comparison detects a token and a session that disagree (a token minted for another session state); it does **not** read the user record, so it never notices that the user's role, permissions or status changed afterwards.

How a change reaches existing sessions:

- **`InvalidateUserSessions` (or `LogoutAll`)** ends every session of the user. Call it whenever you change a user's role, permissions or status outside goAuth's own account-status calls. This is required, not optional, unless the next point is on.
- **`Security.RecheckUserOnRefresh = true`** (default `false`): `Refresh` reads the user through the tenant-scoped lookup before it rotates the token. If the user's `PermissionVersion`, `RoleVersion` or `AccountVersion` differs from the session's, or the status is blocking, the session is deleted and `Refresh` returns `ErrSessionNotFound` (or the status error). If the provider cannot be reached `Refresh` returns `ErrSystemUnavailable` and rotates nothing, so the same refresh token works once the provider is back. It costs one provider read per refresh. The provider must return `ErrUserNotFound` for a user that no longer exists; any other error is treated as an outage.
- Strict `Validate` stays snapshot-based in both cases: an access token already issued is accepted until it expires or the session is deleted.

Lint: `refresh_user_recheck_off` (INFO) is reported while the flag is off.

### Binary Encoding (v5, and v6 for profiles)

`Encode(s *Session) ([]byte, error)` / `Decode(data []byte) (*Session, error)`

Wire format: `[version][userID_len][userID][tenantID_len][tenantID][role_len][role][permV][roleV][acctV][status][mask_len][mask][refreshHash][ipHash][uaHash][createdAt][expiresAt]`

Supports decoding v1–v6. Older records migrate forward to v5 on read (missing fields get safe defaults); migration never produces or rewrites v6.

**v6** (sessions created under a [session profile](#session-profiles)) is the v5 layout with `[profile_len u8][profile]` appended after `expiresAt`; the name is 1–32 bytes. `Encode` writes v6 only when `Session.Profile` is set and v5 otherwise, so a session without a profile is byte-identical to before.

### Session assurance (role-switch step-up)

When `Config.RoleSwitch.StepUp` is non-empty, a session issued after a successful second factor also gets a Redis key `asa:<tenant>:<sessionID>` holding the MFA-verified time, the factor (`totp`, `backup_code`, `webauthn`) and the last-proof time. It lives **outside** the session blob, so the v5 wire format and `golden_bytes_test.go` are unchanged. Its TTL is the session's remaining absolute lifetime; `SwapSession` moves it to the new session ID; an assurance orphaned by a logout expires by TTL (the delete scripts are untouched). With no `StepUp` configured no `asa:` key is ever written. Sessions created before step-up was configured have none. See [role_switching.md](role_switching.md#step-up).

### Errors

| Error | Description |
|-------|-------------|
| `ErrRefreshHashMismatch` | Replay detected — old refresh token reused |
| `ErrRedisUnavailable` | Redis connection failure |
| `ErrRefreshSessionNotFound` | Session ID not in Redis |
| `ErrRefreshSessionExpired` | Session TTL elapsed |
| `ErrRefreshSessionCorrupt` | Decode failure on stored data |
| `ErrProfileUnknown` | A profile session names a profile the configuration no longer defines; the session was deleted (joined with `redis.Nil`; `EndedProfileName(err)` returns the name) |
| `ErrSessionExpired` | A profile session reached its effective ceiling on a strict read; the session was deleted (joined with `redis.Nil`) |

## Strategies

| Feature | Config Knob | Description |
|---------|------------|-------------|
| Sliding expiry | `SessionConfig.SlidingExpiration` | Extend TTL on each read, up to the session ceiling |
| Session ceiling | `SessionConfig.MaxSessionDuration` | Absolute lifetime cap; remember-me sessions live up to it |
| Jitter | `SessionConfig.JitterEnabled` + `JitterRange` | Randomize TTL to avoid thundering herd |
| Binary encoding | Default (`SessionConfig.SessionEncoding = "binary"`) | Compact wire format |

## Session Lifetimes & Remember-Me

Every session's absolute expiry is written **once** at creation
(`Session.ExpiresAt = CreatedAt + lifetime`) and is never rewritten afterwards.
Sliding renewal and refresh rotation extend the Redis TTL only *up to* that
stored expiry (additionally clamped by `CreatedAt + MaxSessionDuration` at the
store level), so no session can outlive its ceiling regardless of how often it
is used or refreshed.

The lifetime assigned at creation depends on the remember-me flag:

| Login | Lifetime |
|-------|----------|
| Default (`Engine.Login`, `LoginWithResult`, …) | `min(JWT.RefreshTTL, Session.AbsoluteSessionLifetime)`, capped at `MaxSessionDuration` |
| Remember-me (`Engine.LoginWithOptions` with `LoginOptions{RememberMe: true}`) | `Session.MaxSessionDuration` (or its per-mode default) |

When MFA is required, the remember-me choice made at step 1 is stored with the
MFA challenge and honored when `ConfirmLoginMFA` issues the session. Auto-login
during account creation honors `CreateAccountRequest.RememberMe` the same way.

See [config.md](config.md) for how an unset `MaxSessionDuration` resolves to a
per-validation-mode default (Strict → 24 h, Hybrid/JWTOnly → 7 d).

## Session Profiles

A **session profile** is a named lifetime and access-token policy. One engine
can then serve clients that need different things: a web app whose sessions
last a fixed 15 days from login, a mobile app that stays signed in as long as
it is used at least every 90 days (up to a 365-day ceiling), an agent with its
own policy. Profiles are opt-in. With `Config.SessionProfiles.Profiles` empty (the
default) nothing changes: the same session bytes, Redis commands, tokens,
errors, audit events and metrics as before, pinned by
`TestSessionProfilesUnusedMatchesV070`.

### Two models

| Model | `IdleTimeout` | A session ends when |
|-------|---------------|---------------------|
| **Fixed** | `0` | `AbsoluteLifetime` has passed since login. Refreshing never moves it |
| **Renewing** | `> 0` | it goes `IdleTimeout` without a successful refresh, **or** `AbsoluteLifetime` has passed since login, whichever comes first |

`AbsoluteLifetime` is a hard ceiling measured from login. A renewing profile
may set `AllowUnbounded` instead of a ceiling (stored as the sentinel
`session.UnboundedExpiresAt`, 31 Dec 9999): such a session ends only by
inactivity, logout or revocation, and lint warns about it. A fixed profile
always needs a ceiling, since nothing else would ever end it.

```go
cfg.SessionProfiles.Profiles = map[string]goAuth.SessionProfile{
    "web":    {AbsoluteLifetime: 15 * 24 * time.Hour},
    "mobile": {IdleTimeout: 90 * 24 * time.Hour, AbsoluteLifetime: 365 * 24 * time.Hour, RenewOnUse: true},
}
cfg.SessionProfiles.DefaultProfile = "web"

ctx = goAuth.WithSessionProfile(ctx, "mobile") // chosen by your server, see below
access, refresh, err := engine.Login(ctx, identifier, password)
```

`SessionProfile.AccessTTL` gives a profile its own access-token lifetime
(`0` inherits `JWT.AccessTTL`); only `exp` differs from any other token. Field
reference and validation rules: [config.md](config.md#session-profiles-configsessionprofiles).

### Choosing a profile

`WithSessionProfile` applies to every path that creates a session: `Login`,
`LoginWithResult`, `LoginWithOptions`, `LoginWithTOTP`, `LoginWithBackupCode`,
`ConfirmLoginMFA` / `ConfirmLoginMFAWithType` and `CreateAccount` with
`AutoLogin`. With no profile on the context the `DefaultProfile` applies. The
choice is made **before** any limiter is read, any password verified or any
provider called.

| Request | Result |
|---------|--------|
| profile not configured (or any profile on an engine with none) | `ErrUnknownSessionProfile`, no Redis command, no provider call, no Argon2 |
| `RememberMe: true` and `SessionProfiles.RememberMeProfile` set | that profile |
| `RememberMe: true` and no `RememberMeProfile` | `ErrSessionProfileConflict` |
| `RememberMe: true` together with an explicit profile | `ErrSessionProfileConflict` |
| no profile named | `DefaultProfile` |

`CreateAccountRequest.RememberMe` follows the same rules (when `AutoLogin` is
on; with it off no session is created and nothing is resolved). With no
profiles configured, remember-me is exactly what it was.

**Choose the profile only from trusted, server-side signals**: which client
application's endpoint was called, the authenticated API client, a route. Never
from a header, query parameter or body field the end user controls, or a user
could ask for the longest-lived profile. `WithSessionProfile` is for your
server code, not for request input.

### The expiry math

Let `created` be the login time and `ceiling = created + AbsoluteLifetime`
(the stored `ExpiresAt`).

- **At login.** `ExpiresAt = ceiling`. The key TTL is `AbsoluteLifetime` for a
  fixed profile and `min(IdleTimeout, AbsoluteLifetime)` for a renewing one.
- **At refresh** (atomically, in the same Lua call as the refresh-token
  compare-and-swap, after every existing check): the new key TTL is
  `min(IdleTimeout, ceiling - now)` for a renewing profile (never below one
  second, or what is left if that is less) and the unchanged remaining TTL for
  a fixed one. A role switch is a use and does the same.
- **At a strict read** (`ModeStrict`): untouched, unless the profile sets
  `RenewOnUse`, in which case it is renewed exactly as at refresh. A v6 session
  is **never** given the legacy sliding reset (`TTL = time to ExpiresAt`),
  which would cancel the idle window.

Worked example with Dressin's two profiles, in days since login:

| Day | `web` (fixed, 15d) | `mobile` (90d idle, 365d ceiling) |
|-----|--------------------|-----------------------------------|
| 0   | login: key TTL 15d | login: key TTL 90d, so the window ends on day 90 |
| 7   | refresh: TTL stays at the 8d left | refresh: TTL 90d, window now ends on day 97 |
| 14  | refresh: TTL stays at the 1d left | |
| 15  | **ended**, however often it was refreshed | |
| 89  | | refresh: TTL 90d, window now ends on day **179** |
| 90  | | with no refresh since day 0, the key has lapsed: **ended** (91 idle days never survive) |
| 300 | | refresh: only 65d of ceiling remain, so TTL is **65d** |
| 360 | | refresh: TTL **5d** |
| 365 | | ceiling reached: **ended**, however recently it was refreshed |

Every number is exercised by `TestSessionProfilesAC1*` against a controllable
clock and miniredis.

### Hybrid and strict

Only `ModeStrict` reads the session. A refresh always renews a renewing
profile's window. `RenewOnUse` additionally renews it on strict reads and has
**no effect** on `ModeHybrid` or `ModeJWTOnly` routes, which never touch Redis
(lint: `session_profile_renew_on_use_stateless`). A Hybrid deployment such as
Dressin's therefore keeps a mobile session alive by refreshing, which a mobile
app does on every access-token expiry anyway. Profiles do not change what
Hybrid means: a token already issued stays valid until it expires.

### Live configuration

A session stores only its profile **name**; the policy is resolved from the
current configuration each time the session is refreshed, switched or read
strictly. So:

- **Shortening** a profile's `AbsoluteLifetime` shortens sessions already
  issued: the effective ceiling is `min(stored ExpiresAt, CreatedAt + current
  AbsoluteLifetime)`. A session already past it is deleted at its next refresh
  or strict read; one not yet past has its key TTL clamped to it.
- **Lengthening** never extends a session: the stored `ExpiresAt` still wins.
  Only sessions created afterwards get the longer ceiling.
- **Removing or renaming** a profile ends every session issued under it at its
  next refresh, role switch or strict read. They are deleted exactly like an
  expired session and report `ErrSessionNotFound`. A refresh is audited as
  `refresh_invalid` with reason `profile_unknown`; a strict read as
  `session_invalid` with reason `profile_unknown` (or `expired` for a passed
  ceiling). Retire a profile by keeping it until its sessions have drained, or
  accept the forced sign-out (lint: `session_profile_removal_ends_sessions`).
- Read-only views (`GetSessionInfo`, `ListActiveSessions`) hide such sessions
  without deleting them.

### Jitter

With `Session.JitterEnabled`, the idle window is randomized by up to
`Session.JitterRange` either way, as legacy sliding renewal always was. The
jitter is drawn in Go and passed to the Lua script (which stays
deterministic). It applies only to the idle window: it can never carry a key
past the effective ceiling or below one second. A fixed profile's key lifetime
is not jittered.

### Storage and compatibility

A session created under a profile is stored in a **separate schema version 6**:
the unchanged v5 layout followed by `[profile_len u8][profile]` after
`ExpiresAt`. A session without a profile is still v5, byte for byte
(`CurrentSchemaVersion` stays 5, `golden_bytes_test.go` is unmodified, and
migration never converts v5 into v6 or rewrites a v6 record). Both Lua copies
of the blob parser read v6.

The profile table reaches the refresh and swap scripts as one ARGV string,
`name:idle_ms:abs_ms:renew` entries joined by `;` (`abs_ms = 0` means
unbounded), alongside a jitter in milliseconds and the millisecond clock. With
no profiles configured those arguments are not sent, so the Redis commands are
the legacy ones.

The MFA challenge stores the profile resolved at step one (record **v3**: the
v2 layout plus a one-byte length-prefixed name) and the stored profile wins at
confirm; see [mfa.md](mfa.md#session-profiles). v6 sessions and v3 challenge
records cannot be read by v0.7.0 binaries: **finish a rolling deploy before
enabling profiles**, or older instances will fail on the new records.

### Cost

With profiles unused there is no cost: no extra command, argument or byte. With
profiles configured:

| Operation | Added Redis work |
|-----------|------------------|
| Login | none (the profile's TTL replaces the legacy one) |
| Refresh, role switch | none: the rules run inside the same Lua call; the script gets three more arguments |
| `ModeStrict` read | none, or one `EXPIRE` with `RenewOnUse` (what legacy sliding expiration already costs) |
| `GetSessionInfo` / `ListActiveSessions` | one `PTTL` (one pipelined round trip for a list), only for renewing-profile sessions |
| `Logout`, `LogoutByAccessToken` | one `GET` before the delete, to put the profile in the audit event |

Hybrid and JWT-only validation never touch Redis, with or without profiles.

### Guarantees

These end the sessions of **every** profile immediately, as they end legacy
ones: refresh-token reuse (deletion), `Logout`, `LogoutAll` /
`LogoutAllInTenant`, `InvalidateUserSessions`, password change and reset,
account disable, lock and delete, and permission, role or account version
drift. Concurrent sessions of different profiles for one user coexist and age
independently. Profiles are tenant-agnostic: they apply identically with
`MultiTenant.Enabled`, see [multi_tenancy.md](multi_tenancy.md).

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

- **`DeleteAllForUser` is atomic** (since v0.8.0). One Lua script reads the user's session set, deletes every session key that exists together with its `asa:` MFA-proof key, lowers the tenant counter by the number it actually deleted (never below zero; the counter key is removed at zero) and clears the set. A session saved before the script runs is deleted, one saved after it is untouched, and the counter always equals the sessions left. Earlier versions did this in several round trips, so a session created in between could survive and the counter could drift. Like the rotation and swap scripts it builds session keys from the IDs in the set, so it needs a single-node or non-sharded deployment.
- **Sessions are stored under a revocation epoch** (since v0.8.1). Every delete-all increments `aue:<tenant>:<user>` inside its script. A login reads the epoch before it reads the account and stores the session with `SaveFenced`, which refuses if the epoch moved, so a password change, disable or logout-all that lands while a login is in flight cannot leave that login's session behind. The same script enforces the caps, so parallel logins cannot exceed them; a tenant counter that drifted upwards is corrected by a compare-and-set against the value read before the scan. The epoch key expires an hour after the last bump, longer than any login takes.
- **MFA-proof keys go with their session.** Every path that deletes a session (`Delete`, expiry and profile-ceiling deletion in `Get`, the rotation script's expiry, reuse and profile branches, the swap script's failure branches, `DeleteAllForUser`) also deletes `asa:<tenant>:<sessionID>` in the same script. Before v0.8.0 a left-behind key aged out by its TTL. The scripts derive the key from the tenant counter key, so their keys and arguments are unchanged.
- First Lua call may use 2 commands (EVALSHA miss + EVAL fallback); subsequent calls are 1.
- `Delete` is idempotent — deleting a non-existent session succeeds silently.
- Counter can never go negative (Lua script clamps at 0).
- Session schema migration happens transparently on `Decode` — v1–v4 sessions are read-compatible. The one-time rewrite uses `SET ... XX`, so a read of a legacy session can never recreate a session that was deleted (logout, reuse revocation, role switch) between the read and the rewrite.
- **Profile sessions and the legacy knobs.** `AbsoluteSessionLifetime`, `MaxSessionDuration` and `SlidingExpiration` describe legacy sessions. A profile session is governed by its profile alone: its strict-read renewal is `RenewOnUse`, independent of `SlidingExpiration`.
- A profile session whose profile is not in the current configuration is deleted at its next refresh, switch or strict read, **including when profiles are switched off entirely**: rolling profiles back ends their sessions.
- `SwapSession` refuses a replacement ID that is empty, equal to the old ID, or held by a live session (`ErrSessionIDInUse`; checked after the rotate-equivalent checks, before any write). It re-reads the old session and applies the rotation script's checks in the same order; a refresh-hash mismatch deletes the old session exactly as a rotation does. It touches keys in more than one hash slot, like the rotation script.

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
| Profile Schema | `session/profile_schema_test.go` | v6 golden bytes, v5 stays v5 through every read path, Lua parser v6 |
| Profile Expiry | `session/profile_expiry_test.go` | Fixed/renewing math, ceiling clamp, jitter bounds, live config, strict-read renewal, swap, concurrent refresh |
| Profile Engine | `engine_session_profiles*_test.go` | Dressin acceptance criteria, selection on every path, MFA, remember-me, invalidation, audit |
| Profile Baseline | `engine_session_profiles_baseline_test.go` | With no profiles, everything matches the v0.7.0 tag |
| Profile Redis | `test/redis_compat_profiles_test.go` | Profile scripts on miniredis and real Redis |
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
- **MaxSessionDuration (v0.4.0)**: sessions created before the field existed keep their stored `ExpiresAt` and are unaffected. To force-shorten *existing* sessions operationally, set `MaxSessionDuration` explicitly below their remaining lifetime — the store-level clamp (`CreatedAt + MaxSessionDuration`) expires them on next strict read.
- **Session profiles (v0.8.0)**: no action unless you adopt them. See [migrations.md](migrations.md#v080-migration-notes-non-breaking) for adoption steps and the rolling-deploy caveat (v6 sessions and v3 MFA records are unreadable by v0.7.0).
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
- [Role Switching](role_switching.md)
