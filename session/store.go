package session

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/MrEthical07/goAuth/internal/clock"
	"github.com/redis/go-redis/v9"
)

// ErrRefreshHashMismatch is an exported constant or variable used by the authentication engine.
var ErrRefreshHashMismatch = errors.New("refresh hash mismatch")

// ErrRedisUnavailable is an exported constant or variable used by the authentication engine.
var ErrRedisUnavailable = errors.New("redis unavailable")

// ErrRefreshSessionNotFound is returned when the refresh target session does not exist.
var ErrRefreshSessionNotFound = errors.New("refresh session not found")

// ErrRefreshSessionExpired is returned when the refresh target session is expired.
var ErrRefreshSessionExpired = errors.New("refresh session expired")

// ErrRefreshSessionCorrupt is returned when the refresh target session blob is invalid.
var ErrRefreshSessionCorrupt = errors.New("refresh session corrupt")

const minSlidingTTL = time.Second

const (
	rotateStatusNotFound    int64 = 0
	rotateStatusExpired     int64 = 1
	rotateStatusMismatch    int64 = 2
	rotateStatusRotated     int64 = 3
	rotateStatusInvalidBlob int64 = 4
)

// deleteSessionScript ends one session: key, user-index entry, counter and
// the session's role-switch MFA-proof key ("asa:<tenant>:<id>"). The proof key
// is not passed in: its tenant is the middle of the counter key
// ("ast:<tenant>:count"), so the script's keys and arguments stay as they were.
const deleteSessionScript = `
local existed = redis.call("EXISTS", KEYS[1])
redis.call("SREM", KEYS[2], ARGV[1])
redis.call("DEL", "asa:" .. string.sub(KEYS[3], 5, -7) .. ":" .. ARGV[1])
if existed == 1 then
  redis.call("DEL", KEYS[1])
  local count = tonumber(redis.call("GET", KEYS[3]) or "0")
  if count > 1 then
    redis.call("DECR", KEYS[3])
  elseif count == 1 then
    redis.call("DEL", KEYS[3])
  end
end
return existed
`

var deleteSessionLua = redis.NewScript(deleteSessionScript)

// deleteAllForUserScript ends every session of one user in one atomic step.
//
// KEYS: the user's session set, the tenant counter.
// ARGV: the session key prefix ("<prefix>:<tenant>:"), the MFA-proof key prefix
// ("asa:<tenant>:") and the ID of one session to keep ("" keeps none).
//
// It reads the set, deletes every session key that still exists together with
// its proof key, lowers the counter by the number of keys it actually deleted
// (never below zero; the counter key is removed at zero) and clears the set. A
// kept session stays in the set and in the count. It returns the number of
// sessions deleted. Because a script runs without interleaving, a session saved
// before it started is deleted and one saved after it finished is untouched,
// and the counter always equals the sessions left.
//
// The session and proof keys are built here from the IDs in the set, so, like
// the rotation and swap scripts, it touches keys in more than one hash slot.
const deleteAllForUserScript = `
local keep = ARGV[3]
local members = redis.call("SMEMBERS", KEYS[1])
local deleted = 0
for _, sid in ipairs(members) do
  if sid ~= keep then
    if redis.call("DEL", ARGV[1] .. sid) == 1 then
      deleted = deleted + 1
    end
    redis.call("DEL", ARGV[2] .. sid)
    if keep ~= "" then
      redis.call("SREM", KEYS[1], sid)
    end
  end
end
if keep == "" then
  redis.call("DEL", KEYS[1])
end
if deleted > 0 then
  local count = tonumber(redis.call("GET", KEYS[2]) or "0")
  if count <= deleted then
    redis.call("DEL", KEYS[2])
  else
    redis.call("DECRBY", KEYS[2], deleted)
  end
end
return deleted
`

var deleteAllForUserLua = redis.NewScript(deleteAllForUserScript)

// migrateSchemaScript rewrites a pre-v5 session blob as v5 only if the stored
// value is still the bytes the caller read, keeping the TTL. KEYS[1] = the
// session, ARGV[1] = the bytes read, ARGV[2] = the v5 blob. A deleted key, a
// rotated refresh hash or any other change makes the compare fail and nothing
// is written. It returns 1 when it wrote.
const migrateSchemaScript = `
if redis.call("PTTL", KEYS[1]) <= 0 then
  return 0
end
if redis.call("GET", KEYS[1]) ~= ARGV[1] then
  return 0
end
redis.call("SET", KEYS[1], ARGV[2], "KEEPTTL")
return 1
`

var migrateSchemaLua = redis.NewScript(migrateSchemaScript)

const rotateRefreshScript = `
local function read_be64(s, i)
  local b1 = string.byte(s, i)
  local b2 = string.byte(s, i + 1)
  local b3 = string.byte(s, i + 2)
  local b4 = string.byte(s, i + 3)
  local b5 = string.byte(s, i + 4)
  local b6 = string.byte(s, i + 5)
  local b7 = string.byte(s, i + 6)
  local b8 = string.byte(s, i + 7)
  if not b8 then
    return nil
  end
  return ((((((((b1 * 256) + b2) * 256 + b3) * 256 + b4) * 256 + b5) * 256 + b6) * 256 + b7) * 256 + b8)
end

local function parse_session(data)
  local version = string.byte(data, 1)
  if not version or version < 1 or version > 6 then
    return nil
  end

  local idx = 2
  local user_len = string.byte(data, idx)
  if not user_len then
    return nil
  end
  idx = idx + 1
  if #data < idx + user_len - 1 then
    return nil
  end
  local user_id = string.sub(data, idx, idx + user_len - 1)
  idx = idx + user_len

  local tenant_len = string.byte(data, idx)
  if not tenant_len then
    return nil
  end
  idx = idx + 1 + tenant_len

  local role_len = string.byte(data, idx)
  if not role_len then
    return nil
  end
  idx = idx + 1 + role_len

  if #data < idx + 3 then
    return nil
  end
  idx = idx + 4

  if version >= 3 then
    if #data < idx + 3 then
      return nil
    end
    idx = idx + 4
  end

  if version >= 4 then
    if #data < idx + 4 then
      return nil
    end
    idx = idx + 5
  end

  local mask_len = string.byte(data, idx)
  if not mask_len then
    return nil
  end
  idx = idx + 1 + mask_len

  local refresh_offset = nil
  local refresh_hash = nil
  if version >= 2 then
    if #data < idx + 31 then
      return nil
    end
    refresh_offset = idx
    refresh_hash = string.sub(data, idx, idx + 31)
    idx = idx + 32
  end

  if version >= 5 then
    if #data < idx + 63 then
      return nil
    end
    idx = idx + 64
  end

  if #data < idx + 15 then
    return nil
  end
  local created_at = read_be64(data, idx)
  idx = idx + 8
  local expires_at = read_be64(data, idx)
  if not created_at or not expires_at then
    return nil
  end
  idx = idx + 8

  local profile = nil
  if version >= 6 then
    local profile_len = string.byte(data, idx)
    if not profile_len or profile_len < 1 or profile_len > 32 then
      return nil
    end
    if #data < idx + profile_len then
      return nil
    end
    profile = string.sub(data, idx + 1, idx + profile_len)
  end

  return {
    user_id = user_id,
    refresh_hash = refresh_hash,
    refresh_offset = refresh_offset,
    created_at = created_at,
    expires_at = expires_at,
    profile = profile
  }
end

-- find_profile looks a session profile up in the table passed in ARGV: entries
-- separated by ';', each name:idle_ms:abs_ms:renew. idle_ms > 0 makes the
-- profile renewing; abs_ms == 0 means no ceiling. Returns nil when the name is
-- absent (the profile was removed from the configuration).
local function find_profile(table_arg, name)
  if not table_arg or table_arg == "" or not name then
    return nil
  end
  for entry in string.gmatch(table_arg, "[^;]+") do
    local n, idle, abs, renew = string.match(entry, "^([a-z0-9_%-]+):(%d+):(%d+):([01])$")
    if n == name then
      return {
        idle_ms = tonumber(idle),
        abs_ms = tonumber(abs),
        renew = renew == "1"
      }
    end
  end
  return nil
end

local function decrement_count(count_key)
  local count = tonumber(redis.call("GET", count_key) or "0")
  if count > 1 then
    redis.call("DECR", count_key)
  elseif count == 1 then
    redis.call("DEL", count_key)
  end
end

-- A session that ends takes its role-switch MFA-proof key with it. The key
-- ("asa:<tenant>:<id>") is derived from the counter key ("ast:<tenant>:count")
-- so the script's keys and arguments are unchanged.
local function drop_assurance(count_key, session_id)
  redis.call("DEL", "asa:" .. string.sub(count_key, 5, -7) .. ":" .. session_id)
end

local session_key = KEYS[1]
local count_key = KEYS[2]
local session_id = ARGV[1]
local user_prefix = ARGV[2]
local provided_hash = ARGV[3]
local next_hash = ARGV[4]
local now_unix = tonumber(ARGV[5])
-- Present only when session profiles are configured: the profile table, a
-- jitter in milliseconds (already drawn in Go, so the script stays
-- deterministic) and the millisecond clock.
local profile_table = ARGV[6]
local jitter_ms = tonumber(ARGV[7] or "0") or 0
local now_ms = tonumber(ARGV[8] or "0") or (now_unix * 1000)

local data = redis.call("GET", session_key)
if not data then
  return {0}
end

local parsed = parse_session(data)
if not parsed or not parsed.user_id then
  return {4}
end

local user_key = user_prefix .. parsed.user_id

if parsed.expires_at <= now_unix then
  local deleted = redis.call("DEL", session_key)
  redis.call("SREM", user_key, session_id)
  if deleted == 1 then
    decrement_count(count_key)
  end
  drop_assurance(count_key, session_id)
  return {1}
end

if not parsed.refresh_hash or parsed.refresh_hash ~= provided_hash then
  local deleted = redis.call("DEL", session_key)
  redis.call("SREM", user_key, session_id)
  if deleted == 1 then
    decrement_count(count_key)
  end
  drop_assurance(count_key, session_id)
  return {2}
end

local ttl = redis.call("PTTL", session_key)
if ttl <= 0 then
  local deleted = redis.call("DEL", session_key)
  redis.call("SREM", user_key, session_id)
  if deleted == 1 then
    decrement_count(count_key)
  end
  drop_assurance(count_key, session_id)
  return {1}
end

if not parsed.refresh_offset then
  return {4}
end

-- A v6 session carries a profile. Everything above ran first and unchanged
-- (missing, invalid blob, expired, hash mismatch, PTTL); only a session that
-- survived all of it reaches the profile rules. A legacy session skips this
-- block entirely and is written back with its existing PTTL, as before.
if parsed.profile then
  local policy = find_profile(profile_table, parsed.profile)
  if not policy then
    -- The profile was removed from the configuration: end the session
    -- exactly as expiry does and say why.
    local deleted = redis.call("DEL", session_key)
    redis.call("SREM", user_key, session_id)
    if deleted == 1 then
      decrement_count(count_key)
    end
    drop_assurance(count_key, session_id)
    return {1, "profile_unknown", parsed.profile}
  end

  -- Effective ceiling: the stored one, or CreatedAt plus the profile's
  -- current AbsoluteLifetime when that is sooner.
  local ceiling_ms = parsed.expires_at * 1000
  if policy.abs_ms > 0 then
    local cap_ms = parsed.created_at * 1000 + policy.abs_ms
    if cap_ms < ceiling_ms then
      ceiling_ms = cap_ms
    end
  end
  local remaining_ms = ceiling_ms - now_ms
  if remaining_ms <= 0 then
    local deleted = redis.call("DEL", session_key)
    redis.call("SREM", user_key, session_id)
    if deleted == 1 then
      decrement_count(count_key)
    end
    drop_assurance(count_key, session_id)
    return {1}
  end

  if policy.idle_ms > 0 then
    -- Renewing: a fresh idle window, never past the ceiling and never
    -- shorter than a second (or than what is left).
    ttl = policy.idle_ms + jitter_ms
    if ttl > remaining_ms then
      ttl = remaining_ms
    end
    local floor_ms = 1000
    if remaining_ms < floor_ms then
      floor_ms = remaining_ms
    end
    if ttl < floor_ms then
      ttl = floor_ms
    end
  elseif ttl > remaining_ms then
    -- Fixed: the key keeps its PTTL; only a ceiling shortened in the
    -- configuration can pull it in.
    ttl = remaining_ms
  end
end

local prefix = string.sub(data, 1, parsed.refresh_offset - 1)
local suffix = string.sub(data, parsed.refresh_offset + 32)
local updated = prefix .. next_hash .. suffix

redis.call("SET", session_key, updated, "PX", string.format("%d", ttl))
redis.call("SADD", user_key, session_id)

return {3, updated}
`

var rotateRefreshLua = redis.NewScript(rotateRefreshScript)

// Store is a Redis-backed session store that handles persistence, expiration,
// sliding window renewal, and atomic refresh-token rotation.
//
//	Docs: docs/session.md
type Store struct {
	redis         redis.UniversalClient
	prefix        string
	sliding       bool
	jitterEnabled bool
	jitterRange   time.Duration

	// profiles is the session profile table and its Lua ARGV encoding; nil
	// unless WithProfiles was called. It is a pointer so that Store, which
	// callers could always compare with ==, stays comparable.
	profiles *profileTable
}

// NewStore creates a session [Store] backed by the given Redis client.
// prefix sets the Redis key namespace; slidingExp, jitterEnabled, and
// jitterRange control expiration behavior.
//
//	Docs: docs/session.md
func NewStore(
	redis redis.UniversalClient,
	prefix string,
	sliding bool,
	jitterEnabled bool,
	jitterRange time.Duration,
) *Store {
	return &Store{
		redis:         redis,
		prefix:        prefix,
		sliding:       sliding,
		jitterEnabled: jitterEnabled,
		jitterRange:   jitterRange,
	}
}

func (s *Store) key(tenantID, sessionID string) string {
	return s.prefix + ":" + normalizeTenantID(tenantID) + ":" + sessionID
}

func (s *Store) userKey(tenantID, userID string) string {
	return "au:" + normalizeTenantID(tenantID) + ":" + userID
}

func (s *Store) tenantCountKey(tenantID string) string {
	return "ast:" + normalizeTenantID(tenantID) + ":count"
}

func (s *Store) replayKey(sessionID string) string {
	return "arp:" + sessionID
}

func (s *Store) deviceAnomalyKey(sessionID, kind string) string {
	return "ada:" + sessionID + ":" + kind
}

func normalizeTenantID(tenantID string) string {
	if tenantID == "" {
		return "0"
	}
	return tenantID
}

// Save persists a [Session] to Redis with the given TTL.
//
//	Performance: 2–3 Redis commands (SET + counter increment).
//	Docs: docs/session.md
func (s *Store) Save(ctx context.Context, sess *Session, ttl time.Duration) error {
	data, err := Encode(sess)
	if err != nil {
		return err
	}

	sessionKey := s.key(sess.TenantID, sess.SessionID)
	userKey := s.userKey(sess.TenantID, sess.UserID)
	countKey := s.tenantCountKey(sess.TenantID)

	_, err = s.redis.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, sessionKey, data, ttl)
		pipe.SAdd(ctx, userKey, sess.SessionID)
		pipe.Incr(ctx, countKey)
		return nil
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	return nil
}

// Get retrieves a session by tenant and session ID. Returns the decoded
// [Session] or an error if not found or Redis is unavailable.
//
//	Performance: 1 Redis GET.
//	Docs: docs/session.md
func (s *Store) Get(ctx context.Context, tenantID, sessionID string, ttl time.Duration) (*Session, error) {
	key := s.key(tenantID, sessionID)

	data, err := s.redis.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	sess, err := Decode(data)
	if err != nil {
		return nil, err
	}
	sess.SessionID = sessionID

	now := clock.Now()
	if sess.Profile != "" {
		return s.getProfiled(ctx, key, sess, now)
	}
	remainingAbsolute := s.remainingAbsoluteTTL(sess, ttl, now)
	if remainingAbsolute <= 0 {
		if err := s.deleteSessionAndIndex(ctx, sess.TenantID, sess.UserID, sessionID); err != nil {
			return nil, err
		}
		return nil, redis.Nil
	}

	if err := s.maybeMigrateSessionSchema(ctx, key, sess, data); err != nil {
		return nil, err
	}

	if s.sliding {
		nextTTL, err := s.nextSlidingTTL(remainingAbsolute)
		if err != nil {
			return nil, err
		}

		if err := s.redis.Expire(ctx, key, nextTTL).Err(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
		}
	}

	return sess, nil
}

// Delete removes a session from Redis and decrements the session counter.
//
//	Performance: 2–3 Redis commands (DEL + counter decrement).
//	Docs: docs/session.md
func (s *Store) Delete(ctx context.Context, tenantID, sessionID string) error {
	key := s.key(tenantID, sessionID)

	data, err := s.redis.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil
		}
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	sess, err := Decode(data)
	if err != nil {
		return err
	}

	return s.deleteSessionAndIndex(ctx, sess.TenantID, sess.UserID, sessionID)
}

// DeleteAllForUser removes all sessions for a user within a tenant, together
// with their role-switch MFA-proof keys, and lowers the tenant session counter
// by the number of sessions removed.
//
// The whole operation is one Lua script, so it is atomic: a session created
// before the call starts is removed, one created after it returns is not, and
// the counter never drifts from the sessions that actually exist.
//
//	Performance: 1 Lua EVALSHA, O(sessions of the user).
//	Docs: docs/session.md
func (s *Store) DeleteAllForUser(ctx context.Context, tenantID, userID string) error {
	_, err := s.deleteAllForUser(ctx, tenantID, userID, "")
	return err
}

// DeleteAllForUserExcept is [Store.DeleteAllForUser] that leaves one session
// alone: keepSessionID stays stored, stays in the user's session set and stays
// counted. An empty keepSessionID, or one that is not the user's, removes
// everything. It reports how many sessions it removed.
//
//	Performance: 1 Lua EVALSHA, O(sessions of the user).
//	Docs: docs/session.md
func (s *Store) DeleteAllForUserExcept(ctx context.Context, tenantID, userID, keepSessionID string) (int, error) {
	return s.deleteAllForUser(ctx, tenantID, userID, keepSessionID)
}

func (s *Store) deleteAllForUser(ctx context.Context, tenantID, userID, keepSessionID string) (int, error) {
	res, err := deleteAllForUserLua.Run(
		ctx,
		s.redis,
		[]string{s.userKey(tenantID, userID), s.tenantCountKey(tenantID)},
		s.key(tenantID, ""),
		s.assuranceKey(tenantID, ""),
		keepSessionID,
	).Int()
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	return res, nil
}

// TenantSessionCount returns the tracked tenant-wide session counter.
func (s *Store) TenantSessionCount(ctx context.Context, tenantID string) (int, error) {
	count, err := s.redis.Get(ctx, s.tenantCountKey(tenantID)).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	if count < 0 {
		return 0, nil
	}
	return int(count), nil
}

// SetTenantSessionCount sets (or clears) the tracked tenant session counter.
func (s *Store) SetTenantSessionCount(ctx context.Context, tenantID string, count int) error {
	key := s.tenantCountKey(tenantID)
	if count <= 0 {
		if err := s.redis.Del(ctx, key).Err(); err != nil {
			return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
		}
		return nil
	}

	if err := s.redis.Set(ctx, key, count, 0).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	return nil
}

// ActiveSessionCount returns the number of tracked session IDs for a user in a tenant.
func (s *Store) ActiveSessionCount(ctx context.Context, tenantID, userID string) (int, error) {
	count, err := s.redis.SCard(ctx, s.userKey(tenantID, userID)).Result()
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	return int(count), nil
}

// ActiveSessionIDs returns tracked session IDs for a user in a tenant.
func (s *Store) ActiveSessionIDs(ctx context.Context, tenantID, userID string) ([]string, error) {
	ids, err := s.redis.SMembers(ctx, s.userKey(tenantID, userID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	return ids, nil
}

// GetReadOnly fetches a session without mutating TTL, index, or any Redis state.
func (s *Store) GetReadOnly(ctx context.Context, tenantID, sessionID string) (*Session, error) {
	data, err := s.redis.Get(ctx, s.key(tenantID, sessionID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	sess, err := Decode(data)
	if err != nil {
		return nil, err
	}
	sess.SessionID = sessionID
	now := clock.Now()
	if now.Unix() > sess.ExpiresAt {
		return nil, redis.Nil
	}
	if sess.Profile != "" {
		policy, live := s.profileLive(sess, now)
		if !live {
			return nil, redis.Nil
		}
		if err := s.fillIdleExpiry(ctx, s.key(tenantID, sessionID), sess, policy, now); err != nil {
			return nil, err
		}
		return sess, nil
	}
	if err := s.maybeMigrateSessionSchema(ctx, s.key(tenantID, sessionID), sess, data); err != nil {
		return nil, err
	}

	return sess, nil
}

// GetManyReadOnly fetches multiple sessions without mutating Redis state.
func (s *Store) GetManyReadOnly(ctx context.Context, tenantID string, sessionIDs []string) ([]*Session, error) {
	if len(sessionIDs) == 0 {
		return []*Session{}, nil
	}

	pipe := s.redis.Pipeline()
	cmds := make([]*redis.StringCmd, len(sessionIDs))
	for i, sid := range sessionIDs {
		cmds[i] = pipe.Get(ctx, s.key(tenantID, sid))
	}

	_, err := pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	sessions := make([]*Session, 0, len(sessionIDs))
	now := clock.Now()
	nowUnix := now.Unix()
	var idleKeys []string
	var idleSessions []*Session
	for i, cmd := range cmds {
		data, cmdErr := cmd.Bytes()
		if cmdErr != nil {
			if errors.Is(cmdErr, redis.Nil) {
				continue
			}
			return nil, fmt.Errorf("%w: %v", ErrRedisUnavailable, cmdErr)
		}

		sess, decErr := Decode(data)
		if decErr != nil {
			return nil, decErr
		}
		sess.SessionID = sessionIDs[i]
		if nowUnix > sess.ExpiresAt {
			continue
		}
		if sess.Profile != "" {
			policy, live := s.profileLive(sess, now)
			if !live {
				continue
			}
			if policy.Renewing() {
				idleKeys = append(idleKeys, s.key(tenantID, sessionIDs[i]))
				idleSessions = append(idleSessions, sess)
			}
			sessions = append(sessions, sess)
			continue
		}
		if err := s.maybeMigrateSessionSchema(ctx, s.key(tenantID, sessionIDs[i]), sess, data); err != nil {
			return nil, err
		}

		sessions = append(sessions, sess)
	}

	// One more round trip, only when renewing-profile sessions were found:
	// their idle expiry is the remaining lifetime of the key.
	if len(idleKeys) > 0 {
		pipe := s.redis.Pipeline()
		ttlCmds := make([]*redis.DurationCmd, len(idleKeys))
		for i, key := range idleKeys {
			ttlCmds[i] = pipe.PTTL(ctx, key)
		}
		if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
		}
		for i, cmd := range ttlCmds {
			pttl, err := cmd.Result()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
			}
			idleSessions[i].IdleExpiresAt = idleExpiry(now, pttl)
		}
	}

	return sessions, nil
}

// EstimateActiveSessions scans tenant session keys and counts matches.
// This is an admin-only O(n) operation and must not be used in request hot paths.
func (s *Store) EstimateActiveSessions(ctx context.Context, tenantID string) (int, error) {
	pattern := s.prefix + ":" + normalizeTenantID(tenantID) + ":*"
	var (
		cursor uint64
		total  int
	)

	for {
		keys, next, err := s.redis.Scan(ctx, cursor, pattern, 1000).Result()
		if err != nil {
			return 0, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
		}
		total += len(keys)
		cursor = next
		if cursor == 0 {
			break
		}
	}

	return total, nil
}

// Ping returns a point-in-time Redis availability check and latency.
func (s *Store) Ping(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	if err := s.redis.Ping(ctx).Err(); err != nil {
		return time.Since(start), fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	return time.Since(start), nil
}

// TrackReplayAnomaly increments replay anomaly counter for a session ID.
func (s *Store) TrackReplayAnomaly(ctx context.Context, sessionID string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	key := s.replayKey(sessionID)
	count, err := s.redis.Incr(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	if count == 1 {
		if err := s.redis.Expire(ctx, key, ttl).Err(); err != nil {
			return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
		}
	}
	return nil
}

// ShouldEmitDeviceAnomaly returns true only for the first anomaly in the window per session/kind.
func (s *Store) ShouldEmitDeviceAnomaly(ctx context.Context, sessionID, kind string, window time.Duration) (bool, error) {
	if window <= 0 {
		window = time.Minute
	}
	key := s.deviceAnomalyKey(sessionID, kind)

	count, err := s.redis.Incr(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	if count == 1 {
		if err := s.redis.Expire(ctx, key, window).Err(); err != nil {
			return false, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
		}
		return true, nil
	}

	return false, nil
}

func (s *Store) remainingAbsoluteTTL(sess *Session, absoluteLifetime time.Duration, now time.Time) time.Duration {
	storedExpiry := time.Unix(sess.ExpiresAt, 0)
	if absoluteLifetime <= 0 {
		return storedExpiry.Sub(now)
	}

	configCap := time.Unix(sess.CreatedAt, 0).Add(absoluteLifetime)
	if configCap.Before(storedExpiry) {
		return configCap.Sub(now)
	}

	return storedExpiry.Sub(now)
}

func (s *Store) nextSlidingTTL(remainingAbsolute time.Duration) (time.Duration, error) {
	nextTTL := remainingAbsolute

	if s.jitterEnabled && s.jitterRange > 0 {
		jitter, err := randomJitter(s.jitterRange)
		if err != nil {
			return 0, err
		}
		nextTTL += jitter
	}

	if nextTTL > remainingAbsolute {
		nextTTL = remainingAbsolute
	}

	minTTL := minSlidingTTL
	if remainingAbsolute < minTTL {
		minTTL = remainingAbsolute
	}
	if nextTTL < minTTL {
		nextTTL = minTTL
	}

	return nextTTL, nil
}

// maybeMigrateSessionSchema lifts a pre-v5 record to v5. original is the exact
// bytes the caller read. The rewrite is one script that compares the stored
// value with them and writes only if they are unchanged: a delete in between
// leaves the session deleted, and a refresh rotation in between leaves the
// rotated hash in place instead of restoring the one that was rotated out.
func (s *Store) maybeMigrateSessionSchema(ctx context.Context, key string, sess *Session, original []byte) error {
	// Only records older than the legacy current version are migrated, and
	// only up to it. A v5 record stays v5 and a v6 (profile) record is never
	// rewritten: Encode would drop or misplace the profile, and v5 -> v6 is
	// not a migration.
	if sess == nil || sess.SchemaVersion >= CurrentSchemaVersion {
		return nil
	}

	sess.SchemaVersion = CurrentSchemaVersion
	encoded, err := Encode(sess)
	if err != nil {
		return err
	}

	if err := migrateSchemaLua.Run(ctx, s.redis, []string{key}, original, encoded).Err(); err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	return nil
}

func randomJitter(jitterRange time.Duration) (time.Duration, error) {
	if jitterRange <= 0 {
		return 0, nil
	}

	max := jitterRange.Nanoseconds()
	if max > (math.MaxInt64-1)/2 {
		return 0, errors.New("jitter range too large")
	}
	span := max*2 + 1

	n, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return 0, err
	}

	return time.Duration(n.Int64() - max), nil
}

// RotateRefreshHash atomically replaces the refresh-token hash in the
// session using a Lua CAS script. This is the core of the rotation
// protocol that enables reuse detection.
//
//	Performance: 1 Lua EVALSHA (atomic compare-and-swap).
//	Docs: docs/session.md, docs/flows.md#refresh-token-rotation
//	Security: CAS prevents lost updates under concurrency.
func (s *Store) RotateRefreshHash(
	ctx context.Context,
	tenantID, sessionID string,
	providedHash [32]byte,
	nextHash [32]byte,
) (*Session, error) {
	key := s.key(tenantID, sessionID)
	now := clock.Now()
	args := []interface{}{
		sessionID,
		s.userKey(tenantID, ""),
		providedHash[:],
		nextHash[:],
		now.Unix(),
	}
	// With no profile table the arguments are exactly the legacy five.
	extra, err := s.profileScriptArgs(now)
	if err != nil {
		return nil, err
	}
	args = append(args, extra...)

	result, err := rotateRefreshLua.Run(
		ctx,
		s.redis,
		[]string{key, s.tenantCountKey(tenantID)},
		args...,
	).Result()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	parts, ok := result.([]interface{})
	if !ok || len(parts) == 0 {
		return nil, fmt.Errorf("%w: invalid refresh script response", ErrRedisUnavailable)
	}

	code, ok := parts[0].(int64)
	if !ok {
		return nil, fmt.Errorf("%w: invalid refresh script status", ErrRedisUnavailable)
	}

	switch code {
	case rotateStatusNotFound:
		return nil, errors.Join(redis.Nil, ErrRefreshSessionNotFound)
	case rotateStatusExpired:
		return nil, expiredScriptError(parts)
	case rotateStatusMismatch:
		return nil, ErrRefreshHashMismatch
	case rotateStatusRotated:
		if len(parts) < 2 {
			return nil, fmt.Errorf("%w: missing updated session payload", ErrRedisUnavailable)
		}

		var blob []byte
		switch v := parts[1].(type) {
		case string:
			blob = []byte(v)
		case []byte:
			blob = v
		default:
			return nil, fmt.Errorf("%w: invalid updated session payload", ErrRedisUnavailable)
		}

		sess, decErr := Decode(blob)
		if decErr != nil {
			return nil, decErr
		}
		sess.SessionID = sessionID
		if err := s.maybeMigrateSessionSchema(ctx, key, sess, blob); err != nil {
			return nil, err
		}
		return sess, nil
	case rotateStatusInvalidBlob:
		return nil, errors.Join(ErrRedisUnavailable, ErrRefreshSessionCorrupt)
	default:
		return nil, fmt.Errorf("%w: unknown refresh script status", ErrRedisUnavailable)
	}
}

// expiredScriptError builds the error for the scripts' "expired" status. A
// second element "profile_unknown" says the session ended because its
// profile is no longer configured rather than because time ran out; both read
// as an expired session to every caller, which can tell them apart with
// [ErrProfileUnknown].
func expiredScriptError(parts []interface{}) error {
	if len(parts) > 1 {
		if reason, _ := parts[1].(string); reason == "profile_unknown" {
			name := ""
			if len(parts) > 2 {
				name, _ = parts[2].(string)
			}
			return errors.Join(redis.Nil, ErrRefreshSessionExpired, &profileEndError{name: name, reason: ErrProfileUnknown})
		}
	}
	return errors.Join(redis.Nil, ErrRefreshSessionExpired)
}

func (s *Store) deleteSessionAndIndex(ctx context.Context, tenantID, userID, sessionID string) error {
	key := s.key(tenantID, sessionID)
	userKey := s.userKey(tenantID, userID)
	countKey := s.tenantCountKey(tenantID)

	_, err := deleteSessionLua.Run(ctx, s.redis, []string{key, userKey, countKey}, sessionID).Result()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	return nil
}
