package session

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Assurance records when, and with which factor, a session last proved who
// is holding it. It is stored beside the session, never inside the session
// blob, so the session wire format (and its golden bytes) is untouched.
type Assurance struct {
	// MFAAt is the unix time of the last second-factor proof; zero when the
	// session never held one.
	MFAAt int64
	// MFAMethod is the factor that produced MFAAt ("totp", "backup_code" or
	// "webauthn"); empty when MFAAt is zero.
	MFAMethod string
	// AuthAt is the unix time of the last proof of any kind, including a
	// password re-check. It is never older than MFAAt.
	AuthAt int64
}

const assuranceEncodingV1 = "1"

// EncodeAssurance serializes a for storage.
func EncodeAssurance(a Assurance) string {
	return strings.Join([]string{
		assuranceEncodingV1,
		strconv.FormatInt(a.MFAAt, 10),
		a.MFAMethod,
		strconv.FormatInt(a.AuthAt, 10),
	}, "|")
}

// ErrAssuranceCorrupt is returned when a stored assurance cannot be decoded.
var ErrAssuranceCorrupt = errors.New("session assurance corrupt")

// DecodeAssurance parses a value produced by [EncodeAssurance].
func DecodeAssurance(raw string) (Assurance, error) {
	parts := strings.Split(raw, "|")
	if len(parts) != 4 || parts[0] != assuranceEncodingV1 {
		return Assurance{}, ErrAssuranceCorrupt
	}
	mfaAt, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return Assurance{}, ErrAssuranceCorrupt
	}
	authAt, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return Assurance{}, ErrAssuranceCorrupt
	}
	return Assurance{MFAAt: mfaAt, MFAMethod: parts[2], AuthAt: authAt}, nil
}

func (s *Store) assuranceKey(tenantID, sessionID string) string {
	return "asa:" + normalizeTenantID(tenantID) + ":" + sessionID
}

// SaveAssurance stores the assurance for a session. ttl must be the
// session's remaining absolute lifetime so the key can never outlive it; an
// assurance left behind by a logout simply expires by that TTL.
func (s *Store) SaveAssurance(ctx context.Context, tenantID, sessionID string, a Assurance, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	if err := s.redis.Set(ctx, s.assuranceKey(tenantID, sessionID), EncodeAssurance(a), ttl).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	return nil
}

// GetAssurance returns the stored assurance, or nil when the session has none.
func (s *Store) GetAssurance(ctx context.Context, tenantID, sessionID string) (*Assurance, error) {
	raw, err := s.redis.Get(ctx, s.assuranceKey(tenantID, sessionID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	a, err := DecodeAssurance(raw)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// Peek reads a session exactly as stored. Unlike [Store.GetReadOnly] it does
// not filter expired sessions and never rewrites the blob (no schema
// migration), so it performs no Redis write of any kind. The caller decides
// what an expired or mismatching session means; the destructive paths
// ([Store.RotateRefreshHash], [Store.SwapSession]) re-check atomically.
func (s *Store) Peek(ctx context.Context, tenantID, sessionID string) (*Session, error) {
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
	return sess, nil
}

// luaSessionParser is a verbatim copy of the blob parser inside
// rotateRefreshScript. It is copied rather than shared so the existing
// scripts stay untouched; a test pins the two copies together.
const luaSessionParser = `
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
  if not version or version < 1 or version > 5 then
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
  idx = idx + 8
  local expires_at = read_be64(data, idx)
  if not expires_at then
    return nil
  end

  return {
    user_id = user_id,
    refresh_hash = refresh_hash,
    refresh_offset = refresh_offset,
    expires_at = expires_at
  }
end

local function decrement_count(count_key)
  local count = tonumber(redis.call("GET", count_key) or "0")
  if count > 1 then
    redis.call("DECR", count_key)
  elseif count == 1 then
    redis.call("DEL", count_key)
  end
end
`

// swapSessionScript replaces one session with another atomically. It
// re-reads the old session and applies exactly rotateRefreshScript's checks
// in the same order (missing, invalid blob, expired, refresh-hash mismatch,
// PTTL), with the same side effects on the failing branches. Only when every
// check passes does it delete the old session and write the new one.
//
// KEYS: old session, new session, tenant count, old assurance, new assurance.
// ARGV: old session id, user-index prefix, presented refresh hash, now (unix),
// new session blob, new session id, new assurance ("" = carry the old one
// over, if any), expected user id.
//
// The tenant count is left alone on success: one session out, one in.
const swapSessionScript = luaSessionParser + `
local old_key = KEYS[1]
local new_key = KEYS[2]
local count_key = KEYS[3]
local old_asa_key = KEYS[4]
local new_asa_key = KEYS[5]
local old_session_id = ARGV[1]
local user_prefix = ARGV[2]
local provided_hash = ARGV[3]
local now_unix = tonumber(ARGV[4])
local new_blob = ARGV[5]
local new_session_id = ARGV[6]
local new_assurance = ARGV[7]
local expected_user = ARGV[8]

local data = redis.call("GET", old_key)
if not data then
  return {0}
end

local parsed = parse_session(data)
if not parsed or not parsed.user_id then
  return {4}
end
if parsed.user_id ~= expected_user then
  return {4}
end

local user_key = user_prefix .. parsed.user_id

if parsed.expires_at <= now_unix then
  local deleted = redis.call("DEL", old_key)
  redis.call("SREM", user_key, old_session_id)
  if deleted == 1 then
    decrement_count(count_key)
  end
  return {1}
end

if not parsed.refresh_hash or parsed.refresh_hash ~= provided_hash then
  local deleted = redis.call("DEL", old_key)
  redis.call("SREM", user_key, old_session_id)
  if deleted == 1 then
    decrement_count(count_key)
  end
  return {2}
end

local ttl = redis.call("PTTL", old_key)
if ttl <= 0 then
  local deleted = redis.call("DEL", old_key)
  redis.call("SREM", user_key, old_session_id)
  if deleted == 1 then
    decrement_count(count_key)
  end
  return {1}
end

-- The new session lives for exactly the old one's remaining absolute
-- lifetime, so a switch can never extend a session.
local lifetime_ms = (parsed.expires_at - now_unix) * 1000

redis.call("DEL", old_key)
redis.call("SREM", user_key, old_session_id)
redis.call("SET", new_key, new_blob, "PX", lifetime_ms)
redis.call("SADD", user_key, new_session_id)

if new_assurance ~= "" then
  redis.call("SET", new_asa_key, new_assurance, "PX", lifetime_ms)
  redis.call("DEL", old_asa_key)
else
  local carried = redis.call("GET", old_asa_key)
  if carried then
    redis.call("SET", new_asa_key, carried, "PX", lifetime_ms)
    redis.call("DEL", old_asa_key)
  end
end

return {3}
`

var swapSessionLua = redis.NewScript(swapSessionScript)

// SwapSession atomically replaces the session oldSessionID with next. The
// old session is identified by the refresh hash the caller presented: the
// script re-reads it and applies the same checks, in the same order, as
// [Store.RotateRefreshHash], and the failures it reports are the same errors
// (not found, expired, [ErrRefreshHashMismatch] -- which deletes the old
// session exactly as a refresh-token reuse does -- and corrupt blob).
//
// On success the old session key and its user-index entry are removed and next
// is stored with the old session's remaining absolute lifetime; the tenant
// session counter is unchanged. next must be a complete session for the same
// user and tenant; callers copy CreatedAt and ExpiresAt from the old session.
//
// When assurance is non-nil it is written for next; otherwise any assurance
// the old session held is moved to next.
//
//	Performance: 1 Lua EVALSHA.
//	Docs: docs/role_switching.md
func (s *Store) SwapSession(
	ctx context.Context,
	tenantID, oldSessionID string,
	providedHash [32]byte,
	next *Session,
	assurance *Assurance,
) error {
	if next == nil {
		return errors.New("swap session: next session required")
	}
	if normalizeTenantID(next.TenantID) != normalizeTenantID(tenantID) {
		return errors.New("swap session: tenant mismatch")
	}
	blob, err := Encode(next)
	if err != nil {
		return err
	}

	newAssurance := ""
	if assurance != nil {
		newAssurance = EncodeAssurance(*assurance)
	}

	result, err := swapSessionLua.Run(
		ctx,
		s.redis,
		[]string{
			s.key(tenantID, oldSessionID),
			s.key(tenantID, next.SessionID),
			s.tenantCountKey(tenantID),
			s.assuranceKey(tenantID, oldSessionID),
			s.assuranceKey(tenantID, next.SessionID),
		},
		oldSessionID,
		s.userKey(tenantID, ""),
		providedHash[:],
		time.Now().Unix(),
		blob,
		next.SessionID,
		newAssurance,
		next.UserID,
	).Result()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	parts, ok := result.([]interface{})
	if !ok || len(parts) == 0 {
		return fmt.Errorf("%w: invalid swap script response", ErrRedisUnavailable)
	}
	code, ok := parts[0].(int64)
	if !ok {
		return fmt.Errorf("%w: invalid swap script status", ErrRedisUnavailable)
	}

	switch code {
	case rotateStatusNotFound:
		return errors.Join(redis.Nil, ErrRefreshSessionNotFound)
	case rotateStatusExpired:
		return errors.Join(redis.Nil, ErrRefreshSessionExpired)
	case rotateStatusMismatch:
		return ErrRefreshHashMismatch
	case rotateStatusRotated:
		return nil
	case rotateStatusInvalidBlob:
		return errors.Join(ErrRedisUnavailable, ErrRefreshSessionCorrupt)
	default:
		return fmt.Errorf("%w: unknown swap script status", ErrRedisUnavailable)
	}
}
