package stores

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	verificationRecordVersionV1 = 1
)

var (
	ErrVerificationNotFound         = errors.New("verification record not found")
	ErrVerificationSecretMismatch   = errors.New("verification secret mismatch")
	ErrVerificationAttemptsExceeded = errors.New("verification attempts exceeded")
	ErrVerificationRedisUnavailable = errors.New("verification redis unavailable")
)

// consumeVerificationLua atomically performs GET→validate→DEL/SET on a verification record.
// KEYS[1] = record key
// ARGV[1] = provided hash (32 bytes)
// ARGV[2] = expected strategy (byte)
// ARGV[3] = max attempts (int string)
// ARGV[4] = current unix timestamp (int string)
//
// Returns:
//
//	record bytes on success
//	error string: "not_found", "expired", "strategy_mismatch", "attempts_exceeded", "secret_mismatch"
var consumeVerificationLua = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then
  return {err='not_found'}
end

local providedHash = ARGV[1]
local expectedStrategy = tonumber(ARGV[2])
local maxAttempts = tonumber(ARGV[3])
local nowUnix = tonumber(ARGV[4])

-- Minimal binary decode: version(1) strategy(1) attempts(2 big-endian) expiresAt(8 big-endian) ...
local version = string.byte(data, 1)
if version ~= 1 then
  redis.call('DEL', KEYS[1])
  return {err='not_found'}
end

local strategy = string.byte(data, 2)

local a0 = string.byte(data, 3)
local a1 = string.byte(data, 4)
local attempts = a0 * 256 + a1

local e0,e1,e2,e3,e4,e5,e6,e7 = string.byte(data, 5, 12)
local expiresAt = e0
for _, b in ipairs({e1,e2,e3,e4,e5,e6,e7}) do
  expiresAt = expiresAt * 256 + b
end

if nowUnix > expiresAt then
  redis.call('DEL', KEYS[1])
  return {err='expired'}
end

if strategy ~= expectedStrategy then
  redis.call('DEL', KEYS[1])
  return {err='strategy_mismatch'}
end

-- Secret hash starts after version(1)+strategy(1)+attempts(2)+expiresAt(8)+userIDLen(2)+userID(variable)
local userIDLen = string.byte(data, 13) * 256 + string.byte(data, 14)
local hashOffset = 15 + userIDLen
local storedHash = string.sub(data, hashOffset, hashOffset + 31)

if storedHash ~= providedHash then
  attempts = attempts + 1
  if attempts >= maxAttempts then
    redis.call('DEL', KEYS[1])
    return {err='attempts_exceeded'}
  end
  -- Rewrite attempts bytes in the record
  local newA0 = math.floor(attempts / 256)
  local newA1 = attempts % 256
  local newData = string.sub(data, 1, 2) .. string.char(newA0, newA1) .. string.sub(data, 5)
  local ttlMs = redis.call('PTTL', KEYS[1])
  if ttlMs <= 0 then
    redis.call('DEL', KEYS[1])
    return {err='expired'}
  end
  redis.call('SET', KEYS[1], newData, 'PX', ttlMs)
  return {err='secret_mismatch'}
end

redis.call('DEL', KEYS[1])
return data
`)

type EmailVerificationRecord struct {
	UserID     string
	SecretHash [32]byte
	ExpiresAt  int64
	Attempts   uint16
	Strategy   int
}

type EmailVerificationStore struct {
	redis  redis.UniversalClient
	prefix string
	now    func() time.Time
}

// verificationPointerPrefix names the per-(tenant, user) pointer to the newest
// verification record ("aevg:<tenant>:<user>"). It holds that record's ID, or a
// tombstone after an event that supersedes every outstanding record (an email
// change). It is independent of the store's record prefix.
const verificationPointerPrefix = "aevg"

// verificationTombstone is stored in the pointer to supersede every record: no
// verification ID equals it.
const verificationTombstone = "-"

func (s *EmailVerificationStore) currentKey(tenantID, userID string) string {
	return verificationPointerPrefix + ":" + normalizeTenantID(tenantID) + ":" + userID
}

// SetCurrent makes verificationID the user's only valid verification record:
// records issued earlier stop being redeemable. Call it after the record is
// stored, so a request whose record failed to store leaves the code the user
// already holds alone. ttl must cover the record's own life.
func (s *EmailVerificationStore) SetCurrent(ctx context.Context, tenantID, userID, verificationID string, ttl time.Duration) error {
	if err := s.redis.Set(ctx, s.currentKey(tenantID, userID), verificationID, ttl).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrVerificationRedisUnavailable, err)
	}
	return nil
}

// InvalidateOutstanding supersedes every verification record the user has. ttl
// must cover the life of a record issued just before.
func (s *EmailVerificationStore) InvalidateOutstanding(ctx context.Context, tenantID, userID string, ttl time.Duration) error {
	return s.SetCurrent(ctx, tenantID, userID, verificationTombstone, ttl)
}

// PointerState reports how verificationID stands against the user's pointer:
// current, superseded, or (no pointer written) absent.
func (s *EmailVerificationStore) PointerState(ctx context.Context, tenantID, userID, verificationID string) (PointerState, error) {
	current, err := s.redis.Get(ctx, s.currentKey(tenantID, userID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return PointerAbsent, nil
		}
		return PointerAbsent, fmt.Errorf("%w: %v", ErrVerificationRedisUnavailable, err)
	}
	if current == verificationID {
		return PointerCurrent, nil
	}
	return PointerSuperseded, nil
}

// WithClock sets the time source the store compares record expiry against
// (the wall clock by default) and returns the store. Call it before use.
func (s *EmailVerificationStore) WithClock(now func() time.Time) *EmailVerificationStore {
	s.now = nowFn(now)
	return s
}

func NewEmailVerificationStore(redisClient redis.UniversalClient, prefix string) *EmailVerificationStore {
	if prefix == "" {
		prefix = "apv"
	}
	return &EmailVerificationStore{
		redis:  redisClient,
		prefix: prefix,
		now:    time.Now,
	}
}

func (s *EmailVerificationStore) key(tenantID, verificationID string) string {
	return s.prefix + ":" + normalizeTenantID(tenantID) + ":" + verificationID
}

func (s *EmailVerificationStore) Save(
	ctx context.Context,
	tenantID, verificationID string,
	record *EmailVerificationRecord,
	ttl time.Duration,
) error {
	encoded, err := encodeEmailVerificationRecord(record)
	if err != nil {
		return err
	}

	if err := s.redis.Set(ctx, s.key(tenantID, verificationID), encoded, ttl).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrVerificationRedisUnavailable, err)
	}

	return nil
}

func (s *EmailVerificationStore) Consume(
	ctx context.Context,
	tenantID, verificationID string,
	providedHash [32]byte,
	expectedStrategy int,
	maxAttempts int,
) (*EmailVerificationRecord, error) {
	key := s.key(tenantID, verificationID)
	nowUnix := s.now().Unix()

	result, err := consumeVerificationLua.Run(ctx, s.redis,
		[]string{key},
		string(providedHash[:]),
		expectedStrategy,
		maxAttempts,
		nowUnix,
	).Result()

	if err != nil {
		msg := err.Error()
		switch msg {
		case "not_found":
			return nil, ErrVerificationNotFound
		case "expired":
			return nil, ErrVerificationNotFound
		case "strategy_mismatch":
			return nil, ErrVerificationSecretMismatch
		case "attempts_exceeded":
			return nil, ErrVerificationAttemptsExceeded
		case "secret_mismatch":
			return nil, ErrVerificationSecretMismatch
		default:
			return nil, fmt.Errorf("%w: %v", ErrVerificationRedisUnavailable, err)
		}
	}

	data, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected lua result type", ErrVerificationRedisUnavailable)
	}

	record, decErr := decodeEmailVerificationRecord([]byte(data))
	if decErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerificationRedisUnavailable, decErr)
	}

	// Final constant-time comparison in Go as defense-in-depth
	// (Lua already checked, but Lua string comparison is not constant-time)
	if subtle.ConstantTimeCompare(record.SecretHash[:], providedHash[:]) != 1 {
		return nil, ErrVerificationSecretMismatch
	}

	return record, nil
}

func encodeEmailVerificationRecord(record *EmailVerificationRecord) ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteByte(verificationRecordVersionV1)
	buf.WriteByte(byte(record.Strategy))

	if err := binary.Write(&buf, binary.BigEndian, record.Attempts); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, record.ExpiresAt); err != nil {
		return nil, err
	}

	if len(record.UserID) > 65535 {
		return nil, errors.New("verification record user id too long")
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(record.UserID))); err != nil {
		return nil, err
	}
	buf.WriteString(record.UserID)
	buf.Write(record.SecretHash[:])

	return buf.Bytes(), nil
}

func decodeEmailVerificationRecord(data []byte) (*EmailVerificationRecord, error) {
	reader := bytes.NewReader(data)

	version, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if version != verificationRecordVersionV1 {
		return nil, errors.New("invalid verification record version")
	}

	strategy, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	record := &EmailVerificationRecord{
		Strategy: int(strategy),
	}

	if err := binary.Read(reader, binary.BigEndian, &record.Attempts); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.BigEndian, &record.ExpiresAt); err != nil {
		return nil, err
	}

	var userIDLen uint16
	if err := binary.Read(reader, binary.BigEndian, &userIDLen); err != nil {
		return nil, err
	}

	userID := make([]byte, userIDLen)
	if _, err := io.ReadFull(reader, userID); err != nil {
		return nil, err
	}
	record.UserID = string(userID)

	if _, err := io.ReadFull(reader, record.SecretHash[:]); err != nil {
		return nil, err
	}

	return record, nil
}
