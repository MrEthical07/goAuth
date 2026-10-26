package stores

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

const emailChangeRecordVersionV1 = 1

var (
	ErrEmailChangeNotFound         = errors.New("email change challenge not found")
	ErrEmailChangeExpired          = errors.New("email change challenge expired")
	ErrEmailChangeSecretMismatch   = errors.New("email change secret mismatch")
	ErrEmailChangeAttemptsExceeded = errors.New("email change attempts exceeded")
	ErrEmailChangeUnavailable      = errors.New("email change store unavailable")
)

// EmailChangeRecord is one pending email change. It binds the code to the
// user and to the exact change: the identifier it replaces, the one it
// installs, and the account version it was requested at.
type EmailChangeRecord struct {
	UserID         string
	OldIdentifier  string
	NewIdentifier  string
	AccountVersion uint32
	SecretHash     [32]byte
	ExpiresAt      int64
	Attempts       uint16
	Strategy       int
}

// saveEmailChangeLua stores a challenge and makes it the user's only pending
// one: the challenge a previous request left behind is deleted in the same
// step.
//
// KEYS: record, per-user pointer. ARGV: encoded record, ttl (ms), record key
// prefix, verification id.
var saveEmailChangeLua = redis.NewScript(`
local old = redis.call('GET', KEYS[2])
if old and old ~= ARGV[4] then
  redis.call('DEL', ARGV[3] .. old)
end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('SET', KEYS[2], ARGV[4], 'PX', ARGV[2])
return 1
`)

// consumeEmailChangeLua checks a code against a challenge atomically: a match
// deletes the challenge (one use), a mismatch counts an attempt and deletes it
// when the attempts run out, and an expired or foreign-strategy challenge is
// deleted. Every outcome that deletes the record also clears the user's
// pointer if it still names this challenge.
//
// KEYS: record, per-user pointer. ARGV: provided hash, expected strategy,
// max attempts, now (unix), verification id.
//
// The record starts version(1) strategy(1) attempts(2) expiresAt(8) hash(32);
// the rest is read in Go.
var consumeEmailChangeLua = redis.NewScript(`
local function forget()
  if redis.call('GET', KEYS[2]) == ARGV[5] then
    redis.call('DEL', KEYS[2])
  end
end

local data = redis.call('GET', KEYS[1])
if not data then
  return {err='not_found'}
end

if string.byte(data, 1) ~= 1 or #data < 44 then
  redis.call('DEL', KEYS[1])
  forget()
  return {err='not_found'}
end

local strategy = string.byte(data, 2)
local attempts = string.byte(data, 3) * 256 + string.byte(data, 4)
local e0,e1,e2,e3,e4,e5,e6,e7 = string.byte(data, 5, 12)
local expiresAt = e0
for _, b in ipairs({e1,e2,e3,e4,e5,e6,e7}) do
  expiresAt = expiresAt * 256 + b
end

if tonumber(ARGV[4]) > expiresAt then
  redis.call('DEL', KEYS[1])
  forget()
  return {err='expired'}
end

if strategy ~= tonumber(ARGV[2]) then
  redis.call('DEL', KEYS[1])
  forget()
  return {err='strategy_mismatch'}
end

local stored = string.sub(data, 13, 44)
if stored ~= ARGV[1] then
  attempts = attempts + 1
  if attempts >= tonumber(ARGV[3]) then
    redis.call('DEL', KEYS[1])
    forget()
    return {err='attempts_exceeded'}
  end
  local ttlMs = redis.call('PTTL', KEYS[1])
  if ttlMs <= 0 then
    redis.call('DEL', KEYS[1])
    forget()
    return {err='expired'}
  end
  local updated = string.sub(data, 1, 2) .. string.char(math.floor(attempts / 256), attempts % 256) .. string.sub(data, 5)
  redis.call('SET', KEYS[1], updated, 'PX', ttlMs)
  return {err='secret_mismatch'}
end

redis.call('DEL', KEYS[1])
forget()
return data
`)

// cancelEmailChangeLua deletes the user's pending challenge, if any, and
// returns 1 if there was one and 0 if not.
//
// KEYS: per-user pointer. ARGV: record key prefix.
var cancelEmailChangeLua = redis.NewScript(`
local old = redis.call('GET', KEYS[1])
if old then
  redis.call('DEL', ARGV[1] .. old)
end
redis.call('DEL', KEYS[1])
if old then
  return 1
end
return 0
`)

// EmailChangeStore keeps pending email-change challenges, one per user.
type EmailChangeStore struct {
	redis  redis.UniversalClient
	prefix string
}

// NewEmailChangeStore creates the store. An empty prefix selects "aec".
func NewEmailChangeStore(redisClient redis.UniversalClient, prefix string) *EmailChangeStore {
	if prefix == "" {
		prefix = "aec"
	}
	return &EmailChangeStore{redis: redisClient, prefix: prefix}
}

func (s *EmailChangeStore) recordPrefix(tenantID string) string {
	return s.prefix + ":" + normalizeTenantID(tenantID) + ":"
}

func (s *EmailChangeStore) key(tenantID, verificationID string) string {
	return s.recordPrefix(tenantID) + verificationID
}

func (s *EmailChangeStore) pointerKey(tenantID, userID string) string {
	return s.prefix + "p:" + normalizeTenantID(tenantID) + ":" + userID
}

func (s *EmailChangeStore) markerKey(tenantID, userID string) string {
	return s.prefix + "i:" + normalizeTenantID(tenantID) + ":" + userID
}

// Save stores record as the user's pending challenge, replacing any earlier one.
func (s *EmailChangeStore) Save(ctx context.Context, tenantID, verificationID string, record *EmailChangeRecord, ttl time.Duration) error {
	encoded, err := encodeEmailChangeRecord(record)
	if err != nil {
		return err
	}
	_, err = saveEmailChangeLua.Run(ctx, s.redis,
		[]string{s.key(tenantID, verificationID), s.pointerKey(tenantID, record.UserID)},
		encoded, ttl.Milliseconds(), s.recordPrefix(tenantID), verificationID,
	).Result()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEmailChangeUnavailable, err)
	}
	return nil
}

// Consume checks code hash against the challenge. See consumeEmailChangeLua for
// what each outcome does to the stored record.
func (s *EmailChangeStore) Consume(ctx context.Context, tenantID, verificationID string, providedHash [32]byte, expectedStrategy, maxAttempts int) (*EmailChangeRecord, error) {
	// The script clears the per-user pointer, which is keyed by the user, who
	// is only known from the record: read the owner first. The record is not
	// trusted for anything else here; the script re-reads it atomically.
	raw, err := s.redis.Get(ctx, s.key(tenantID, verificationID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrEmailChangeNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrEmailChangeUnavailable, err)
	}
	peeked, err := decodeEmailChangeRecord(raw)
	if err != nil {
		_ = s.redis.Del(ctx, s.key(tenantID, verificationID)).Err()
		return nil, ErrEmailChangeNotFound
	}

	result, err := consumeEmailChangeLua.Run(ctx, s.redis,
		[]string{s.key(tenantID, verificationID), s.pointerKey(tenantID, peeked.UserID)},
		string(providedHash[:]), expectedStrategy, maxAttempts, time.Now().Unix(), verificationID,
	).Result()
	if err != nil {
		switch err.Error() {
		case "not_found":
			return nil, ErrEmailChangeNotFound
		case "expired":
			return nil, ErrEmailChangeExpired
		case "strategy_mismatch", "secret_mismatch":
			return nil, ErrEmailChangeSecretMismatch
		case "attempts_exceeded":
			return nil, ErrEmailChangeAttemptsExceeded
		default:
			return nil, fmt.Errorf("%w: %v", ErrEmailChangeUnavailable, err)
		}
	}
	data, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected script result", ErrEmailChangeUnavailable)
	}
	record, err := decodeEmailChangeRecord([]byte(data))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEmailChangeUnavailable, err)
	}
	// The script compared the hashes already; compare again in constant time.
	if subtle.ConstantTimeCompare(record.SecretHash[:], providedHash[:]) != 1 {
		return nil, ErrEmailChangeSecretMismatch
	}
	return record, nil
}

// Cancel deletes the user's pending challenge. It is idempotent.
func (s *EmailChangeStore) Cancel(ctx context.Context, tenantID, userID string) error {
	_, err := s.CancelPending(ctx, tenantID, userID)
	return err
}

// CancelPending is Cancel that reports whether a challenge was pending.
func (s *EmailChangeStore) CancelPending(ctx context.Context, tenantID, userID string) (bool, error) {
	n, err := cancelEmailChangeLua.Run(ctx, s.redis,
		[]string{s.pointerKey(tenantID, userID)}, s.recordPrefix(tenantID),
	).Int()
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrEmailChangeUnavailable, err)
	}
	return n == 1, nil
}

// MarkIdentifierChanged records, for ttl, that the user's identifier changes at
// the given time. Challenges for the old address issued before it (password
// reset, email verification) are refused afterwards.
func (s *EmailChangeStore) MarkIdentifierChanged(ctx context.Context, tenantID, userID string, at time.Time, ttl time.Duration) error {
	err := s.redis.Set(ctx, s.markerKey(tenantID, userID), strconv.FormatInt(at.Unix(), 10), ttl).Err()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEmailChangeUnavailable, err)
	}
	return nil
}

// IdentifierChangedAt returns the unix time of the user's latest marker, or 0
// when there is none.
func (s *EmailChangeStore) IdentifierChangedAt(ctx context.Context, tenantID, userID string) (int64, error) {
	raw, err := s.redis.Get(ctx, s.markerKey(tenantID, userID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, fmt.Errorf("%w: %v", ErrEmailChangeUnavailable, err)
	}
	at, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: corrupt marker", ErrEmailChangeUnavailable)
	}
	return at, nil
}

func encodeEmailChangeRecord(r *EmailChangeRecord) ([]byte, error) {
	for _, s := range []string{r.UserID, r.OldIdentifier, r.NewIdentifier} {
		if len(s) > 65535 {
			return nil, errors.New("email change record field too long")
		}
	}
	var buf bytes.Buffer
	buf.WriteByte(emailChangeRecordVersionV1)
	buf.WriteByte(byte(r.Strategy))
	_ = binary.Write(&buf, binary.BigEndian, r.Attempts)
	_ = binary.Write(&buf, binary.BigEndian, r.ExpiresAt)
	buf.Write(r.SecretHash[:])
	_ = binary.Write(&buf, binary.BigEndian, r.AccountVersion)
	for _, s := range []string{r.UserID, r.OldIdentifier, r.NewIdentifier} {
		_ = binary.Write(&buf, binary.BigEndian, uint16(len(s)))
		buf.WriteString(s)
	}
	return buf.Bytes(), nil
}

func decodeEmailChangeRecord(data []byte) (*EmailChangeRecord, error) {
	reader := bytes.NewReader(data)
	version, err := reader.ReadByte()
	if err != nil || version != emailChangeRecordVersionV1 {
		return nil, errors.New("invalid email change record version")
	}
	strategy, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	r := &EmailChangeRecord{Strategy: int(strategy)}
	if err := binary.Read(reader, binary.BigEndian, &r.Attempts); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.BigEndian, &r.ExpiresAt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(reader, r.SecretHash[:]); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.BigEndian, &r.AccountVersion); err != nil {
		return nil, err
	}
	for _, f := range []*string{&r.UserID, &r.OldIdentifier, &r.NewIdentifier} {
		var n uint16
		if err := binary.Read(reader, binary.BigEndian, &n); err != nil {
			return nil, err
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(reader, b); err != nil {
			return nil, err
		}
		*f = string(b)
	}
	return r, nil
}
