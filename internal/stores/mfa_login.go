package stores

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	mfaLoginRecordVersion1 = 1
	// mfaLoginRecordVersion2 appends a flags byte (bit 0 = remember-me) after
	// the v1 layout. Decoding accepts both versions; v1 records read as
	// remember-me = false.
	mfaLoginRecordVersion2 = 2
	// mfaLoginRecordVersion3 appends a length-prefixed (one byte) session
	// profile name after the v2 flags byte. It is written only when the
	// record carries a profile, i.e. only while session profiles are
	// configured; every other record is still written as v2, byte for byte.
	// Decoding accepts v1 through v3.
	mfaLoginRecordVersion3 = 3

	mfaLoginFlagRememberMe = 1 << 0

	// maxMFALoginProfileLen mirrors the session profile name limit.
	maxMFALoginProfileLen = 32
)

var (
	ErrMFALoginChallengeNotFound = errors.New("mfa challenge not found")
	ErrMFALoginChallengeExpired  = errors.New("mfa challenge expired")
	ErrMFALoginChallengeExceeded = errors.New("mfa challenge attempts exceeded")
	ErrMFALoginChallengeBackend  = errors.New("mfa challenge backend unavailable")
)

type MFALoginChallenge struct {
	UserID     string
	TenantID   string
	ExpiresAt  int64
	Attempts   uint16
	RememberMe bool
	// Profile is the session profile resolved at login; empty when profiles
	// are not configured.
	Profile string
}

type MFALoginChallengeStore struct {
	redis  redis.UniversalClient
	prefix string
	now    func() time.Time
}

// WithClock sets the time source the store compares challenge expiry against
// (the wall clock by default) and returns the store. Call it before use.
func (s *MFALoginChallengeStore) WithClock(now func() time.Time) *MFALoginChallengeStore {
	s.now = nowFn(now)
	return s
}

func NewMFALoginChallengeStore(redisClient redis.UniversalClient, prefix string) *MFALoginChallengeStore {
	if prefix == "" {
		prefix = "amc"
	}
	return &MFALoginChallengeStore{
		redis:  redisClient,
		prefix: prefix,
		now:    time.Now,
	}
}

func (s *MFALoginChallengeStore) key(challengeID string) string {
	return s.prefix + ":" + challengeID
}

func (s *MFALoginChallengeStore) Save(
	ctx context.Context,
	challengeID string,
	record *MFALoginChallenge,
	ttl time.Duration,
) error {
	encoded, err := encodeMFALoginChallenge(record)
	if err != nil {
		return err
	}
	if err := s.redis.Set(ctx, s.key(challengeID), encoded, ttl).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrMFALoginChallengeBackend, err)
	}
	return nil
}

func (s *MFALoginChallengeStore) Get(ctx context.Context, challengeID string) (*MFALoginChallenge, error) {
	data, err := s.redis.Get(ctx, s.key(challengeID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrMFALoginChallengeNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrMFALoginChallengeBackend, err)
	}

	record, err := decodeMFALoginChallenge(data)
	if err != nil {
		return nil, err
	}
	if s.now().Unix() > record.ExpiresAt {
		_, _ = s.redis.Del(ctx, s.key(challengeID)).Result()
		return nil, ErrMFALoginChallengeExpired
	}
	return record, nil
}

func (s *MFALoginChallengeStore) Delete(ctx context.Context, challengeID string) (bool, error) {
	n, err := s.redis.Del(ctx, s.key(challengeID)).Result()
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrMFALoginChallengeBackend, err)
	}
	_ = s.redis.Del(ctx, s.contextKey(challengeID)).Err()
	return n > 0, nil
}

// contextKey names the companion of a challenge that carries what the password
// step knew: the user's revocation epoch and the factors it advertised. It is a
// separate key so the challenge's binary record keeps its format.
func (s *MFALoginChallengeStore) contextKey(challengeID string) string {
	return s.key(challengeID) + ":ep"
}

// SaveContext records the revocation epoch the password step ran under and the
// bit set of factors it advertised (zero: unknown), for the life of the
// challenge. The value is "<epoch>:<advertised>".
func (s *MFALoginChallengeStore) SaveContext(ctx context.Context, challengeID string, epoch int64, advertised uint8, ttl time.Duration) error {
	value := strconv.FormatInt(epoch, 10) + ":" + strconv.Itoa(int(advertised))
	if err := s.redis.Set(ctx, s.contextKey(challengeID), value, ttl).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrMFALoginChallengeBackend, err)
	}
	return nil
}

// Context returns what SaveContext recorded. ok is false for a challenge created
// without one (by an earlier version); a value without an advertised set (the
// epoch alone) reads as advertised == 0.
func (s *MFALoginChallengeStore) Context(ctx context.Context, challengeID string) (epoch int64, advertised uint8, ok bool, err error) {
	raw, err := s.redis.Get(ctx, s.contextKey(challengeID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, 0, false, nil
		}
		return 0, 0, false, fmt.Errorf("%w: %v", ErrMFALoginChallengeBackend, err)
	}
	epochPart, advPart, hasAdv := strings.Cut(raw, ":")
	epoch, err = strconv.ParseInt(epochPart, 10, 64)
	if err != nil {
		return 0, 0, false, fmt.Errorf("%w: malformed challenge context", ErrMFALoginChallengeBackend)
	}
	if hasAdv {
		n, perr := strconv.ParseUint(advPart, 10, 8)
		if perr != nil {
			return 0, 0, false, fmt.Errorf("%w: malformed challenge context", ErrMFALoginChallengeBackend)
		}
		advertised = uint8(n)
	}
	return epoch, advertised, true, nil
}

// reserveAttemptScript claims one attempt of a challenge and leaves the rest
// of the record, and its TTL, untouched. KEYS[1] = challenge, ARGV[1] = the
// number of attempts allowed, ARGV[2] = now in unix seconds. The attempt
// counter and the expiry sit at fixed offsets of every record version: byte 0
// is the version, bytes 1-2 the big-endian attempts, bytes 3-10 the big-endian
// expiry. It returns the number of attempts used including this one, or a
// negative status: -1 no such challenge, -2 the claim is past the limit (the
// challenge is deleted), -3 the challenge expired (deleted), -4 malformed.
var reserveAttemptScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then
  return -1
end
if #data < 11 then
  return -4
end
local exp = 0
for i = 4, 11 do
  exp = exp * 256 + string.byte(data, i)
end
if tonumber(ARGV[2]) > exp then
  redis.call('DEL', KEYS[1])
  return -3
end
local attempts = string.byte(data, 2) * 256 + string.byte(data, 3) + 1
if attempts > tonumber(ARGV[1]) or attempts > 65535 then
  redis.call('DEL', KEYS[1])
  return -2
end
redis.call('SETRANGE', KEYS[1], 1, string.char(math.floor(attempts / 256), attempts % 256))
return attempts
`)

// releaseAttemptScript gives back one attempt claimed with ReserveAttempt.
var releaseAttemptScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data or #data < 3 then
  return 0
end
local attempts = string.byte(data, 2) * 256 + string.byte(data, 3)
if attempts < 1 then
  return 0
end
attempts = attempts - 1
redis.call('SETRANGE', KEYS[1], 1, string.char(math.floor(attempts / 256), attempts % 256))
return attempts
`)

// ReserveAttempt atomically claims one attempt of the challenge before a
// factor is evaluated, so concurrent confirmations cannot evaluate more codes
// than limit allows: counting the attempt after the factor was checked lets
// every request in flight pass the cap. It returns the number of attempts used
// including this one. A claim past the limit deletes the challenge and returns
// ErrMFALoginChallengeExceeded; a missing challenge is
// ErrMFALoginChallengeNotFound and an expired one ErrMFALoginChallengeExpired.
func (s *MFALoginChallengeStore) ReserveAttempt(ctx context.Context, challengeID string, limit int) (int, error) {
	res, err := reserveAttemptScript.Run(ctx, s.redis, []string{s.key(challengeID)}, limit, s.now().Unix()).Int64()
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrMFALoginChallengeBackend, err)
	}
	switch {
	case res >= 0:
		return int(res), nil
	case res == -1:
		return 0, ErrMFALoginChallengeNotFound
	case res == -2:
		return 0, ErrMFALoginChallengeExceeded
	case res == -3:
		return 0, ErrMFALoginChallengeExpired
	default:
		return 0, fmt.Errorf("%w: malformed challenge record", ErrMFALoginChallengeBackend)
	}
}

// ReleaseAttempt gives back an attempt claimed with ReserveAttempt for a
// request that evaluated no factor (a ceremony that has to be restarted, a
// replayed code).
func (s *MFALoginChallengeStore) ReleaseAttempt(ctx context.Context, challengeID string) error {
	if err := releaseAttemptScript.Run(ctx, s.redis, []string{s.key(challengeID)}).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrMFALoginChallengeBackend, err)
	}
	return nil
}

// RecordFailure counts one failed attempt and reports whether that attempt
// used up maxAttempts, in which case the challenge is deleted. It is a single
// atomic step; the login flow reserves the attempt before evaluating the
// factor instead (see ReserveAttempt).
func (s *MFALoginChallengeStore) RecordFailure(
	ctx context.Context,
	challengeID string,
	maxAttempts int,
) (bool, error) {
	if _, err := s.ReserveAttempt(ctx, challengeID, maxAttempts-1); err != nil {
		if errors.Is(err, ErrMFALoginChallengeExceeded) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

func encodeMFALoginChallenge(record *MFALoginChallenge) ([]byte, error) {
	var buf bytes.Buffer
	if record.Profile != "" {
		if len(record.Profile) > maxMFALoginProfileLen {
			return nil, errors.New("mfa challenge profile name too long")
		}
		buf.WriteByte(mfaLoginRecordVersion3)
	} else {
		buf.WriteByte(mfaLoginRecordVersion2)
	}

	if err := binary.Write(&buf, binary.BigEndian, record.Attempts); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, record.ExpiresAt); err != nil {
		return nil, err
	}

	if len(record.UserID) > 65535 || len(record.TenantID) > 65535 {
		return nil, errors.New("mfa challenge id length exceeded")
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(record.UserID))); err != nil {
		return nil, err
	}
	buf.WriteString(record.UserID)
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(record.TenantID))); err != nil {
		return nil, err
	}
	buf.WriteString(record.TenantID)

	var flags byte
	if record.RememberMe {
		flags |= mfaLoginFlagRememberMe
	}
	buf.WriteByte(flags)

	if record.Profile != "" {
		buf.WriteByte(byte(len(record.Profile)))
		buf.WriteString(record.Profile)
	}

	return buf.Bytes(), nil
}

func decodeMFALoginChallenge(data []byte) (*MFALoginChallenge, error) {
	reader := bytes.NewReader(data)

	version, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if version != mfaLoginRecordVersion1 && version != mfaLoginRecordVersion2 && version != mfaLoginRecordVersion3 {
		return nil, errors.New("invalid mfa challenge version")
	}

	record := &MFALoginChallenge{}
	if err := binary.Read(reader, binary.BigEndian, &record.Attempts); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.BigEndian, &record.ExpiresAt); err != nil {
		return nil, err
	}

	var userLen uint16
	if err := binary.Read(reader, binary.BigEndian, &userLen); err != nil {
		return nil, err
	}
	user := make([]byte, userLen)
	if _, err := io.ReadFull(reader, user); err != nil {
		return nil, err
	}
	record.UserID = string(user)

	var tenantLen uint16
	if err := binary.Read(reader, binary.BigEndian, &tenantLen); err != nil {
		return nil, err
	}
	tenant := make([]byte, tenantLen)
	if _, err := io.ReadFull(reader, tenant); err != nil {
		return nil, err
	}
	record.TenantID = string(tenant)

	if version >= mfaLoginRecordVersion2 {
		flags, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		record.RememberMe = flags&mfaLoginFlagRememberMe != 0
	}

	if version >= mfaLoginRecordVersion3 {
		n, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		if n < 1 || n > maxMFALoginProfileLen {
			return nil, errors.New("invalid mfa challenge profile length")
		}
		profile := make([]byte, n)
		if _, err := io.ReadFull(reader, profile); err != nil {
			return nil, err
		}
		record.Profile = string(profile)
	}

	return record, nil
}
