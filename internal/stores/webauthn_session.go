package stores

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/redis/go-redis/v9"
)

const webAuthnSessionVersion1 = 1

// WebAuthn ceremony purposes. A session saved for one purpose must never be
// consumable for the other.
const (
	WebAuthnPurposeRegistration byte = 1
	WebAuthnPurposeLogin        byte = 2
)

var (
	ErrWebAuthnSessionNotFound = errors.New("webauthn ceremony session not found")
	ErrWebAuthnSessionBackend  = errors.New("webauthn ceremony backend unavailable")
)

// WebAuthnSession is a pending WebAuthn ceremony: the library session data
// (challenge et al.) bound to the user and purpose it was begun for.
type WebAuthnSession struct {
	UserID      string
	TenantID    string
	Purpose     byte
	SessionJSON []byte
}

// WebAuthnSessionStore persists pending ceremony sessions in Redis with a
// TTL. Sessions are single-use: Consume atomically reads and deletes.
type WebAuthnSessionStore struct {
	redis  redis.UniversalClient
	prefix string
}

func NewWebAuthnSessionStore(redisClient redis.UniversalClient, prefix string) *WebAuthnSessionStore {
	if prefix == "" {
		prefix = "awn"
	}
	return &WebAuthnSessionStore{
		redis:  redisClient,
		prefix: prefix,
	}
}

func (s *WebAuthnSessionStore) key(ceremonyID string) string {
	return s.prefix + ":" + ceremonyID
}

func (s *WebAuthnSessionStore) Save(
	ctx context.Context,
	ceremonyID string,
	record *WebAuthnSession,
	ttl time.Duration,
) error {
	encoded, err := encodeWebAuthnSession(record)
	if err != nil {
		return err
	}
	if err := s.redis.Set(ctx, s.key(ceremonyID), encoded, ttl).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrWebAuthnSessionBackend, err)
	}
	return nil
}

// Consume atomically fetches and deletes the ceremony session, enforcing
// single use: a replayed ceremony ID observes ErrWebAuthnSessionNotFound.
func (s *WebAuthnSessionStore) Consume(ctx context.Context, ceremonyID string) (*WebAuthnSession, error) {
	data, err := s.redis.GetDel(ctx, s.key(ceremonyID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrWebAuthnSessionNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrWebAuthnSessionBackend, err)
	}
	return decodeWebAuthnSession(data)
}

// Delete removes a pending ceremony session (best-effort cleanup).
func (s *WebAuthnSessionStore) Delete(ctx context.Context, ceremonyID string) error {
	if err := s.redis.Del(ctx, s.key(ceremonyID)).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrWebAuthnSessionBackend, err)
	}
	return nil
}

func encodeWebAuthnSession(record *WebAuthnSession) ([]byte, error) {
	if len(record.UserID) > 65535 || len(record.TenantID) > 65535 {
		return nil, errors.New("webauthn session id length exceeded")
	}
	if len(record.SessionJSON) > 1<<20 {
		return nil, errors.New("webauthn session data too large")
	}

	var buf bytes.Buffer
	buf.WriteByte(webAuthnSessionVersion1)
	buf.WriteByte(record.Purpose)
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(record.UserID))); err != nil {
		return nil, err
	}
	buf.WriteString(record.UserID)
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(record.TenantID))); err != nil {
		return nil, err
	}
	buf.WriteString(record.TenantID)
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(record.SessionJSON))); err != nil {
		return nil, err
	}
	buf.Write(record.SessionJSON)
	return buf.Bytes(), nil
}

func decodeWebAuthnSession(data []byte) (*WebAuthnSession, error) {
	reader := bytes.NewReader(data)

	version, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if version != webAuthnSessionVersion1 {
		return nil, errors.New("invalid webauthn session version")
	}

	record := &WebAuthnSession{}
	if record.Purpose, err = reader.ReadByte(); err != nil {
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

	var blobLen uint32
	if err := binary.Read(reader, binary.BigEndian, &blobLen); err != nil {
		return nil, err
	}
	if int(blobLen) > reader.Len() {
		return nil, errors.New("invalid webauthn session data length")
	}
	blob := make([]byte, blobLen)
	if _, err := io.ReadFull(reader, blob); err != nil {
		return nil, err
	}
	record.SessionJSON = blob

	return record, nil
}
