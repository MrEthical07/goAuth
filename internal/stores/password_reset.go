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
	resetRecordVersionV1 = 1
)

var (
	ErrResetNotFound         = errors.New("reset record not found")
	ErrResetSecretMismatch   = errors.New("reset secret mismatch")
	ErrResetAttemptsExceeded = errors.New("reset attempts exceeded")
	ErrResetRedisUnavailable = errors.New("reset redis unavailable")
)

type PasswordResetRecord struct {
	UserID     string
	SecretHash [32]byte
	ExpiresAt  int64
	Attempts   uint16
	Strategy   int
}

type PasswordResetStore struct {
	redis  redis.UniversalClient
	prefix string
	now    func() time.Time
}

// WithClock sets the time source the store compares record expiry against
// (the wall clock by default) and returns the store. Call it before use.
func (s *PasswordResetStore) WithClock(now func() time.Time) *PasswordResetStore {
	s.now = nowFn(now)
	return s
}

func NewPasswordResetStore(redisClient redis.UniversalClient, prefix string) *PasswordResetStore {
	if prefix == "" {
		prefix = "apr"
	}
	return &PasswordResetStore{
		redis:  redisClient,
		prefix: prefix,
		now:    time.Now,
	}
}

func (s *PasswordResetStore) key(tenantID, resetID string) string {
	return s.prefix + ":" + normalizeTenantID(tenantID) + ":" + resetID
}

// currentKey names the per-(tenant, user) pointer to the newest reset record
// ("<prefix>g:<tenant>:<user>"). It holds that record's reset ID, or a
// tombstone after a reset completed.
func (s *PasswordResetStore) currentKey(tenantID, userID string) string {
	return s.prefix + "g:" + normalizeTenantID(tenantID) + ":" + userID
}

// resetCompletedTombstone is stored in the pointer when a reset has completed:
// no reset ID equals it, so every record issued before is superseded.
const resetCompletedTombstone = "-"

// SetCurrent makes resetID the user's only valid reset record: records issued
// earlier stop being redeemable. ttl must cover the record's own life.
func (s *PasswordResetStore) SetCurrent(ctx context.Context, tenantID, userID, resetID string, ttl time.Duration) error {
	if err := s.redis.Set(ctx, s.currentKey(tenantID, userID), resetID, ttl).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrResetRedisUnavailable, err)
	}
	return nil
}

// InvalidateOutstanding supersedes every reset record the user has, as a
// completed reset does. ttl must cover the life of a record issued just before.
func (s *PasswordResetStore) InvalidateOutstanding(ctx context.Context, tenantID, userID string, ttl time.Duration) error {
	return s.SetCurrent(ctx, tenantID, userID, resetCompletedTombstone, ttl)
}

// IsCurrent reports whether resetID has not been superseded. A user with no
// pointer (records issued before pointers existed, or whose pointer expired
// together with every record it could supersede) has no superseded records.
func (s *PasswordResetStore) IsCurrent(ctx context.Context, tenantID, userID, resetID string) (bool, error) {
	state, err := s.PointerState(ctx, tenantID, userID, resetID)
	return state != PointerSuperseded, err
}

// PointerState reports how resetID stands against the user's pointer: current,
// superseded, or (no pointer written) absent.
func (s *PasswordResetStore) PointerState(ctx context.Context, tenantID, userID, resetID string) (PointerState, error) {
	current, err := s.redis.Get(ctx, s.currentKey(tenantID, userID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return PointerAbsent, nil
		}
		return PointerAbsent, fmt.Errorf("%w: %v", ErrResetRedisUnavailable, err)
	}
	if current == resetID {
		return PointerCurrent, nil
	}
	return PointerSuperseded, nil
}

func (s *PasswordResetStore) Save(
	ctx context.Context,
	tenantID, resetID string,
	record *PasswordResetRecord,
	ttl time.Duration,
) error {
	encoded, err := encodePasswordResetRecord(record)
	if err != nil {
		return err
	}

	if err := s.redis.Set(ctx, s.key(tenantID, resetID), encoded, ttl).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrResetRedisUnavailable, err)
	}

	return nil
}

func (s *PasswordResetStore) Consume(
	ctx context.Context,
	tenantID, resetID string,
	providedHash [32]byte,
	expectedStrategy int,
	maxAttempts int,
) (*PasswordResetRecord, error) {
	const maxRetries = 4
	key := s.key(tenantID, resetID)

	for i := 0; i < maxRetries; i++ {
		var matched *PasswordResetRecord

		err := s.redis.Watch(ctx, func(tx *redis.Tx) error {
			data, err := tx.Get(ctx, key).Bytes()
			if err != nil {
				return err
			}

			record, err := decodePasswordResetRecord(data)
			if err != nil {
				return err
			}

			now := s.now()
			if now.Unix() > record.ExpiresAt {
				_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					pipe.Del(ctx, key)
					return nil
				})
				if err != nil {
					return err
				}
				return ErrResetNotFound
			}

			if record.Strategy != expectedStrategy {
				_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					pipe.Del(ctx, key)
					return nil
				})
				if err != nil {
					return err
				}
				return ErrResetSecretMismatch
			}

			if subtle.ConstantTimeCompare(record.SecretHash[:], providedHash[:]) != 1 {
				record.Attempts++
				if int(record.Attempts) >= maxAttempts {
					_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
						pipe.Del(ctx, key)
						return nil
					})
					if err != nil {
						return err
					}
					return ErrResetAttemptsExceeded
				}

				ttl := time.Unix(record.ExpiresAt, 0).Sub(now)
				if ttl <= 0 {
					_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
						pipe.Del(ctx, key)
						return nil
					})
					if err != nil {
						return err
					}
					return ErrResetNotFound
				}

				updated, err := encodePasswordResetRecord(record)
				if err != nil {
					return err
				}

				_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					pipe.Set(ctx, key, updated, ttl)
					return nil
				})
				if err != nil {
					return err
				}
				return ErrResetSecretMismatch
			}

			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Del(ctx, key)
				return nil
			})
			if err != nil {
				return err
			}

			matched = record
			return nil
		}, key)

		if err == redis.TxFailedErr {
			continue
		}
		if err != nil {
			switch {
			case errors.Is(err, redis.Nil), errors.Is(err, ErrResetNotFound), errors.Is(err, ErrResetSecretMismatch), errors.Is(err, ErrResetAttemptsExceeded):
				return nil, err
			default:
				return nil, fmt.Errorf("%w: %v", ErrResetRedisUnavailable, err)
			}
		}

		return matched, nil
	}

	return nil, ErrResetNotFound
}

func (s *PasswordResetStore) Get(ctx context.Context, tenantID, resetID string) (*PasswordResetRecord, error) {
	data, err := s.redis.Get(ctx, s.key(tenantID, resetID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrResetNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrResetRedisUnavailable, err)
	}

	record, err := decodePasswordResetRecord(data)
	if err != nil {
		return nil, err
	}
	if s.now().Unix() > record.ExpiresAt {
		return nil, ErrResetNotFound
	}

	return record, nil
}

func encodePasswordResetRecord(record *PasswordResetRecord) ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteByte(resetRecordVersionV1)
	buf.WriteByte(byte(record.Strategy))

	if err := binary.Write(&buf, binary.BigEndian, record.Attempts); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, record.ExpiresAt); err != nil {
		return nil, err
	}

	if len(record.UserID) > 65535 {
		return nil, errors.New("reset record user id too long")
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(record.UserID))); err != nil {
		return nil, err
	}
	buf.WriteString(record.UserID)
	buf.Write(record.SecretHash[:])

	return buf.Bytes(), nil
}

func decodePasswordResetRecord(data []byte) (*PasswordResetRecord, error) {
	reader := bytes.NewReader(data)

	version, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if version != resetRecordVersionV1 {
		return nil, errors.New("invalid reset record version")
	}

	strategy, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	record := &PasswordResetRecord{
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
