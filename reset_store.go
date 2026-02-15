package goAuth

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
	resetKeyPrefix       = "apr"
	resetRecordVersionV1 = 1
)

var (
	errResetNotFound         = errors.New("reset record not found")
	errResetSecretMismatch   = errors.New("reset secret mismatch")
	errResetAttemptsExceeded = errors.New("reset attempts exceeded")
	errResetRedisUnavailable = errors.New("reset redis unavailable")
)

type passwordResetRecord struct {
	UserID     string
	SecretHash [32]byte
	ExpiresAt  int64
	Attempts   uint16
	Strategy   ResetStrategyType
}

type passwordResetStore struct {
	redis  *redis.Client
	prefix string
}

func newPasswordResetStore(redisClient *redis.Client) *passwordResetStore {
	return &passwordResetStore{
		redis:  redisClient,
		prefix: resetKeyPrefix,
	}
}

func (s *passwordResetStore) key(tenantID, resetID string) string {
	return s.prefix + ":" + normalizeResetTenantID(tenantID) + ":" + resetID
}

// Save describes the save operation and its observable behavior.
//
// Save may return an error when input validation, dependency calls, or security checks fail.
// Save does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (s *passwordResetStore) Save(
	ctx context.Context,
	tenantID, resetID string,
	record *passwordResetRecord,
	ttl time.Duration,
) error {
	encoded, err := encodePasswordResetRecord(record)
	if err != nil {
		return err
	}

	if err := s.redis.Set(ctx, s.key(tenantID, resetID), encoded, ttl).Err(); err != nil {
		return fmt.Errorf("%w: %v", errResetRedisUnavailable, err)
	}

	return nil
}

// Consume describes the consume operation and its observable behavior.
//
// Consume may return an error when input validation, dependency calls, or security checks fail.
// Consume does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (s *passwordResetStore) Consume(
	ctx context.Context,
	tenantID, resetID string,
	providedHash [32]byte,
	expectedStrategy ResetStrategyType,
	maxAttempts int,
) (*passwordResetRecord, error) {
	const maxRetries = 4
	key := s.key(tenantID, resetID)

	for i := 0; i < maxRetries; i++ {
		var matched *passwordResetRecord

		err := s.redis.Watch(ctx, func(tx *redis.Tx) error {
			data, err := tx.Get(ctx, key).Bytes()
			if err != nil {
				return err
			}

			record, err := decodePasswordResetRecord(data)
			if err != nil {
				return err
			}

			now := time.Now()
			if now.Unix() > record.ExpiresAt {
				_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					pipe.Del(ctx, key)
					return nil
				})
				if err != nil {
					return err
				}
				return errResetNotFound
			}

			if record.Strategy != expectedStrategy {
				_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					pipe.Del(ctx, key)
					return nil
				})
				if err != nil {
					return err
				}
				return errResetSecretMismatch
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
					return errResetAttemptsExceeded
				}

				ttl := time.Until(time.Unix(record.ExpiresAt, 0))
				if ttl <= 0 {
					_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
						pipe.Del(ctx, key)
						return nil
					})
					if err != nil {
						return err
					}
					return errResetNotFound
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
				return errResetSecretMismatch
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
			case errors.Is(err, redis.Nil), errors.Is(err, errResetNotFound), errors.Is(err, errResetSecretMismatch), errors.Is(err, errResetAttemptsExceeded):
				return nil, err
			default:
				return nil, fmt.Errorf("%w: %v", errResetRedisUnavailable, err)
			}
		}

		return matched, nil
	}

	return nil, errResetNotFound
}

// Get describes the get operation and its observable behavior.
//
// Get may return an error when input validation, dependency calls, or security checks fail.
// Get does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (s *passwordResetStore) Get(ctx context.Context, tenantID, resetID string) (*passwordResetRecord, error) {
	data, err := s.redis.Get(ctx, s.key(tenantID, resetID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, errResetNotFound
		}
		return nil, fmt.Errorf("%w: %v", errResetRedisUnavailable, err)
	}

	record, err := decodePasswordResetRecord(data)
	if err != nil {
		return nil, err
	}
	if time.Now().Unix() > record.ExpiresAt {
		return nil, errResetNotFound
	}

	return record, nil
}

func encodePasswordResetRecord(record *passwordResetRecord) ([]byte, error) {
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

func decodePasswordResetRecord(data []byte) (*passwordResetRecord, error) {
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

	record := &passwordResetRecord{
		Strategy: ResetStrategyType(strategy),
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

func normalizeResetTenantID(tenantID string) string {
	if tenantID == "" {
		return "0"
	}
	return tenantID
}
