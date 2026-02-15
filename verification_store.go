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
	verificationKeyPrefix       = "apv"
	verificationRecordVersionV1 = 1
)

var (
	errVerificationNotFound         = errors.New("verification record not found")
	errVerificationSecretMismatch   = errors.New("verification secret mismatch")
	errVerificationAttemptsExceeded = errors.New("verification attempts exceeded")
	errVerificationRedisUnavailable = errors.New("verification redis unavailable")
)

type emailVerificationRecord struct {
	UserID     string
	SecretHash [32]byte
	ExpiresAt  int64
	Attempts   uint16
	Strategy   VerificationStrategyType
}

type emailVerificationStore struct {
	redis  *redis.Client
	prefix string
}

func newEmailVerificationStore(redisClient *redis.Client) *emailVerificationStore {
	return &emailVerificationStore{
		redis:  redisClient,
		prefix: verificationKeyPrefix,
	}
}

func (s *emailVerificationStore) key(tenantID, verificationID string) string {
	return s.prefix + ":" + normalizeResetTenantID(tenantID) + ":" + verificationID
}

// Save describes the save operation and its observable behavior.
//
// Save may return an error when input validation, dependency calls, or security checks fail.
// Save does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (s *emailVerificationStore) Save(
	ctx context.Context,
	tenantID, verificationID string,
	record *emailVerificationRecord,
	ttl time.Duration,
) error {
	encoded, err := encodeEmailVerificationRecord(record)
	if err != nil {
		return err
	}

	if err := s.redis.Set(ctx, s.key(tenantID, verificationID), encoded, ttl).Err(); err != nil {
		return fmt.Errorf("%w: %v", errVerificationRedisUnavailable, err)
	}

	return nil
}

// Consume describes the consume operation and its observable behavior.
//
// Consume may return an error when input validation, dependency calls, or security checks fail.
// Consume does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (s *emailVerificationStore) Consume(
	ctx context.Context,
	tenantID, verificationID string,
	providedHash [32]byte,
	expectedStrategy VerificationStrategyType,
	maxAttempts int,
) (*emailVerificationRecord, error) {
	const maxRetries = 4
	key := s.key(tenantID, verificationID)

	for i := 0; i < maxRetries; i++ {
		var matched *emailVerificationRecord

		err := s.redis.Watch(ctx, func(tx *redis.Tx) error {
			data, err := tx.Get(ctx, key).Bytes()
			if err != nil {
				return err
			}

			record, err := decodeEmailVerificationRecord(data)
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
				return errVerificationNotFound
			}

			if record.Strategy != expectedStrategy {
				_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					pipe.Del(ctx, key)
					return nil
				})
				if err != nil {
					return err
				}
				return errVerificationSecretMismatch
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
					return errVerificationAttemptsExceeded
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
					return errVerificationNotFound
				}

				updated, err := encodeEmailVerificationRecord(record)
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
				return errVerificationSecretMismatch
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
			case errors.Is(err, redis.Nil), errors.Is(err, errVerificationNotFound), errors.Is(err, errVerificationSecretMismatch), errors.Is(err, errVerificationAttemptsExceeded):
				return nil, err
			default:
				return nil, fmt.Errorf("%w: %v", errVerificationRedisUnavailable, err)
			}
		}

		return matched, nil
	}

	return nil, errVerificationNotFound
}

func encodeEmailVerificationRecord(record *emailVerificationRecord) ([]byte, error) {
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

func decodeEmailVerificationRecord(data []byte) (*emailVerificationRecord, error) {
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

	record := &emailVerificationRecord{
		Strategy: VerificationStrategyType(strategy),
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
