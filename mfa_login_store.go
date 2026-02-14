package goAuth

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

const (
	mfaLoginKeyPrefix      = "amc"
	mfaLoginRecordVersion1 = 1
)

var (
	errMFALoginChallengeNotFound = errors.New("mfa challenge not found")
	errMFALoginChallengeExpired  = errors.New("mfa challenge expired")
	errMFALoginChallengeExceeded = errors.New("mfa challenge attempts exceeded")
	errMFALoginChallengeBackend  = errors.New("mfa challenge backend unavailable")
)

type mfaLoginChallenge struct {
	UserID    string
	TenantID  string
	ExpiresAt int64
	Attempts  uint16
}

type mfaLoginChallengeStore struct {
	redis *redis.Client
}

func newMFALoginChallengeStore(redisClient *redis.Client) *mfaLoginChallengeStore {
	return &mfaLoginChallengeStore{redis: redisClient}
}

func (s *mfaLoginChallengeStore) key(challengeID string) string {
	return mfaLoginKeyPrefix + ":" + challengeID
}

func (s *mfaLoginChallengeStore) Save(
	ctx context.Context,
	challengeID string,
	record *mfaLoginChallenge,
	ttl time.Duration,
) error {
	encoded, err := encodeMFALoginChallenge(record)
	if err != nil {
		return err
	}
	if err := s.redis.Set(ctx, s.key(challengeID), encoded, ttl).Err(); err != nil {
		return fmt.Errorf("%w: %v", errMFALoginChallengeBackend, err)
	}
	return nil
}

func (s *mfaLoginChallengeStore) Get(ctx context.Context, challengeID string) (*mfaLoginChallenge, error) {
	data, err := s.redis.Get(ctx, s.key(challengeID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, errMFALoginChallengeNotFound
		}
		return nil, fmt.Errorf("%w: %v", errMFALoginChallengeBackend, err)
	}

	record, err := decodeMFALoginChallenge(data)
	if err != nil {
		return nil, err
	}
	if time.Now().Unix() > record.ExpiresAt {
		_, _ = s.redis.Del(ctx, s.key(challengeID)).Result()
		return nil, errMFALoginChallengeExpired
	}
	return record, nil
}

func (s *mfaLoginChallengeStore) Delete(ctx context.Context, challengeID string) (bool, error) {
	n, err := s.redis.Del(ctx, s.key(challengeID)).Result()
	if err != nil {
		return false, fmt.Errorf("%w: %v", errMFALoginChallengeBackend, err)
	}
	return n > 0, nil
}

func (s *mfaLoginChallengeStore) RecordFailure(
	ctx context.Context,
	challengeID string,
	maxAttempts int,
) (bool, error) {
	const maxRetries = 4
	key := s.key(challengeID)

	for i := 0; i < maxRetries; i++ {
		var exceeded bool
		err := s.redis.Watch(ctx, func(tx *redis.Tx) error {
			data, err := tx.Get(ctx, key).Bytes()
			if err != nil {
				return err
			}

			record, err := decodeMFALoginChallenge(data)
			if err != nil {
				return err
			}
			if time.Now().Unix() > record.ExpiresAt {
				_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					pipe.Del(ctx, key)
					return nil
				})
				if err != nil {
					return err
				}
				return errMFALoginChallengeExpired
			}

			record.Attempts++
			if int(record.Attempts) >= maxAttempts {
				exceeded = true
				_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					pipe.Del(ctx, key)
					return nil
				})
				if err != nil {
					return err
				}
				return nil
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
				return errMFALoginChallengeExpired
			}

			updated, err := encodeMFALoginChallenge(record)
			if err != nil {
				return err
			}
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, key, updated, ttl)
				return nil
			})
			return err
		}, key)

		if err == redis.TxFailedErr {
			continue
		}
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return false, errMFALoginChallengeNotFound
			}
			if errors.Is(err, errMFALoginChallengeExpired) {
				return false, err
			}
			return false, fmt.Errorf("%w: %v", errMFALoginChallengeBackend, err)
		}
		return exceeded, nil
	}

	return false, errMFALoginChallengeNotFound
}

func encodeMFALoginChallenge(record *mfaLoginChallenge) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(mfaLoginRecordVersion1)

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

	return buf.Bytes(), nil
}

func decodeMFALoginChallenge(data []byte) (*mfaLoginChallenge, error) {
	reader := bytes.NewReader(data)

	version, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if version != mfaLoginRecordVersion1 {
		return nil, errors.New("invalid mfa challenge version")
	}

	record := &mfaLoginChallenge{}
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

	return record, nil
}
