package stores

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrBackupGrantBackend reports that the grant store could not reach Redis.
var ErrBackupGrantBackend = errors.New("backup grant store unavailable")

// BackupGrantStore keeps the short-lived, single-use marker that lets a user
// who has just proven their authenticator (confirmed TOTP setup) generate the
// first set of backup codes without a further proof. Key format:
// "<prefix>:<tenant>:<user>" with a value of "1" and the grant's TTL; the
// default tenant is spelled "0".
type BackupGrantStore struct {
	redis  redis.UniversalClient
	prefix string
}

// NewBackupGrantStore creates the store. An empty prefix selects "abg".
func NewBackupGrantStore(redisClient redis.UniversalClient, prefix string) *BackupGrantStore {
	if prefix == "" {
		prefix = "abg"
	}
	return &BackupGrantStore{redis: redisClient, prefix: prefix}
}

func (s *BackupGrantStore) key(tenantID, userID string) string {
	if tenantID == "" {
		tenantID = "0"
	}
	return s.prefix + ":" + tenantID + ":" + userID
}

// Grant records the marker for ttl, replacing an earlier one.
func (s *BackupGrantStore) Grant(ctx context.Context, tenantID, userID string, ttl time.Duration) error {
	if err := s.redis.Set(ctx, s.key(tenantID, userID), "1", ttl).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrBackupGrantBackend, err)
	}
	return nil
}

// Consume uses the marker up. DEL is atomic and reports whether the key
// existed, so two concurrent generations cannot both use it. It reports false
// when there is no marker.
func (s *BackupGrantStore) Consume(ctx context.Context, tenantID, userID string) (bool, error) {
	n, err := s.redis.Del(ctx, s.key(tenantID, userID)).Result()
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrBackupGrantBackend, err)
	}
	return n == 1, nil
}

// Revoke removes the marker, if any.
func (s *BackupGrantStore) Revoke(ctx context.Context, tenantID, userID string) error {
	if err := s.redis.Del(ctx, s.key(tenantID, userID)).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrBackupGrantBackend, err)
	}
	return nil
}
