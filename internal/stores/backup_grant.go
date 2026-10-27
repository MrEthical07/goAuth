package stores

import (
	"context"
	"errors"
	"fmt"
	"strconv"
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

// Grant records the marker for ttl, replacing an earlier one. epoch is the
// user's revocation epoch at that moment: the marker is only good while no
// revocation of the user's sessions has moved it since.
func (s *BackupGrantStore) Grant(ctx context.Context, tenantID, userID string, epoch int64, ttl time.Duration) error {
	if err := s.redis.Set(ctx, s.key(tenantID, userID), strconv.FormatInt(epoch, 10), ttl).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrBackupGrantBackend, err)
	}
	return nil
}

// consumeGrantScript deletes the marker and reports whether it existed and held
// the given epoch, in one step, so two concurrent generations cannot both use it.
var consumeGrantScript = redis.NewScript(`
local held = redis.call("GET", KEYS[1])
if not held then
  return 0
end
redis.call("DEL", KEYS[1])
if held == ARGV[1] then
  return 1
end
return 0
`)

// Consume uses the marker up. It reports false when there is none or when it was
// granted under another epoch (the user's sessions were revoked since); either
// way the marker is gone afterwards.
func (s *BackupGrantStore) Consume(ctx context.Context, tenantID, userID string, epoch int64) (bool, error) {
	n, err := consumeGrantScript.Run(ctx, s.redis, []string{s.key(tenantID, userID)}, strconv.FormatInt(epoch, 10)).Int()
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
