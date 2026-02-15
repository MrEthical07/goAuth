package goAuth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var errBackupCodeRateLimited = errors.New("backup code rate limited")

type backupCodeLimiter struct {
	redis       *redis.Client
	maxAttempts int
	cooldown    int64
}

func newBackupCodeLimiter(redisClient *redis.Client, cfg TOTPConfig) *backupCodeLimiter {
	return &backupCodeLimiter{
		redis:       redisClient,
		maxAttempts: cfg.BackupCodeMaxAttempts,
		cooldown:    int64(cfg.BackupCodeCooldown.Seconds()),
	}
}

func (l *backupCodeLimiter) key(tenantID, userID string) string {
	if tenantID == "" {
		tenantID = "0"
	}
	return "abk:" + tenantID + ":" + userID
}

// Check describes the check operation and its observable behavior.
//
// Check may return an error when input validation, dependency calls, or security checks fail.
// Check does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (l *backupCodeLimiter) Check(ctx context.Context, tenantID, userID string) error {
	if l == nil || l.redis == nil {
		return nil
	}
	count, err := l.redis.Get(ctx, l.key(tenantID, userID)).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil
		}
		return fmt.Errorf("%w: %v", ErrBackupCodeUnavailable, err)
	}
	if int(count) >= l.maxAttempts {
		return errBackupCodeRateLimited
	}
	return nil
}

// RecordFailure describes the recordfailure operation and its observable behavior.
//
// RecordFailure may return an error when input validation, dependency calls, or security checks fail.
// RecordFailure does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (l *backupCodeLimiter) RecordFailure(ctx context.Context, tenantID, userID string) error {
	if l == nil || l.redis == nil {
		return nil
	}
	count, err := l.redis.Incr(ctx, l.key(tenantID, userID)).Result()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBackupCodeUnavailable, err)
	}
	if count == 1 {
		if err := l.redis.Expire(ctx, l.key(tenantID, userID), time.Duration(l.cooldown)*time.Second).Err(); err != nil {
			return fmt.Errorf("%w: %v", ErrBackupCodeUnavailable, err)
		}
	}
	if int(count) >= l.maxAttempts {
		return errBackupCodeRateLimited
	}
	return nil
}

// Reset describes the reset operation and its observable behavior.
//
// Reset may return an error when input validation, dependency calls, or security checks fail.
// Reset does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (l *backupCodeLimiter) Reset(ctx context.Context, tenantID, userID string) error {
	if l == nil || l.redis == nil {
		return nil
	}
	if err := l.redis.Del(ctx, l.key(tenantID, userID)).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrBackupCodeUnavailable, err)
	}
	return nil
}
