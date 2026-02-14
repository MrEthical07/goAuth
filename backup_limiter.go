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

func (l *backupCodeLimiter) Reset(ctx context.Context, tenantID, userID string) error {
	if l == nil || l.redis == nil {
		return nil
	}
	if err := l.redis.Del(ctx, l.key(tenantID, userID)).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrBackupCodeUnavailable, err)
	}
	return nil
}
