package limiters

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrBackupCodeRateLimited = errors.New("backup code rate limited")
	ErrBackupCodeUnavailable = errors.New("backup code unavailable")
)

type BackupCodeConfig struct {
	MaxAttempts int
	Cooldown    time.Duration
}

type BackupCodeLimiter struct {
	redis       redis.UniversalClient
	maxAttempts int
	cooldown    time.Duration
}

func NewBackupCodeLimiter(redisClient redis.UniversalClient, cfg BackupCodeConfig) *BackupCodeLimiter {
	return &BackupCodeLimiter{
		redis:       redisClient,
		maxAttempts: cfg.MaxAttempts,
		cooldown:    cfg.Cooldown,
	}
}

func (l *BackupCodeLimiter) key(tenantID, userID string) string {
	return "abk:" + normalizeTenantID(tenantID) + ":" + userID
}

func (l *BackupCodeLimiter) Check(ctx context.Context, tenantID, userID string) error {
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
		return ErrBackupCodeRateLimited
	}
	return nil
}

func (l *BackupCodeLimiter) RecordFailure(ctx context.Context, tenantID, userID string) error {
	if l == nil || l.redis == nil {
		return nil
	}
	count, err := l.redis.Incr(ctx, l.key(tenantID, userID)).Result()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBackupCodeUnavailable, err)
	}
	if count == 1 {
		if err := l.redis.Expire(ctx, l.key(tenantID, userID), l.cooldown).Err(); err != nil {
			return fmt.Errorf("%w: %v", ErrBackupCodeUnavailable, err)
		}
	}
	if int(count) >= l.maxAttempts {
		return ErrBackupCodeRateLimited
	}
	return nil
}

func (l *BackupCodeLimiter) Reset(ctx context.Context, tenantID, userID string) error {
	if l == nil || l.redis == nil {
		return nil
	}
	if err := l.redis.Del(ctx, l.key(tenantID, userID)).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrBackupCodeUnavailable, err)
	}
	return nil
}
