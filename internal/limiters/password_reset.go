package limiters

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrResetRateLimited      = errors.New("reset rate limited")
	ErrResetRedisUnavailable = errors.New("reset redis unavailable")
)

type PasswordResetConfig struct {
	EnableRequestLimiter        bool
	EnableConfirmFailureLimiter bool
	ResetTTL                    time.Duration
	MaxAttempts                 int
}

type PasswordResetLimiter struct {
	redis  redis.UniversalClient
	config PasswordResetConfig
}

func NewPasswordResetLimiter(redisClient redis.UniversalClient, cfg PasswordResetConfig) *PasswordResetLimiter {
	return &PasswordResetLimiter{
		redis:  redisClient,
		config: cfg,
	}
}

func (l *PasswordResetLimiter) CheckRequest(ctx context.Context, tenantID, identifier string) error {
	if !l.config.EnableRequestLimiter || identifier == "" {
		return nil
	}
	if err := l.enforceFixedWindow(ctx, requestIdentifierKey(tenantID, identifier)); err != nil {
		return err
	}
	return nil
}

func (l *PasswordResetLimiter) CheckConfirm(ctx context.Context, tenantID, resetID string) error {
	if !l.config.EnableConfirmFailureLimiter || resetID == "" {
		return nil
	}
	if err := l.enforceFixedWindow(ctx, confirmIdentifierKey(tenantID, resetID)); err != nil {
		return err
	}
	return nil
}

func (l *PasswordResetLimiter) Cooldown() time.Duration {
	return l.config.ResetTTL
}

func (l *PasswordResetLimiter) enforceFixedWindow(ctx context.Context, key string) error {
	count, err := l.redis.Incr(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrResetRedisUnavailable, err)
	}

	if count == 1 {
		if err := l.redis.Expire(ctx, key, l.config.ResetTTL).Err(); err != nil {
			return fmt.Errorf("%w: %v", ErrResetRedisUnavailable, err)
		}
	}

	if count > int64(l.config.MaxAttempts) {
		return ErrResetRateLimited
	}

	return nil
}

func requestIdentifierKey(tenantID, identifier string) string {
	return "rl:reset:req:" + tenantID + ":" + identifier
}

func confirmIdentifierKey(tenantID, resetID string) string {
	return "rl:reset:confirm:fail:" + tenantID + ":" + resetID
}
