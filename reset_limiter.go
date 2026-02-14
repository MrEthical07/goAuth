package goAuth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var errResetRateLimited = errors.New("reset rate limited")

type passwordResetLimiter struct {
	redis  *redis.Client
	config PasswordResetConfig
}

func newPasswordResetLimiter(redisClient *redis.Client, cfg PasswordResetConfig) *passwordResetLimiter {
	return &passwordResetLimiter{
		redis:  redisClient,
		config: cfg,
	}
}

func (l *passwordResetLimiter) CheckRequest(ctx context.Context, tenantID, identifier, ip string) error {
	if l.config.EnableIdentifierThrottle {
		if err := l.enforceFixedWindow(ctx, requestIdentifierKey(tenantID, identifier)); err != nil {
			return err
		}
	}
	if l.config.EnableIPThrottle && ip != "" {
		if err := l.enforceFixedWindow(ctx, requestIPKey(tenantID, ip)); err != nil {
			return err
		}
	}
	return nil
}

func (l *passwordResetLimiter) CheckConfirm(ctx context.Context, tenantID, resetID, ip string) error {
	if l.config.EnableIdentifierThrottle {
		if err := l.enforceFixedWindow(ctx, confirmIdentifierKey(tenantID, resetID)); err != nil {
			return err
		}
	}
	if l.config.EnableIPThrottle && ip != "" {
		if err := l.enforceFixedWindow(ctx, confirmIPKey(tenantID, ip)); err != nil {
			return err
		}
	}
	return nil
}

func (l *passwordResetLimiter) enforceFixedWindow(ctx context.Context, key string) error {
	count, err := l.redis.Incr(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("%w: %v", errResetRedisUnavailable, err)
	}

	if count == 1 {
		if err := l.redis.Expire(ctx, key, l.config.ResetTTL).Err(); err != nil {
			return fmt.Errorf("%w: %v", errResetRedisUnavailable, err)
		}
	}

	if count > int64(l.config.MaxAttempts) {
		return errResetRateLimited
	}

	return nil
}

func requestIdentifierKey(tenantID, identifier string) string {
	return "apri:" + normalizeResetTenantID(tenantID) + ":" + identifier
}

func requestIPKey(tenantID, ip string) string {
	return "aprip:" + normalizeResetTenantID(tenantID) + ":" + ip
}

func confirmIdentifierKey(tenantID, resetID string) string {
	return "aprc:" + normalizeResetTenantID(tenantID) + ":" + resetID
}

func confirmIPKey(tenantID, ip string) string {
	return "aprcip:" + normalizeResetTenantID(tenantID) + ":" + ip
}

func (l *passwordResetLimiter) Cooldown() time.Duration {
	return l.config.ResetTTL
}
