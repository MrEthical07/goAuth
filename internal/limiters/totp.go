package limiters

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	defaultTOTPMaxAttempts = 5
	defaultTOTPCooldown    = time.Minute
)

var (
	ErrTOTPRateLimited = errors.New("totp rate limited")
	ErrTOTPUnavailable = errors.New("totp unavailable")
)

// TOTPLimiterConfig holds configurable thresholds for the TOTP rate limiter.
type TOTPLimiterConfig struct {
	MaxAttempts int
	Cooldown    time.Duration
}

type TOTPLimiter struct {
	redis       redis.UniversalClient
	maxAttempts int64
	cooldown    time.Duration
}

// NewTOTPLimiter creates a TOTP rate limiter. Zero-value fields in cfg
// fall back to defaults (5 attempts / 60s).
func NewTOTPLimiter(redisClient redis.UniversalClient, cfg TOTPLimiterConfig) *TOTPLimiter {
	max := cfg.MaxAttempts
	if max <= 0 {
		max = defaultTOTPMaxAttempts
	}
	cd := cfg.Cooldown
	if cd <= 0 {
		cd = defaultTOTPCooldown
	}
	return &TOTPLimiter{redis: redisClient, maxAttempts: int64(max), cooldown: cd}
}

func (l *TOTPLimiter) key(userID string) string {
	return "att:" + userID
}

func (l *TOTPLimiter) Check(ctx context.Context, userID string) error {
	count, err := l.redis.Get(ctx, l.key(userID)).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil
		}
		return fmt.Errorf("%w: %v", ErrTOTPUnavailable, err)
	}
	if count >= l.maxAttempts {
		return ErrTOTPRateLimited
	}
	return nil
}

func (l *TOTPLimiter) RecordFailure(ctx context.Context, userID string) error {
	count, err := l.redis.Incr(ctx, l.key(userID)).Result()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTOTPUnavailable, err)
	}
	if count == 1 {
		if err := l.redis.Expire(ctx, l.key(userID), l.cooldown).Err(); err != nil {
			return fmt.Errorf("%w: %v", ErrTOTPUnavailable, err)
		}
	}
	if count >= l.maxAttempts {
		return ErrTOTPRateLimited
	}
	return nil
}

func (l *TOTPLimiter) Reset(ctx context.Context, userID string) error {
	if err := l.redis.Del(ctx, l.key(userID)).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrTOTPUnavailable, err)
	}
	return nil
}
