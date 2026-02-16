package limiters

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	totpMaxAttempts = 5
	totpCooldown    = time.Minute
)

var (
	ErrTOTPRateLimited = errors.New("totp rate limited")
	ErrTOTPUnavailable = errors.New("totp unavailable")
)

type TOTPLimiter struct {
	redis redis.UniversalClient
}

func NewTOTPLimiter(redisClient redis.UniversalClient) *TOTPLimiter {
	return &TOTPLimiter{redis: redisClient}
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
	if count >= totpMaxAttempts {
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
		if err := l.redis.Expire(ctx, l.key(userID), totpCooldown).Err(); err != nil {
			return fmt.Errorf("%w: %v", ErrTOTPUnavailable, err)
		}
	}
	if count >= totpMaxAttempts {
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
