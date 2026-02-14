package goAuth

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

var errTOTPRateLimited = errors.New("totp rate limited")

type totpLimiter struct {
	redis *redis.Client
}

func newTOTPLimiter(redisClient *redis.Client) *totpLimiter {
	return &totpLimiter{redis: redisClient}
}

func (l *totpLimiter) key(userID string) string {
	return "att:" + userID
}

func (l *totpLimiter) Check(ctx context.Context, userID string) error {
	count, err := l.redis.Get(ctx, l.key(userID)).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil
		}
		return fmt.Errorf("%w: %v", ErrTOTPUnavailable, err)
	}
	if count >= totpMaxAttempts {
		return errTOTPRateLimited
	}
	return nil
}

func (l *totpLimiter) RecordFailure(ctx context.Context, userID string) error {
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
		return errTOTPRateLimited
	}
	return nil
}

func (l *totpLimiter) Reset(ctx context.Context, userID string) error {
	if err := l.redis.Del(ctx, l.key(userID)).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrTOTPUnavailable, err)
	}
	return nil
}
