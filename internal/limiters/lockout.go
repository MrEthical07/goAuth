package limiters

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// LockoutConfig holds configuration for the automatic account lockout limiter.
type LockoutConfig struct {
	Enabled   bool
	Threshold int
	Duration  time.Duration // 0 = manual unlock only
}

var (
	// ErrLockoutUnavailable indicates the lockout backend is unreachable.
	ErrLockoutUnavailable = errors.New("lockout backend unavailable")
)

// LockoutLimiter tracks persistent failed login attempts and triggers
// account lockout when the configured threshold is reached.
type LockoutLimiter struct {
	redis  redis.UniversalClient
	config LockoutConfig
}

// NewLockoutLimiter creates a new lockout limiter.
func NewLockoutLimiter(redisClient redis.UniversalClient, cfg LockoutConfig) *LockoutLimiter {
	return &LockoutLimiter{redis: redisClient, config: cfg}
}

func (l *LockoutLimiter) key(userID string) string {
	return "alo:" + userID
}

// RecordFailure increments the failure counter for a user.
// Returns true if the threshold has been reached (caller should lock the account).
func (l *LockoutLimiter) RecordFailure(ctx context.Context, userID string) (bool, error) {
	if !l.config.Enabled || userID == "" {
		return false, nil
	}

	count, err := l.redis.Incr(ctx, l.key(userID)).Result()
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrLockoutUnavailable, err)
	}

	if count == 1 && l.config.Duration > 0 {
		// Set TTL on first failure so counter auto-resets after lockout duration.
		// This acts as a rolling window for counting failures.
		if err := l.redis.Expire(ctx, l.key(userID), l.config.Duration).Err(); err != nil {
			return false, fmt.Errorf("%w: %v", ErrLockoutUnavailable, err)
		}
	}

	return count >= int64(l.config.Threshold), nil
}

// Reset clears the failure counter for a user (e.g., after successful login or manual unlock).
func (l *LockoutLimiter) Reset(ctx context.Context, userID string) error {
	if !l.config.Enabled || userID == "" {
		return nil
	}

	if err := l.redis.Del(ctx, l.key(userID)).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrLockoutUnavailable, err)
	}
	return nil
}

// GetFailureCount returns the current failure count for a user.
func (l *LockoutLimiter) GetFailureCount(ctx context.Context, userID string) (int, error) {
	if !l.config.Enabled || userID == "" {
		return 0, nil
	}

	count, err := l.redis.Get(ctx, l.key(userID)).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, fmt.Errorf("%w: %v", ErrLockoutUnavailable, err)
	}
	return int(count), nil
}
