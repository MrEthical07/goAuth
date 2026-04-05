package rate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Config holds rate limiter tuning parameters.
type Config struct {
	EnableLoginFailureLimiter bool
	MaxLoginAttempts          int
	LoginCooldownDuration     time.Duration
}

// Limiter enforces identifier-scoped login failure limits using Redis counters.
type Limiter struct {
	redis  redis.UniversalClient
	config Config
}

// New creates a rate [Limiter] backed by the given Redis client.
func New(redisClient redis.UniversalClient, cfg Config) *Limiter {
	return &Limiter{
		redis:  redisClient,
		config: cfg,
	}
}

// CheckLogin checks whether the identifier is within the login attempt budget.
// Returns an error if rate-limited.
func (l *Limiter) CheckLogin(ctx context.Context, tenantID, identifier string) error {
	if !l.config.EnableLoginFailureLimiter {
		return nil
	}

	if err := l.checkCounter(ctx, loginUserKey(tenantID, identifier), l.config.MaxLoginAttempts); err != nil {
		return err
	}

	return nil
}

// IncrementLogin records a failed login attempt for the identifier.
func (l *Limiter) IncrementLogin(ctx context.Context, tenantID, identifier string) error {
	if !l.config.EnableLoginFailureLimiter {
		return nil
	}

	count, err := l.incrementWithTTL(ctx, loginUserKey(tenantID, identifier), l.config.LoginCooldownDuration)
	if err != nil {
		return err
	}
	if count > int64(l.config.MaxLoginAttempts) {
		return ErrRateLimited
	}

	return nil
}

// ResetLogin clears the failed-login counter for the identifier.
// Called after successful login or password change.
func (l *Limiter) ResetLogin(ctx context.Context, tenantID, identifier string) error {
	if !l.config.EnableLoginFailureLimiter {
		return nil
	}

	if err := l.redis.Del(ctx, loginUserKey(tenantID, identifier)).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	return nil
}

// GetLoginAttempts returns the current attempt counter for an identifier.
// Missing keys return zero and do not reveal account existence.
func (l *Limiter) GetLoginAttempts(ctx context.Context, tenantID, identifier string) (int, error) {
	count, err := l.redis.Get(ctx, loginUserKey(tenantID, identifier)).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	if count < 0 {
		return 0, nil
	}
	return int(count), nil
}

func (l *Limiter) checkCounter(ctx context.Context, key string, maxAttempts int) error {
	count, err := l.redis.Get(ctx, key).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil
		}
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	if count > int64(maxAttempts) {
		return ErrRateLimited
	}

	return nil
}

func (l *Limiter) incrementWithTTL(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	count, err := l.redis.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	// Fixed-window semantics: set TTL only for the first hit in the window.
	if count == 1 {
		if err := l.redis.Expire(ctx, key, ttl).Err(); err != nil {
			return 0, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
		}
	}

	return count, nil
}
