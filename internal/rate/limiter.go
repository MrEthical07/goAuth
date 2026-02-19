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
	EnableIPThrottle        bool
	EnableRefreshThrottle   bool
	MaxLoginAttempts        int
	LoginCooldownDuration   time.Duration
	MaxRefreshAttempts      int
	RefreshCooldownDuration time.Duration
}

// Limiter enforces per-identifier and per-IP rate limits for login
// and refresh operations using Redis counters.
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

// CheckLogin checks whether the identifier+IP pair is within
// the login attempt budget. Returns an error if rate-limited.
func (l *Limiter) CheckLogin(ctx context.Context, username, ip string) error {
	if err := l.checkCounter(ctx, loginUserKey(username), l.config.MaxLoginAttempts); err != nil {
		return err
	}

	if l.config.EnableIPThrottle && ip != "" {
		if err := l.checkCounter(ctx, loginIPKey(ip), l.config.MaxLoginAttempts); err != nil {
			return err
		}
	}

	return nil
}

// IncrementLogin records a failed login attempt for the identifier+IP pair.
func (l *Limiter) IncrementLogin(ctx context.Context, username, ip string) error {
	count, err := l.incrementWithTTL(ctx, loginUserKey(username), l.config.LoginCooldownDuration)
	if err != nil {
		return err
	}
	if count > int64(l.config.MaxLoginAttempts) {
		return ErrRateLimited
	}

	if l.config.EnableIPThrottle && ip != "" {
		count, err = l.incrementWithTTL(ctx, loginIPKey(ip), l.config.LoginCooldownDuration)
		if err != nil {
			return err
		}
		if count > int64(l.config.MaxLoginAttempts) {
			return ErrRateLimited
		}
	}

	return nil
}

// ResetLogin clears the failed-login counter for the identifier+IP pair.
// Called after successful login or password change.
func (l *Limiter) ResetLogin(ctx context.Context, username, ip string) error {
	keys := []string{loginUserKey(username)}
	if l.config.EnableIPThrottle && ip != "" {
		keys = append(keys, loginIPKey(ip))
	}

	if err := l.redis.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	return nil
}

// CheckRefresh enforces the refresh limit by incrementing the counter and applying cooldown TTL.
func (l *Limiter) CheckRefresh(ctx context.Context, sessionID string) error {
	if !l.config.EnableRefreshThrottle {
		return nil
	}

	count, err := l.incrementWithTTL(ctx, refreshKey(sessionID), l.config.RefreshCooldownDuration)
	if err != nil {
		return err
	}
	if count > int64(l.config.MaxRefreshAttempts) {
		return ErrRateLimited
	}

	return nil
}

// IncrementRefresh records a refresh attempt for the session.
// Returns an error if the refresh rate limit is exceeded.
func (l *Limiter) IncrementRefresh(ctx context.Context, sessionID string) error {
	if !l.config.EnableRefreshThrottle {
		return nil
	}

	_, err := l.incrementWithTTL(ctx, refreshKey(sessionID), l.config.RefreshCooldownDuration)
	return err
}

// GetLoginAttempts returns the current attempt counter for an identifier.
// Missing keys return zero and do not reveal account existence.
func (l *Limiter) GetLoginAttempts(ctx context.Context, username string) (int, error) {
	count, err := l.redis.Get(ctx, loginUserKey(username)).Int64()
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
