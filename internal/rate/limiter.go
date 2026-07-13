package rate

import (
	"context"
	"fmt"
	"time"

	"github.com/MrEthical07/goAuth/internal/window"
	"github.com/redis/go-redis/v9"
)

// Config holds rate limiter tuning parameters.
type Config struct {
	EnableLoginFailureLimiter bool
	MaxLoginAttempts          int
	LoginCooldownDuration     time.Duration
	// WindowMode selects the counting algorithm (zero value = fixed window).
	WindowMode window.Mode
}

// Limiter enforces identifier-scoped login failure limits using Redis counters.
type Limiter struct {
	window *window.Window
	config Config
}

// New creates a rate [Limiter] backed by the given Redis client.
func New(redisClient redis.UniversalClient, cfg Config) *Limiter {
	return &Limiter{
		window: window.New(redisClient, cfg.WindowMode),
		config: cfg,
	}
}

// CheckLogin checks whether the identifier is within the login attempt budget.
// Returns an error if rate-limited.
func (l *Limiter) CheckLogin(ctx context.Context, tenantID, identifier string) error {
	if !l.config.EnableLoginFailureLimiter {
		return nil
	}

	count, err := l.window.Count(ctx, loginUserKey(tenantID, identifier), l.config.LoginCooldownDuration)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	if count > int64(l.config.MaxLoginAttempts) {
		return ErrRateLimited
	}

	return nil
}

// IncrementLogin records a failed login attempt for the identifier.
func (l *Limiter) IncrementLogin(ctx context.Context, tenantID, identifier string) error {
	if !l.config.EnableLoginFailureLimiter {
		return nil
	}

	count, err := l.window.Incr(ctx, loginUserKey(tenantID, identifier), l.config.LoginCooldownDuration)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
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

	if err := l.window.Reset(ctx, loginUserKey(tenantID, identifier), l.config.LoginCooldownDuration); err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	return nil
}

// GetLoginAttempts returns the current attempt counter for an identifier.
// Missing keys return zero and do not reveal account existence. In sliding
// mode this is the weighted count over the current window.
func (l *Limiter) GetLoginAttempts(ctx context.Context, tenantID, identifier string) (int, error) {
	count, err := l.window.Count(ctx, loginUserKey(tenantID, identifier), l.config.LoginCooldownDuration)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	if count < 0 {
		return 0, nil
	}
	return int(count), nil
}
