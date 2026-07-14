package limiters

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/MrEthical07/goAuth/internal/window"
	"github.com/redis/go-redis/v9"
)

// LockoutConfig holds configuration for the automatic account lockout limiter.
type LockoutConfig struct {
	Enabled   bool
	Threshold int
	Duration  time.Duration // 0 = manual unlock only
	// WindowMode selects the counting algorithm (zero value = fixed window).
	// With Duration = 0 the counter never expires regardless of mode.
	WindowMode window.Mode
}

var (
	// ErrLockoutUnavailable indicates the lockout backend is unreachable.
	ErrLockoutUnavailable = errors.New("lockout backend unavailable")
)

// LockoutLimiter tracks persistent failed login attempts and triggers
// account lockout when the configured threshold is reached.
type LockoutLimiter struct {
	window *window.Window
	config LockoutConfig
}

// NewLockoutLimiter creates a new lockout limiter.
func NewLockoutLimiter(redisClient redis.UniversalClient, cfg LockoutConfig) *LockoutLimiter {
	return &LockoutLimiter{window: window.New(redisClient, cfg.WindowMode), config: cfg}
}

func (l *LockoutLimiter) key(tenantID, userID string) string {
	return "rl:lockout:" + tenantID + ":" + userID
}

// RecordFailure increments the failure counter for a user.
// Returns true if the threshold has been reached (caller should lock the account).
func (l *LockoutLimiter) RecordFailure(ctx context.Context, tenantID, userID string) (bool, error) {
	if !l.config.Enabled || userID == "" {
		return false, nil
	}

	// Duration acts as a rolling window for counting failures; zero means the
	// counter never expires (manual unlock only) — the window primitive falls
	// back to a plain INCR in that case.
	count, err := l.window.Incr(ctx, l.key(tenantID, userID), l.config.Duration)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrLockoutUnavailable, err)
	}

	return count >= int64(l.config.Threshold), nil
}

// Reset clears the failure counter for a user (e.g., after successful login or manual unlock).
func (l *LockoutLimiter) Reset(ctx context.Context, tenantID, userID string) error {
	if !l.config.Enabled || userID == "" {
		return nil
	}

	if err := l.window.Reset(ctx, l.key(tenantID, userID), l.config.Duration); err != nil {
		return fmt.Errorf("%w: %v", ErrLockoutUnavailable, err)
	}
	return nil
}

// GetFailureCount returns the current failure count for a user.
func (l *LockoutLimiter) GetFailureCount(ctx context.Context, tenantID, userID string) (int, error) {
	if !l.config.Enabled || userID == "" {
		return 0, nil
	}

	count, err := l.window.Count(ctx, l.key(tenantID, userID), l.config.Duration)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrLockoutUnavailable, err)
	}
	return int(count), nil
}
