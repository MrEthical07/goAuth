package limiters

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/MrEthical07/goAuth/internal/window"
	"github.com/redis/go-redis/v9"
)

const (
	defaultEmailChangeMaxAttempts = 5
	defaultEmailChangeCooldown    = time.Hour
)

var (
	ErrEmailChangeRateLimited = errors.New("email change rate limited")
	ErrEmailChangeUnavailable = errors.New("email change limiter unavailable")
)

// EmailChangeConfig holds the thresholds for the email-change request limiter.
type EmailChangeConfig struct {
	MaxAttempts int
	Cooldown    time.Duration
	// WindowMode selects the counting algorithm (zero value = fixed window).
	WindowMode window.Mode
}

// EmailChangeLimiter rate-limits email-change requests per (tenant, user), so
// one account cannot be used to mail codes to arbitrary addresses.
type EmailChangeLimiter struct {
	window      *window.Window
	maxAttempts int64
	cooldown    time.Duration
}

// NewEmailChangeLimiter creates an email-change request limiter. Zero-value
// fields in cfg fall back to defaults (5 requests / 1h).
func NewEmailChangeLimiter(redisClient redis.UniversalClient, cfg EmailChangeConfig) *EmailChangeLimiter {
	max := cfg.MaxAttempts
	if max <= 0 {
		max = defaultEmailChangeMaxAttempts
	}
	cd := cfg.Cooldown
	if cd <= 0 {
		cd = defaultEmailChangeCooldown
	}
	return &EmailChangeLimiter{
		window:      window.New(redisClient, cfg.WindowMode),
		maxAttempts: int64(max),
		cooldown:    cd,
	}
}

// key uses its own rl:emailchange:* namespace, distinct from every other
// limiter.
func (l *EmailChangeLimiter) key(tenantID, userID string) string {
	return "rl:emailchange:" + tenantID + ":" + userID
}

// Reserve atomically claims one request slot. It returns
// ErrEmailChangeRateLimited once the claim would exceed the budget.
func (l *EmailChangeLimiter) Reserve(ctx context.Context, tenantID, userID string) error {
	count, err := l.window.Incr(ctx, l.key(tenantID, userID), l.cooldown)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEmailChangeUnavailable, err)
	}
	if count > l.maxAttempts {
		return ErrEmailChangeRateLimited
	}
	return nil
}
