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
	// WindowMode selects the counting algorithm (zero value = fixed window).
	WindowMode window.Mode
}

type TOTPLimiter struct {
	window      *window.Window
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
	return &TOTPLimiter{
		window:      window.New(redisClient, cfg.WindowMode),
		maxAttempts: int64(max),
		cooldown:    cd,
	}
}

func (l *TOTPLimiter) key(tenantID, userID string) string {
	return "rl:totp:fail:" + tenantID + ":" + userID
}

func (l *TOTPLimiter) Check(ctx context.Context, tenantID, userID string) error {
	count, err := l.window.Count(ctx, l.key(tenantID, userID), l.cooldown)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTOTPUnavailable, err)
	}
	if count >= l.maxAttempts {
		return ErrTOTPRateLimited
	}
	return nil
}

func (l *TOTPLimiter) RecordFailure(ctx context.Context, tenantID, userID string) error {
	count, err := l.window.Incr(ctx, l.key(tenantID, userID), l.cooldown)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTOTPUnavailable, err)
	}
	if count >= l.maxAttempts {
		return ErrTOTPRateLimited
	}
	return nil
}

func (l *TOTPLimiter) Reset(ctx context.Context, tenantID, userID string) error {
	if err := l.window.Reset(ctx, l.key(tenantID, userID), l.cooldown); err != nil {
		return fmt.Errorf("%w: %v", ErrTOTPUnavailable, err)
	}
	return nil
}
