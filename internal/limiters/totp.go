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

// Check reports whether the budget is spent without claiming anything. Code
// verification uses Reserve; this is for the paths that refuse a request
// before any code is evaluated.
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

// Reserve atomically claims one attempt before the code is evaluated, so a
// burst of concurrent requests can never evaluate more than maxAttempts codes
// per window: reading the count, evaluating and recording the failure
// afterwards lets every request in flight see a count below the limit. It
// returns ErrTOTPRateLimited, without letting the caller evaluate anything,
// once the budget is spent. last reports that the claim took the final slot,
// so a wrong code must be reported as rate limited, as the failure that fills
// the budget always was. A good code clears the budget with Reset.
func (l *TOTPLimiter) Reserve(ctx context.Context, tenantID, userID string) (last bool, err error) {
	count, ok, err := l.window.Reserve(ctx, l.key(tenantID, userID), l.cooldown, l.maxAttempts)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrTOTPUnavailable, err)
	}
	if !ok {
		return false, ErrTOTPRateLimited
	}
	return count >= l.maxAttempts, nil
}

// Release gives back a slot claimed with Reserve for an attempt that was not a
// wrong guess (a replayed code, a provider failure).
func (l *TOTPLimiter) Release(ctx context.Context, tenantID, userID string) error {
	if err := l.window.Release(ctx, l.key(tenantID, userID), l.cooldown); err != nil {
		return fmt.Errorf("%w: %v", ErrTOTPUnavailable, err)
	}
	return nil
}

func (l *TOTPLimiter) Reset(ctx context.Context, tenantID, userID string) error {
	if err := l.window.Reset(ctx, l.key(tenantID, userID), l.cooldown); err != nil {
		return fmt.Errorf("%w: %v", ErrTOTPUnavailable, err)
	}
	return nil
}
