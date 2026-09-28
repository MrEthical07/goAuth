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
	defaultPasswordVerifyMaxAttempts = 5
	defaultPasswordVerifyCooldown    = 15 * time.Minute
)

var (
	ErrPasswordVerifyRateLimited = errors.New("password verify rate limited")
	ErrPasswordVerifyUnavailable = errors.New("password verify limiter unavailable")
)

// PasswordVerifyConfig holds configurable thresholds for the password-verify
// rate limiter shared by Engine.ChangePassword (old-password check) and
// Engine.VerifyPassword. Callers are expected to pass
// Security.MaxLoginAttempts / Security.LoginCooldownDuration rather than
// introduce a dedicated config surface.
type PasswordVerifyConfig struct {
	MaxAttempts int
	Cooldown    time.Duration
	// WindowMode selects the counting algorithm (zero value = fixed window).
	WindowMode window.Mode
}

// PasswordVerifyLimiter rate-limits repeated password-verification failures
// for a user, independent of and never triggering account auto-lockout: a
// caller holding only a stolen access token must not be able to lock the
// real owner out of login by exhausting this limiter.
type PasswordVerifyLimiter struct {
	window      *window.Window
	maxAttempts int64
	cooldown    time.Duration
}

// NewPasswordVerifyLimiter creates a password-verify rate limiter. Zero-value
// fields in cfg fall back to defaults (5 attempts / 15m).
func NewPasswordVerifyLimiter(redisClient redis.UniversalClient, cfg PasswordVerifyConfig) *PasswordVerifyLimiter {
	max := cfg.MaxAttempts
	if max <= 0 {
		max = defaultPasswordVerifyMaxAttempts
	}
	cd := cfg.Cooldown
	if cd <= 0 {
		cd = defaultPasswordVerifyCooldown
	}
	return &PasswordVerifyLimiter{
		window:      window.New(redisClient, cfg.WindowMode),
		maxAttempts: int64(max),
		cooldown:    cd,
	}
}

// key uses its own rl:pwdverify:* namespace, distinct from the login failure
// limiter (rl:login:fail:*) and the auto-lockout limiter, so exhausting it
// never touches either.
func (l *PasswordVerifyLimiter) key(tenantID, userID string) string {
	return "rl:pwdverify:fail:" + tenantID + ":" + userID
}

// Check reports whether the caller is currently rate-limited, without
// recording an attempt. Callers must check before running Argon2, so a
// rate-limited caller costs no verification CPU.
func (l *PasswordVerifyLimiter) Check(ctx context.Context, tenantID, userID string) error {
	count, err := l.window.Count(ctx, l.key(tenantID, userID), l.cooldown)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPasswordVerifyUnavailable, err)
	}
	if count >= l.maxAttempts {
		return ErrPasswordVerifyRateLimited
	}
	return nil
}

func (l *PasswordVerifyLimiter) RecordFailure(ctx context.Context, tenantID, userID string) error {
	count, err := l.window.Incr(ctx, l.key(tenantID, userID), l.cooldown)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPasswordVerifyUnavailable, err)
	}
	if count >= l.maxAttempts {
		return ErrPasswordVerifyRateLimited
	}
	return nil
}

func (l *PasswordVerifyLimiter) Reset(ctx context.Context, tenantID, userID string) error {
	if err := l.window.Reset(ctx, l.key(tenantID, userID), l.cooldown); err != nil {
		return fmt.Errorf("%w: %v", ErrPasswordVerifyUnavailable, err)
	}
	return nil
}
