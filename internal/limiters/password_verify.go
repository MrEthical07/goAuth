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

// PasswordVerifyLimiter rate-limits password-verification attempts for a
// user, independent of and never triggering account auto-lockout: a caller
// holding only a stolen access token must not be able to lock the real
// owner out of login by exhausting this limiter.
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

// Reserve atomically claims one verification attempt before Argon2 runs, so
// a burst of concurrent requests can never run more verifications than
// maxAttempts within the window: a plain "read the count, then verify, then
// record on failure" sequence leaves a check-then-verify race where every
// concurrent caller can observe a count below the limit before any of them
// records an attempt, letting an arbitrarily large concurrent burst bypass
// the limit entirely. Reserving the slot with a single atomic INCR before
// verification closes that race -- only the first maxAttempts reservations
// within the window are ever allowed to proceed to Argon2, whatever the
// concurrency. It returns ErrPasswordVerifyRateLimited, without letting the
// caller proceed to verification, once the claim would exceed maxAttempts.
func (l *PasswordVerifyLimiter) Reserve(ctx context.Context, tenantID, userID string) error {
	count, err := l.window.Incr(ctx, l.key(tenantID, userID), l.cooldown)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPasswordVerifyUnavailable, err)
	}
	if count > l.maxAttempts {
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
