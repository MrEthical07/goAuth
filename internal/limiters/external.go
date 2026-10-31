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
	defaultExternalMaxAttempts = 10
	defaultExternalCooldown    = 15 * time.Minute
)

var (
	ErrExternalRateLimited = errors.New("external login rate limited")
	ErrExternalUnavailable = errors.New("external login limiter unavailable")
)

// ExternalConfig holds the thresholds for the external-login limiter.
type ExternalConfig struct {
	MaxAttempts int
	Cooldown    time.Duration
	// WindowMode selects the counting algorithm (zero value = fixed window).
	WindowMode window.Mode
	// Now is the time source for the sliding window's buckets (nil = wall clock).
	Now func() time.Time
}

// ExternalLimiter rate-limits external (third-party) sign-in attempts in two
// stages, both with the same budget:
//
//   - before the token is verified, per (tenant, client IP), so a flood of
//     junk tokens from one source costs no further signature verification;
//   - after verification, per (tenant, provider, subject), so one external
//     identity cannot be used to probe account resolution without bound.
//
// There is deliberately no pre-verification bucket for a request whose IP is
// unknown. Any bucket shared by every such request (per provider, say) can be
// exhausted by anyone with a handful of junk tokens, locking every user of
// the provider out; callers are expected to pass the client IP.
type ExternalLimiter struct {
	window      *window.Window
	maxAttempts int64
	cooldown    time.Duration
}

// NewExternalLimiter creates the limiter. Zero-value fields in cfg fall back
// to defaults (10 attempts / 15m).
func NewExternalLimiter(redisClient redis.UniversalClient, cfg ExternalConfig) *ExternalLimiter {
	max := cfg.MaxAttempts
	if max <= 0 {
		max = defaultExternalMaxAttempts
	}
	cd := cfg.Cooldown
	if cd <= 0 {
		cd = defaultExternalCooldown
	}
	return &ExternalLimiter{
		window:      window.NewWithClock(redisClient, cfg.WindowMode, cfg.Now),
		maxAttempts: int64(max),
		cooldown:    cd,
	}
}

// Keys use their own rl:extlogin:* namespace, distinct from every other
// limiter, so exhausting it never touches login, TOTP or password limits.

// SourceKey is the pre-verification bucket of a client IP. It is empty when
// the IP is unknown, in which case there is no such bucket and the caller
// must skip the stage.
func (l *ExternalLimiter) SourceKey(tenantID, ip string) string {
	if ip == "" {
		return ""
	}
	return "rl:extlogin:ip:" + tenantID + ":" + ip
}

// SubjectKey is the post-verification bucket.
func (l *ExternalLimiter) SubjectKey(tenantID, provider, subject string) string {
	return "rl:extlogin:sub:" + tenantID + ":" + provider + ":" + subject
}

// Reserve atomically claims one attempt in the bucket before the guarded work
// runs, so a burst of concurrent callers can never exceed maxAttempts within
// the window. It returns ErrExternalRateLimited once the claim would exceed
// it.
func (l *ExternalLimiter) Reserve(ctx context.Context, key string) error {
	count, err := l.window.Incr(ctx, key, l.cooldown)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrExternalUnavailable, err)
	}
	if count > l.maxAttempts {
		return ErrExternalRateLimited
	}
	return nil
}

// Reset clears a bucket, after a successful sign-in.
func (l *ExternalLimiter) Reset(ctx context.Context, key string) error {
	if err := l.window.Reset(ctx, key, l.cooldown); err != nil {
		return fmt.Errorf("%w: %v", ErrExternalUnavailable, err)
	}
	return nil
}
