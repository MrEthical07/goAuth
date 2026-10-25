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

	// IPLimiterEnabled turns on the per-client-IP login throttle; IPMaxAttempts
	// and IPCooldown size it.
	IPLimiterEnabled bool
	IPMaxAttempts    int
	IPCooldown       time.Duration
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

// ReserveLogin atomically claims one login attempt for the identifier before
// the password is verified, so a burst of concurrent logins can never verify
// more than MaxLoginAttempts passwords per window: a read-only check followed
// by a failure counter lets every request in flight observe a count below the
// limit before any of them records a failure. It returns ErrRateLimited once
// the budget is spent. A successful login clears the claim with ResetLogin.
func (l *Limiter) ReserveLogin(ctx context.Context, tenantID, identifier string) error {
	if !l.config.EnableLoginFailureLimiter {
		return nil
	}
	return l.reserve(ctx, loginUserKey(tenantID, identifier), l.config.MaxLoginAttempts, l.config.LoginCooldownDuration)
}

// ReserveLoginUser claims one login attempt against the resolved account,
// after the provider has found it and before the password is verified. The
// identifier budget (ReserveLogin) is keyed by the string the caller typed, so
// a provider that matches identifiers case-insensitively gives every spelling
// of one account a fresh budget; this one is shared by all of them. It returns
// ErrRateLimited once the account's budget is spent. A successful login clears
// it with ResetLoginUser.
func (l *Limiter) ReserveLoginUser(ctx context.Context, tenantID, userID string) error {
	if !l.config.EnableLoginFailureLimiter {
		return nil
	}
	return l.reserve(ctx, loginAccountKey(tenantID, userID), l.config.MaxLoginAttempts, l.config.LoginCooldownDuration)
}

// ReserveLoginIP claims one login attempt for the client address before the
// password is verified, when the per-IP throttle is enabled. The address is
// hashed, so the key does not grow with it. It returns ErrRateLimited once the
// address's budget is spent.
func (l *Limiter) ReserveLoginIP(ctx context.Context, tenantID, ip string) error {
	if !l.config.IPLimiterEnabled || ip == "" {
		return nil
	}
	return l.reserve(ctx, loginIPKey(tenantID, ip), l.config.IPMaxAttempts, l.config.IPCooldown)
}

// ReleaseLoginIP gives back the slot ReserveLoginIP claimed for a login whose
// password turned out right, so the count stays the failures per address. It
// does not clear the budget: one good login must not reset an address that is
// still guessing at other accounts.
func (l *Limiter) ReleaseLoginIP(ctx context.Context, tenantID, ip string) error {
	if !l.config.IPLimiterEnabled || ip == "" {
		return nil
	}
	if err := l.window.Release(ctx, loginIPKey(tenantID, ip), l.config.IPCooldown); err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	return nil
}

// ResetLoginUser clears the account's login budget.
func (l *Limiter) ResetLoginUser(ctx context.Context, tenantID, userID string) error {
	if !l.config.EnableLoginFailureLimiter {
		return nil
	}
	if err := l.window.Reset(ctx, loginAccountKey(tenantID, userID), l.config.LoginCooldownDuration); err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	return nil
}

func (l *Limiter) reserve(ctx context.Context, key string, limit int, cooldown time.Duration) error {
	_, ok, err := l.window.Reserve(ctx, key, cooldown, int64(limit))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	if !ok {
		return ErrRateLimited
	}
	return nil
}

// CheckLogin checks whether the identifier is within the login attempt budget.
// Returns an error if rate-limited. It only reads the counter; login itself
// uses ReserveLogin.
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
