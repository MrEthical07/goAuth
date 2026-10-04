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
	defaultRoleSwitchMaxAttempts = 10
	defaultRoleSwitchCooldown    = 15 * time.Minute
)

var (
	ErrRoleSwitchRateLimited = errors.New("role switch rate limited")
	ErrRoleSwitchUnavailable = errors.New("role switch limiter unavailable")
)

// RoleSwitchConfig holds the thresholds for the role-switch attempt limiter.
type RoleSwitchConfig struct {
	MaxAttempts int
	Cooldown    time.Duration
	// WindowMode selects the counting algorithm (zero value = fixed window).
	WindowMode window.Mode
}

// RoleSwitchLimiter rate-limits switch attempts per (tenant, session). The
// session ID comes from the presented refresh token, so a slot is consumed
// even when the session does not exist or belongs to another tenant: an
// attacker spraying guessed or foreign session IDs is throttled the same as
// a legitimate caller.
type RoleSwitchLimiter struct {
	window      *window.Window
	maxAttempts int64
	cooldown    time.Duration
}

// NewRoleSwitchLimiter creates a role-switch limiter. Zero-value fields in
// cfg fall back to defaults (10 attempts / 15m).
func NewRoleSwitchLimiter(redisClient redis.UniversalClient, cfg RoleSwitchConfig) *RoleSwitchLimiter {
	max := cfg.MaxAttempts
	if max <= 0 {
		max = defaultRoleSwitchMaxAttempts
	}
	cd := cfg.Cooldown
	if cd <= 0 {
		cd = defaultRoleSwitchCooldown
	}
	return &RoleSwitchLimiter{
		window:      window.New(redisClient, cfg.WindowMode),
		maxAttempts: int64(max),
		cooldown:    cd,
	}
}

// key uses its own rl:roleswitch:* namespace, distinct from every other
// limiter, so exhausting it never touches login, TOTP or password limits.
func (l *RoleSwitchLimiter) key(tenantID, sessionID string) string {
	return "rl:roleswitch:" + tenantID + ":" + sessionID
}

// Reserve atomically claims one switch attempt before any provider, Argon2
// or session work runs, so a burst of concurrent callers can never exceed
// maxAttempts within the window. It returns ErrRoleSwitchRateLimited once
// the claim would exceed it.
func (l *RoleSwitchLimiter) Reserve(ctx context.Context, tenantID, sessionID string) error {
	count, err := l.window.Incr(ctx, l.key(tenantID, sessionID), l.cooldown)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRoleSwitchUnavailable, err)
	}
	if count > l.maxAttempts {
		return ErrRoleSwitchRateLimited
	}
	return nil
}

// Reset clears the attempt counter, after a successful switch.
func (l *RoleSwitchLimiter) Reset(ctx context.Context, tenantID, sessionID string) error {
	if err := l.window.Reset(ctx, l.key(tenantID, sessionID), l.cooldown); err != nil {
		return fmt.Errorf("%w: %v", ErrRoleSwitchUnavailable, err)
	}
	return nil
}
