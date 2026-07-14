package limiters

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/MrEthical07/goAuth/internal/window"
	"github.com/redis/go-redis/v9"
)

var (
	ErrResetRateLimited      = errors.New("reset rate limited")
	ErrResetRedisUnavailable = errors.New("reset redis unavailable")
)

type PasswordResetConfig struct {
	EnableRequestLimiter        bool
	EnableConfirmFailureLimiter bool
	ResetTTL                    time.Duration
	MaxAttempts                 int
	// WindowMode selects the counting algorithm (zero value = fixed window).
	WindowMode window.Mode
}

type PasswordResetLimiter struct {
	window *window.Window
	config PasswordResetConfig
}

func NewPasswordResetLimiter(redisClient redis.UniversalClient, cfg PasswordResetConfig) *PasswordResetLimiter {
	return &PasswordResetLimiter{
		window: window.New(redisClient, cfg.WindowMode),
		config: cfg,
	}
}

func (l *PasswordResetLimiter) CheckRequest(ctx context.Context, tenantID, identifier string) error {
	if !l.config.EnableRequestLimiter || identifier == "" {
		return nil
	}
	if err := l.enforceWindow(ctx, requestIdentifierKey(tenantID, identifier)); err != nil {
		return err
	}
	return nil
}

func (l *PasswordResetLimiter) CheckConfirm(ctx context.Context, tenantID, resetID string) error {
	if !l.config.EnableConfirmFailureLimiter || resetID == "" {
		return nil
	}
	if err := l.enforceWindow(ctx, confirmIdentifierKey(tenantID, resetID)); err != nil {
		return err
	}
	return nil
}

func (l *PasswordResetLimiter) Cooldown() time.Duration {
	return l.config.ResetTTL
}

func (l *PasswordResetLimiter) enforceWindow(ctx context.Context, key string) error {
	count, err := l.window.Incr(ctx, key, l.config.ResetTTL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrResetRedisUnavailable, err)
	}

	if count > int64(l.config.MaxAttempts) {
		return ErrResetRateLimited
	}

	return nil
}

func requestIdentifierKey(tenantID, identifier string) string {
	return "rl:reset:req:" + tenantID + ":" + identifier
}

func confirmIdentifierKey(tenantID, resetID string) string {
	return "rl:reset:confirm:fail:" + tenantID + ":" + resetID
}
