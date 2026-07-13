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
	ErrAccountRateLimited      = errors.New("account rate limited")
	ErrAccountRedisUnavailable = errors.New("account redis unavailable")
)

type AccountConfig struct {
	EnableLimiter bool
	MaxAttempts   int
	Cooldown      time.Duration
	// WindowMode selects the counting algorithm (zero value = fixed window).
	WindowMode window.Mode
}

type AccountCreationLimiter struct {
	window *window.Window
	config AccountConfig
}

func NewAccountCreationLimiter(redisClient redis.UniversalClient, cfg AccountConfig) *AccountCreationLimiter {
	return &AccountCreationLimiter{
		window: window.New(redisClient, cfg.WindowMode),
		config: cfg,
	}
}

func (l *AccountCreationLimiter) Enforce(ctx context.Context, tenantID, identifier string) error {
	if !l.config.EnableLimiter || identifier == "" {
		return nil
	}

	if err := l.enforceKey(ctx, accountIdentifierKey(tenantID, identifier)); err != nil {
		return err
	}

	return nil
}

func (l *AccountCreationLimiter) enforceKey(ctx context.Context, key string) error {
	count, err := l.window.Incr(ctx, key, l.config.Cooldown)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAccountRedisUnavailable, err)
	}

	if count > int64(l.config.MaxAttempts) {
		return ErrAccountRateLimited
	}

	return nil
}

func accountIdentifierKey(tenantID, identifier string) string {
	return "rl:account:req:" + tenantID + ":" + identifier
}
