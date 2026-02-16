package limiters

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrAccountRateLimited      = errors.New("account rate limited")
	ErrAccountRedisUnavailable = errors.New("account redis unavailable")
)

type AccountConfig struct {
	EnableIdentifierThrottle bool
	EnableIPThrottle         bool
	MaxAttempts              int
	Cooldown                 time.Duration
}

type AccountCreationLimiter struct {
	redis  redis.UniversalClient
	config AccountConfig
}

func NewAccountCreationLimiter(redisClient redis.UniversalClient, cfg AccountConfig) *AccountCreationLimiter {
	return &AccountCreationLimiter{
		redis:  redisClient,
		config: cfg,
	}
}

func (l *AccountCreationLimiter) Enforce(ctx context.Context, tenantID, identifier, ip string) error {
	if l.config.EnableIdentifierThrottle {
		if err := l.enforceKey(ctx, accountIdentifierKey(tenantID, identifier)); err != nil {
			return err
		}
	}

	if l.config.EnableIPThrottle && ip != "" {
		if err := l.enforceKey(ctx, accountIPKey(tenantID, ip)); err != nil {
			return err
		}
	}

	return nil
}

func (l *AccountCreationLimiter) enforceKey(ctx context.Context, key string) error {
	count, err := l.redis.Incr(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAccountRedisUnavailable, err)
	}

	if count == 1 {
		if err := l.redis.Expire(ctx, key, l.config.Cooldown).Err(); err != nil {
			return fmt.Errorf("%w: %v", ErrAccountRedisUnavailable, err)
		}
	}

	if count > int64(l.config.MaxAttempts) {
		return ErrAccountRateLimited
	}

	return nil
}

func accountIdentifierKey(tenantID, identifier string) string {
	return "aca:" + normalizeTenantID(tenantID) + ":" + identifier
}

func accountIPKey(tenantID, ip string) string {
	return "acaip:" + normalizeTenantID(tenantID) + ":" + ip
}
