package goAuth

import (
	"context"
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"
)

var (
	errAccountRateLimited      = errors.New("account rate limited")
	errAccountRedisUnavailable = errors.New("account redis unavailable")
)

type accountCreationLimiter struct {
	redis  *redis.Client
	config AccountConfig
}

func newAccountCreationLimiter(redisClient *redis.Client, cfg AccountConfig) *accountCreationLimiter {
	return &accountCreationLimiter{
		redis:  redisClient,
		config: cfg,
	}
}

// Enforce describes the enforce operation and its observable behavior.
//
// Enforce may return an error when input validation, dependency calls, or security checks fail.
// Enforce does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (l *accountCreationLimiter) Enforce(ctx context.Context, tenantID, identifier, ip string) error {
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

func (l *accountCreationLimiter) enforceKey(ctx context.Context, key string) error {
	count, err := l.redis.Incr(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("%w: %v", errAccountRedisUnavailable, err)
	}

	if count == 1 {
		if err := l.redis.Expire(ctx, key, l.config.AccountCreationCooldown).Err(); err != nil {
			return fmt.Errorf("%w: %v", errAccountRedisUnavailable, err)
		}
	}

	if count > int64(l.config.AccountCreationMaxAttempts) {
		return errAccountRateLimited
	}

	return nil
}

func accountIdentifierKey(tenantID, identifier string) string {
	return "aca:" + normalizeResetTenantID(tenantID) + ":" + identifier
}

func accountIPKey(tenantID, ip string) string {
	return "acaip:" + normalizeResetTenantID(tenantID) + ":" + ip
}
