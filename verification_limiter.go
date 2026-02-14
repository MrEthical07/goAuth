package goAuth

import (
	"context"
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"
)

var (
	errVerificationRateLimited      = errors.New("verification rate limited")
	errVerificationLimiterUnavailable = errors.New("verification limiter unavailable")
)

type emailVerificationLimiter struct {
	redis  *redis.Client
	config EmailVerificationConfig
}

func newEmailVerificationLimiter(redisClient *redis.Client, cfg EmailVerificationConfig) *emailVerificationLimiter {
	return &emailVerificationLimiter{
		redis:  redisClient,
		config: cfg,
	}
}

func (l *emailVerificationLimiter) CheckRequest(ctx context.Context, tenantID, identifier, ip string) error {
	if l.config.EnableIdentifierThrottle {
		if err := l.enforceFixedWindow(ctx, verificationRequestIdentifierKey(tenantID, identifier)); err != nil {
			return err
		}
	}
	if l.config.EnableIPThrottle && ip != "" {
		if err := l.enforceFixedWindow(ctx, verificationRequestIPKey(tenantID, ip)); err != nil {
			return err
		}
	}
	return nil
}

func (l *emailVerificationLimiter) CheckConfirm(ctx context.Context, tenantID, verificationID, ip string) error {
	if l.config.EnableIdentifierThrottle {
		if err := l.enforceFixedWindow(ctx, verificationConfirmIdentifierKey(tenantID, verificationID)); err != nil {
			return err
		}
	}
	if l.config.EnableIPThrottle && ip != "" {
		if err := l.enforceFixedWindow(ctx, verificationConfirmIPKey(tenantID, ip)); err != nil {
			return err
		}
	}
	return nil
}

func (l *emailVerificationLimiter) enforceFixedWindow(ctx context.Context, key string) error {
	count, err := l.redis.Incr(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("%w: %v", errVerificationLimiterUnavailable, err)
	}

	if count == 1 {
		if err := l.redis.Expire(ctx, key, l.config.VerificationTTL).Err(); err != nil {
			return fmt.Errorf("%w: %v", errVerificationLimiterUnavailable, err)
		}
	}

	if count > int64(l.config.MaxAttempts) {
		return errVerificationRateLimited
	}

	return nil
}

func verificationRequestIdentifierKey(tenantID, identifier string) string {
	return "apvi:" + normalizeResetTenantID(tenantID) + ":" + identifier
}

func verificationRequestIPKey(tenantID, ip string) string {
	return "apvip:" + normalizeResetTenantID(tenantID) + ":" + ip
}

func verificationConfirmIdentifierKey(tenantID, verificationID string) string {
	return "apvc:" + normalizeResetTenantID(tenantID) + ":" + verificationID
}

func verificationConfirmIPKey(tenantID, ip string) string {
	return "apvcip:" + normalizeResetTenantID(tenantID) + ":" + ip
}
