package limiters

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrVerificationRateLimited        = errors.New("verification rate limited")
	ErrVerificationLimiterUnavailable = errors.New("verification limiter unavailable")
)

type EmailVerificationConfig struct {
	EnableIdentifierThrottle bool
	EnableIPThrottle         bool
	VerificationTTL          time.Duration
	MaxAttempts              int
}

type EmailVerificationLimiter struct {
	redis  redis.UniversalClient
	config EmailVerificationConfig
}

func NewEmailVerificationLimiter(redisClient redis.UniversalClient, cfg EmailVerificationConfig) *EmailVerificationLimiter {
	return &EmailVerificationLimiter{
		redis:  redisClient,
		config: cfg,
	}
}

func (l *EmailVerificationLimiter) CheckRequest(ctx context.Context, tenantID, identifier, ip string) error {
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

func (l *EmailVerificationLimiter) CheckConfirm(ctx context.Context, tenantID, verificationID, ip string) error {
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

func (l *EmailVerificationLimiter) enforceFixedWindow(ctx context.Context, key string) error {
	count, err := l.redis.Incr(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVerificationLimiterUnavailable, err)
	}

	if count == 1 {
		if err := l.redis.Expire(ctx, key, l.config.VerificationTTL).Err(); err != nil {
			return fmt.Errorf("%w: %v", ErrVerificationLimiterUnavailable, err)
		}
	}

	if count > int64(l.config.MaxAttempts) {
		return ErrVerificationRateLimited
	}

	return nil
}

func verificationRequestIdentifierKey(tenantID, identifier string) string {
	return "apvi:" + normalizeTenantID(tenantID) + ":" + identifier
}

func verificationRequestIPKey(tenantID, ip string) string {
	return "apvip:" + normalizeTenantID(tenantID) + ":" + ip
}

func verificationConfirmIdentifierKey(tenantID, verificationID string) string {
	return "apvc:" + normalizeTenantID(tenantID) + ":" + verificationID
}

func verificationConfirmIPKey(tenantID, ip string) string {
	return "apvcip:" + normalizeTenantID(tenantID) + ":" + ip
}
