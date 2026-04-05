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
	EnableRequestLimiter        bool
	EnableConfirmFailureLimiter bool
	VerificationTTL             time.Duration
	MaxAttempts                 int
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

func (l *EmailVerificationLimiter) CheckRequest(ctx context.Context, tenantID, identifier string) error {
	if !l.config.EnableRequestLimiter || identifier == "" {
		return nil
	}
	if err := l.enforceFixedWindow(ctx, verificationRequestIdentifierKey(tenantID, identifier)); err != nil {
		return err
	}
	return nil
}

func (l *EmailVerificationLimiter) CheckConfirm(ctx context.Context, tenantID, verificationID string) error {
	if !l.config.EnableConfirmFailureLimiter || verificationID == "" {
		return nil
	}
	if err := l.enforceFixedWindow(ctx, verificationConfirmIdentifierKey(tenantID, verificationID)); err != nil {
		return err
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
	return "rl:verify:req:" + tenantID + ":" + identifier
}

func verificationConfirmIdentifierKey(tenantID, verificationID string) string {
	return "rl:verify:confirm:fail:" + tenantID + ":" + verificationID
}
