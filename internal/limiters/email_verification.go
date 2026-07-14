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
	ErrVerificationRateLimited        = errors.New("verification rate limited")
	ErrVerificationLimiterUnavailable = errors.New("verification limiter unavailable")
)

type EmailVerificationConfig struct {
	EnableRequestLimiter        bool
	EnableConfirmFailureLimiter bool
	VerificationTTL             time.Duration
	MaxAttempts                 int
	// WindowMode selects the counting algorithm (zero value = fixed window).
	WindowMode window.Mode
}

type EmailVerificationLimiter struct {
	window *window.Window
	config EmailVerificationConfig
}

func NewEmailVerificationLimiter(redisClient redis.UniversalClient, cfg EmailVerificationConfig) *EmailVerificationLimiter {
	return &EmailVerificationLimiter{
		window: window.New(redisClient, cfg.WindowMode),
		config: cfg,
	}
}

func (l *EmailVerificationLimiter) CheckRequest(ctx context.Context, tenantID, identifier string) error {
	if !l.config.EnableRequestLimiter || identifier == "" {
		return nil
	}
	if err := l.enforceWindow(ctx, verificationRequestIdentifierKey(tenantID, identifier)); err != nil {
		return err
	}
	return nil
}

func (l *EmailVerificationLimiter) CheckConfirm(ctx context.Context, tenantID, verificationID string) error {
	if !l.config.EnableConfirmFailureLimiter || verificationID == "" {
		return nil
	}
	if err := l.enforceWindow(ctx, verificationConfirmIdentifierKey(tenantID, verificationID)); err != nil {
		return err
	}
	return nil
}

func (l *EmailVerificationLimiter) enforceWindow(ctx context.Context, key string) error {
	count, err := l.window.Incr(ctx, key, l.config.VerificationTTL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVerificationLimiterUnavailable, err)
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
