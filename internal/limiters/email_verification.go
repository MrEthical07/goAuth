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

// CheckRequestUser counts a verification request against the resolved
// account. The identifier budget (CheckRequest) is keyed by the string the
// caller typed, so a provider that matches identifiers case-insensitively gives
// every spelling of one account its own budget; this one is shared by all of
// them.
func (l *EmailVerificationLimiter) CheckRequestUser(ctx context.Context, tenantID, userID string) error {
	if !l.config.EnableRequestLimiter || userID == "" {
		return nil
	}
	return l.enforceWindow(ctx, verificationRequestUserKey(tenantID, userID))
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
	return "rl:verify:req:" + hashPart(tenantID) + ":" + hashPart(identifier)
}

func verificationRequestUserKey(tenantID, userID string) string {
	return "rl:verify:req:user:" + hashPart(tenantID) + ":" + hashPart(userID)
}

func verificationConfirmIdentifierKey(tenantID, verificationID string) string {
	return "rl:verify:confirm:fail:" + hashPart(tenantID) + ":" + hashPart(verificationID)
}
