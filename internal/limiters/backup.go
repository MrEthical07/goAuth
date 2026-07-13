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
	ErrBackupCodeRateLimited = errors.New("backup code rate limited")
	ErrBackupCodeUnavailable = errors.New("backup code unavailable")
)

type BackupCodeConfig struct {
	MaxAttempts int
	Cooldown    time.Duration
	// WindowMode selects the counting algorithm (zero value = fixed window).
	WindowMode window.Mode
}

type BackupCodeLimiter struct {
	window      *window.Window
	maxAttempts int
	cooldown    time.Duration
}

func NewBackupCodeLimiter(redisClient redis.UniversalClient, cfg BackupCodeConfig) *BackupCodeLimiter {
	var w *window.Window
	if redisClient != nil {
		w = window.New(redisClient, cfg.WindowMode)
	}
	return &BackupCodeLimiter{
		window:      w,
		maxAttempts: cfg.MaxAttempts,
		cooldown:    cfg.Cooldown,
	}
}

func (l *BackupCodeLimiter) key(tenantID, userID string) string {
	return "rl:backup:fail:" + tenantID + ":" + userID
}

func (l *BackupCodeLimiter) Check(ctx context.Context, tenantID, userID string) error {
	if l == nil || l.window == nil {
		return nil
	}
	count, err := l.window.Count(ctx, l.key(tenantID, userID), l.cooldown)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBackupCodeUnavailable, err)
	}
	// count == 0 mirrors the previous missing-key early return, so an
	// unconfigured MaxAttempts of zero still admits the first check.
	if count > 0 && int(count) >= l.maxAttempts {
		return ErrBackupCodeRateLimited
	}
	return nil
}

func (l *BackupCodeLimiter) RecordFailure(ctx context.Context, tenantID, userID string) error {
	if l == nil || l.window == nil {
		return nil
	}
	count, err := l.window.Incr(ctx, l.key(tenantID, userID), l.cooldown)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBackupCodeUnavailable, err)
	}
	if int(count) >= l.maxAttempts {
		return ErrBackupCodeRateLimited
	}
	return nil
}

func (l *BackupCodeLimiter) Reset(ctx context.Context, tenantID, userID string) error {
	if l == nil || l.window == nil {
		return nil
	}
	if err := l.window.Reset(ctx, l.key(tenantID, userID), l.cooldown); err != nil {
		return fmt.Errorf("%w: %v", ErrBackupCodeUnavailable, err)
	}
	return nil
}
