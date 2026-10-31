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
	// Now is the time source for the sliding window's buckets (nil = wall clock).
	Now func() time.Time
}

type BackupCodeLimiter struct {
	window      *window.Window
	maxAttempts int
	cooldown    time.Duration
}

func NewBackupCodeLimiter(redisClient redis.UniversalClient, cfg BackupCodeConfig) *BackupCodeLimiter {
	var w *window.Window
	if redisClient != nil {
		w = window.NewWithClock(redisClient, cfg.WindowMode, cfg.Now)
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

// Reserve atomically claims one attempt before the code is evaluated, so a
// burst of concurrent requests can never evaluate more than maxAttempts codes
// per window. It returns ErrBackupCodeRateLimited, without letting the caller
// evaluate anything, once the budget is spent. last reports that the claim
// took the final slot, so a wrong code must be reported as rate limited, as
// the failure that fills the budget always was. An unconfigured MaxAttempts of
// zero still admits the first attempt. A good code clears the budget with
// Reset.
func (l *BackupCodeLimiter) Reserve(ctx context.Context, tenantID, userID string) (last bool, err error) {
	if l == nil || l.window == nil {
		return false, nil
	}
	limit := int64(l.maxAttempts)
	if limit < 1 {
		limit = 1
	}
	count, ok, err := l.window.Reserve(ctx, l.key(tenantID, userID), l.cooldown, limit)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrBackupCodeUnavailable, err)
	}
	if !ok {
		return false, ErrBackupCodeRateLimited
	}
	return count >= limit, nil
}

// Release gives back a slot claimed with Reserve for an attempt that was not a
// wrong guess (a provider failure).
func (l *BackupCodeLimiter) Release(ctx context.Context, tenantID, userID string) error {
	if l == nil || l.window == nil {
		return nil
	}
	if err := l.window.Release(ctx, l.key(tenantID, userID), l.cooldown); err != nil {
		return fmt.Errorf("%w: %v", ErrBackupCodeUnavailable, err)
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
