package limiters

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// FAILED-BEFORE (R2-21): the reset, verification and account-creation limiters
// stored the caller's identifier or ID verbatim in the key, so a request body
// of N bytes cost N bytes of Redis memory for the whole limiter window.
func TestCallerSizedInputNeverLandsInALimiterKey(t *testing.T) {
	const maxKeyLen = 160
	huge := strings.Repeat("A", 256<<10)

	mr, rdb := newRoleSwitchTestRedis(t)
	ctx := context.Background()
	reset := NewPasswordResetLimiter(rdb, PasswordResetConfig{EnableRequestLimiter: true, EnableConfirmFailureLimiter: true, ResetTTL: time.Minute, MaxAttempts: 3})
	verify := NewEmailVerificationLimiter(rdb, EmailVerificationConfig{EnableRequestLimiter: true, EnableConfirmFailureLimiter: true, VerificationTTL: time.Minute, MaxAttempts: 3})
	account := NewAccountCreationLimiter(rdb, AccountConfig{EnableLimiter: true, MaxAttempts: 3, Cooldown: time.Minute})

	for name, call := range map[string]func() error{
		"reset request":        func() error { return reset.CheckRequest(ctx, "tenant", huge) },
		"reset confirm":        func() error { return reset.CheckConfirm(ctx, "tenant", huge) },
		"verification request": func() error { return verify.CheckRequest(ctx, "tenant", huge) },
		"verification confirm": func() error { return verify.CheckConfirm(ctx, "tenant", huge) },
		"account creation":     func() error { return account.Enforce(ctx, "tenant", huge) },
	} {
		if err := call(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	keys := mr.Keys()
	if len(keys) != 5 {
		t.Fatalf("expected one counter per limiter, got %d keys", len(keys))
	}
	for _, key := range keys {
		if len(key) > maxKeyLen {
			t.Fatalf("limiter key is %d bytes for a 256 KiB input: %.80s...", len(key), key)
		}
		if strings.Contains(key, "AAAA") || strings.Contains(key, "tenant") {
			t.Fatalf("limiter key carries caller input: %s", key)
		}
	}
}

// Hashing keeps the counting itself: the same input shares one budget, a
// different identifier or tenant has its own.
func TestHashedLimiterKeysStillCountPerIdentifierAndTenant(t *testing.T) {
	_, rdb := newRoleSwitchTestRedis(t)
	ctx := context.Background()
	reset := NewPasswordResetLimiter(rdb, PasswordResetConfig{EnableRequestLimiter: true, ResetTTL: time.Minute, MaxAttempts: 2})

	for i := 0; i < 2; i++ {
		if err := reset.CheckRequest(ctx, "t1", "alice"); err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	if err := reset.CheckRequest(ctx, "t1", "alice"); !errors.Is(err, ErrResetRateLimited) {
		t.Fatalf("third attempt: %v, want ErrResetRateLimited", err)
	}
	for _, other := range [][2]string{{"t1", "bob"}, {"t2", "alice"}} {
		if err := reset.CheckRequest(ctx, other[0], other[1]); err != nil {
			t.Fatalf("%v must have its own budget: %v", other, err)
		}
	}
}
