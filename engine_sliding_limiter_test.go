package goAuth

import (
	"context"
	"errors"
	"testing"
)

func TestLoginFailureLimiterSlidingMode(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Security.LimiterWindowMode = "sliding"
	cfg.Security.MaxLoginAttempts = 2

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	if _, _, err := engine.Login(context.Background(), "alice", "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials on first failure, got %v", err)
	}
	for i := 0; i < 2; i++ {
		_, _, _ = engine.Login(context.Background(), "alice", "wrong-password")
	}

	// Budget exhausted: even the correct password is throttled.
	if _, _, err := engine.Login(context.Background(), "alice", "correct-password-123"); !errors.Is(err, ErrLoginRateLimited) {
		t.Fatalf("expected ErrLoginRateLimited after exceeding attempts, got %v", err)
	}
}

func TestLoginFailureLimiterSlidingModeResetsOnSuccess(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Security.LimiterWindowMode = "sliding"
	cfg.Security.MaxLoginAttempts = 3

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	for i := 0; i < 2; i++ {
		_, _, _ = engine.Login(context.Background(), "alice", "wrong-password")
	}
	if _, _, err := engine.Login(context.Background(), "alice", "correct-password-123"); err != nil {
		t.Fatalf("expected login within budget to succeed, got %v", err)
	}

	// The success must have cleared both sliding buckets: a fresh budget applies.
	for i := 0; i < 2; i++ {
		_, _, _ = engine.Login(context.Background(), "alice", "wrong-password")
	}
	if _, _, err := engine.Login(context.Background(), "alice", "correct-password-123"); err != nil {
		t.Fatalf("expected reset budget after successful login, got %v", err)
	}
}
