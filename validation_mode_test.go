package goAuth

import (
	"context"
	"errors"
	"testing"
)

func TestValidationModeStrictRejectsRevokedSession(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeStrict

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	access, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	if err := engine.LogoutByAccessToken(context.Background(), access); err != nil {
		t.Fatalf("logout failed: %v", err)
	}

	if _, err := engine.Validate(context.Background(), access, ModeInherit); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected strict mode to reject revoked session, got %v", err)
	}
}

func TestValidationModeJWTOnlyDoesNotRequireRedis(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeJWTOnly
	cfg.Security.EnableAccountVersionCheck = false

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)

	access, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		done()
		t.Fatalf("login failed: %v", err)
	}

	// Bring Redis down to prove JWT-only validation remains stateless.
	done()

	if _, err := engine.Validate(context.Background(), access, ModeInherit); err != nil {
		t.Fatalf("expected jwt-only validation without redis, got %v", err)
	}
}
