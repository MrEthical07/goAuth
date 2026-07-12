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

func TestHybridEngineStrictRouteRejectsRevokedSession(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeHybrid

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

	// A route overridden to Strict fails closed on the revoked session.
	if _, err := engine.Validate(context.Background(), access, ModeStrict); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected strict route to reject revoked session, got %v", err)
	}
	// Hybrid-resolved routes are stateless: the still-valid JWT passes.
	if _, err := engine.Validate(context.Background(), access, ModeInherit); err != nil {
		t.Fatalf("expected inherited hybrid validation to pass, got %v", err)
	}
	if _, err := engine.Validate(context.Background(), access, ModeHybrid); err != nil {
		t.Fatalf("expected explicit hybrid route to pass, got %v", err)
	}
}

func TestHybridEngineValidatesStatelesslyWithoutRedis(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeHybrid

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)

	access, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		done()
		t.Fatalf("login failed: %v", err)
	}

	// Bring Redis down: hybrid-resolved routes must stay stateless.
	done()

	if _, err := engine.Validate(context.Background(), access, ModeInherit); err != nil {
		t.Fatalf("expected inherited hybrid validation without redis, got %v", err)
	}
	if _, err := engine.Validate(context.Background(), access, ModeHybrid); err != nil {
		t.Fatalf("expected explicit hybrid route without redis, got %v", err)
	}
	// Strict routes fail closed when Redis is unavailable.
	if _, err := engine.Validate(context.Background(), access, ModeStrict); err == nil {
		t.Fatal("expected strict route to fail closed without redis")
	}
}

func TestHybridRouteOverrideOnStrictEngine(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeStrict

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	access, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// Explicit ModeHybrid used to fall through to ErrInvalidRouteMode.
	if _, err := engine.Validate(context.Background(), access, ModeHybrid); err != nil {
		t.Fatalf("expected explicit hybrid override to resolve, got %v", err)
	}

	if err := engine.LogoutByAccessToken(context.Background(), access); err != nil {
		t.Fatalf("logout failed: %v", err)
	}

	// An explicit route mode wins over the engine default: hybrid stays
	// stateless even on a Strict engine, while inherited validation fails closed.
	if _, err := engine.Validate(context.Background(), access, ModeHybrid); err != nil {
		t.Fatalf("expected hybrid override to stay stateless, got %v", err)
	}
	if _, err := engine.Validate(context.Background(), access, ModeInherit); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected inherited strict validation to reject revoked session, got %v", err)
	}
}

func TestZeroValueRouteModeRejected(t *testing.T) {
	cfg := accountTestConfig()

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	access, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// The ValidationMode zero value is not a mode (ModeJWTOnly is 1).
	if _, err := engine.Validate(context.Background(), access, RouteMode(0)); !errors.Is(err, ErrInvalidRouteMode) {
		t.Fatalf("expected ErrInvalidRouteMode for zero route mode, got %v", err)
	}
}

func TestValidationModeJWTOnlyReturnsTenantFromClaims(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeJWTOnly
	cfg.Security.EnableAccountVersionCheck = false

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	loginCtx := WithTenantID(context.Background(), "tenant-acme")
	access, _, err := engine.Login(loginCtx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	result, err := engine.Validate(context.Background(), access, ModeInherit)
	if err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if result.TenantID != "tenant-acme" {
		t.Fatalf("expected tenant-acme from JWT claims, got %q", result.TenantID)
	}
}
