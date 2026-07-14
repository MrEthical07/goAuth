package goAuth

import (
	"context"
	"errors"
	"testing"
	"time"

	authjwt "github.com/MrEthical07/goAuth/jwt"
	gjwt "github.com/golang-jwt/jwt/v5"
)

// craftExpiredAccessToken signs an already-expired hs256 access token that
// mirrors the identity claims of a live token minted by the engine.
func craftExpiredAccessToken(t *testing.T, secret []byte, live *authjwt.AccessClaims) string {
	t.Helper()

	claims := authjwt.AccessClaims{
		UID: live.UID,
		TID: live.TID,
		SID: live.SID,
		RegisteredClaims: gjwt.RegisteredClaims{
			ExpiresAt: gjwt.NewNumericDate(time.Now().Add(-2 * time.Minute)),
			IssuedAt:  gjwt.NewNumericDate(time.Now().Add(-3 * time.Minute)),
		},
	}
	tok := gjwt.NewWithClaims(gjwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(secret)
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}
	return signed
}

func TestLogoutByExpiredAccessTokenDeletesSession(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeStrict

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	access, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	liveClaims, err := engine.jwtManager.ParseAccess(access)
	if err != nil {
		t.Fatalf("parse live token: %v", err)
	}

	expired := craftExpiredAccessToken(t, []byte("test-secret"), liveClaims)

	if err := engine.LogoutByAccessToken(context.Background(), expired); err != nil {
		t.Fatalf("expected expired-token logout to succeed, got %v", err)
	}

	// The live session must actually be gone.
	if _, err := engine.Validate(context.Background(), access, ModeStrict); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected session to be deleted after expired-token logout, got %v", err)
	}

	// Logging out again with the same expired token stays a success (idempotent).
	if err := engine.LogoutByAccessToken(context.Background(), expired); err != nil {
		t.Fatalf("expected repeated expired-token logout to succeed, got %v", err)
	}
}

func TestLogoutByExpiredTokenWithForgedSignatureRejected(t *testing.T) {
	cfg := accountTestConfig()

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	access, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	liveClaims, err := engine.jwtManager.ParseAccess(access)
	if err != nil {
		t.Fatalf("parse live token: %v", err)
	}

	forged := craftExpiredAccessToken(t, []byte("wrong-secret-key"), liveClaims)

	if err := engine.LogoutByAccessToken(context.Background(), forged); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid for forged expired token, got %v", err)
	}

	// The session must be untouched.
	if _, err := engine.Validate(context.Background(), access, ModeStrict); err != nil {
		t.Fatalf("expected session to survive forged logout attempt, got %v", err)
	}
}

func TestLogoutByInvalidTokenStillRejected(t *testing.T) {
	cfg := accountTestConfig()

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	if err := engine.LogoutByAccessToken(context.Background(), "not-a-jwt"); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid for garbage token, got %v", err)
	}
}
