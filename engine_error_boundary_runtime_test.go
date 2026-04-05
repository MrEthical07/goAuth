package goAuth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func assertBoundaryAuthError(t *testing.T, err error, sentinel error) *AuthError {
	t.Helper()
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("expected *AuthError at public boundary, got %T (%v)", err, err)
	}
	if sentinel != nil && !errors.Is(err, sentinel) {
		t.Fatalf("expected errors.Is(err, %v) to be true, got %v", sentinel, err)
	}
	return ae
}

func TestEngineErrorBoundaryRuntime_AuthFailureIsAuthError(t *testing.T) {
	engine, _, done := newStatusEngine(t, AccountActive, ModeHybrid)
	defer done()

	_, _, err := engine.Login(context.Background(), "alice", "wrong-password")
	assertBoundaryAuthError(t, err, ErrInvalidCredentials)
}

func TestEngineErrorBoundaryRuntime_MFAFailureIsAuthError(t *testing.T) {
	cfg := totpTestConfig()
	cfg.TOTP.RequireForLogin = true
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	_ = enableUserTOTP(t, engine, "u1", cfg)

	result, err := engine.LoginWithResult(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("LoginWithResult failed: %v", err)
	}
	if result == nil || !result.MFARequired {
		t.Fatalf("expected MFA challenge result, got %+v", result)
	}

	_, err = engine.ConfirmLoginMFA(context.Background(), result.MFASession, "000000")
	assertBoundaryAuthError(t, err, ErrMFALoginInvalid)
}

func TestEngineErrorBoundaryRuntime_TokenFailureIsAuthError(t *testing.T) {
	engine, _, done := newStatusEngine(t, AccountActive, ModeHybrid)
	defer done()

	_, _, err := engine.Refresh(context.Background(), "not-a-refresh-token")
	assertBoundaryAuthError(t, err, ErrRefreshInvalid)
}

func TestEngineErrorBoundaryRuntime_ResetFailureIsAuthError(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	hasher := newTestHasher(t)
	oldHash, err := hasher.Hash("old-password-123")
	if err != nil {
		t.Fatalf("Hash old password failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {UserID: "u1", Identifier: "alice", PasswordHash: oldHash, TenantID: "0"},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine := newTestResetEngine(t, rdb, up, hasher, testResetConfig(ResetToken))

	err = engine.ConfirmPasswordReset(context.Background(), "bad-format", "new-password-123")
	assertBoundaryAuthError(t, err, ErrPasswordResetInvalid)
}

func TestEngineErrorBoundaryRuntime_UnknownProviderFailureCollapsesToSystemInternal(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	hasher := newTestHasher(t)
	oldHash, err := hasher.Hash("old-password-123")
	if err != nil {
		t.Fatalf("Hash old password failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {
				UserID:            "u1",
				Identifier:        "alice",
				PasswordHash:      oldHash,
				Role:              "member",
				PermissionVersion: 1,
				RoleVersion:       1,
				AccountVersion:    1,
			},
		},
		byIdentifier: map[string]string{"alice": "u1"},
		updateErr:    errors.New("provider-db-write-failed"),
	}

	engine := newTestEngine(t, rdb, up, hasher)

	err = engine.ChangePassword(context.Background(), "u1", "old-password-123", "new-password-123")
	ae := assertBoundaryAuthError(t, err, ErrSystemInternal)

	if strings.Contains(ae.Message, "provider-db-write-failed") || strings.Contains(err.Error(), "provider-db-write-failed") {
		t.Fatalf("raw provider failure leaked to public error: %v", err)
	}
}

func TestEngineErrorBoundaryRuntime_BackendUnavailableMapsToSystemUnavailable(t *testing.T) {
	engine, _, done := newStatusEngine(t, AccountActive, ModeHybrid)
	done()

	_, err := engine.GetActiveSessionCount(context.Background(), "u1")
	assertBoundaryAuthError(t, err, ErrSystemUnavailable)
}
