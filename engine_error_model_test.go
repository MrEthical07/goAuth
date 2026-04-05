package goAuth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func requireAuthError(t *testing.T, err error) *AuthError {
	t.Helper()
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("expected AuthError, got %T (%v)", err, err)
	}
	return ae
}

func TestAuthErrorNoRawLeakRepresentativeMethods(t *testing.T) {
	cfg := accountTestConfig()
	hasher := newTestHasher(t)
	hash, err := hasher.Hash("correct-password-123")
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {
				UserID:            "u1",
				Identifier:        "alice",
				TenantID:          "0",
				PasswordHash:      hash,
				Status:            AccountActive,
				Role:              "member",
				PermissionVersion: 1,
				RoleVersion:       1,
				AccountVersion:    1,
			},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	checks := []struct {
		name string
		call func() error
	}{
		{
			name: "Login",
			call: func() error {
				_, _, err := engine.Login(context.Background(), "alice", "wrong-password")
				return err
			},
		},
		{
			name: "Refresh",
			call: func() error {
				_, _, err := engine.Refresh(context.Background(), "not-a-refresh-token")
				return err
			},
		},
		{
			name: "Validate",
			call: func() error {
				_, err := engine.Validate(context.Background(), "not-a-jwt", ModeInherit)
				return err
			},
		},
		{
			name: "LogoutByAccessToken",
			call: func() error {
				return engine.LogoutByAccessToken(context.Background(), "not-a-jwt")
			},
		},
		{
			name: "ChangePassword",
			call: func() error {
				return engine.ChangePassword(context.Background(), "u1", "", "")
			},
		},
		{
			name: "CreateAccount",
			call: func() error {
				_, err := engine.CreateAccount(context.Background(), CreateAccountRequest{})
				return err
			},
		},
	}

	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			requireAuthError(t, err)
		})
	}
}

func TestAuthErrorMappingInvalidCredentials(t *testing.T) {
	engine, _, done := newStatusEngine(t, AccountActive, ModeHybrid)
	defer done()

	_, _, err := engine.Login(context.Background(), "alice", "wrong-password")
	ae := requireAuthError(t, err)

	if ae.Code != string(CodeAuthInvalidCredentials) {
		t.Fatalf("expected code %s, got %s", CodeAuthInvalidCredentials, ae.Code)
	}
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected errors.Is(err, ErrInvalidCredentials) to be true, got %v", err)
	}
}

func TestAuthErrorMappingAccountLocked(t *testing.T) {
	engine, _, done := newStatusEngine(t, AccountLocked, ModeHybrid)
	defer done()

	_, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	ae := requireAuthError(t, err)

	if ae.Code != string(CodeAuthAccountLocked) {
		t.Fatalf("expected code %s, got %s", CodeAuthAccountLocked, ae.Code)
	}
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("expected errors.Is(err, ErrAccountLocked) to be true, got %v", err)
	}
}

func TestAuthErrorMappingMFAInvalidCode(t *testing.T) {
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

	_, err = engine.ConfirmLoginMFA(context.Background(), result.MFASession, "000000")
	ae := requireAuthError(t, err)

	if ae.Code != string(CodeAuthMFAInvalidCode) {
		t.Fatalf("expected code %s, got %s", CodeAuthMFAInvalidCode, ae.Code)
	}
	if !errors.Is(err, ErrMFALoginInvalid) {
		t.Fatalf("expected errors.Is(err, ErrMFALoginInvalid) to be true, got %v", err)
	}
}

func TestAuthErrorMappingResetInvalid(t *testing.T) {
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
	ae := requireAuthError(t, err)

	if ae.Code != string(CodeAuthResetInvalid) {
		t.Fatalf("expected code %s, got %s", CodeAuthResetInvalid, ae.Code)
	}
	if !errors.Is(err, ErrPasswordResetInvalid) {
		t.Fatalf("expected errors.Is(err, ErrPasswordResetInvalid) to be true, got %v", err)
	}
}

func TestAuthErrorUnknownProviderFailureFallsBackToSystemInternal(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	ctx := context.Background()
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

	err = engine.ChangePassword(ctx, "u1", "old-password-123", "new-password-123")
	ae := requireAuthError(t, err)

	if ae.Code != string(CodeSystemInternalError) {
		t.Fatalf("expected code %s, got %s", CodeSystemInternalError, ae.Code)
	}
	if !errors.Is(err, ErrSystemInternal) {
		t.Fatalf("expected errors.Is(err, ErrSystemInternal) to be true, got %v", err)
	}
	if strings.Contains(err.Error(), "provider-db-write-failed") {
		t.Fatalf("raw provider error leaked in public message: %v", err)
	}
}
