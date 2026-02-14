package goAuth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func enableUserTOTP(t *testing.T, engine *Engine, userID string, cfg Config) string {
	t.Helper()

	setup, err := engine.GenerateTOTPSetup(context.Background(), userID)
	if err != nil {
		t.Fatalf("GenerateTOTPSetup failed: %v", err)
	}
	if setup.SecretBase32 == "" {
		t.Fatal("expected non-empty setup secret")
	}

	code := codeForNow(t, setup.SecretBase32, cfg.TOTP)
	if err := engine.ConfirmTOTPSetup(context.Background(), userID, code); err != nil {
		t.Fatalf("ConfirmTOTPSetup failed: %v", err)
	}

	return setup.SecretBase32
}

func TestMFALoginWithoutTOTPReturnsTokens(t *testing.T) {
	cfg := totpTestConfig()
	cfg.TOTP.RequireForLogin = true
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	result, err := engine.LoginWithResult(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("LoginWithResult failed: %v", err)
	}
	if result.MFARequired {
		t.Fatal("expected no MFA challenge when TOTP is not enabled for user")
	}
	if result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatal("expected tokens for non-MFA login")
	}
}

func TestMFALoginChallengeAndConfirmSuccess(t *testing.T) {
	cfg := totpTestConfig()
	cfg.TOTP.RequireForLogin = true
	up := newHardeningUserProvider(t)

	engine, rdb, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	secret := enableUserTOTP(t, engine, "u1", cfg)

	result, err := engine.LoginWithResult(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("LoginWithResult failed: %v", err)
	}
	if !result.MFARequired || result.MFASession == "" || result.MFAType != "totp" {
		t.Fatalf("expected MFA challenge, got %+v", result)
	}
	if result.AccessToken != "" || result.RefreshToken != "" {
		t.Fatal("expected no tokens before MFA confirmation")
	}
	if exists := rdb.Exists(context.Background(), "amc:"+result.MFASession).Val(); exists != 1 {
		t.Fatal("expected MFA challenge key to exist")
	}

	code := codeForOffset(t, secret, cfg.TOTP, 1)
	confirmed, err := engine.ConfirmLoginMFA(context.Background(), result.MFASession, code)
	if err != nil {
		t.Fatalf("ConfirmLoginMFA failed: %v", err)
	}
	if confirmed.MFARequired {
		t.Fatal("expected MFA to be completed")
	}
	if confirmed.AccessToken == "" || confirmed.RefreshToken == "" {
		t.Fatal("expected tokens after MFA confirmation")
	}
	if exists := rdb.Exists(context.Background(), "amc:"+result.MFASession).Val(); exists != 0 {
		t.Fatal("expected MFA challenge key to be deleted after success")
	}
}

func TestMFALoginWrongCodeAndAttemptsExceeded(t *testing.T) {
	cfg := totpTestConfig()
	cfg.TOTP.RequireForLogin = true
	cfg.TOTP.MFALoginMaxAttempts = 2
	up := newHardeningUserProvider(t)

	engine, rdb, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	_ = enableUserTOTP(t, engine, "u1", cfg)
	result, err := engine.LoginWithResult(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("LoginWithResult failed: %v", err)
	}

	if _, err := engine.ConfirmLoginMFA(context.Background(), result.MFASession, "000000"); !errors.Is(err, ErrMFALoginInvalid) {
		t.Fatalf("expected ErrMFALoginInvalid, got %v", err)
	}
	if exists := rdb.Exists(context.Background(), "amc:"+result.MFASession).Val(); exists != 1 {
		t.Fatal("expected challenge to remain after first failed attempt")
	}
	if _, err := engine.ConfirmLoginMFA(context.Background(), result.MFASession, "000000"); !errors.Is(err, ErrMFALoginAttemptsExceeded) {
		t.Fatalf("expected ErrMFALoginAttemptsExceeded, got %v", err)
	}
	if exists := rdb.Exists(context.Background(), "amc:"+result.MFASession).Val(); exists != 0 {
		t.Fatal("expected challenge to be deleted after max attempts")
	}
}

func TestMFALoginChallengeExpired(t *testing.T) {
	cfg := totpTestConfig()
	cfg.TOTP.RequireForLogin = true
	cfg.TOTP.MFALoginChallengeTTL = time.Second
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	secret := enableUserTOTP(t, engine, "u1", cfg)
	result, err := engine.LoginWithResult(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("LoginWithResult failed: %v", err)
	}

	time.Sleep(2 * time.Second)
	if _, err := engine.ConfirmLoginMFA(context.Background(), result.MFASession, codeForOffset(t, secret, cfg.TOTP, 1)); !errors.Is(err, ErrMFALoginExpired) {
		t.Fatalf("expected ErrMFALoginExpired, got %v", err)
	}
}

func TestMFALoginReplayRejected(t *testing.T) {
	cfg := totpTestConfig()
	cfg.TOTP.RequireForLogin = true
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	secret := enableUserTOTP(t, engine, "u1", cfg)
	result, err := engine.LoginWithResult(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("LoginWithResult failed: %v", err)
	}

	code := codeForOffset(t, secret, cfg.TOTP, 1)
	if _, err := engine.ConfirmLoginMFA(context.Background(), result.MFASession, code); err != nil {
		t.Fatalf("first ConfirmLoginMFA failed: %v", err)
	}
	if _, err := engine.ConfirmLoginMFA(context.Background(), result.MFASession, code); !errors.Is(err, ErrMFALoginInvalid) && !errors.Is(err, ErrMFALoginReplay) {
		t.Fatalf("expected replay rejection, got %v", err)
	}
}

func TestMFALoginTenantMismatchFails(t *testing.T) {
	cfg := totpTestConfig()
	cfg.TOTP.RequireForLogin = true
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	secret := enableUserTOTP(t, engine, "u1", cfg)
	ctxTenant0 := WithTenantID(context.Background(), "0")
	result, err := engine.LoginWithResult(ctxTenant0, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("LoginWithResult failed: %v", err)
	}

	ctxTenant1 := WithTenantID(context.Background(), "1")
	if _, err := engine.ConfirmLoginMFA(ctxTenant1, result.MFASession, codeForOffset(t, secret, cfg.TOTP, 1)); !errors.Is(err, ErrMFALoginInvalid) {
		t.Fatalf("expected tenant mismatch ErrMFALoginInvalid, got %v", err)
	}
}

func TestMFALoginFailsIfTOTPDisabledAfterChallenge(t *testing.T) {
	cfg := totpTestConfig()
	cfg.TOTP.RequireForLogin = true
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	secret := enableUserTOTP(t, engine, "u1", cfg)
	result, err := engine.LoginWithResult(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("LoginWithResult failed: %v", err)
	}
	if err := engine.DisableTOTP(context.Background(), "u1"); err != nil {
		t.Fatalf("DisableTOTP failed: %v", err)
	}

	if _, err := engine.ConfirmLoginMFA(context.Background(), result.MFASession, codeForOffset(t, secret, cfg.TOTP, 1)); !errors.Is(err, ErrMFALoginInvalid) {
		t.Fatalf("expected ErrMFALoginInvalid after disable, got %v", err)
	}
}
