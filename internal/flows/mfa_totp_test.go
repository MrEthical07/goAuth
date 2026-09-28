package flows

import (
	"context"
	"errors"
	"testing"
)

func totpTestDeps() (TOTPDeps, *int) {
	enableCalls := 0
	return TOTPDeps{
		Enabled: true,
		GetUserByID: func(context.Context, string) (TOTPUser, error) {
			return TOTPUser{UserID: "u1", Identifier: "alice", TenantID: "t1"}, nil
		},
		AccountStatusError: func(uint8) error { return nil },
		GenerateSecret: func() ([]byte, string, error) {
			return []byte("raw-secret"), "BASE32SECRET", nil
		},
		ProvisionURI: func(secret, account string) string {
			return "otpauth://totp/" + account + "?secret=" + secret
		},
		EnableTOTP: func(context.Context, string, []byte) error {
			enableCalls++
			return nil
		},
		Errors: TOTPErrors{
			TOTPFeatureDisabled: errors.New("totp feature disabled"),
			EngineNotReady:      errors.New("engine not ready"),
			UserNotFound:        errors.New("user not found"),
			TOTPUnavailable:     errors.New("totp unavailable"),
			TOTPAlreadyEnabled:  errors.New("totp already enabled"),
		},
	}, &enableCalls
}

func TestGenerateTOTPSetupRefusesWhenAlreadyEnabled(t *testing.T) {
	deps, enableCalls := totpTestDeps()
	deps.GetTOTPSecret = func(context.Context, string) (*TOTPRecord, error) {
		return &TOTPRecord{Secret: []byte("existing"), Enabled: true}, nil
	}

	_, err := RunGenerateTOTPSetup(context.Background(), "u1", deps)
	if !errors.Is(err, deps.Errors.TOTPAlreadyEnabled) {
		t.Fatalf("expected ErrTOTPAlreadyEnabled, got %v", err)
	}
	if *enableCalls != 0 {
		t.Fatalf("expected EnableTOTP not to be called, got %d calls", *enableCalls)
	}
}

func TestGenerateTOTPSetupSucceedsWithNoExistingTOTP(t *testing.T) {
	deps, enableCalls := totpTestDeps()
	deps.GetTOTPSecret = func(context.Context, string) (*TOTPRecord, error) {
		return nil, nil
	}

	setup, err := RunGenerateTOTPSetup(context.Background(), "u1", deps)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if setup == nil || setup.SecretBase32 == "" {
		t.Fatal("expected a generated secret")
	}
	if *enableCalls != 1 {
		t.Fatalf("expected EnableTOTP to be called once, got %d calls", *enableCalls)
	}
}

func TestGenerateTOTPSetupSucceedsAfterUnconfirmedSetup(t *testing.T) {
	deps, enableCalls := totpTestDeps()
	deps.GetTOTPSecret = func(context.Context, string) (*TOTPRecord, error) {
		// A previous setup was started but never confirmed: Enabled is false
		// even though a secret is present.
		return &TOTPRecord{Secret: []byte("stale-secret"), Enabled: false}, nil
	}

	setup, err := RunGenerateTOTPSetup(context.Background(), "u1", deps)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if setup == nil || setup.SecretBase32 == "" {
		t.Fatal("expected a generated (replacement) secret")
	}
	if *enableCalls != 1 {
		t.Fatalf("expected EnableTOTP to be called once, got %d calls", *enableCalls)
	}
}

func TestGenerateTOTPSetupSucceedsWhenGetTOTPSecretErrors(t *testing.T) {
	deps, enableCalls := totpTestDeps()
	deps.GetTOTPSecret = func(context.Context, string) (*TOTPRecord, error) {
		return nil, errors.New("sql: no rows in result set")
	}

	setup, err := RunGenerateTOTPSetup(context.Background(), "u1", deps)
	if err != nil {
		t.Fatalf("expected success (v0.5.0 behavior preserved on provider error), got %v", err)
	}
	if setup == nil || setup.SecretBase32 == "" {
		t.Fatal("expected a generated secret")
	}
	if *enableCalls != 1 {
		t.Fatalf("expected EnableTOTP to be called once, got %d calls", *enableCalls)
	}
}

func TestProvisionTOTPRefusesWhenAlreadyEnabled(t *testing.T) {
	deps, enableCalls := totpTestDeps()
	deps.GetTOTPSecret = func(context.Context, string) (*TOTPRecord, error) {
		return &TOTPRecord{Secret: []byte("existing"), Enabled: true}, nil
	}

	_, err := RunProvisionTOTP(context.Background(), "u1", deps)
	if !errors.Is(err, deps.Errors.TOTPAlreadyEnabled) {
		t.Fatalf("expected ErrTOTPAlreadyEnabled, got %v", err)
	}
	if *enableCalls != 0 {
		t.Fatalf("expected EnableTOTP not to be called, got %d calls", *enableCalls)
	}
}

func TestProvisionTOTPSucceedsWithNoExistingTOTP(t *testing.T) {
	deps, enableCalls := totpTestDeps()
	deps.GetTOTPSecret = func(context.Context, string) (*TOTPRecord, error) {
		return nil, nil
	}

	provision, err := RunProvisionTOTP(context.Background(), "u1", deps)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if provision == nil || provision.Secret == "" {
		t.Fatal("expected a generated secret")
	}
	if *enableCalls != 1 {
		t.Fatalf("expected EnableTOTP to be called once, got %d calls", *enableCalls)
	}
}

func TestProvisionTOTPSucceedsAfterUnconfirmedSetup(t *testing.T) {
	deps, enableCalls := totpTestDeps()
	deps.GetTOTPSecret = func(context.Context, string) (*TOTPRecord, error) {
		return &TOTPRecord{Secret: []byte("stale-secret"), Enabled: false}, nil
	}

	provision, err := RunProvisionTOTP(context.Background(), "u1", deps)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if provision == nil || provision.Secret == "" {
		t.Fatal("expected a generated (replacement) secret")
	}
	if *enableCalls != 1 {
		t.Fatalf("expected EnableTOTP to be called once, got %d calls", *enableCalls)
	}
}

func TestProvisionTOTPSucceedsWhenGetTOTPSecretErrors(t *testing.T) {
	deps, enableCalls := totpTestDeps()
	deps.GetTOTPSecret = func(context.Context, string) (*TOTPRecord, error) {
		return nil, errors.New("sql: no rows in result set")
	}

	provision, err := RunProvisionTOTP(context.Background(), "u1", deps)
	if err != nil {
		t.Fatalf("expected success (v0.5.0 behavior preserved on provider error), got %v", err)
	}
	if provision == nil || provision.Secret == "" {
		t.Fatal("expected a generated secret")
	}
	if *enableCalls != 1 {
		t.Fatalf("expected EnableTOTP to be called once, got %d calls", *enableCalls)
	}
}

// TestGenerateTOTPSetupNilGetTOTPSecretProceeds locks in that leaving
// GetTOTPSecret unset (a caller that has not wired the guard's dependency)
// behaves exactly like v0.5.0: no guard, setup proceeds.
func TestGenerateTOTPSetupNilGetTOTPSecretProceeds(t *testing.T) {
	deps, enableCalls := totpTestDeps()
	deps.GetTOTPSecret = nil

	_, err := RunGenerateTOTPSetup(context.Background(), "u1", deps)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if *enableCalls != 1 {
		t.Fatalf("expected EnableTOTP to be called once, got %d calls", *enableCalls)
	}
}
