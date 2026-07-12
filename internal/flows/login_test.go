package flows

import (
	"context"
	"errors"
	"testing"
)

func timingTestDeps(verifyCalls *int) LoginDeps {
	return LoginDeps{
		AccountStatusError: func(uint8) error { return nil },
		GetUserByIdentifier: func(string) (LoginUserRecord, error) {
			return LoginUserRecord{}, errors.New("user not found")
		},
		VerifyPassword: func(string, string) (bool, error) {
			*verifyCalls++
			return false, nil
		},
		IssueLoginSessionTokens: func(context.Context, string, LoginUserRecord, string, bool) (string, string, error) {
			return "", "", errors.New("unexpected token issuance")
		},
		EnforceSessionHardening: func(context.Context, string, string) error { return nil },
		Errors: LoginErrors{
			EngineNotReady:     errors.New("engine not ready"),
			InvalidCredentials: errors.New("invalid credentials"),
		},
	}
}

func TestLoginUnknownUserPerformsDummyVerification(t *testing.T) {
	verifyCalls := 0
	deps := timingTestDeps(&verifyCalls)

	_, err := RunLoginWithResult(context.Background(), "ghost", "some-password", LoginOptions{}, deps)
	if !errors.Is(err, deps.Errors.InvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
	if verifyCalls != 1 {
		t.Fatalf("expected exactly 1 dummy password verification on unknown user, got %d", verifyCalls)
	}
}

func TestLoginEmptyPasswordPerformsDummyVerification(t *testing.T) {
	verifyCalls := 0
	deps := timingTestDeps(&verifyCalls)

	_, err := RunLoginWithResult(context.Background(), "ghost", "", LoginOptions{}, deps)
	if !errors.Is(err, deps.Errors.InvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
	if verifyCalls != 1 {
		t.Fatalf("expected exactly 1 dummy password verification on empty password, got %d", verifyCalls)
	}
}
