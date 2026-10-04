package flows

import (
	"context"
	"errors"
	"testing"
	"time"
)

type assuranceCall struct {
	tenantID     string
	refreshToken string
	method       string
	rememberMe   bool
}

func assuranceTestDeps(calls *[]assuranceCall) LoginDeps {
	errInvalid := errors.New("mfa invalid")
	return LoginDeps{
		TOTPEnabled:             true,
		RequireTOTPForLogin:     true,
		WebAuthnEnabled:         true,
		WebAuthnRequireForLogin: true,
		MFALoginMaxAttempts:     3,
		MFALoginChallengeTTL:    time.Minute,
		AccountStatusError:      func(uint8) error { return nil },
		GetMFAChallenge: func(context.Context, string) (*MFALoginChallengeRecord, error) {
			return &MFALoginChallengeRecord{UserID: "u1", TenantID: "t1", RememberMe: true}, nil
		},
		DeleteMFAChallenge: func(context.Context, string) (bool, error) { return true, nil },
		RecordMFAFailure:   func(context.Context, string, int) (bool, error) { return false, nil },
		GetUserByID: func(context.Context, string) (LoginUserRecord, error) {
			return LoginUserRecord{UserID: "u1", TenantID: "t1"}, nil
		},
		GetTOTPSecret: func(context.Context, string) (*LoginTOTPRecord, error) {
			return &LoginTOTPRecord{Secret: []byte("secret"), Enabled: true}, nil
		},
		VerifyTOTPCode: func(_ []byte, code string, _ time.Time) (bool, int64, error) {
			return code == "good", 1, nil
		},
		UpdateTOTPLastUsedCounter: func(context.Context, string, int64) error { return nil },
		VerifyBackupCodeInTenant: func(_ context.Context, _, _, code string) error {
			if code == "good" {
				return nil
			}
			return errInvalid
		},
		ConfirmWebAuthnAssertion: func(_ context.Context, _, _ string, assertion []byte) error {
			if string(assertion) == "good" {
				return nil
			}
			return errInvalid
		},
		IssueLoginSessionTokens: func(context.Context, string, LoginUserRecord, string, bool) (string, string, error) {
			return "access", "refresh-token", nil
		},
		RecordAssurance: func(_ context.Context, tenantID, refreshToken, method string, rememberMe bool) {
			*calls = append(*calls, assuranceCall{tenantID: tenantID, refreshToken: refreshToken, method: method, rememberMe: rememberMe})
		},
		Errors: LoginErrors{
			EngineNotReady:           errors.New("engine not ready"),
			MFALoginInvalid:          errInvalid,
			MFALoginAttemptsExceeded: errors.New("attempts exceeded"),
			MFALoginReplay:           errors.New("replay"),
			MFALoginUnavailable:      errors.New("unavailable"),
			UserNotFound:             errors.New("user not found"),
			BackupCodeInvalid:        errInvalid,
			BackupCodeRateLimited:    errors.New("rate limited"),
			BackupCodesNotConfigured: errors.New("not configured"),
		},
	}
}

func TestConfirmLoginMFARecordsAssuranceForEveryFactor(t *testing.T) {
	tests := []struct {
		name    string
		mfaType string
		code    string
		want    string
	}{
		{"default type is totp", "", "good", StepUpMethodTOTP},
		{"totp", "totp", "good", StepUpMethodTOTP},
		{"totp is case and space insensitive", " TOTP ", "good", StepUpMethodTOTP},
		{"backup code", "backup", "good", StepUpMethodBackupCode},
		{"webauthn", "webauthn", "good", "webauthn"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls []assuranceCall
			deps := assuranceTestDeps(&calls)

			result, err := RunConfirmLoginMFAWithType(context.Background(), "challenge", tc.code, tc.mfaType, deps)
			if err != nil {
				t.Fatalf("confirm failed: %v", err)
			}
			if result.RefreshToken != "refresh-token" {
				t.Fatalf("refresh token = %q", result.RefreshToken)
			}
			if len(calls) != 1 {
				t.Fatalf("RecordAssurance calls = %d, want 1", len(calls))
			}
			got := calls[0]
			if got.method != tc.want || got.tenantID != "t1" || got.refreshToken != "refresh-token" || !got.rememberMe {
				t.Fatalf("RecordAssurance(%+v), want method %q for tenant t1 with the issued refresh token and remember-me", got, tc.want)
			}
		})
	}
}

func TestConfirmLoginMFAWithoutRecorderIsUnchanged(t *testing.T) {
	var calls []assuranceCall
	deps := assuranceTestDeps(&calls)
	deps.RecordAssurance = nil

	if _, err := RunConfirmLoginMFAWithType(context.Background(), "challenge", "good", "totp", deps); err != nil {
		t.Fatalf("confirm failed: %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("a nil recorder must never be called, saw %d calls", len(calls))
	}
}

func TestConfirmLoginMFAFailureRecordsNoAssurance(t *testing.T) {
	for _, mfaType := range []string{"totp", "backup", "webauthn"} {
		t.Run(mfaType, func(t *testing.T) {
			var calls []assuranceCall
			deps := assuranceTestDeps(&calls)
			if _, err := RunConfirmLoginMFAWithType(context.Background(), "challenge", "bad", mfaType, deps); err == nil {
				t.Fatal("expected the wrong code to fail")
			}
			if len(calls) != 0 {
				t.Fatalf("a failed factor must not record an assurance, saw %d calls", len(calls))
			}
		})
	}
}

func TestPasswordOnlyLoginRecordsNoAssurance(t *testing.T) {
	var calls []assuranceCall
	deps := assuranceTestDeps(&calls)
	deps.TOTPEnabled, deps.RequireTOTPForLogin = false, false
	deps.WebAuthnEnabled, deps.WebAuthnRequireForLogin = false, false
	deps.GetUserByIdentifier = func(context.Context, string) (LoginUserRecord, error) {
		return LoginUserRecord{UserID: "u1", TenantID: "t1", PasswordHash: "hash"}, nil
	}
	deps.VerifyPassword = func(string, string) (bool, error) { return true, nil }
	deps.EnforceSessionHardening = func(context.Context, string, string) error { return nil }

	if _, err := RunLoginWithResult(context.Background(), "alice", "password", LoginOptions{}, deps); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("a password-only login must not record an MFA assurance, saw %d calls", len(calls))
	}
}
