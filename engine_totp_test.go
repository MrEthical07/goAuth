package goAuth

import (
	"context"
	"encoding/base32"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal"
)

func totpTestConfig() Config {
	cfg := accountTestConfig()
	cfg.TOTP.Enabled = true
	cfg.TOTP.Issuer = "goAuth"
	cfg.TOTP.Digits = 6
	cfg.TOTP.Period = 30
	cfg.TOTP.Algorithm = "SHA1"
	cfg.TOTP.Skew = 1
	cfg.TOTP.EnforceReplayProtection = true
	cfg.TOTP.RequireForLogin = false
	cfg.TOTP.RequireForSensitive = false
	cfg.TOTP.RequireTOTPForPasswordReset = false
	return cfg
}

func codeForNow(t *testing.T, secret string, cfg TOTPConfig) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		t.Fatalf("decode secret failed: %v", err)
	}
	counter := time.Now().Unix() / int64(cfg.Period)
	code, err := hotpCode(key, counter, cfg.Digits, cfg.Algorithm)
	if err != nil {
		t.Fatalf("hotpCode failed: %v", err)
	}
	return code
}

func codeForOffset(t *testing.T, secret string, cfg TOTPConfig, offset int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		t.Fatalf("decode secret failed: %v", err)
	}
	counter := (time.Now().Unix() / int64(cfg.Period)) + offset
	code, err := hotpCode(key, counter, cfg.Digits, cfg.Algorithm)
	if err != nil {
		t.Fatalf("hotpCode failed: %v", err)
	}
	return code
}

func TestTOTPProvisionReturnsSecretAndURI(t *testing.T) {
	cfg := totpTestConfig()
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	provision, err := engine.ProvisionTOTP(context.Background(), "u1")
	if err != nil {
		t.Fatalf("ProvisionTOTP failed: %v", err)
	}
	if provision == nil || provision.Secret == "" || provision.URI == "" {
		t.Fatal("expected secret and uri from provision")
	}
	if !strings.HasPrefix(provision.URI, "otpauth://totp/") {
		t.Fatalf("expected otpauth uri, got %s", provision.URI)
	}
	if up.users["u1"].TOTPEnabled {
		t.Fatal("expected TOTP to remain disabled after provisioning")
	}
}

func TestTOTPConfirmSetupEnablesAndInvalidatesSessions(t *testing.T) {
	cfg := totpTestConfig()
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	_, refresh, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	sid, _, err := internal.DecodeRefreshToken(refresh)
	if err != nil {
		t.Fatalf("decode refresh failed: %v", err)
	}

	provision, err := engine.ProvisionTOTP(context.Background(), "u1")
	if err != nil {
		t.Fatalf("ProvisionTOTP failed: %v", err)
	}
	code := codeForNow(t, provision.Secret, cfg.TOTP)

	if err := engine.ConfirmTOTPSetup(context.Background(), "u1", code); err != nil {
		t.Fatalf("ConfirmTOTPSetup failed: %v", err)
	}
	if !up.users["u1"].TOTPEnabled {
		t.Fatal("expected TOTP enabled after confirmation")
	}

	if _, err := engine.sessionStore.Get(context.Background(), "0", sid, engine.sessionLifetime()); err == nil {
		t.Fatal("expected sessions invalidated after enabling TOTP")
	}
}

func TestTOTPConfirmSetupRejectsInvalidCode(t *testing.T) {
	cfg := totpTestConfig()
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	provision, err := engine.ProvisionTOTP(context.Background(), "u1")
	if err != nil {
		t.Fatalf("ProvisionTOTP failed: %v", err)
	}

	valid := codeForNow(t, provision.Secret, cfg.TOTP)
	invalid := valid
	if invalid[0] != '0' {
		invalid = "0" + invalid[1:]
	} else {
		invalid = "1" + invalid[1:]
	}

	if err := engine.ConfirmTOTPSetup(context.Background(), "u1", invalid); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("expected ErrTOTPInvalid, got %v", err)
	}
	if up.users["u1"].TOTPEnabled {
		t.Fatal("expected TOTP to stay disabled on invalid setup code")
	}

	if err := engine.ConfirmTOTPSetup(context.Background(), "u1", valid); err != nil {
		t.Fatalf("expected setup to succeed with valid code, got %v", err)
	}
}

func TestTOTPLoginFlowRequiredInvalidValid(t *testing.T) {
	cfg := totpTestConfig()
	cfg.TOTP.RequireForLogin = true
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	provision, err := engine.ProvisionTOTP(context.Background(), "u1")
	if err != nil {
		t.Fatalf("ProvisionTOTP failed: %v", err)
	}
	code := codeForNow(t, provision.Secret, cfg.TOTP)
	if err := engine.ConfirmTOTPSetup(context.Background(), "u1", code); err != nil {
		t.Fatalf("ConfirmTOTPSetup failed: %v", err)
	}

	if _, _, err := engine.Login(context.Background(), "alice", "correct-password-123"); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("expected ErrTOTPRequired, got %v", err)
	}
	if _, _, err := engine.LoginWithTOTP(context.Background(), "alice", "correct-password-123", "000000"); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("expected ErrTOTPInvalid, got %v", err)
	}

	valid := codeForOffset(t, provision.Secret, cfg.TOTP, 1)
	if _, _, err := engine.LoginWithTOTP(context.Background(), "alice", "correct-password-123", valid); err != nil {
		t.Fatalf("expected login success with valid totp, got %v", err)
	}
}

func TestTOTPDisableClearsAndInvalidatesSessions(t *testing.T) {
	cfg := totpTestConfig()
	cfg.TOTP.RequireForLogin = true
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	provision, err := engine.ProvisionTOTP(context.Background(), "u1")
	if err != nil {
		t.Fatalf("ProvisionTOTP failed: %v", err)
	}
	code := codeForNow(t, provision.Secret, cfg.TOTP)
	if err := engine.ConfirmTOTPSetup(context.Background(), "u1", code); err != nil {
		t.Fatalf("ConfirmTOTPSetup failed: %v", err)
	}

	access, refresh, err := engine.LoginWithTOTP(context.Background(), "alice", "correct-password-123", codeForOffset(t, provision.Secret, cfg.TOTP, 1))
	if err != nil || access == "" || refresh == "" {
		t.Fatalf("login with totp failed: %v", err)
	}
	sid, _, err := internal.DecodeRefreshToken(refresh)
	if err != nil {
		t.Fatalf("decode refresh failed: %v", err)
	}

	if err := engine.DisableTOTP(context.Background(), "u1"); err != nil {
		t.Fatalf("DisableTOTP failed: %v", err)
	}
	if up.users["u1"].TOTPEnabled {
		t.Fatal("expected TOTP disabled after disable call")
	}
	if _, ok := up.totpRecords["u1"]; ok {
		t.Fatal("expected TOTP secret cleared after disable")
	}
	if _, err := engine.sessionStore.Get(context.Background(), "0", sid, engine.sessionLifetime()); err == nil {
		t.Fatal("expected sessions invalidated after disabling TOTP")
	}
}

func TestTOTPPasswordResetRequirementPreservesChallenge(t *testing.T) {
	cfg := totpTestConfig()
	cfg.PasswordReset.Enabled = true
	cfg.PasswordReset.Strategy = ResetToken
	cfg.TOTP.RequireTOTPForPasswordReset = true
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	provision, err := engine.ProvisionTOTP(context.Background(), "u1")
	if err != nil {
		t.Fatalf("ProvisionTOTP failed: %v", err)
	}
	code := codeForNow(t, provision.Secret, cfg.TOTP)
	if err := engine.ConfirmTOTPSetup(context.Background(), "u1", code); err != nil {
		t.Fatalf("ConfirmTOTPSetup failed: %v", err)
	}

	challenge, err := engine.RequestPasswordReset(context.Background(), "alice")
	if err != nil {
		t.Fatalf("RequestPasswordReset failed: %v", err)
	}

	if err := engine.ConfirmPasswordReset(context.Background(), challenge, "new-password-123"); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("expected ErrTOTPRequired, got %v", err)
	}

	valid := codeForOffset(t, provision.Secret, cfg.TOTP, 1)
	if err := engine.ConfirmPasswordResetWithTOTP(context.Background(), challenge, "new-password-123", valid); err != nil {
		t.Fatalf("ConfirmPasswordResetWithTOTP failed: %v", err)
	}
}

func TestTOTPValidatePathNoProviderCallsRegression(t *testing.T) {
	cfg := totpTestConfig()
	cfg.ValidationMode = ModeStrict
	cfg.TOTP.RequireForLogin = true
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	provision, err := engine.ProvisionTOTP(context.Background(), "u1")
	if err != nil {
		t.Fatalf("ProvisionTOTP failed: %v", err)
	}
	if err := engine.ConfirmTOTPSetup(context.Background(), "u1", codeForNow(t, provision.Secret, cfg.TOTP)); err != nil {
		t.Fatalf("ConfirmTOTPSetup failed: %v", err)
	}

	access, _, err := engine.LoginWithTOTP(context.Background(), "alice", "correct-password-123", codeForOffset(t, provision.Secret, cfg.TOTP, 1))
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	up.getByIdentifierCalls = 0
	up.getByIDCalls = 0
	up.createCalls = 0
	up.updatePasswordCalls = 0
	up.updateStatusCalls = 0
	up.getTOTPSecretCalls = 0
	up.enableTOTPCalls = 0
	up.disableTOTPCalls = 0
	up.markTOTPVerifiedCalls = 0
	up.updateTOTPCounterCalls = 0

	if _, err := engine.Validate(context.Background(), access, ModeInherit); err != nil {
		t.Fatalf("validate failed: %v", err)
	}

	if up.getByIdentifierCalls != 0 || up.getByIDCalls != 0 || up.createCalls != 0 || up.updatePasswordCalls != 0 || up.updateStatusCalls != 0 ||
		up.getTOTPSecretCalls != 0 || up.enableTOTPCalls != 0 || up.disableTOTPCalls != 0 || up.markTOTPVerifiedCalls != 0 || up.updateTOTPCounterCalls != 0 {
		t.Fatalf("expected validate to avoid provider calls, got counts: %+v", up)
	}
}
