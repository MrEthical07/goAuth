package goAuth

import (
	"strings"
	"testing"
)

func TestConfigValidateProductionRejectsWeakHS256Key(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Security.ProductionMode = true
	cfg.JWT.PrivateKey = []byte("weak-key")

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "256 bits") {
		t.Fatalf("expected weak HS256 key rejection, got %v", err)
	}
}

func TestConfigValidateProductionRejectsWeakArgon2(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Security.ProductionMode = true
	cfg.JWT.PrivateKey = []byte("12345678901234567890123456789012")
	cfg.Password.Memory = 32 * 1024

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "Memory") {
		t.Fatalf("expected weak argon2 rejection, got %v", err)
	}
}

func TestConfigValidateDangerousJWTOnlyDeviceBindingEnforceRejected(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeJWTOnly
	cfg.Security.EnableAccountVersionCheck = false
	cfg.DeviceBinding.Enabled = true
	cfg.DeviceBinding.EnforceIPBinding = true
	cfg.DeviceBinding.DetectIPChange = true

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "JWTOnly mode cannot enforce device binding") {
		t.Fatalf("expected jwt-only device binding enforce rejection, got %v", err)
	}
}

func TestConfigValidateDangerousJWTOnlyAccountVersionCheckRejected(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeJWTOnly
	cfg.Security.EnableAccountVersionCheck = true

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "JWTOnly mode cannot enforce AccountVersion checks") {
		t.Fatalf("expected jwt-only account version check rejection, got %v", err)
	}
}

func TestConfigValidateTOTPRequiredButDisabledRejected(t *testing.T) {
	cfg := accountTestConfig()
	cfg.TOTP.Enabled = false
	cfg.TOTP.RequireForLogin = true

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "RequireForLogin") {
		t.Fatalf("expected totp required without feature rejection, got %v", err)
	}
}

func TestConfigValidateDevModeAllowsRelaxedCrypto(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Security.ProductionMode = false
	cfg.Password.Memory = 8 * 1024
	cfg.Password.Time = 1
	cfg.Password.KeyLength = 16

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected relaxed dev config to pass, got %v", err)
	}
}

func TestBuildConfigImmutabilityAgainstExternalMutation(t *testing.T) {
	cfg := accountTestConfig()
	cfg.JWT.PrivateKey = []byte("01234567890123456789012345678901")

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	before := engine.config.JWT.PrivateKey[0]
	cfg.JWT.PrivateKey[0] = 'X'

	if engine.config.JWT.PrivateKey[0] != before {
		t.Fatal("engine config key mutated from external config after build")
	}
}

func TestSecurityReportReflectsPosture(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Security.ProductionMode = true
	cfg.JWT.PrivateKey = []byte("01234567890123456789012345678901")
	cfg.ValidationMode = ModeStrict
	cfg.SessionHardening.MaxSessionsPerUser = 2
	cfg.TOTP.Enabled = true
	cfg.TOTP.Issuer = "goAuth"
	cfg.EmailVerification.Enabled = true
	cfg.PasswordReset.Enabled = true

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	report := engine.SecurityReport()
	if !report.ProductionMode {
		t.Fatal("expected ProductionMode=true in report")
	}
	if report.SigningAlgorithm != "hs256" {
		t.Fatalf("expected hs256 signing algorithm in report, got %s", report.SigningAlgorithm)
	}
	if !report.StrictMode {
		t.Fatal("expected StrictMode=true in report")
	}
	if !report.TOTPEnabled || !report.BackupEnabled {
		t.Fatal("expected totp and backup enabled in report")
	}
	if !report.SessionCapsActive {
		t.Fatal("expected session caps active in report")
	}
	if !report.EmailVerificationActive || !report.PasswordResetActive {
		t.Fatal("expected email verification and password reset active in report")
	}
}

func TestBuilderStrictModeRequiresRedis(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeStrict

	_, err := New().WithConfig(cfg).Build()
	if err == nil || !strings.Contains(err.Error(), "Strict mode requires redis client") {
		t.Fatalf("expected strict mode redis requirement error, got %v", err)
	}
}

func TestBuilderSessionCapsRequireRedis(t *testing.T) {
	cfg := accountTestConfig()
	cfg.SessionHardening.MaxSessionsPerUser = 1

	_, err := New().WithConfig(cfg).Build()
	if err == nil || !strings.Contains(err.Error(), "SessionHardening requires redis client") {
		t.Fatalf("expected session hardening redis requirement error, got %v", err)
	}
}
