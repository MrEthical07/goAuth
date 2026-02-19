package goAuth

import (
	"testing"
	"time"
)

func TestLint_DefaultConfigNoWarnings(t *testing.T) {
	// The default config is intentionally non-production (ProductionMode=false),
	// so it will have some warnings. But it should NOT have "dangerous" warnings
	// like disabled rate limits or contradictory mode settings.
	cfg := defaultConfig()
	ws := cfg.Lint()

	codes := ws.Codes()

	// Default config has refresh throttle enabled but not IP throttle,
	// so we expect ip_throttle_disabled but NOT rate_limits_disabled.
	if containsCode(codes, "rate_limits_disabled") {
		t.Error("default config should not have rate_limits_disabled (refresh throttle is on)")
	}
}

func TestLint_HighSecurityConfigMinimalWarnings(t *testing.T) {
	cfg := HighSecurityConfig()
	ws := cfg.Lint()
	codes := ws.Codes()

	// High security should not warn about most things.
	unwanted := []string{
		"leeway_large",
		"access_ttl_long",
		"refresh_ttl_long",
		"rate_limits_disabled",
		"jwtonly_device_binding",
		"session_shorter_than_refresh",
	}
	for _, code := range unwanted {
		if containsCode(codes, code) {
			t.Errorf("HighSecurityConfig should not produce warning %q", code)
		}
	}
}

func TestLint_LargeLeeway(t *testing.T) {
	cfg := defaultConfig()
	cfg.JWT.Leeway = 90 * time.Second
	ws := cfg.Lint()
	if !containsCode(ws.Codes(), "leeway_large") {
		t.Error("expected leeway_large warning")
	}
}

func TestLint_LongAccessTTL(t *testing.T) {
	cfg := defaultConfig()
	cfg.JWT.AccessTTL = 15 * time.Minute
	ws := cfg.Lint()
	if !containsCode(ws.Codes(), "access_ttl_long") {
		t.Error("expected access_ttl_long warning")
	}
}

func TestLint_LongRefreshTTL(t *testing.T) {
	cfg := defaultConfig()
	cfg.JWT.RefreshTTL = 30 * 24 * time.Hour
	ws := cfg.Lint()
	if !containsCode(ws.Codes(), "refresh_ttl_long") {
		t.Error("expected refresh_ttl_long warning")
	}
}

func TestLint_JWTOnlyWithDeviceBinding(t *testing.T) {
	cfg := defaultConfig()
	cfg.ValidationMode = ModeJWTOnly
	cfg.DeviceBinding.Enabled = true
	cfg.DeviceBinding.DetectIPChange = true
	cfg.Security.EnableAccountVersionCheck = false // JWTOnly requires this
	ws := cfg.Lint()
	if !containsCode(ws.Codes(), "jwtonly_device_binding") {
		t.Error("expected jwtonly_device_binding warning")
	}
}

func TestLint_AllRateLimitsDisabled(t *testing.T) {
	cfg := defaultConfig()
	cfg.Security.EnableIPThrottle = false
	cfg.Security.EnableRefreshThrottle = false
	ws := cfg.Lint()
	if !containsCode(ws.Codes(), "rate_limits_disabled") {
		t.Error("expected rate_limits_disabled warning")
	}
}

func TestLint_SessionShorterThanRefresh(t *testing.T) {
	cfg := defaultConfig()
	cfg.Session.AbsoluteSessionLifetime = 1 * time.Hour
	cfg.JWT.RefreshTTL = 7 * 24 * time.Hour
	ws := cfg.Lint()
	if !containsCode(ws.Codes(), "session_shorter_than_refresh") {
		t.Error("expected session_shorter_than_refresh warning")
	}
}

func TestLint_AuditDisabled(t *testing.T) {
	cfg := defaultConfig()
	cfg.Audit.Enabled = false
	ws := cfg.Lint()
	if !containsCode(ws.Codes(), "audit_disabled") {
		t.Error("expected audit_disabled warning when audit is off")
	}
}

func TestLint_HS256Warning(t *testing.T) {
	cfg := defaultConfig()
	cfg.JWT.SigningMethod = "hs256"
	ws := cfg.Lint()
	if !containsCode(ws.Codes(), "signing_hs256") {
		t.Error("expected signing_hs256 warning")
	}
}

func TestLint_Argon2MemoryLow(t *testing.T) {
	cfg := defaultConfig()
	cfg.Password.Memory = 16 * 1024 // 16 MB, below 64 MB
	ws := cfg.Lint()
	if !containsCode(ws.Codes(), "argon2_memory_low") {
		t.Error("expected argon2_memory_low warning")
	}
}

func TestLint_NoWarningForGoodArgon2(t *testing.T) {
	cfg := defaultConfig()
	cfg.Password.Memory = 64 * 1024 // exactly 64 MB
	ws := cfg.Lint()
	if containsCode(ws.Codes(), "argon2_memory_low") {
		t.Error("should not warn when memory == 64 MB")
	}
}

func TestLint_SeverityAssignment(t *testing.T) {
	// HIGH: contradictory mode settings
	cfg := defaultConfig()
	cfg.ValidationMode = ModeJWTOnly
	cfg.DeviceBinding.Enabled = true
	cfg.DeviceBinding.DetectIPChange = true
	cfg.Security.EnableAccountVersionCheck = false
	ws := cfg.Lint()
	for _, w := range ws {
		if w.Code == "jwtonly_device_binding" {
			if w.Severity != LintHigh {
				t.Errorf("jwtonly_device_binding should be HIGH, got %s", w.Severity)
			}
		}
	}
}

func TestLint_AsError(t *testing.T) {
	cfg := defaultConfig()
	// Default config should not have HIGH severity issues
	if err := cfg.Lint().AsError(LintHigh); err != nil {
		t.Errorf("default config should not fail AsError(LintHigh): %v", err)
	}

	// Introduce a HIGH severity issue
	cfg.ValidationMode = ModeJWTOnly
	cfg.DeviceBinding.Enabled = true
	cfg.DeviceBinding.DetectIPChange = true
	cfg.Security.EnableAccountVersionCheck = false
	if err := cfg.Lint().AsError(LintHigh); err == nil {
		t.Error("expected AsError(LintHigh) to return error for contradictory config")
	}
}

func TestLint_BySeverity(t *testing.T) {
	cfg := defaultConfig()
	cfg.ValidationMode = ModeJWTOnly
	cfg.DeviceBinding.Enabled = true
	cfg.DeviceBinding.DetectIPChange = true
	cfg.Security.EnableAccountVersionCheck = false
	ws := cfg.Lint()

	high := ws.BySeverity(LintHigh)
	if len(high) == 0 {
		t.Error("expected at least one HIGH severity warning")
	}
	for _, w := range high {
		if w.Severity < LintHigh {
			t.Errorf("BySeverity(LintHigh) returned warning with severity %s", w.Severity)
		}
	}
}

// helpers

func containsCode(codes []string, code string) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}
