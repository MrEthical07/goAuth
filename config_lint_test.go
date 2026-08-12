package goAuth

import (
	"testing"
	"time"
)

func TestLint_DefaultConfigNoWarnings(t *testing.T) {
	// The default config is intentionally non-production (ProductionMode=false),
	// so it will have some warnings. But it should NOT have "dangerous" warnings
	// like disabled login-failure limiting or contradictory mode settings.
	cfg := defaultConfig()
	ws := cfg.Lint()

	codes := ws.Codes()

	if containsCode(codes, "login_failure_limiter_disabled") {
		t.Error("default config should not have login_failure_limiter_disabled")
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
		"login_failure_limiter_disabled",
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

func TestLint_HybridEnforcedDeviceBindingIsInfo(t *testing.T) {
	cfg := defaultConfig()
	cfg.ValidationMode = ModeHybrid
	cfg.DeviceBinding.Enabled = true
	cfg.DeviceBinding.EnforceIPBinding = true
	ws := cfg.Lint()

	found := false
	for _, w := range ws {
		if w.Code != "hybrid_enforcement_strict_routes_only" {
			continue
		}
		found = true
		if w.Severity != LintInfo {
			t.Errorf("hybrid_enforcement_strict_routes_only should be INFO, got %s", w.Severity)
		}
	}
	if !found {
		t.Fatal("expected hybrid_enforcement_strict_routes_only warning")
	}
}

func TestLint_StrictEnforcedDeviceBindingNoHybridNote(t *testing.T) {
	cfg := HighSecurityConfig()
	ws := cfg.Lint()
	if containsCode(ws.Codes(), "hybrid_enforcement_strict_routes_only") {
		t.Error("strict engine should not produce hybrid_enforcement_strict_routes_only")
	}
}

func TestLint_LoginFailureLimiterDisabled(t *testing.T) {
	cfg := defaultConfig()
	cfg.Security.EnableLoginFailureLimiter = false
	ws := cfg.Lint()
	if !containsCode(ws.Codes(), "login_failure_limiter_disabled") {
		t.Error("expected login_failure_limiter_disabled warning")
	}
}

func TestLint_LoginFailureLimiterDisabledIsHigh(t *testing.T) {
	cfg := defaultConfig()
	cfg.Security.EnableLoginFailureLimiter = false
	ws := cfg.Lint()

	found := false
	for _, w := range ws {
		if w.Code != "login_failure_limiter_disabled" {
			continue
		}
		found = true
		if w.Severity != LintHigh {
			t.Errorf("login_failure_limiter_disabled should be HIGH, got %s", w.Severity)
		}
	}

	if !found {
		t.Fatal("expected login_failure_limiter_disabled warning")
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

func TestLint_MaxSessionDurationCapsDefault(t *testing.T) {
	cfg := defaultConfig()
	cfg.Session.MaxSessionDuration = time.Hour // below min(RefreshTTL, AbsoluteSessionLifetime) = 7d
	ws := cfg.Lint()
	if !containsCode(ws.Codes(), "max_session_duration_caps_default") {
		t.Error("expected max_session_duration_caps_default warning")
	}
}

func TestLint_MaxSessionDurationNoCapWarningWhenAboveDefault(t *testing.T) {
	cfg := defaultConfig()
	cfg.Session.MaxSessionDuration = 14 * 24 * time.Hour
	ws := cfg.Lint()
	if containsCode(ws.Codes(), "max_session_duration_caps_default") {
		t.Error("should not warn when MaxSessionDuration exceeds the default lifetime")
	}
}

func TestLint_MaxSessionDurationLong(t *testing.T) {
	cfg := defaultConfig()
	cfg.Session.MaxSessionDuration = 60 * 24 * time.Hour
	ws := cfg.Lint()
	if !containsCode(ws.Codes(), "max_session_duration_long") {
		t.Error("expected max_session_duration_long warning")
	}
}

func TestLint_MaxSessionDurationUnsetNotLong(t *testing.T) {
	cfg := defaultConfig()
	ws := cfg.Lint()
	if containsCode(ws.Codes(), "max_session_duration_long") {
		t.Error("default config resolves to 7d and should not warn max_session_duration_long")
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

func TestLint_NoOpKnobs(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*Config)
		code     string
		severity LintSeverity
	}{
		{"security_ip_binding", func(c *Config) { c.Security.EnableIPBinding = true }, "security_ip_binding_noop", LintWarn},
		{"security_ip_signal", func(c *Config) { c.Security.EnableIPSignal = true }, "security_ip_signal_noop", LintWarn},
		{"cache_lru", func(c *Config) { c.Cache.LRUEnabled = true }, "cache_lru_noop", LintWarn},
		{"database_address", func(c *Config) { c.Database.Address = "localhost:6379" }, "database_config_noop", LintInfo},
		{"tenant_header", func(c *Config) { c.MultiTenant.Enabled = true }, "tenant_header_noop", LintInfo},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := defaultConfig()
			tc.mutate(&cfg)
			found := false
			for _, w := range cfg.Lint() {
				if w.Code != tc.code {
					continue
				}
				found = true
				if w.Severity != tc.severity {
					t.Errorf("%s should be %s, got %s", tc.code, tc.severity, w.Severity)
				}
			}
			if !found {
				t.Fatalf("expected %s warning", tc.code)
			}
		})
	}
}

func TestLint_NoOpKnobsSilentWhenUnset(t *testing.T) {
	cfg := defaultConfig()
	codes := cfg.Lint().Codes()
	for _, code := range []string{
		"security_ip_binding_noop",
		"security_ip_signal_noop",
		"cache_lru_noop",
		"database_config_noop",
		"tenant_header_noop",
	} {
		if containsCode(codes, code) {
			t.Errorf("default config should not produce %s", code)
		}
	}
}

func TestLint_CookieSettingsNoOpOnDefaults(t *testing.T) {
	// defaultConfig ships RequireSecureCookies/CSRFProtection enabled even
	// though the engine never issues cookies; the advisory lint fires at INFO
	// so integrators learn cookie/CSRF policy is theirs to enforce.
	cfg := defaultConfig()
	found := false
	for _, w := range cfg.Lint() {
		if w.Code != "cookie_settings_noop" {
			continue
		}
		found = true
		if w.Severity != LintInfo {
			t.Errorf("cookie_settings_noop should be INFO, got %s", w.Severity)
		}
	}
	if !found {
		t.Fatal("expected cookie_settings_noop warning")
	}

	cfg.Security.RequireSecureCookies = false
	cfg.Security.CSRFProtection = false
	cfg.Security.SameSitePolicy = 0
	if containsCode(cfg.Lint().Codes(), "cookie_settings_noop") {
		t.Error("cookie_settings_noop should not fire when all cookie knobs are unset")
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

func TestLint_DeprecatedEnforceIsolationWarns(t *testing.T) {
	cfg := defaultConfig()
	cfg.MultiTenant.EnforceIsolation = true

	if !containsCode(cfg.Lint().Codes(), "tenant_enforce_isolation_noop") {
		t.Error("expected tenant_enforce_isolation_noop when the deprecated field is set")
	}
}

// The field is deprecated and unread, so the shipped defaults must not set
// it — otherwise every consumer sees a deprecation warning for a value they
// never chose.
func TestLint_DefaultsDoNotTripDeprecationWarnings(t *testing.T) {
	for name, cfg := range map[string]Config{
		"DefaultConfig":        DefaultConfig(),
		"HighSecurityConfig":   HighSecurityConfig(),
		"HighThroughputConfig": HighThroughputConfig(),
	} {
		codes := cfg.Lint().Codes()
		for _, code := range []string{
			"tenant_enforce_isolation_noop",
			"account_duplicate_identifier_provider_owned",
		} {
			if containsCode(codes, code) {
				t.Errorf("%s trips deprecation warning %q out of the box", name, code)
			}
		}
	}
}

func TestLint_DuplicateIdentifierIsProviderOwned(t *testing.T) {
	cfg := defaultConfig()
	cfg.Account.AllowDuplicateIdentifierAcrossTenants = true

	if !containsCode(cfg.Lint().Codes(), "account_duplicate_identifier_provider_owned") {
		t.Error("expected account_duplicate_identifier_provider_owned when the flag is set")
	}
}
