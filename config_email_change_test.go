package goAuth

import (
	"strings"
	"testing"
	"time"
)

// EmailChangeConfig stays comparable with == (no maps or slices), and Config's
// own comparability is unchanged by it.
var _ = EmailChangeConfig{} == EmailChangeConfig{}

func emailChangeEnabledConfig() Config {
	cfg := totpTestConfig()
	cfg.EmailChange.Enabled = true
	return cfg
}

func TestEmailChangeConfigDefaultsAreDisabled(t *testing.T) {
	for name, cfg := range map[string]Config{
		"default":         DefaultConfig(),
		"high security":   HighSecurityConfig(),
		"high throughput": HighThroughputConfig(),
	} {
		if cfg.EmailChange != (EmailChangeConfig{}) {
			t.Fatalf("%s preset changed the EmailChange zero value: %+v", name, cfg.EmailChange)
		}
	}
}

func TestEmailChangeDisabledIsNotValidated(t *testing.T) {
	cfg := totpTestConfig()
	cfg.EmailChange = EmailChangeConfig{Strategy: 99, VerificationTTL: -1, MaxAttempts: -5}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a disabled feature must not be validated: %v", err)
	}
}

func TestConfigValidateEmailChange(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*EmailChangeConfig)
		wantErr string
	}{
		{"bad strategy", func(c *EmailChangeConfig) { c.Strategy = 99 }, "Strategy"},
		{"ttl below a minute", func(c *EmailChangeConfig) { c.VerificationTTL = 30 * time.Second }, "VerificationTTL"},
		{"ttl above a day", func(c *EmailChangeConfig) { c.VerificationTTL = 25 * time.Hour }, "VerificationTTL"},
		{"negative ttl", func(c *EmailChangeConfig) { c.VerificationTTL = -time.Minute }, "VerificationTTL"},
		{"negative attempts", func(c *EmailChangeConfig) { c.MaxAttempts = -1 }, "MaxAttempts"},
		{"negative request attempts", func(c *EmailChangeConfig) { c.RequestMaxAttempts = -1 }, "RequestMaxAttempts"},
		{"negative cooldown", func(c *EmailChangeConfig) { c.RequestCooldown = -time.Second }, "RequestCooldown"},
		{"negative digits", func(c *EmailChangeConfig) { c.OTPDigits = -6 }, "OTPDigits"},
		{"otp digits too few", func(c *EmailChangeConfig) { c.Strategy = VerificationOTP; c.OTPDigits = 5 }, "OTPDigits"},
		{"otp digits too many", func(c *EmailChangeConfig) { c.Strategy = VerificationOTP; c.OTPDigits = 11 }, "OTPDigits"},
		{"otp attempts", func(c *EmailChangeConfig) { c.Strategy = VerificationOTP; c.MaxAttempts = 6 }, "MaxAttempts"},
		{"otp ttl", func(c *EmailChangeConfig) { c.Strategy = VerificationOTP; c.VerificationTTL = 20 * time.Minute }, "VerificationTTL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := emailChangeEnabledConfig()
			tc.mutate(&cfg.EmailChange)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestConfigValidateEmailChangeAccepts(t *testing.T) {
	cases := map[string]func(*EmailChangeConfig){
		"zero values with Enabled": func(c *EmailChangeConfig) {},
		"token with a day": func(c *EmailChangeConfig) {
			c.Strategy = VerificationToken
			c.VerificationTTL = 24 * time.Hour
			c.MaxAttempts = 50
		},
		"uuid with a minute": func(c *EmailChangeConfig) { c.Strategy = VerificationUUID; c.VerificationTTL = time.Minute },
		"otp at its limits": func(c *EmailChangeConfig) {
			c.Strategy = VerificationOTP
			c.OTPDigits = 10
			c.MaxAttempts = 5
			c.VerificationTTL = 15 * time.Minute
		},
		"otp with the defaults":     func(c *EmailChangeConfig) { c.Strategy = VerificationOTP },
		"explicit limiter settings": func(c *EmailChangeConfig) { c.RequestMaxAttempts = 20; c.RequestCooldown = 24 * time.Hour },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := emailChangeEnabledConfig()
			mutate(&cfg.EmailChange)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

func TestEmailChangeResolvedDefaults(t *testing.T) {
	got := EmailChangeConfig{Enabled: true}.resolved()
	if got.VerificationTTL != 15*time.Minute || got.MaxAttempts != 5 || got.OTPDigits != 6 || got.Strategy != VerificationToken {
		t.Fatalf("resolved defaults = %+v", got)
	}
	keep := EmailChangeConfig{Enabled: true, VerificationTTL: time.Hour, MaxAttempts: 9, OTPDigits: 8}.resolved()
	if keep.VerificationTTL != time.Hour || keep.MaxAttempts != 9 || keep.OTPDigits != 8 {
		t.Fatalf("explicit values were overwritten: %+v", keep)
	}
}

func TestBuildEmailChangeRequiresProviderCapability(t *testing.T) {
	cfg := emailChangeEnabledConfig()
	b, done := roleSwitchBuilder(t, cfg, legacyOnlyProvider{})
	defer done()
	_, err := b.Build()
	if err == nil || !strings.Contains(err.Error(), "EmailChangeProvider") {
		t.Fatalf("expected an EmailChangeProvider capability error, got %v", err)
	}
}

func TestBuildEmailChangeWithCapabilitySucceeds(t *testing.T) {
	cfg := emailChangeEnabledConfig()
	b, done := roleSwitchBuilder(t, cfg, newTenantMockProvider())
	defer done()
	engine, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer engine.Close()
	if !engine.emailChangeEnabled() {
		t.Fatal("the engine did not enable email change")
	}
}

func TestBuildDisabledEmailChangeNeedsNoCapability(t *testing.T) {
	cfg := totpTestConfig()
	b, done := roleSwitchBuilder(t, cfg, legacyOnlyProvider{})
	defer done()
	engine, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer engine.Close()
	if engine.emailChangeEnabled() || engine.emailChangeStore != nil || engine.emailChangeLimiter != nil {
		t.Fatal("a disabled feature allocated email-change state")
	}
}

func TestEmailChangeLint(t *testing.T) {
	cfg := emailChangeEnabledConfig()
	if hasLintCode(cfg.Lint(), "email_change_keeps_other_sessions") {
		t.Fatal("lint reported KeepOtherSessions while it is off")
	}
	cfg.EmailChange.KeepOtherSessions = true
	var found *LintWarning
	for _, w := range cfg.Lint() {
		if w.Code == "email_change_keeps_other_sessions" {
			w := w
			found = &w
		}
	}
	if found == nil || found.Severity != LintInfo {
		t.Fatalf("expected an INFO note, got %+v", found)
	}
	cfg.EmailChange.Enabled = false
	if hasLintCode(cfg.Lint(), "email_change_keeps_other_sessions") {
		t.Fatal("lint reported a disabled feature")
	}
}
