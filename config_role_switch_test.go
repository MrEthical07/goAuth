package goAuth

import (
	"strings"
	"testing"
	"time"
)

func roleSwitchEnabledConfig() Config {
	cfg := totpTestConfig()
	cfg.RoleSwitch.Enabled = true
	return cfg
}

func TestRoleSwitchConfigDefaultsAreDisabled(t *testing.T) {
	for name, cfg := range map[string]Config{
		"default":         DefaultConfig(),
		"high security":   HighSecurityConfig(),
		"high throughput": HighThroughputConfig(),
	} {
		rs := cfg.RoleSwitch
		if rs.Enabled || len(rs.StepUp) != 0 || rs.MaxAttempts != 0 || rs.Cooldown != 0 {
			t.Fatalf("%s preset changed the RoleSwitch zero value: %+v", name, rs)
		}
	}
}

func TestConfigValidateRoleSwitch(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"negative attempts", func(c *Config) { c.RoleSwitch.MaxAttempts = -1 }, "MaxAttempts"},
		{"negative cooldown", func(c *Config) { c.RoleSwitch.Cooldown = -time.Second }, "Cooldown"},
		{
			"negative max age",
			func(c *Config) {
				c.RoleSwitch.StepUp = map[string]RoleStepUpPolicy{"admin": {MaxAge: -time.Minute}}
			},
			"MaxAge",
		},
		{
			"blank role key",
			func(c *Config) {
				c.RoleSwitch.StepUp = map[string]RoleStepUpPolicy{" ": {MaxAge: time.Minute}}
			},
			"non-empty role",
		},
		{
			"require mfa without any second factor",
			func(c *Config) {
				c.TOTP.Enabled = false
				c.RoleSwitch.StepUp = map[string]RoleStepUpPolicy{"admin": {RequireMFA: true}}
			},
			"RequireMFA requires TOTP or WebAuthn",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := roleSwitchEnabledConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestConfigValidateRoleSwitchAccepts(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"enabled with defaults", func(c *Config) {}},
		{"require mfa with totp", func(c *Config) {
			c.RoleSwitch.StepUp = map[string]RoleStepUpPolicy{"admin": {RequireMFA: true, MaxAge: 10 * time.Minute}}
		}},
		{"require mfa with webauthn only", func(c *Config) {
			*c = webauthnTestConfig()
			c.RoleSwitch.Enabled = true
			c.RoleSwitch.StepUp = map[string]RoleStepUpPolicy{"admin": {RequireMFA: true}}
		}},
		{"recent authentication without mfa", func(c *Config) {
			c.TOTP.Enabled = false
			c.RoleSwitch.StepUp = map[string]RoleStepUpPolicy{"admin": {MaxAge: 5 * time.Minute}}
		}},
		{"explicit limiter", func(c *Config) {
			c.RoleSwitch.MaxAttempts = 3
			c.RoleSwitch.Cooldown = time.Minute
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := roleSwitchEnabledConfig()
			tc.mutate(&cfg)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("expected a valid config, got %v", err)
			}
		})
	}
}

func TestCloneConfigDeepCopiesRoleSwitchStepUp(t *testing.T) {
	cfg := roleSwitchEnabledConfig()
	cfg.RoleSwitch.StepUp = map[string]RoleStepUpPolicy{"admin": {RequireMFA: true}}

	cloned := cloneConfig(cfg)
	cloned.RoleSwitch.StepUp["admin"] = RoleStepUpPolicy{MaxAge: time.Hour}
	cloned.RoleSwitch.StepUp["root"] = RoleStepUpPolicy{RequireMFA: true}

	if got := cfg.RoleSwitch.StepUp["admin"]; !got.RequireMFA || got.MaxAge != 0 {
		t.Fatalf("mutating the clone changed the original: %+v", got)
	}
	if _, leaked := cfg.RoleSwitch.StepUp["root"]; leaked {
		t.Fatal("a key added to the clone leaked into the original")
	}

	empty := cloneConfig(Config{})
	if empty.RoleSwitch.StepUp != nil {
		t.Fatal("an empty StepUp should stay nil")
	}
}

func TestBuilderIgnoresCallerMutationOfStepUpAfterWithConfig(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	up := newRoleSwitchMockProvider()
	cfg := roleSwitchEnabledConfig()
	cfg.RoleSwitch.StepUp = map[string]RoleStepUpPolicy{"admin": {RequireMFA: true}}

	b := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"perm.read"}).
		WithRoles(map[string][]string{"member": {}, "admin": {"perm.read"}}).
		WithUserProvider(up)
	cfg.RoleSwitch.StepUp["admin"] = RoleStepUpPolicy{}

	engine, err := b.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if !engine.config.RoleSwitch.StepUp["admin"].RequireMFA {
		t.Fatal("engine saw the caller's later mutation of the step-up map")
	}
}

func TestLintRoleSwitchStatelessValidation(t *testing.T) {
	cases := []struct {
		name    string
		mode    ValidationMode
		enabled bool
		want    bool
	}{
		{"hybrid enabled", ModeHybrid, true, true},
		{"jwt-only enabled", ModeJWTOnly, true, true},
		{"strict enabled", ModeStrict, true, false},
		{"hybrid disabled", ModeHybrid, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := defaultConfig()
			cfg.ValidationMode = tc.mode
			cfg.RoleSwitch.Enabled = tc.enabled
			var found *LintWarning
			for _, w := range cfg.Lint() {
				if w.Code == "role_switch_stateless_validation" {
					w := w
					found = &w
				}
			}
			if (found != nil) != tc.want {
				t.Fatalf("lint warning present = %v, want %v", found != nil, tc.want)
			}
			if found != nil {
				if found.Severity != LintInfo {
					t.Fatalf("severity = %v, want info", found.Severity)
				}
				if !strings.Contains(found.Message, "docs/role_switching.md") {
					t.Fatalf("message should point at the revocation table: %q", found.Message)
				}
			}
		})
	}
}

func roleSwitchBuilder(t *testing.T, cfg Config, up UserProvider) (*Builder, func()) {
	t.Helper()
	mr, rdb := newTestRedis(t)
	return New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"perm.read"}).
		WithRoles(map[string][]string{"member": {}, "admin": {"perm.read"}}).
		WithUserProvider(up), mr.Close
}

func TestBuildRoleSwitchRequiresProviderCapability(t *testing.T) {
	cfg := roleSwitchEnabledConfig()
	b, done := roleSwitchBuilder(t, cfg, newTenantMockProvider())
	defer done()

	_, err := b.Build()
	if err == nil || !strings.Contains(err.Error(), "RoleSwitchProvider") {
		t.Fatalf("expected a RoleSwitchProvider capability error, got %v", err)
	}
}

func TestBuildRoleSwitchWithCapabilitySucceeds(t *testing.T) {
	cfg := roleSwitchEnabledConfig()
	b, done := roleSwitchBuilder(t, cfg, newRoleSwitchMockProvider())
	defer done()

	engine, err := b.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if engine.roleSwitchProvider == nil || engine.roleSwitchLimiter == nil {
		t.Fatal("role switching dependencies were not wired")
	}
}

func TestBuildRoleSwitchDisabledNeedsNoCapability(t *testing.T) {
	cfg := totpTestConfig()
	b, done := roleSwitchBuilder(t, cfg, newTenantMockProvider())
	defer done()

	engine, err := b.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if engine.roleSwitchProvider != nil || engine.roleSwitchLimiter != nil {
		t.Fatal("role switching dependencies must stay unset while the feature is off")
	}
}

func TestBuildRoleSwitchStepUpRoleMustBeRegistered(t *testing.T) {
	cfg := roleSwitchEnabledConfig()
	cfg.RoleSwitch.StepUp = map[string]RoleStepUpPolicy{"ghost": {RequireMFA: true}}
	b, done := roleSwitchBuilder(t, cfg, newRoleSwitchMockProvider())
	defer done()

	_, err := b.Build()
	if err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("expected an unregistered-role error naming the role, got %v", err)
	}
}
