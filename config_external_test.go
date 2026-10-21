package goAuth

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func externalEnabledConfig() Config {
	cfg := totpTestConfig()
	cfg.ExternalAuth.Enabled = true
	cfg.ExternalAuth.Providers = map[string]ExternalProviderConfig{
		"google": {Kind: ExternalKindGoogle, ClientIDs: []string{"web.apps.googleusercontent.com"}},
	}
	return cfg
}

// NEW-API.
func TestExternalAuthConfigDefaultsAreDisabled(t *testing.T) {
	for name, cfg := range map[string]Config{
		"default":         DefaultConfig(),
		"high security":   HighSecurityConfig(),
		"high throughput": HighThroughputConfig(),
	} {
		if !reflect.DeepEqual(cfg.ExternalAuth, ExternalAuthConfig{}) {
			t.Fatalf("%s preset changed the ExternalAuth zero value: %+v", name, cfg.ExternalAuth)
		}
	}
}

// A disabled feature is not inspected, so stray settings cannot break Build.
//
// NEW-API.
func TestExternalAuthDisabledIsNotValidated(t *testing.T) {
	cfg := totpTestConfig()
	cfg.ExternalAuth.Providers = map[string]ExternalProviderConfig{"BAD NAME": {Kind: "nope"}}
	cfg.ExternalAuth.AllowSignup = true
	cfg.ExternalAuth.ClockLeeway = time.Hour
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a disabled ExternalAuth was validated: %v", err)
	}
}

func oneProvider(p ExternalProviderConfig) func(*Config) {
	return func(c *Config) {
		c.ExternalAuth.Providers = map[string]ExternalProviderConfig{"x": p}
	}
}

// NEW-API.
func TestConfigValidateExternalAuth(t *testing.T) {
	oidcBase := ExternalProviderConfig{Kind: "oidc", ClientIDs: []string{"a"}, Issuer: "https://i.test", JWKSURL: "https://i.test/k"}
	withAlg := func(alg string) ExternalProviderConfig {
		p := oidcBase
		p.Algorithms = []string{alg}
		return p
	}
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"no providers", func(c *Config) { c.ExternalAuth.Providers = nil }, "no Providers"},
		{"bad provider name", func(c *Config) {
			c.ExternalAuth.Providers = map[string]ExternalProviderConfig{"Google!": {Kind: "google", ClientIDs: []string{"a"}}}
		}, "[a-z0-9_-]"},
		{"provider name too long", func(c *Config) {
			c.ExternalAuth.Providers = map[string]ExternalProviderConfig{strings.Repeat("a", 33): {Kind: "google", ClientIDs: []string{"a"}}}
		}, "[a-z0-9_-]"},
		{"unknown kind", oneProvider(ExternalProviderConfig{Kind: "github", ClientIDs: []string{"a"}}), "Kind"},
		{"empty kind", oneProvider(ExternalProviderConfig{ClientIDs: []string{"a"}}), "Kind"},
		{"no client ids", oneProvider(ExternalProviderConfig{Kind: "google"}), "ClientIDs"},
		{"blank client id", oneProvider(ExternalProviderConfig{Kind: "google", ClientIDs: []string{"a", " "}}), "ClientIDs"},
		{"oidc without issuer", oneProvider(ExternalProviderConfig{Kind: "oidc", ClientIDs: []string{"a"}, JWKSURL: "https://i.test/k"}), "Issuer is required"},
		{"oidc without jwks url", oneProvider(ExternalProviderConfig{Kind: "oidc", ClientIDs: []string{"a"}, Issuer: "https://i.test"}), "JWKSURL is required"},
		{"http jwks url", oneProvider(ExternalProviderConfig{Kind: "google", ClientIDs: []string{"a"}, JWKSURL: "http://keys.test/k"}), "JWKSURL must be an https"},
		{"scheme-less jwks url", oneProvider(ExternalProviderConfig{Kind: "google", ClientIDs: []string{"a"}, JWKSURL: "keys.test/k"}), "JWKSURL must be an https"},
		{"http issuer", oneProvider(ExternalProviderConfig{Kind: "apple", ClientIDs: []string{"a"}, Issuer: "http://i.test"}), "Issuer must be an https"},
		{"hosted domains on apple", oneProvider(ExternalProviderConfig{Kind: "apple", ClientIDs: []string{"a"}, AllowedHostedDomains: []string{"example.com"}}), "AllowedHostedDomains"},
		{"hosted domain that is an email", oneProvider(ExternalProviderConfig{Kind: "google", ClientIDs: []string{"a"}, AllowedHostedDomains: []string{"me@example.com"}}), "AllowedHostedDomains"},
		{"algorithms on google", oneProvider(ExternalProviderConfig{Kind: "google", ClientIDs: []string{"a"}, Algorithms: []string{"RS256"}}), "Algorithms"},
		{"HS256", oneProvider(withAlg("HS256")), "not allowed"},
		{"none", oneProvider(withAlg("none")), "not allowed"},
		{"PS256", oneProvider(withAlg("PS256")), "not allowed"},
		{"negative attempts", func(c *Config) { c.ExternalAuth.MaxAttempts = -1 }, "MaxAttempts"},
		{"negative cooldown", func(c *Config) { c.ExternalAuth.Cooldown = -time.Second }, "Cooldown"},
		{"negative leeway", func(c *Config) { c.ExternalAuth.ClockLeeway = -time.Second }, "ClockLeeway"},
		{"leeway above 5m", func(c *Config) { c.ExternalAuth.ClockLeeway = 5*time.Minute + time.Second }, "ClockLeeway"},
		{"refresh min below 1s", func(c *Config) { c.ExternalAuth.KeyRefreshMin = time.Millisecond }, "KeyRefreshMin"},
		{"refresh min above 24h", func(c *Config) { c.ExternalAuth.KeyRefreshMin = 25 * time.Hour }, "KeyRefreshMin"},
		{"negative max stale", func(c *Config) { c.ExternalAuth.KeyMaxStale = -time.Hour }, "KeyMaxStale"},
		{"max stale above 30d", func(c *Config) { c.ExternalAuth.KeyMaxStale = 31 * 24 * time.Hour }, "KeyMaxStale"},
		{"max stale below refresh min", func(c *Config) {
			c.ExternalAuth.KeyRefreshMin = time.Hour
			c.ExternalAuth.KeyMaxStale = time.Minute
		}, "KeyMaxStale"},
		{"two providers accepting the same token", func(c *Config) {
			c.ExternalAuth.Providers["google-ios"] = ExternalProviderConfig{Kind: "google", ClientIDs: []string{"web.apps.googleusercontent.com", "ios"}}
		}, "accept the same issuer and client ID"},
		{"max stale below the default refresh minimum", func(c *Config) {
			c.ExternalAuth.KeyMaxStale = time.Second
		}, "KeyMaxStale must be >= KeyRefreshMin"},
		{"signup without accounts", func(c *Config) {
			c.Account.Enabled = false
			c.ExternalAuth.AllowSignup = true
		}, "AllowSignup requires Account.Enabled"},
		{"auto link without email verification", func(c *Config) {
			c.EmailVerification.Enabled = false
			c.ExternalAuth.AutoLinkVerifiedEmail = true
		}, "AutoLinkVerifiedEmail requires EmailVerification.Enabled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := externalEnabledConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// NEW-API.
func TestConfigValidateExternalAuthAccepts(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"google with defaults", func(c *Config) {}},
		{"apple with services id and bundle id", func(c *Config) {
			c.ExternalAuth.Providers = map[string]ExternalProviderConfig{"apple": {Kind: "apple", ClientIDs: []string{"com.example.web", "com.example.app"}}}
		}},
		{"google with hosted domains and an override", func(c *Config) {
			c.ExternalAuth.Providers = map[string]ExternalProviderConfig{"workspace": {
				Kind: "google", ClientIDs: []string{"a"}, AllowedHostedDomains: []string{"example.com"},
				Issuer: "https://accounts.google.com", JWKSURL: "https://keys.test/k",
			}}
		}},
		{"oidc with every algorithm", func(c *Config) {
			c.ExternalAuth.Providers = map[string]ExternalProviderConfig{"corp-sso": {
				Kind: "oidc", ClientIDs: []string{"a"}, Issuer: "https://sso.test/tenant/v2.0", JWKSURL: "https://sso.test/keys",
				Algorithms: []string{"RS256", "RS384", "RS512", "ES256", "ES384"},
			}}
		}},
		{"several providers", func(c *Config) {
			c.ExternalAuth.Providers["apple"] = ExternalProviderConfig{Kind: "apple", ClientIDs: []string{"a"}}
		}},
		{"providers of one kind with disjoint client IDs", func(c *Config) {
			c.ExternalAuth.Providers["google-ios"] = ExternalProviderConfig{Kind: "google", ClientIDs: []string{"ios"}}
		}},
		{"providers sharing a client ID under different issuers", func(c *Config) {
			c.ExternalAuth.Providers["apple"] = ExternalProviderConfig{Kind: "apple", ClientIDs: []string{"web.apps.googleusercontent.com"}}
		}},
		{"all durations at their bounds", func(c *Config) {
			c.ExternalAuth.ClockLeeway = 5 * time.Minute
			c.ExternalAuth.KeyRefreshMin = 24 * time.Hour
			c.ExternalAuth.KeyMaxStale = 30 * 24 * time.Hour
			c.ExternalAuth.MaxAttempts = 1
			c.ExternalAuth.Cooldown = time.Second
		}},
		{"max stale equal to an explicit refresh minimum", func(c *Config) {
			c.ExternalAuth.KeyRefreshMin = time.Second
			c.ExternalAuth.KeyMaxStale = time.Second
		}},
		{"signup with accounts", func(c *Config) {
			c.Account.Enabled = true
			c.ExternalAuth.AllowSignup = true
		}},
		{"auto link with email verification", func(c *Config) {
			c.EmailVerification.Enabled = true
			c.ExternalAuth.AutoLinkVerifiedEmail = true
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := externalEnabledConfig()
			tc.mutate(&cfg)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

// cloneConfig must not share the maps and slices a caller can still mutate.
//
// NEW-API.
func TestCloneConfigDeepCopiesExternalAuth(t *testing.T) {
	cfg := externalEnabledConfig()
	cfg.ExternalAuth.Providers = map[string]ExternalProviderConfig{
		"google": {Kind: "google", ClientIDs: []string{"a", "b"}, AllowedHostedDomains: []string{"example.com"}},
		"corp":   {Kind: "oidc", ClientIDs: []string{"c"}, Issuer: "https://i.test", JWKSURL: "https://i.test/k", Algorithms: []string{"RS256"}},
	}
	clone := cloneConfig(cfg)

	cfg.ExternalAuth.Providers["google"].ClientIDs[0] = "mutated"
	cfg.ExternalAuth.Providers["google"].AllowedHostedDomains[0] = "mutated"
	cfg.ExternalAuth.Providers["corp"].Algorithms[0] = "mutated"
	cfg.ExternalAuth.Providers["added"] = ExternalProviderConfig{}

	got := clone.ExternalAuth.Providers
	if got["google"].ClientIDs[0] != "a" || got["google"].AllowedHostedDomains[0] != "example.com" || got["corp"].Algorithms[0] != "RS256" {
		t.Fatalf("clone shares slices with the original: %+v", got)
	}
	if _, ok := got["added"]; ok || len(got) != 2 {
		t.Fatalf("clone shares the map with the original: %+v", got)
	}

	if cloneConfig(Config{}).ExternalAuth.Providers != nil {
		t.Fatal("the zero value must clone to nil")
	}
}

func lintSeverityOf(cfg Config, code string) (LintSeverity, bool) {
	for _, w := range cfg.Lint() {
		if w.Code == code {
			return w.Severity, true
		}
	}
	return 0, false
}

// NEW-API.
func TestLintExternalAuth(t *testing.T) {
	cfg := externalEnabledConfig()
	for _, code := range []string{"external_signup_passwordless", "external_key_max_stale_long"} {
		if _, found := lintSeverityOf(cfg, code); found {
			t.Fatalf("plain enabled config warned %s", code)
		}
	}

	cfg.Account.Enabled = true
	cfg.ExternalAuth.AllowSignup = true
	if sev, found := lintSeverityOf(cfg, "external_signup_passwordless"); !found || sev != LintInfo {
		t.Fatalf("external_signup_passwordless = %v, %v; want INFO", sev, found)
	}

	cfg = externalEnabledConfig()
	if _, found := lintSeverityOf(cfg, "external_autolink_trusts_active_status"); found {
		t.Fatal("auto-link warned while off")
	}
	cfg.EmailVerification.Enabled = true
	cfg.ExternalAuth.AutoLinkVerifiedEmail = true
	if sev, found := lintSeverityOf(cfg, "external_autolink_trusts_active_status"); !found || sev != LintInfo {
		t.Fatalf("external_autolink_trusts_active_status = %v, %v; want INFO", sev, found)
	}

	cfg = externalEnabledConfig()
	cfg.ExternalAuth.KeyMaxStale = 72 * time.Hour
	if _, found := lintSeverityOf(cfg, "external_key_max_stale_long"); found {
		t.Fatal("72h is the limit, not over it")
	}
	cfg.ExternalAuth.KeyMaxStale = 72*time.Hour + time.Second
	if sev, found := lintSeverityOf(cfg, "external_key_max_stale_long"); !found || sev != LintWarn {
		t.Fatalf("external_key_max_stale_long = %v, %v; want WARN", sev, found)
	}

	off := totpTestConfig()
	off.ExternalAuth.AllowSignup = true
	off.ExternalAuth.KeyMaxStale = 100 * time.Hour
	for _, code := range []string{"external_signup_passwordless", "external_key_max_stale_long"} {
		if _, found := lintSeverityOf(off, code); found {
			t.Fatalf("a disabled feature was linted: %s", code)
		}
	}
}
