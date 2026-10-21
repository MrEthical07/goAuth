package goAuth

import (
	"strings"
	"testing"
	"time"
)

const spDay = 24 * time.Hour

// dressinProfiles are the two profiles the first consumer needs: web is a
// fixed 15-spDay session, mobile a 90-spDay inactivity window with a 365-spDay
// ceiling that every strict read also renews.
func dressinProfiles() map[string]SessionProfile {
	return map[string]SessionProfile{
		"web":    {AbsoluteLifetime: 15 * spDay},
		"mobile": {IdleTimeout: 90 * spDay, AbsoluteLifetime: 365 * spDay, RenewOnUse: true},
	}
}

func profileConfig(mutate func(*Config)) Config {
	cfg := accountTestConfig()
	cfg.SessionProfiles.Profiles = dressinProfiles()
	cfg.SessionProfiles.DefaultProfile = "web"
	if mutate != nil {
		mutate(&cfg)
	}
	return cfg
}

func TestSessionProfilesConfigDefaultsAreEmpty(t *testing.T) {
	for name, cfg := range map[string]Config{
		"default":         DefaultConfig(),
		"high security":   HighSecurityConfig(),
		"high throughput": HighThroughputConfig(),
	} {
		s := cfg.SessionProfiles
		if len(s.Profiles) != 0 || s.DefaultProfile != "" || s.RememberMeProfile != "" {
			t.Fatalf("%s preset changed the session profile zero value: %+v", name, s)
		}
	}
}

func TestConfigValidateSessionProfiles(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string // empty: must validate
	}{
		{"valid dressin profiles", nil, ""},
		{"valid remember-me mapping", func(c *Config) { c.SessionProfiles.RememberMeProfile = "mobile" }, ""},
		{"valid unbounded renewing", func(c *Config) {
			c.SessionProfiles.Profiles["agent"] = SessionProfile{IdleTimeout: spDay, AllowUnbounded: true}
		}, ""},
		{"valid per-profile access ttl", func(c *Config) {
			c.SessionProfiles.Profiles["web"] = SessionProfile{AbsoluteLifetime: 15 * spDay, AccessTTL: time.Minute}
		}, ""},
		{"valid name characters", func(c *Config) {
			c.SessionProfiles.Profiles["a_b-9"] = SessionProfile{AbsoluteLifetime: spDay}
		}, ""},
		{"valid 32 char name", func(c *Config) {
			c.SessionProfiles.Profiles[strings.Repeat("a", 32)] = SessionProfile{AbsoluteLifetime: spDay}
		}, ""},

		{"profiles without default", func(c *Config) { c.SessionProfiles.DefaultProfile = "" }, "require DefaultProfile"},
		{"default not defined", func(c *Config) { c.SessionProfiles.DefaultProfile = "ghost" }, "not a defined profile"},
		{"remember-me not defined", func(c *Config) { c.SessionProfiles.RememberMeProfile = "ghost" }, "RememberMeProfile"},
		{"default without profiles", func(c *Config) { c.SessionProfiles.Profiles = nil }, "no Profiles are defined"},
		{"remember-me without profiles", func(c *Config) {
			c.SessionProfiles.Profiles = nil
			c.SessionProfiles.DefaultProfile = ""
			c.SessionProfiles.RememberMeProfile = "mobile"
		}, "no Profiles are defined"},
		{"empty name", func(c *Config) { c.SessionProfiles.Profiles[""] = SessionProfile{AbsoluteLifetime: spDay} }, "names must be"},
		{"uppercase name", func(c *Config) { c.SessionProfiles.Profiles["Web2"] = SessionProfile{AbsoluteLifetime: spDay} }, "names must be"},
		{"space in name", func(c *Config) { c.SessionProfiles.Profiles["a b"] = SessionProfile{AbsoluteLifetime: spDay} }, "names must be"},
		{"colon in name", func(c *Config) { c.SessionProfiles.Profiles["a:b"] = SessionProfile{AbsoluteLifetime: spDay} }, "names must be"},
		{"semicolon in name", func(c *Config) { c.SessionProfiles.Profiles["a;b"] = SessionProfile{AbsoluteLifetime: spDay} }, "names must be"},
		{"33 char name", func(c *Config) {
			c.SessionProfiles.Profiles[strings.Repeat("a", 33)] = SessionProfile{AbsoluteLifetime: spDay}
		}, "names must be"},
		{"negative access ttl", func(c *Config) {
			c.SessionProfiles.Profiles["web"] = SessionProfile{AbsoluteLifetime: spDay, AccessTTL: -time.Second}
		}, "AccessTTL must be >= 0"},
		{"negative idle", func(c *Config) {
			c.SessionProfiles.Profiles["web"] = SessionProfile{AbsoluteLifetime: spDay, IdleTimeout: -time.Second}
		}, "IdleTimeout must be >= 0"},
		{"negative absolute", func(c *Config) {
			c.SessionProfiles.Profiles["web"] = SessionProfile{AbsoluteLifetime: -time.Second}
		}, "AbsoluteLifetime must be >= 0"},
		{"zero profile", func(c *Config) { c.SessionProfiles.Profiles["web"] = SessionProfile{} }, "AbsoluteLifetime must be > 0 unless AllowUnbounded"},
		{"unbounded without opt-in", func(c *Config) {
			c.SessionProfiles.Profiles["agent"] = SessionProfile{IdleTimeout: spDay}
		}, "AbsoluteLifetime must be > 0 unless AllowUnbounded"},
		{"unbounded with a ceiling", func(c *Config) {
			c.SessionProfiles.Profiles["agent"] = SessionProfile{IdleTimeout: spDay, AbsoluteLifetime: 2 * spDay, AllowUnbounded: true}
		}, "mutually exclusive"},
		{"unbounded fixed", func(c *Config) {
			c.SessionProfiles.Profiles["agent"] = SessionProfile{AllowUnbounded: true}
		}, "AllowUnbounded requires IdleTimeout"},
		{"renew on use without idle", func(c *Config) {
			c.SessionProfiles.Profiles["web"] = SessionProfile{AbsoluteLifetime: spDay, RenewOnUse: true}
		}, "RenewOnUse requires IdleTimeout"},
		{"idle beyond ceiling", func(c *Config) {
			c.SessionProfiles.Profiles["mobile"] = SessionProfile{IdleTimeout: 2 * spDay, AbsoluteLifetime: spDay}
		}, "IdleTimeout must be <= AbsoluteLifetime"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := profileConfig(tc.mutate)
			err := cfg.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("Validate = %v, want success", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("Validate = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// productionProfileConfig is a ProductionMode config that validates before
// any profile is added, so a failure in the table below is the profile's.
func productionProfileConfig(t *testing.T, mutate func(*Config)) Config {
	t.Helper()
	cfg := HighSecurityConfig()
	cfg.JWT.SigningMethod = "hs256"
	cfg.JWT.PrivateKey = []byte("12345678901234567890123456789012")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("production base config does not validate: %v", err)
	}
	cfg.SessionProfiles.Profiles = map[string]SessionProfile{
		"web":    {AbsoluteLifetime: 15 * spDay},
		"mobile": {IdleTimeout: 90 * spDay, AbsoluteLifetime: 365 * spDay},
	}
	cfg.SessionProfiles.DefaultProfile = "web"
	if mutate != nil {
		mutate(&cfg)
	}
	return cfg
}

// AC5: ProductionMode limits, per profile.
func TestConfigValidateSessionProfilesProduction(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"dressin profiles are production-valid", nil, ""},
		{"fixed profile at 30d", func(c *Config) { c.SessionProfiles.Profiles["web"] = SessionProfile{AbsoluteLifetime: 30 * spDay} }, ""},
		{"renewing profile at 90d idle", func(c *Config) {
			c.SessionProfiles.Profiles["mobile"] = SessionProfile{IdleTimeout: 90 * spDay, AbsoluteLifetime: 400 * spDay}
		}, ""},
		{"unbounded renewing with opt-in", func(c *Config) {
			c.SessionProfiles.Profiles["agent"] = SessionProfile{IdleTimeout: spDay, AllowUnbounded: true}
		}, ""},
		{"access ttl 15m", func(c *Config) {
			c.SessionProfiles.Profiles["web"] = SessionProfile{AbsoluteLifetime: 15 * spDay, AccessTTL: 15 * time.Minute}
		}, ""},

		{"fixed profile beyond 30d", func(c *Config) {
			c.SessionProfiles.Profiles["web"] = SessionProfile{AbsoluteLifetime: 30*spDay + time.Second}
		}, "fixed Session Profile AbsoluteLifetime <= 30d"},
		{"renewing profile idle beyond 90d", func(c *Config) {
			c.SessionProfiles.Profiles["mobile"] = SessionProfile{IdleTimeout: 90*spDay + time.Second, AbsoluteLifetime: 365 * spDay}
		}, "IdleTimeout <= 90d"},
		{"access ttl beyond 15m", func(c *Config) {
			c.SessionProfiles.Profiles["web"] = SessionProfile{AbsoluteLifetime: 15 * spDay, AccessTTL: 15*time.Minute + time.Second}
		}, "access TTL <= 15m"},
		// A profile with no IdleTimeout is fixed by definition, so the only
		// way to ask for a renewing profile without one is RenewOnUse (or a
		// long ceiling that production then reads as a fixed profile).
		{"renewing profile without idle timeout", func(c *Config) {
			c.SessionProfiles.Profiles["mobile"] = SessionProfile{AbsoluteLifetime: 365 * spDay, RenewOnUse: true}
		}, "RenewOnUse requires IdleTimeout"},
		{"mobile profile that forgot its idle timeout", func(c *Config) {
			c.SessionProfiles.Profiles["mobile"] = SessionProfile{AbsoluteLifetime: 365 * spDay}
		}, "fixed Session Profile AbsoluteLifetime <= 30d"},
		{"unbounded renewing without opt-in", func(c *Config) {
			c.SessionProfiles.Profiles["agent"] = SessionProfile{IdleTimeout: spDay}
		}, "AbsoluteLifetime must be > 0 unless AllowUnbounded"},
		{"unbounded fixed", func(c *Config) {
			c.SessionProfiles.Profiles["agent"] = SessionProfile{}
		}, "AbsoluteLifetime must be > 0 unless AllowUnbounded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := productionProfileConfig(t, tc.mutate)
			err := cfg.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("Validate = %v, want success", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("Validate = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}

	// The same profiles are accepted outside ProductionMode: the limits are a
	// production-only guard.
	cfg := productionProfileConfig(t, func(c *Config) {
		c.Security.ProductionMode = false
		c.SessionProfiles.Profiles["web"] = SessionProfile{AbsoluteLifetime: 90 * spDay, AccessTTL: time.Hour}
		c.SessionProfiles.Profiles["mobile"] = SessionProfile{IdleTimeout: 200 * spDay, AbsoluteLifetime: 400 * spDay}
	})
	if err := cfg.Validate(); err != nil {
		t.Fatalf("non-production config rejected: %v", err)
	}
}

func TestSessionProfilesCloneConfigIsDeep(t *testing.T) {
	cfg := profileConfig(nil)
	cloned := cloneConfig(cfg)
	cloned.SessionProfiles.Profiles["web"] = SessionProfile{AbsoluteLifetime: time.Second}
	delete(cloned.SessionProfiles.Profiles, "mobile")

	if got := cfg.SessionProfiles.Profiles["web"].AbsoluteLifetime; got != 15*spDay {
		t.Fatalf("mutating the clone changed the original: web = %v", got)
	}
	if _, ok := cfg.SessionProfiles.Profiles["mobile"]; !ok {
		t.Fatal("deleting from the clone removed the original's profile")
	}
	if got := cloneConfig(DefaultConfig()).SessionProfiles.Profiles; got != nil {
		t.Fatalf("a config without profiles must clone to nil, got %v", got)
	}
}

func TestLint_SessionProfiles(t *testing.T) {
	lint := func(mutate func(*Config)) LintResult {
		cfg := profileConfig(mutate)
		return cfg.Lint()
	}
	byCode := func(ws LintResult, code string) *LintWarning {
		for i := range ws {
			if ws[i].Code == code {
				return &ws[i]
			}
		}
		return nil
	}

	// The removal note is informational and appears whenever profiles exist.
	base := lint(func(c *Config) { c.ValidationMode = ModeStrict })
	w := byCode(base, "session_profile_removal_ends_sessions")
	if w == nil || w.Severity != LintInfo {
		t.Fatalf("session_profile_removal_ends_sessions = %+v, want an info finding", w)
	}
	for _, code := range []string{"session_profile_ceiling_long", "session_profile_unbounded", "session_profile_renew_on_use_stateless"} {
		if byCode(base, code) != nil {
			t.Errorf("%s fired for a clean strict config", code)
		}
	}

	ws := lint(func(c *Config) {
		c.SessionProfiles.Profiles["long"] = SessionProfile{IdleTimeout: spDay, AbsoluteLifetime: 365*spDay + time.Second}
	})
	if w := byCode(ws, "session_profile_ceiling_long"); w == nil || w.Severity != LintWarn || !strings.Contains(w.Message, "long") {
		t.Fatalf("session_profile_ceiling_long = %+v", w)
	}
	ws = lint(func(c *Config) {
		c.SessionProfiles.Profiles["mobile"] = SessionProfile{IdleTimeout: 90 * spDay, AbsoluteLifetime: 365 * spDay}
	})
	if byCode(ws, "session_profile_ceiling_long") != nil {
		t.Fatal("a 365d ceiling is exactly at the limit and must not warn")
	}

	ws = lint(func(c *Config) {
		c.SessionProfiles.Profiles["agent"] = SessionProfile{IdleTimeout: spDay, AllowUnbounded: true}
	})
	if w := byCode(ws, "session_profile_unbounded"); w == nil || w.Severity != LintWarn || !strings.Contains(w.Message, "agent") {
		t.Fatalf("session_profile_unbounded = %+v", w)
	}

	for _, mode := range []ValidationMode{ModeHybrid, ModeJWTOnly} {
		ws = lint(func(c *Config) { c.ValidationMode = mode })
		if w := byCode(ws, "session_profile_renew_on_use_stateless"); w == nil || w.Severity != LintInfo {
			t.Fatalf("mode %v: session_profile_renew_on_use_stateless = %+v", mode, w)
		}
	}
	ws = lint(func(c *Config) {
		c.ValidationMode = ModeHybrid
		c.SessionProfiles.Profiles["mobile"] = SessionProfile{IdleTimeout: 90 * spDay, AbsoluteLifetime: 365 * spDay}
	})
	if byCode(ws, "session_profile_renew_on_use_stateless") != nil {
		t.Fatal("no profile sets RenewOnUse, so there is nothing to warn about")
	}

	// Without profiles none of the codes can appear.
	cfg := accountTestConfig()
	for _, w := range cfg.Lint() {
		if strings.HasPrefix(w.Code, "session_profile_") {
			t.Fatalf("lint code %s fired for a config without profiles", w.Code)
		}
	}
}
