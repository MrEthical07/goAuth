package goAuth

import (
	"context"
	"testing"
	"time"
)

func TestResolvedMaxSessionDuration(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   time.Duration
	}{
		{
			name:   "hybrid defaults resolve to 7d",
			mutate: func(c *Config) {},
			want:   7 * 24 * time.Hour,
		},
		{
			name: "strict with matching 24h lifetimes resolves to 24h",
			mutate: func(c *Config) {
				c.ValidationMode = ModeStrict
				c.JWT.RefreshTTL = 24 * time.Hour
				c.Session.AbsoluteSessionLifetime = 24 * time.Hour
			},
			want: 24 * time.Hour,
		},
		{
			name: "strict with 7d lifetimes is raised to 7d for compatibility",
			mutate: func(c *Config) {
				c.ValidationMode = ModeStrict
			},
			want: 7 * 24 * time.Hour,
		},
		{
			name: "hybrid with 14d lifetimes is raised to 14d for compatibility",
			mutate: func(c *Config) {
				c.JWT.RefreshTTL = 14 * 24 * time.Hour
				c.Session.AbsoluteSessionLifetime = 14 * 24 * time.Hour
			},
			want: 14 * 24 * time.Hour,
		},
		{
			name: "explicit value wins over mode default",
			mutate: func(c *Config) {
				c.Session.MaxSessionDuration = 30 * 24 * time.Hour
			},
			want: 30 * 24 * time.Hour,
		},
		{
			name: "explicit value wins even below the default lifetime",
			mutate: func(c *Config) {
				c.Session.MaxSessionDuration = time.Hour
			},
			want: time.Hour,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := defaultConfig()
			tc.mutate(&cfg)
			if got := cfg.resolvedMaxSessionDuration(); got != tc.want {
				t.Fatalf("resolvedMaxSessionDuration = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildFreezesResolvedMaxSessionDuration(t *testing.T) {
	cfg := accountTestConfig()
	if cfg.Session.MaxSessionDuration != 0 {
		t.Fatal("test precondition: MaxSessionDuration must start unset")
	}
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	if got := engine.config.Session.MaxSessionDuration; got != 7*24*time.Hour {
		t.Fatalf("built config MaxSessionDuration = %v, want 7d", got)
	}
	if got := engine.maxSessionLifetime(); got != 7*24*time.Hour {
		t.Fatalf("maxSessionLifetime = %v, want 7d", got)
	}
}

func TestSessionLifetimeForRememberMe(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Session.MaxSessionDuration = 30 * 24 * time.Hour
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	if got := engine.sessionLifetimeFor(true); got != 30*24*time.Hour {
		t.Fatalf("remember-me lifetime = %v, want 30d", got)
	}
	if got := engine.sessionLifetimeFor(false); got != 7*24*time.Hour {
		t.Fatalf("default lifetime = %v, want 7d", got)
	}
	if got := engine.sessionLifetime(); got != 7*24*time.Hour {
		t.Fatalf("sessionLifetime() = %v, want unchanged 7d", got)
	}
}

func TestSessionLifetimeExplicitCapBoundsDefaultSessions(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Session.MaxSessionDuration = time.Hour
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	if got := engine.sessionLifetimeFor(false); got != time.Hour {
		t.Fatalf("default lifetime with explicit 1h cap = %v, want 1h", got)
	}
	if got := engine.sessionLifetimeFor(true); got != time.Hour {
		t.Fatalf("remember-me lifetime with explicit 1h cap = %v, want 1h", got)
	}
}

func sessionLifetimeSeconds(t *testing.T, engine *Engine, userID string) int64 {
	t.Helper()
	sessions, err := engine.ListActiveSessions(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListActiveSessions failed: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected exactly 1 session, got %d", len(sessions))
	}
	return sessions[0].ExpiresAt - sessions[0].CreatedAt
}

func TestLoginWithOptionsRememberMeSessionLifetime(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Session.MaxSessionDuration = 30 * 24 * time.Hour
	up := newHardeningUserProvider(t)
	engine, rdb, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	result, err := engine.LoginWithOptions(context.Background(), "alice", "correct-password-123", LoginOptions{RememberMe: true})
	if err != nil {
		t.Fatalf("LoginWithOptions failed: %v", err)
	}
	if result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatal("expected tokens")
	}

	if got := sessionLifetimeSeconds(t, engine, "u1"); got != int64(30*24*time.Hour/time.Second) {
		t.Fatalf("remember-me session lifetime = %ds, want 30d", got)
	}

	sessions, err := engine.ListActiveSessions(context.Background(), "u1")
	if err != nil {
		t.Fatalf("ListActiveSessions failed: %v", err)
	}
	pttl := rdb.PTTL(context.Background(), "as:0:"+sessions[0].SessionID).Val()
	if pttl < 29*24*time.Hour || pttl > 30*24*time.Hour {
		t.Fatalf("remember-me session Redis TTL = %v, want ≈30d", pttl)
	}
}

func TestLoginDefaultSessionLifetimeUnchanged(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Session.MaxSessionDuration = 30 * 24 * time.Hour
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	if _, _, err := engine.Login(context.Background(), "alice", "correct-password-123"); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if got := sessionLifetimeSeconds(t, engine, "u1"); got != int64(7*24*time.Hour/time.Second) {
		t.Fatalf("default session lifetime = %ds, want 7d", got)
	}
}

func TestSlidingRenewalDoesNotClampRememberMeSession(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Session.MaxSessionDuration = 30 * 24 * time.Hour
	up := newHardeningUserProvider(t)
	engine, rdb, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	if _, err := engine.LoginWithOptions(context.Background(), "alice", "correct-password-123", LoginOptions{RememberMe: true}); err != nil {
		t.Fatalf("LoginWithOptions failed: %v", err)
	}
	sessions, err := engine.ListActiveSessions(context.Background(), "u1")
	if err != nil {
		t.Fatalf("ListActiveSessions failed: %v", err)
	}
	sid := sessions[0].SessionID

	// The strict-validation read path passes the engine-wide clamp to the
	// store; with sliding enabled it re-EXPIREs the key. The clamp must be
	// the ceiling, so the TTL must stay near 30d rather than shrink to the
	// 7d default lifetime.
	if _, err := engine.sessionStore.Get(context.Background(), "0", sid, engine.maxSessionLifetime()); err != nil {
		t.Fatalf("session Get failed: %v", err)
	}
	pttl := rdb.PTTL(context.Background(), "as:0:"+sid).Val()
	if pttl < 29*24*time.Hour {
		t.Fatalf("sliding renewal clamped remember-me session TTL to %v, want ≈30d", pttl)
	}
}

func TestRememberMePersistsThroughMFA(t *testing.T) {
	cfg := totpTestConfig()
	cfg.TOTP.RequireForLogin = true
	cfg.Session.MaxSessionDuration = 30 * 24 * time.Hour
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	secret := enableUserTOTP(t, engine, "u1", cfg)

	result, err := engine.LoginWithOptions(context.Background(), "alice", "correct-password-123", LoginOptions{RememberMe: true})
	if err != nil {
		t.Fatalf("LoginWithOptions failed: %v", err)
	}
	if !result.MFARequired || result.MFASession == "" {
		t.Fatalf("expected MFA challenge, got %+v", result)
	}

	code := codeForOffset(t, secret, cfg.TOTP, 1)
	confirmed, err := engine.ConfirmLoginMFA(context.Background(), result.MFASession, code)
	if err != nil {
		t.Fatalf("ConfirmLoginMFA failed: %v", err)
	}
	if confirmed.AccessToken == "" {
		t.Fatal("expected tokens after MFA confirmation")
	}

	if got := sessionLifetimeSeconds(t, engine, "u1"); got != int64(30*24*time.Hour/time.Second) {
		t.Fatalf("post-MFA remember-me session lifetime = %ds, want 30d", got)
	}
}

func TestCreateAccountAutoLoginRememberMe(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Account.AutoLogin = true
	cfg.Session.MaxSessionDuration = 30 * 24 * time.Hour
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	result, err := engine.CreateAccount(context.Background(), CreateAccountRequest{
		Identifier: "carol",
		Password:   "secure-password-123",
		RememberMe: true,
	})
	if err != nil {
		t.Fatalf("CreateAccount failed: %v", err)
	}
	if result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatal("expected auto-login tokens")
	}

	if got := sessionLifetimeSeconds(t, engine, result.UserID); got != int64(30*24*time.Hour/time.Second) {
		t.Fatalf("auto-login remember-me session lifetime = %ds, want 30d", got)
	}
}
