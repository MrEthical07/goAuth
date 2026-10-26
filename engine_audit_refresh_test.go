package goAuth

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

// Regression tests for the refresh findings of the v0.8.0 security audit
// (run 2): R2-11 and R2-17. Each is labelled FAILED-BEFORE with the finding ID.

// outageUserProvider makes the by-ID lookups fail on demand.
type outageUserProvider struct {
	*mockUserProvider
	down atomic.Bool
}

func (p *outageUserProvider) GetUserByID(userID string) (UserRecord, error) {
	if p.down.Load() {
		return UserRecord{}, errors.New("database unavailable")
	}
	return p.mockUserProvider.GetUserByID(userID)
}

func (p *outageUserProvider) GetUserByIDInTenant(ctx context.Context, tenantID, userID string) (UserRecord, error) {
	if p.down.Load() {
		return UserRecord{}, errors.New("database unavailable")
	}
	return p.mockUserProvider.GetUserByIDInTenant(ctx, tenantID, userID)
}

func changeUser(up *mockUserProvider, mutate func(*UserRecord)) {
	up.mu.Lock()
	defer up.mu.Unlock()
	user := up.users["u1"]
	mutate(&user)
	up.users["u1"] = user
}

// FAILED-BEFORE (R2-11): Refresh never compared the session's version stamps
// with the user, so a demoted user kept refreshing a session minted with the
// old permissions. With Security.RecheckUserOnRefresh the refresh is refused
// and the session ends; without it nothing changes.
func TestRefreshRechecksTheUserWhenAsked(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*UserRecord)
	}{
		{"permission version", func(u *UserRecord) { u.PermissionVersion++ }},
		{"role version", func(u *UserRecord) { u.RoleVersion++ }},
		{"account version", func(u *UserRecord) { u.AccountVersion++ }},
	} {
		t.Run(tc.name+"/on", func(t *testing.T) {
			cfg := accountTestConfig()
			cfg.Security.RecheckUserOnRefresh = true
			up := newHardeningUserProvider(t)
			engine, _, done := newCreateAccountEngine(t, cfg, up)
			defer done()
			ctx := context.Background()

			_, refresh, err := engine.Login(ctx, "alice", "correct-password-123")
			if err != nil {
				t.Fatal(err)
			}
			changeUser(up, tc.mutate)
			if _, _, err := engine.Refresh(ctx, refresh); !errors.Is(err, ErrSessionNotFound) {
				t.Fatalf("refresh after the change: %v, want ErrSessionNotFound", err)
			}
			if n := activeSessions(t, engine); n != 0 {
				t.Fatalf("the session survived: %d", n)
			}
		})
		t.Run(tc.name+"/off", func(t *testing.T) {
			cfg := accountTestConfig()
			up := newHardeningUserProvider(t)
			engine, _, done := newCreateAccountEngine(t, cfg, up)
			defer done()
			ctx := context.Background()

			_, refresh, err := engine.Login(ctx, "alice", "correct-password-123")
			if err != nil {
				t.Fatal(err)
			}
			changeUser(up, tc.mutate)
			if _, _, err := engine.Refresh(ctx, refresh); err != nil {
				t.Fatalf("with the flag off a refresh must behave as before: %v", err)
			}
		})
	}
}

// FAILED-BEFORE (R2-11): a status the provider changed without revoking the
// sessions.
func TestRefreshRecheckRefusesABlockedUser(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Security.RecheckUserOnRefresh = true
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := context.Background()

	_, refresh, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatal(err)
	}
	changeUser(up, func(u *UserRecord) { u.Status = AccountDisabled })
	if _, _, err := engine.Refresh(ctx, refresh); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("refresh of a disabled user: %v, want ErrAccountDisabled", err)
	}
	if n := activeSessions(t, engine); n != 0 {
		t.Fatalf("the session survived: %d", n)
	}
}

func TestRefreshRecheckKeepsTheSessionWhenNothingChanged(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Security.RecheckUserOnRefresh = true
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := context.Background()

	_, refresh, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, refresh, err = engine.Refresh(ctx, refresh); err != nil {
			t.Fatalf("refresh %d: %v", i, err)
		}
	}
}

func TestRefreshRecheckOutageIsUnavailableAndRotatesNothing(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Security.RecheckUserOnRefresh = true
	up := &outageUserProvider{mockUserProvider: newHardeningUserProvider(t)}
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := context.Background()

	_, refresh, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatal(err)
	}
	up.down.Store(true)
	if _, _, err := engine.Refresh(ctx, refresh); !errors.Is(err, ErrSystemUnavailable) {
		t.Fatalf("during the outage: %v, want ErrSystemUnavailable", err)
	}
	up.down.Store(false)
	if _, _, err := engine.Refresh(ctx, refresh); err != nil {
		t.Fatalf("the same token must work once the provider is back: %v", err)
	}
}

func TestRefreshRecheckLintIsInfoWhenOff(t *testing.T) {
	cfg := accountTestConfig()
	find := func() (LintWarning, bool) {
		for _, w := range cfg.Lint() {
			if w.Code == "refresh_user_recheck_off" {
				return w, true
			}
		}
		return LintWarning{}, false
	}
	w, ok := find()
	if !ok {
		t.Fatal("no refresh_user_recheck_off lint with the flag off")
	}
	if w.Severity != LintInfo {
		t.Fatalf("severity = %v, want LintInfo", w.Severity)
	}
	cfg.Security.RecheckUserOnRefresh = true
	if _, ok := find(); ok {
		t.Fatal("refresh_user_recheck_off lint with the flag on")
	}
}

// FAILED-BEFORE (R2-17): in enforce mode Refresh ignored device binding, so a
// stolen refresh token worked from any address.
func TestRefreshEnforcesDeviceBinding(t *testing.T) {
	login := func(t *testing.T, mutate func(*Config)) (*Engine, string) {
		t.Helper()
		cfg := accountTestConfig()
		cfg.DeviceBinding.Enabled = true
		mutate(&cfg)
		up := newHardeningUserProvider(t)
		engine, _, done := newCreateAccountEngine(t, cfg, up)
		t.Cleanup(done)
		_, refresh, err := engine.Login(boundDevice(), "alice", "correct-password-123")
		if err != nil {
			t.Fatal(err)
		}
		return engine, refresh
	}

	t.Run("enforced IP", func(t *testing.T) {
		engine, refresh := login(t, func(c *Config) {
			c.DeviceBinding.EnforceIPBinding = true
			c.DeviceBinding.DetectIPChange = true
		})
		if _, _, err := engine.Refresh(otherAddress(), refresh); !errors.Is(err, ErrDeviceBindingRejected) {
			t.Fatalf("from another address: %v, want ErrDeviceBindingRejected", err)
		}
		// Nothing was rotated or deleted: the owner's token still works.
		if _, _, err := engine.Refresh(boundDevice(), refresh); err != nil {
			t.Fatalf("from the bound device: %v", err)
		}
	})
	t.Run("enforced user agent", func(t *testing.T) {
		engine, refresh := login(t, func(c *Config) {
			c.DeviceBinding.EnforceUserAgentBinding = true
			c.DeviceBinding.DetectUserAgentChange = true
		})
		if _, _, err := engine.Refresh(otherAgent(), refresh); !errors.Is(err, ErrDeviceBindingRejected) {
			t.Fatalf("from another agent: %v, want ErrDeviceBindingRejected", err)
		}
		if _, _, err := engine.Refresh(boundDevice(), refresh); err != nil {
			t.Fatalf("from the bound device: %v", err)
		}
	})
	t.Run("detect only is unchanged", func(t *testing.T) {
		engine, refresh := login(t, func(c *Config) {
			c.DeviceBinding.DetectIPChange = true
			c.DeviceBinding.DetectUserAgentChange = true
		})
		if _, _, err := engine.Refresh(otherAddress(), refresh); err != nil {
			t.Fatalf("detect mode must not refuse a refresh: %v", err)
		}
	})
	t.Run("off is unchanged", func(t *testing.T) {
		engine, refresh := login(t, func(c *Config) { c.DeviceBinding.Enabled = false })
		if _, _, err := engine.Refresh(otherAddress(), refresh); err != nil {
			t.Fatalf("binding off must not refuse a refresh: %v", err)
		}
	})
	t.Run("a spent token is still reuse", func(t *testing.T) {
		engine, refresh := login(t, func(c *Config) {
			c.DeviceBinding.EnforceIPBinding = true
			c.DeviceBinding.DetectIPChange = true
		})
		if _, _, err := engine.Refresh(boundDevice(), refresh); err != nil {
			t.Fatal(err)
		}
		if _, _, err := engine.Refresh(otherAddress(), refresh); !errors.Is(err, ErrRefreshReuse) {
			t.Fatalf("a spent token: %v, want ErrRefreshReuse", err)
		}
	})
}

func boundDevice() context.Context {
	return WithUserAgent(WithClientIP(context.Background(), "203.0.113.10"), "ua-v1")
}

func otherAddress() context.Context {
	return WithUserAgent(WithClientIP(context.Background(), "198.51.100.7"), "ua-v1")
}

func otherAgent() context.Context {
	return WithUserAgent(WithClientIP(context.Background(), "203.0.113.10"), "ua-v2")
}
