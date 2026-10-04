package goAuth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal/limiters"
	"github.com/redis/go-redis/v9"
)

func requireRoleIs(t *testing.T, res *AuthResult, want string) {
	t.Helper()
	if res == nil {
		t.Fatalf("expected a validation result with role %q, got nil", want)
	}
	if res.Role != want {
		t.Fatalf("role = %q, want %q", res.Role, want)
	}
}

func canWrite(env *rsEnv, res *AuthResult) bool {
	return env.engine.HasPermission(res.Mask, "perm.write")
}

func TestSwitchRoleHappyPath(t *testing.T) {
	env := newRSEnv(t)
	oldAccess, oldRefresh := env.login()

	before, err := env.validate(oldAccess, ModeStrict)
	if err != nil {
		t.Fatalf("strict validate before switch failed: %v", err)
	}
	requireRoleIs(t, before, "teacher")
	if canWrite(env, before) {
		t.Fatal("teacher must not hold perm.write")
	}

	sw := env.mustSwitch(oldRefresh, "admin")
	if sw.Role != "admin" || sw.StepUpRequired || len(sw.StepUpFactors) != 0 {
		t.Fatalf("unexpected result: %+v", sw)
	}

	// The new token carries the admin mask, and strict validation reports it.
	for _, mode := range []RouteMode{ModeStrict, ModeHybrid, ModeJWTOnly} {
		res, err := env.validate(sw.AccessToken, mode)
		if err != nil {
			t.Fatalf("validate(new token, mode %v) failed: %v", mode, err)
		}
		if !canWrite(env, res) {
			t.Fatalf("mode %v: new token should carry the admin mask", mode)
		}
	}
	strict, _ := env.validate(sw.AccessToken, ModeStrict)
	requireRoleIs(t, strict, "admin")

	// The spent refresh token is dead; the new one works.
	if _, _, err := env.engine.Refresh(env.ctx(), oldRefresh); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("old refresh token after switch = %v, want ErrSessionNotFound", err)
	}
	if n := env.metric(MetricRefreshReuseDetected); n != 0 {
		t.Fatalf("presenting the old token after a switch must not trigger reuse handling (reuse metric = %d)", n)
	}
	access, _, err := env.engine.Refresh(env.ctx(), sw.RefreshToken)
	if err != nil {
		t.Fatalf("refresh with the switched token failed: %v", err)
	}
	after, err := env.validate(access, ModeStrict)
	if err != nil {
		t.Fatalf("validate after refresh failed: %v", err)
	}
	requireRoleIs(t, after, "admin")
}

func TestSwitchRoleNewSessionContent(t *testing.T) {
	env := newRSEnv(t)
	_, refresh := env.login()
	oldSID := env.sidOf(refresh)
	old := env.peek(oldSID)

	// Provider-side versions moved after login: the new session carries the
	// freshly resolved values.
	user := env.up.users[rsUserID]
	user.PermissionVersion, user.RoleVersion, user.AccountVersion = 4, 5, 0
	env.up.users[rsUserID] = user

	sw := env.mustSwitch(refresh, "admin")
	newSID := env.sidOf(sw.RefreshToken)
	if newSID == oldSID {
		t.Fatal("the new session must have a fresh session ID")
	}
	got := env.peek(newSID)

	if got.Role != "admin" || got.UserID != old.UserID || got.TenantID != old.TenantID {
		t.Fatalf("identity fields wrong: %+v", got)
	}
	if got.PermissionVersion != 4 || got.RoleVersion != 5 || got.AccountVersion != 1 {
		t.Fatalf("versions = %d/%d/%d, want 4/5/1 (account version 0 becomes 1)", got.PermissionVersion, got.RoleVersion, got.AccountVersion)
	}
	if got.RefreshHash == old.RefreshHash {
		t.Fatal("the refresh secret must be fresh")
	}
	if got.IPHash != old.IPHash || got.UserAgentHash != old.UserAgentHash {
		t.Fatal("device binding hashes must be copied")
	}
	if env.hasSession(oldSID) {
		t.Fatal("the old session must be gone")
	}
	if ids := env.sessionIDs(); len(ids) != 1 || ids[0] != newSID {
		t.Fatalf("user index = %v, want only %s", ids, newSID)
	}
}

// The revocation guarantee, mode by mode. See docs/role_switching.md.
func TestSwitchRoleOldAccessTokenPerMode(t *testing.T) {
	setup := func(t *testing.T, opts ...rsOption) (*rsEnv, string, *RoleSwitchResult) {
		env := newRSEnv(t, opts...)
		oldAccess, refresh := env.login()
		return env, oldAccess, env.mustSwitch(refresh, "admin")
	}

	t.Run("a: ModeStrict route rejects the old token immediately", func(t *testing.T) {
		env, oldAccess, sw := setup(t)
		if _, err := env.validate(oldAccess, ModeStrict); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("strict validate of the old token = %v, want ErrSessionNotFound", err)
		}
		if _, err := env.validate(sw.AccessToken, ModeStrict); err != nil {
			t.Fatalf("strict validate of the new token failed: %v", err)
		}
	})

	t.Run("b: ModeHybrid route still accepts the old token, with the old mask and no role", func(t *testing.T) {
		env, oldAccess, _ := setup(t)
		res, err := env.validate(oldAccess, ModeHybrid)
		if err != nil {
			t.Fatalf("hybrid validate of the old token failed: %v", err)
		}
		if res.Role != "" {
			t.Fatalf("hybrid never sets Role, got %q", res.Role)
		}
		if canWrite(env, res) {
			t.Fatal("the old token carries the old (teacher) mask")
		}
	})

	t.Run("c: ModeHybrid with Redis down behaves exactly like healthy hybrid, strict fails closed", func(t *testing.T) {
		env, oldAccess, sw := setup(t)

		healthy, err := env.validate(oldAccess, ModeHybrid)
		if err != nil {
			t.Fatalf("healthy hybrid failed: %v", err)
		}

		env.mr.Close()

		down, err := env.validate(oldAccess, ModeHybrid)
		if err != nil {
			t.Fatalf("hybrid with Redis down failed: %v", err)
		}
		if down.Role != healthy.Role || down.UserID != healthy.UserID || canWrite(env, down) != canWrite(env, healthy) {
			t.Fatalf("hybrid result changed with Redis down: %+v vs %+v", down, healthy)
		}
		if _, err := env.validate(sw.AccessToken, ModeHybrid); err != nil {
			t.Fatalf("hybrid validate of the new token with Redis down failed: %v", err)
		}

		// Strict rejects every token while Redis is unavailable.
		for name, token := range map[string]string{"old": oldAccess, "new": sw.AccessToken} {
			if _, err := env.validate(token, ModeStrict); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("strict validate of the %s token with Redis down = %v, want ErrUnauthorized", name, err)
			}
		}
	})

	t.Run("d: ModeJWTOnly route behaves like hybrid", func(t *testing.T) {
		env, oldAccess, _ := setup(t)
		res, err := env.validate(oldAccess, ModeJWTOnly)
		if err != nil {
			t.Fatalf("jwt-only validate of the old token failed: %v", err)
		}
		if res.Role != "" || canWrite(env, res) {
			t.Fatalf("jwt-only result should carry the old mask and no role: %+v", res)
		}
	})

	t.Run("e: after AccessTTL the old token is rejected in every mode", func(t *testing.T) {
		env, oldAccess, sw := setup(t, rsConfig(func(c *Config) {
			c.JWT.AccessTTL = time.Second
			c.JWT.Leeway = 0
		}))
		time.Sleep(2200 * time.Millisecond)
		for _, mode := range []RouteMode{ModeStrict, ModeHybrid, ModeJWTOnly} {
			for name, token := range map[string]string{"old": oldAccess, "new": sw.AccessToken} {
				if _, err := env.validate(token, mode); err == nil {
					t.Fatalf("mode %v accepted the %s token after AccessTTL", mode, name)
				}
			}
		}
	})

	t.Run("hybrid engine with an explicit per-route ModeStrict gives behavior (a)", func(t *testing.T) {
		env, oldAccess, _ := setup(t, rsConfig(func(c *Config) { c.ValidationMode = ModeHybrid }))
		// ModeInherit on a hybrid engine is stateless...
		if _, err := env.validate(oldAccess, ModeInherit); err != nil {
			t.Fatalf("inherit on a hybrid engine should accept the old token, got %v", err)
		}
		// ...but an explicit route override to strict is enough.
		if _, err := env.validate(oldAccess, ModeStrict); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("explicit strict route = %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("strict engine rejects the old token on inherited routes", func(t *testing.T) {
		env, oldAccess, _ := setup(t, rsConfig(func(c *Config) { c.ValidationMode = ModeStrict }))
		if _, err := env.validate(oldAccess, ModeInherit); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("inherit on a strict engine = %v, want ErrSessionNotFound", err)
		}
	})
}

func TestSwitchRoleKeepsAbsoluteLifetime(t *testing.T) {
	for name, rememberMe := range map[string]bool{"default session": false, "remember-me session": true} {
		t.Run(name, func(t *testing.T) {
			env := newRSEnv(t)
			res, err := env.engine.LoginWithOptions(env.ctx(), rsIdentifier, rsPassword, LoginOptions{RememberMe: rememberMe})
			if err != nil {
				t.Fatalf("login failed: %v", err)
			}
			refresh := res.RefreshToken
			first := env.peek(env.sidOf(refresh))

			// A switch must never restart the clock.
			time.Sleep(1100 * time.Millisecond)
			roles := []string{"admin", "teacher", "admin", "teacher"}
			for _, role := range roles {
				sw := env.mustSwitch(refresh, role)
				refresh = sw.RefreshToken
				got := env.peek(env.sidOf(refresh))
				if got.CreatedAt != first.CreatedAt || got.ExpiresAt != first.ExpiresAt {
					t.Fatalf("after switching to %s: created %d->%d expires %d->%d",
						role, first.CreatedAt, got.CreatedAt, first.ExpiresAt, got.ExpiresAt)
				}
				ttl, err := env.rdb.PTTL(context.Background(), env.sessionKey(env.sidOf(refresh))).Result()
				if err != nil {
					t.Fatalf("pttl failed: %v", err)
				}
				if remaining := time.Until(time.Unix(first.ExpiresAt, 0)); ttl <= 0 || ttl > remaining+time.Second {
					t.Fatalf("session key TTL %v exceeds the remaining absolute lifetime %v", ttl, remaining)
				}
			}
		})
	}
}

func TestSwitchRoleProviderDeniesLeavesSessionUntouched(t *testing.T) {
	env := newRSEnv(t)
	access, refresh := env.login()
	sid := env.sidOf(refresh)
	before := env.peek(sid)

	env.up.revoke(rsUserID, "admin")
	res, err := env.switchRole(refresh, "admin", RoleSwitchOptions{})
	if !errors.Is(err, ErrRoleNotAllowed) {
		t.Fatalf("SwitchRole = %v, want ErrRoleNotAllowed", err)
	}
	if res != nil {
		t.Fatalf("a refusal must not carry a result, got %+v", res)
	}
	if got := env.peek(sid); !sameSession(t, got, before) {
		t.Fatalf("the session changed on a refused switch: %+v vs %+v", got, before)
	}
	if _, err := env.validate(access, ModeStrict); err != nil {
		t.Fatalf("the old access token must still work: %v", err)
	}
	if _, _, err := env.engine.Refresh(env.ctx(), refresh); err != nil {
		t.Fatalf("the refresh token must still work after a refused switch: %v", err)
	}
}

func TestSwitchRoleDisabled(t *testing.T) {
	env := newRSEnv(t, rsConfig(func(c *Config) { c.RoleSwitch.Enabled = false }))
	access, refresh := env.login()
	sid := env.sidOf(refresh)
	before := env.peek(sid)

	res, err := env.switchRole(refresh, "admin", RoleSwitchOptions{})
	if !errors.Is(err, ErrRoleSwitchDisabled) {
		t.Fatalf("SwitchRole on a disabled engine = %v, want ErrRoleSwitchDisabled", err)
	}
	if res != nil {
		t.Fatalf("expected a nil result, got %+v", res)
	}
	if got := env.peek(sid); !sameSession(t, got, before) {
		t.Fatal("a disabled SwitchRole must change nothing")
	}
	if n := env.up.callCount(); n != 0 {
		t.Fatalf("provider called %d times while disabled", n)
	}
	if keys := env.keys("rl:roleswitch:*"); len(keys) != 0 {
		t.Fatalf("limiter consumed while disabled: %v", keys)
	}
	if _, err := env.validate(access, ModeStrict); err != nil {
		t.Fatalf("the session must keep working: %v", err)
	}
	env.waitForAudit(auditEventRoleSwitchFailed, "disabled")
}

func TestSwitchRoleRejectsSameAndUnknownRole(t *testing.T) {
	env := newRSEnv(t)
	_, refresh := env.login()

	if _, err := env.switchRole(refresh, "teacher", RoleSwitchOptions{}); !errors.Is(err, ErrRoleSwitchSameRole) {
		t.Fatalf("switching to the current role = %v, want ErrRoleSwitchSameRole", err)
	}
	if n := env.up.callCount(); n != 0 {
		t.Fatalf("provider called %d times for a same-role attempt", n)
	}

	for _, role := range []string{"ghost", "", "ADMIN"} {
		res, err := env.switchRole(refresh, role, RoleSwitchOptions{})
		if !errors.Is(err, ErrRoleNotAllowed) {
			t.Fatalf("switch to unknown role %q = %v, want ErrRoleNotAllowed", role, err)
		}
		if res != nil {
			t.Fatalf("unknown role %q returned a result", role)
		}
	}
	if n := env.up.callCount(); n != 0 {
		t.Fatalf("the provider must not be called for an unregistered role, saw %d calls", n)
	}

	// The same-role error also applies after a real switch.
	sw := env.mustSwitch(refresh, "admin")
	if _, err := env.switchRole(sw.RefreshToken, "admin", RoleSwitchOptions{}); !errors.Is(err, ErrRoleSwitchSameRole) {
		t.Fatalf("switching to the new current role = %v, want ErrRoleSwitchSameRole", err)
	}
	// Neither failure spent the token.
	env.mustSwitch(sw.RefreshToken, "teacher")
}

func TestSwitchRoleDeadSessionsMatchRefresh(t *testing.T) {
	t.Run("malformed token", func(t *testing.T) {
		env := newRSEnv(t)
		_, refreshErr := func() (string, error) {
			_, _, err := env.engine.Refresh(env.ctx(), "not-a-refresh-token")
			return "", err
		}()
		_, switchErr := env.switchRole("not-a-refresh-token", "admin", RoleSwitchOptions{})
		if !errors.Is(refreshErr, ErrRefreshInvalid) || !errors.Is(switchErr, ErrRefreshInvalid) {
			t.Fatalf("refresh=%v switch=%v, both want ErrRefreshInvalid", refreshErr, switchErr)
		}
	})

	t.Run("logged out session", func(t *testing.T) {
		env := newRSEnv(t)
		_, r1 := env.login()
		_, r2 := env.login()
		if err := env.engine.Logout(env.ctx(), env.sidOf(r1)); err != nil {
			t.Fatalf("logout failed: %v", err)
		}
		if err := env.engine.Logout(env.ctx(), env.sidOf(r2)); err != nil {
			t.Fatalf("logout failed: %v", err)
		}
		_, _, refreshErr := env.engine.Refresh(env.ctx(), r1)
		_, switchErr := env.switchRole(r2, "admin", RoleSwitchOptions{})
		if !errors.Is(refreshErr, ErrSessionNotFound) || !errors.Is(switchErr, ErrSessionNotFound) {
			t.Fatalf("refresh=%v switch=%v, both want ErrSessionNotFound", refreshErr, switchErr)
		}
	})

	t.Run("expired session is deleted and reported as not found", func(t *testing.T) {
		env := newRSEnv(t)
		expire := func(refresh string) string {
			sid := env.sidOf(refresh)
			sess := env.peek(sid)
			sess.ExpiresAt = time.Now().Add(-time.Minute).Unix()
			if err := env.engine.sessionStore.Save(context.Background(), sess, time.Hour); err != nil {
				t.Fatalf("re-save failed: %v", err)
			}
			return sid
		}
		_, r1 := env.login()
		_, r2 := env.login()
		sid1, sid2 := expire(r1), expire(r2)

		_, _, refreshErr := env.engine.Refresh(env.ctx(), r1)
		_, switchErr := env.switchRole(r2, "admin", RoleSwitchOptions{})
		if !errors.Is(refreshErr, ErrSessionNotFound) || !errors.Is(switchErr, ErrSessionNotFound) {
			t.Fatalf("refresh=%v switch=%v, both want ErrSessionNotFound", refreshErr, switchErr)
		}
		if env.hasSession(sid1) || env.hasSession(sid2) {
			t.Fatal("expired sessions must be deleted by both paths")
		}
		if n := env.up.callCount(); n != 0 {
			t.Fatalf("provider called %d times for dead sessions", n)
		}
	})
}

func TestSwitchRoleUnavailableProvider(t *testing.T) {
	env := newRSEnv(t)
	_, refresh := env.login()
	sid := env.sidOf(refresh)
	before := env.peek(sid)

	env.up.setCanErr(errors.New("provider-db-down"))
	res, err := env.switchRole(refresh, "admin", RoleSwitchOptions{})
	if !errors.Is(err, ErrSystemUnavailable) {
		t.Fatalf("SwitchRole = %v, want ErrSystemUnavailable", err)
	}
	if res != nil {
		t.Fatalf("expected no result, got %+v", res)
	}
	if strings.Contains(err.Error(), "provider-db-down") {
		t.Fatalf("raw provider failure leaked: %v", err)
	}
	if got := env.peek(sid); !sameSession(t, got, before) {
		t.Fatal("an unavailable provider must change nothing")
	}

	// Retrying with the same token works once the provider recovers.
	env.up.setCanErr(nil)
	env.mustSwitch(refresh, "admin")
}

func TestSwitchRoleAccountDisabledAfterLoginDeletesSession(t *testing.T) {
	env := newRSEnv(t)
	_, refresh := env.login()
	sid := env.sidOf(refresh)

	user := env.up.users[rsUserID]
	user.Status = AccountDisabled
	env.up.users[rsUserID] = user

	res, err := env.switchRole(refresh, "admin", RoleSwitchOptions{})
	if !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("SwitchRole = %v, want ErrAccountDisabled", err)
	}
	if res != nil {
		t.Fatalf("expected no result, got %+v", res)
	}
	if env.hasSession(sid) {
		t.Fatal("the session of a disabled account must be deleted, as Refresh does")
	}
	if n := env.up.callCount(); n != 0 {
		t.Fatalf("CanAssumeRole called %d times for a disabled account", n)
	}
	env.waitForAudit(auditEventRoleSwitchFailed, "account_status")
}

func TestSwitchRolePendingVerificationDeletesSession(t *testing.T) {
	env := newRSEnv(t, rsConfig(func(c *Config) {
		c.EmailVerification.Enabled = true
		c.EmailVerification.RequireForLogin = true
		c.EmailVerification.Strategy = VerificationToken
		c.EmailVerification.VerificationTTL = 15 * time.Minute
		c.EmailVerification.MaxAttempts = 5
	}))
	_, refresh := env.login()
	sid := env.sidOf(refresh)

	user := env.up.users[rsUserID]
	user.Status = AccountPendingVerification
	env.up.users[rsUserID] = user

	if _, err := env.switchRole(refresh, "admin", RoleSwitchOptions{}); !errors.Is(err, ErrAccountUnverified) {
		t.Fatalf("SwitchRole = %v, want ErrAccountUnverified", err)
	}
	if env.hasSession(sid) {
		t.Fatal("a pending-verification session must be deleted, as Refresh does")
	}
}

func TestSwitchRoleLeavesOtherSessionsAlone(t *testing.T) {
	env := newRSEnv(t)
	otherAccess, otherRefresh := env.login()
	_, refresh := env.login()
	otherSID := env.sidOf(otherRefresh)
	otherBefore := env.peek(otherSID)

	env.mustSwitch(refresh, "admin")

	if got := env.peek(otherSID); !sameSession(t, got, otherBefore) {
		t.Fatal("another session of the same user was modified")
	}
	if _, err := env.validate(otherAccess, ModeStrict); err != nil {
		t.Fatalf("the other session's access token stopped working: %v", err)
	}
	if _, _, err := env.engine.Refresh(env.ctx(), otherRefresh); err != nil {
		t.Fatalf("the other session's refresh token stopped working: %v", err)
	}
	if ids := env.sessionIDs(); len(ids) != 2 {
		t.Fatalf("expected two sessions after the switch, got %v", ids)
	}
}

func TestSwitchRoleDoesNotTripSessionHardening(t *testing.T) {
	env := newRSEnv(t, rsConfig(func(c *Config) {
		c.SessionHardening.EnforceSingleSession = true
		c.SessionHardening.MaxSessionsPerUser = 1
		c.SessionHardening.MaxSessionsPerTenant = 1
		c.SessionHardening.ConcurrentLoginLimit = 1
	}))
	_, refresh := env.login()
	ctx := context.Background()

	countBefore, err := env.engine.sessionStore.TenantSessionCount(ctx, env.tenant)
	if err != nil {
		t.Fatalf("tenant count: %v", err)
	}
	if countBefore != 1 {
		t.Fatalf("setup: tenant count = %d, want 1", countBefore)
	}

	for _, role := range []string{"admin", "teacher", "admin"} {
		sw := env.mustSwitch(refresh, role)
		refresh = sw.RefreshToken

		if n, _ := env.engine.sessionStore.ActiveSessionCount(ctx, env.tenant, rsUserID); n != 1 {
			t.Fatalf("after switching to %s the user has %d sessions, want 1", role, n)
		}
		if n, _ := env.engine.sessionStore.TenantSessionCount(ctx, env.tenant); n != countBefore {
			t.Fatalf("after switching to %s the tenant counter is %d, want %d", role, n, countBefore)
		}
	}
}

func TestSwitchRoleDeviceBinding(t *testing.T) {
	env := newRSEnv(t, rsConfig(func(c *Config) {
		c.DeviceBinding.Enabled = true
		c.DeviceBinding.EnforceIPBinding = true
		c.DeviceBinding.EnforceUserAgentBinding = true
		c.DeviceBinding.DetectIPChange = true
		c.DeviceBinding.DetectUserAgentChange = true
	}))
	ctx := WithUserAgent(WithClientIP(context.Background(), "203.0.113.7"), "UA/1.0")
	_, refresh, err := env.engine.Login(ctx, rsIdentifier, rsPassword)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	sid := env.sidOf(refresh)
	old := env.peek(sid)

	for name, bad := range map[string]context.Context{
		"different ip": WithUserAgent(WithClientIP(context.Background(), "198.51.100.9"), "UA/1.0"),
		"different ua": WithUserAgent(WithClientIP(context.Background(), "203.0.113.7"), "Other/2.0"),
		"no context":   context.Background(),
	} {
		res, err := env.engine.SwitchRole(bad, refresh, "admin", RoleSwitchOptions{})
		if !errors.Is(err, ErrDeviceBindingRejected) {
			t.Fatalf("%s: SwitchRole = %v, want ErrDeviceBindingRejected", name, err)
		}
		if res != nil {
			t.Fatalf("%s: expected no result", name)
		}
		if !env.hasSession(sid) {
			t.Fatalf("%s: a device-binding rejection must not delete the session", name)
		}
	}

	sw, err := env.engine.SwitchRole(ctx, refresh, "admin", RoleSwitchOptions{})
	if err != nil {
		t.Fatalf("SwitchRole from the bound device failed: %v", err)
	}
	got := env.peek(env.sidOf(sw.RefreshToken))
	if got.IPHash != old.IPHash || got.UserAgentHash != old.UserAgentHash {
		t.Fatal("the new session must stay bound to the same device")
	}
	if _, err := env.engine.Validate(WithUserAgent(WithClientIP(context.Background(), "198.51.100.9"), "UA/1.0"), sw.AccessToken, ModeStrict); !errors.Is(err, ErrDeviceBindingRejected) {
		t.Fatalf("strict validation from another device = %v, want ErrDeviceBindingRejected", err)
	}
}

func TestSwitchRoleLimiter(t *testing.T) {
	env := newRSEnv(t, rsConfig(func(c *Config) {
		c.RoleSwitch.MaxAttempts = 3
		c.RoleSwitch.Cooldown = time.Minute
	}))
	_, refresh := env.login()
	env.up.revoke(rsUserID, "admin")

	for i := 1; i <= 3; i++ {
		if _, err := env.switchRole(refresh, "admin", RoleSwitchOptions{}); !errors.Is(err, ErrRoleNotAllowed) {
			t.Fatalf("attempt %d = %v, want ErrRoleNotAllowed", i, err)
		}
	}
	if n := env.up.callCount(); n != 3 {
		t.Fatalf("provider calls = %d, want 3", n)
	}

	res, err := env.switchRole(refresh, "admin", RoleSwitchOptions{})
	if !errors.Is(err, ErrRoleSwitchRateLimited) {
		t.Fatalf("attempt 4 = %v, want ErrRoleSwitchRateLimited", err)
	}
	if res != nil {
		t.Fatalf("a rate-limited attempt must not carry a result, got %+v", res)
	}
	if n := env.up.callCount(); n != 3 {
		t.Fatalf("a rate-limited attempt called the provider (calls = %d)", n)
	}
	// Even a valid switch is refused while limited.
	env.up.grant(rsUserID, "admin")
	if _, err := env.switchRole(refresh, "admin", RoleSwitchOptions{}); !errors.Is(err, ErrRoleSwitchRateLimited) {
		t.Fatalf("a valid switch while limited = %v, want ErrRoleSwitchRateLimited", err)
	}
	env.waitForAudit(auditEventRoleSwitchFailed, "rate_limited")
	env.waitForAudit(auditEventRateLimitTriggered, "")
}

func TestSwitchRoleSuccessResetsLimiter(t *testing.T) {
	env := newRSEnv(t, rsConfig(func(c *Config) {
		c.RoleSwitch.MaxAttempts = 3
		c.RoleSwitch.Cooldown = time.Minute
	}))
	_, refresh := env.login()
	oldSID := env.sidOf(refresh)

	env.up.revoke(rsUserID, "admin")
	for i := 0; i < 2; i++ {
		if _, err := env.switchRole(refresh, "admin", RoleSwitchOptions{}); !errors.Is(err, ErrRoleNotAllowed) {
			t.Fatalf("setup attempt %d = %v", i, err)
		}
	}
	if keys := env.keys("rl:roleswitch:*" + oldSID); len(keys) != 1 {
		t.Fatalf("expected one limiter key for the old session, got %v", keys)
	}

	env.up.grant(rsUserID, "admin")
	env.mustSwitch(refresh, "admin")
	if keys := env.keys("rl:roleswitch:*" + oldSID); len(keys) != 0 {
		t.Fatalf("a successful switch must reset the limiter, found %v", keys)
	}
}

func TestSwitchRoleLimiterFailsOpenWhenBackendErrors(t *testing.T) {
	env := newRSEnv(t)
	_, refresh := env.login()

	// A limiter-only outage: swap in a limiter pointed at a dead backend.
	deadClient := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond, MaxRetries: -1})
	defer deadClient.Close()
	env.engine.roleSwitchLimiter = limiters.NewRoleSwitchLimiter(deadClient, limiters.RoleSwitchConfig{MaxAttempts: 3, Cooldown: time.Minute})

	if _, err := env.switchRole(refresh, "admin", RoleSwitchOptions{}); err != nil {
		t.Fatalf("a limiter backend failure must fail open, got %v", err)
	}
	env.waitForAudit(auditEventLimiterFailOpen, "")
}

func TestSwitchRoleCrossTenant(t *testing.T) {
	env := newRSEnv(t, rsMultiTenant(), rsConfig(func(c *Config) {
		c.RoleSwitch.MaxAttempts = 3
		c.RoleSwitch.Cooldown = time.Minute
	}))
	_, refresh := env.login()
	sid := env.sidOf(refresh)

	ctxB := WithTenantID(context.Background(), "tenant-b")
	for i := 1; i <= 3; i++ {
		res, err := env.engine.SwitchRole(ctxB, refresh, "admin", RoleSwitchOptions{})
		if !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("cross-tenant attempt %d = %v, want ErrSessionNotFound", i, err)
		}
		if res != nil {
			t.Fatal("a cross-tenant attempt must not return a result")
		}
	}
	if n := env.up.callCount(); n != 0 {
		t.Fatalf("the provider was called %d times for a cross-tenant token", n)
	}

	// Attempts are throttled under the attacker's tenant, wrong-tenant ones included.
	if _, err := env.engine.SwitchRole(ctxB, refresh, "admin", RoleSwitchOptions{}); !errors.Is(err, ErrRoleSwitchRateLimited) {
		t.Fatalf("4th cross-tenant attempt = %v, want ErrRoleSwitchRateLimited", err)
	}
	if n := env.up.callCount(); n != 0 {
		t.Fatalf("the provider was called %d times after throttling", n)
	}

	// The owner's session and their own budget are untouched.
	if !env.hasSession(sid) {
		t.Fatal("the cross-tenant probing must not have deleted the session")
	}
	env.mustSwitch(refresh, "admin")
	if last := env.up.lastCall(); last.tenantID != "tenant-a" || last.userID != rsUserID {
		t.Fatalf("provider saw %+v, want the session's own tenant", last)
	}
}

// A provider that ignores the tenant predicate must still not be able to
// carry a switch across tenants.
func TestSwitchRoleTenantBlindProviderCannotCrossTenants(t *testing.T) {
	env := newRSEnv(t, rsMultiTenant())
	_, refresh := env.login()
	sid := env.sidOf(refresh)

	env.up.ignoreTenantScope = true
	env.up.ignoreTenant = true

	// Same token, other tenant: the session is not even visible there.
	ctxB := WithTenantID(context.Background(), "tenant-b")
	if _, err := env.engine.SwitchRole(ctxB, refresh, "admin", RoleSwitchOptions{}); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("SwitchRole = %v, want ErrSessionNotFound", err)
	}

	// Session of tenant A whose account resolves to another tenant: the
	// engine's own check rejects the foreign record before the provider.
	user := env.up.users[rsUserID]
	user.TenantID = "tenant-b"
	env.up.users[rsUserID] = user
	if _, err := env.switchRole(refresh, "admin", RoleSwitchOptions{}); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("SwitchRole with a foreign account record = %v, want ErrSessionNotFound", err)
	}
	if n := env.up.callCount(); n != 0 {
		t.Fatalf("CanAssumeRole was reached %d times despite the tenant mismatch", n)
	}
	if !env.hasSession(sid) {
		t.Fatal("a tenant mismatch must not delete the session")
	}
}

func TestSwitchRoleSingleTenantNeedsNoTenantInContext(t *testing.T) {
	env := newRSEnv(t)
	if _, ok := TenantIDFromContext(env.ctx()); ok {
		t.Fatal("setup: the single-tenant context must carry no tenant")
	}
	_, refresh := env.login()
	sw, err := env.engine.SwitchRole(context.Background(), refresh, "admin", RoleSwitchOptions{})
	if err != nil {
		t.Fatalf("SwitchRole without a tenant in the context failed: %v", err)
	}
	if last := env.up.lastCall(); last.tenantID != "0" {
		t.Fatalf("provider saw tenant %q, want the default tenant 0", last.tenantID)
	}
	if got := env.peek(env.sidOf(sw.RefreshToken)); got.TenantID != "0" {
		t.Fatalf("session tenant = %q, want 0", got.TenantID)
	}
}

func TestSwitchRoleStoreCorruptSessionIsInvalidRefresh(t *testing.T) {
	env := newRSEnv(t)
	_, refresh := env.login()
	sid := env.sidOf(refresh)
	key := env.sessionKey(sid)
	if err := env.rdb.Set(context.Background(), key, []byte("garbage"), time.Hour).Err(); err != nil {
		t.Fatalf("seed corrupt blob: %v", err)
	}

	_, _, refreshErr := env.engine.Refresh(env.ctx(), refresh)
	_, switchErr := env.switchRole(refresh, "admin", RoleSwitchOptions{})
	if !errors.Is(refreshErr, ErrRefreshInvalid) || !errors.Is(switchErr, ErrRefreshInvalid) {
		t.Fatalf("refresh=%v switch=%v, both want ErrRefreshInvalid", refreshErr, switchErr)
	}
	assertBoundaryAuthError(t, switchErr, ErrRefreshInvalid)
}
