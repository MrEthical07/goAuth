package goAuth

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/session"
)

// rebuild returns a second engine over the same Redis, provider and audit
// sink whose configuration is the env's with mutate applied: how a deploy
// that edits the profile table looks to sessions already issued.
func (e *spEnv) rebuild(mutate func(*Config)) *Engine {
	e.t.Helper()
	cfg := e.cfg
	cfg.SessionProfiles.Profiles = cloneSessionProfiles(e.cfg.SessionProfiles.Profiles)
	mutate(&cfg)
	engine, err := New().
		WithConfig(cfg).
		WithRedis(e.rdb).
		WithPermissions([]string{"perm.read", "perm.write"}).
		WithRoles(map[string][]string{
			"member":  {},
			"teacher": {"perm.read"},
			"admin":   {"perm.read", "perm.write"},
		}).
		WithUserProvider(e.up).
		WithAuditSink(e.sink).
		Build()
	if err != nil {
		e.t.Fatalf("rebuild: %v", err)
	}
	e.t.Cleanup(engine.Close)
	return engine
}

// spLogoutEnv has every profile's session open for one user and strict
// validation of each token possible, so a test can see which ones an action
// ended.
type spOpenSessions struct {
	profile string
	access  string
	refresh string
}

func spOpenAll(env *spEnv) []spOpenSessions {
	env.t.Helper()
	var open []spOpenSessions
	for _, profile := range []string{"web", "mobile", "mobile-use", "agent"} {
		access, refresh := env.loginAs(profile)
		open = append(open, spOpenSessions{profile, access, refresh})
	}
	return open
}

func spWantAllEnded(t *testing.T, env *spEnv, open []spOpenSessions) {
	t.Helper()
	for _, s := range open {
		if env.hasSession(env.sidOf(s.refresh)) {
			t.Fatalf("the %s session survived", s.profile)
		}
		if err := env.strict(s.access); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("strict validation of the %s token = %v, want ErrSessionNotFound", s.profile, err)
		}
		if _, _, err := env.refreshToken(s.refresh); err == nil {
			t.Fatalf("the %s refresh token still works", s.profile)
		}
	}
	if ids := env.sessionIDs(); len(ids) != 0 {
		t.Fatalf("user index still lists %v", ids)
	}
}

// AC3: every way of invalidating a user's sessions ends the sessions of every
// profile at once.
func TestSessionProfilesAC3InvalidationEndsEveryProfile(t *testing.T) {
	const newPassword = "another-password-456"
	actions := map[string]func(t *testing.T, env *spEnv, open []spOpenSessions){
		"LogoutAll": func(t *testing.T, env *spEnv, _ []spOpenSessions) {
			if err := env.engine.LogoutAll(env.ctx(), rsUserID); err != nil {
				t.Fatalf("LogoutAll: %v", err)
			}
		},
		"LogoutAllInTenant": func(t *testing.T, env *spEnv, _ []spOpenSessions) {
			if err := env.engine.LogoutAllInTenant(env.ctx(), env.tenant, rsUserID); err != nil {
				t.Fatalf("LogoutAllInTenant: %v", err)
			}
		},
		"InvalidateUserSessions": func(t *testing.T, env *spEnv, _ []spOpenSessions) {
			if err := env.engine.InvalidateUserSessions(env.ctx(), rsUserID); err != nil {
				t.Fatalf("InvalidateUserSessions: %v", err)
			}
		},
		"ChangePassword": func(t *testing.T, env *spEnv, _ []spOpenSessions) {
			if err := env.engine.ChangePassword(env.ctx(), rsUserID, rsPassword, newPassword); err != nil {
				t.Fatalf("ChangePassword: %v", err)
			}
		},
		"ConfirmPasswordReset": func(t *testing.T, env *spEnv, _ []spOpenSessions) {
			challenge, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
			if err != nil {
				t.Fatalf("RequestPasswordReset: %v", err)
			}
			if err := env.engine.ConfirmPasswordReset(env.ctx(), challenge, newPassword); err != nil {
				t.Fatalf("ConfirmPasswordReset: %v", err)
			}
		},
		"DisableAccount": func(t *testing.T, env *spEnv, _ []spOpenSessions) {
			if err := env.engine.DisableAccount(env.ctx(), rsUserID); err != nil {
				t.Fatalf("DisableAccount: %v", err)
			}
		},
		"LockAccount": func(t *testing.T, env *spEnv, _ []spOpenSessions) {
			if err := env.engine.LockAccount(env.ctx(), rsUserID); err != nil {
				t.Fatalf("LockAccount: %v", err)
			}
		},
		"DeleteAccount": func(t *testing.T, env *spEnv, _ []spOpenSessions) {
			if err := env.engine.DeleteAccount(env.ctx(), rsUserID); err != nil {
				t.Fatalf("DeleteAccount: %v", err)
			}
		},
	}

	for name, act := range actions {
		t.Run(name, func(t *testing.T) {
			env := newSPEnv(t, func(c *Config) {
				c.PasswordReset = testResetConfig(ResetToken)
			})
			open := spOpenAll(env)
			if ids := env.sessionIDs(); len(ids) != len(open) {
				t.Fatalf("sessions = %v, want %d", ids, len(open))
			}
			act(t, env, open)
			spWantAllEnded(t, env, open)
		})
	}
}

// Logout ends exactly the session it names, whatever its profile, leaving the
// user's other sessions alone.
func TestSessionProfilesAC3LogoutEndsThatSession(t *testing.T) {
	for _, via := range []string{"Logout", "LogoutInTenant", "LogoutByAccessToken"} {
		t.Run(via, func(t *testing.T) {
			env := newSPEnv(t, nil)
			open := spOpenAll(env)
			for i, s := range open {
				sid := env.sidOf(s.refresh)
				var err error
				switch via {
				case "Logout":
					err = env.engine.Logout(env.ctx(), sid)
				case "LogoutInTenant":
					err = env.engine.LogoutInTenant(env.ctx(), env.tenant, sid)
				default:
					err = env.engine.LogoutByAccessToken(env.ctx(), s.access)
				}
				if err != nil {
					t.Fatalf("%s of the %s session: %v", via, s.profile, err)
				}
				if env.hasSession(sid) {
					t.Fatalf("the %s session survived %s", s.profile, via)
				}
				if err := env.strict(s.access); !errors.Is(err, ErrSessionNotFound) {
					t.Fatalf("strict validation after logout = %v", err)
				}
				for _, other := range open[i+1:] {
					if !env.hasSession(env.sidOf(other.refresh)) {
						t.Fatalf("logging out %s ended the %s session", s.profile, other.profile)
					}
				}
			}
		})
	}
}

// AC3: version drift ends a profile session on its next strict read, as it
// does a legacy one.
func TestSessionProfilesAC3VersionDriftEndsEveryProfile(t *testing.T) {
	drifts := map[string]func(s *session.Session){
		"permission version": func(s *session.Session) { s.PermissionVersion++ },
		"role version":       func(s *session.Session) { s.RoleVersion++ },
		"account version":    func(s *session.Session) { s.AccountVersion++ },
	}
	for name, drift := range drifts {
		for _, profile := range []string{"web", "mobile", "mobile-use", "agent"} {
			t.Run(fmt.Sprintf("%s/%s", name, profile), func(t *testing.T) {
				env := newSPEnv(t, nil)
				access, refresh := env.loginAs(profile)
				sid := env.sidOf(refresh)

				stored := env.peek(sid)
				ttl := env.mr.TTL(env.sessionKey(sid))
				drift(stored)
				if err := env.engine.sessionStore.Save(context.Background(), stored, ttl); err != nil {
					t.Fatalf("rewrite session: %v", err)
				}
				if err := env.strict(access); !errors.Is(err, ErrSessionNotFound) {
					t.Fatalf("strict validation = %v, want ErrSessionNotFound", err)
				}
				if env.hasSession(sid) {
					t.Fatal("drift did not delete the session")
				}
			})
		}
	}
}

// Role switch: the replacement keeps the profile, CreatedAt and ExpiresAt; a
// switch is a use that renews the idle window; and it never extends the
// ceiling.
func TestSessionProfilesRoleSwitch(t *testing.T) {
	t.Run("renewing profile", func(t *testing.T) {
		env := newSPEnv(t, nil)
		_, refresh := env.loginAs("mobile")
		before := env.peek(env.sidOf(refresh))
		env.advance(50 * spDay)
		env.wantTTL("before the switch", refresh, 40*spDay)

		res := env.mustSwitch(refresh, "admin")
		after := env.peek(env.sidOf(res.RefreshToken))
		if after.Profile != "mobile" || after.CreatedAt != before.CreatedAt || after.ExpiresAt != before.ExpiresAt || after.Role != "admin" {
			t.Fatalf("switched session = %+v, was %+v", after, before)
		}
		env.wantTTL("after the switch (idle window renewed)", res.RefreshToken, 90*spDay)
		if env.hasSession(env.sidOf(refresh)) {
			t.Fatal("the old session survived the switch")
		}
	})

	t.Run("never extends the ceiling", func(t *testing.T) {
		env := newSPEnv(t, nil)
		_, refresh := env.loginAs("mobile")
		for i := 0; i < 5; i++ {
			env.advance(70 * spDay)
			_, refresh = env.mustRefresh(refresh)
		}
		before := env.peek(env.sidOf(refresh))
		res := env.mustSwitch(refresh, "admin")
		after := env.peek(env.sidOf(res.RefreshToken))
		if after.ExpiresAt != before.ExpiresAt || after.CreatedAt != before.CreatedAt {
			t.Fatalf("a switch moved the ceiling: %+v -> %+v", before, after)
		}
		env.wantTTL("clamped to the 15 days left", res.RefreshToken, 15*spDay)

		// Switching back and forth cannot stretch it either.
		back := env.mustSwitch(res.RefreshToken, "teacher")
		env.wantTTL("after switching back", back.RefreshToken, 15*spDay)
	})

	t.Run("fixed profile keeps what is left", func(t *testing.T) {
		env := newSPEnv(t, nil)
		_, refresh := env.loginAs("web")
		env.advance(4 * spDay)
		res := env.mustSwitch(refresh, "admin")
		env.wantTTL("after the switch", res.RefreshToken, 11*spDay)
		if got := env.peek(env.sidOf(res.RefreshToken)).Profile; got != "web" {
			t.Fatalf("profile = %q", got)
		}
	})

	t.Run("a removed profile ends the session at the switch", func(t *testing.T) {
		env := newSPEnv(t, nil)
		_, refresh := env.loginAs("mobile")
		engine2 := env.rebuild(func(c *Config) { delete(c.SessionProfiles.Profiles, "mobile") })
		_, err := engine2.SwitchRole(env.ctx(), refresh, "admin", RoleSwitchOptions{})
		if !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("SwitchRole = %v, want ErrSessionNotFound", err)
		}
		if env.hasSession(env.sidOf(refresh)) {
			t.Fatal("the session of a removed profile survived a switch")
		}
	})
}

// Live configuration: profiles are resolved at use time.
func TestSessionProfilesLiveConfig(t *testing.T) {
	t.Run("shortening the ceiling shortens existing sessions", func(t *testing.T) {
		env := newSPEnv(t, nil)
		_, refresh := env.loginAs("mobile")
		env.advance(40 * spDay)
		engine2 := env.rebuild(func(c *Config) {
			c.SessionProfiles.Profiles["mobile"] = SessionProfile{IdleTimeout: 30 * spDay, AbsoluteLifetime: 60 * spDay}
		})

		_, next, err := engine2.Refresh(env.ctx(), refresh)
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		env.wantTTL("clamped to the shortened ceiling", next, 20*spDay)

		env.advance(25 * spDay) // day 65, past the shortened ceiling
		if _, _, err := engine2.Refresh(env.ctx(), next); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("refresh past the shortened ceiling = %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("a shortened ceiling already passed ends the session at refresh and at a strict read", func(t *testing.T) {
		env := newSPEnv(t, nil)
		access, refresh := env.loginAs("mobile")
		env.advance(70 * spDay)
		engine2 := env.rebuild(func(c *Config) {
			c.SessionProfiles.Profiles["mobile"] = SessionProfile{IdleTimeout: 30 * spDay, AbsoluteLifetime: 60 * spDay}
		})

		if _, err := engine2.Validate(env.ctx(), access, ModeStrict); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("strict read = %v, want ErrSessionNotFound", err)
		}
		ev := env.waitForAudit("session_invalid", "expired")
		if ev.Metadata["profile"] != "mobile" || ev.Success {
			t.Fatalf("session_invalid event = %+v", ev)
		}
		if env.hasSession(env.sidOf(refresh)) {
			t.Fatal("the strict read left the session")
		}

		access2, refresh2 := env.loginAs("mobile") // a fresh session under the old table
		env.advance(70 * spDay)
		_, _ = access2, refresh2
		if _, _, err := engine2.Refresh(env.ctx(), refresh2); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("refresh = %v, want ErrSessionNotFound", err)
		}
		if env.hasSession(env.sidOf(refresh2)) {
			t.Fatal("the refresh left the session")
		}
	})

	t.Run("lengthening never extends ExpiresAt", func(t *testing.T) {
		env := newSPEnv(t, nil)
		_, refresh := env.loginAs("web")
		stored := env.peek(env.sidOf(refresh))
		env.advance(10 * spDay)
		engine2 := env.rebuild(func(c *Config) {
			c.SessionProfiles.Profiles["web"] = SessionProfile{AbsoluteLifetime: 100 * spDay}
		})

		_, next, err := engine2.Refresh(env.ctx(), refresh)
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		env.wantTTL("the stored ceiling still wins", next, 5*spDay)
		if got := env.peek(env.sidOf(next)); got.ExpiresAt != stored.ExpiresAt {
			t.Fatalf("ExpiresAt moved from %d to %d", stored.ExpiresAt, got.ExpiresAt)
		}
		env.advance(5 * spDay)
		if env.hasSession(env.sidOf(next)) {
			t.Fatal("a lengthened config revived a session past its stored ceiling")
		}
	})

	t.Run("removing a profile ends its sessions with audit reason profile_unknown", func(t *testing.T) {
		env := newSPEnv(t, nil)
		access, refresh := env.loginAs("mobile")
		_, webRefresh := env.loginAs("web")
		strictAccess, strictRefresh := env.loginAs("mobile")
		engine2 := env.rebuild(func(c *Config) { delete(c.SessionProfiles.Profiles, "mobile") })

		_, _, err := engine2.Refresh(env.ctx(), refresh)
		if !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("refresh = %v, want the expired-session error ErrSessionNotFound", err)
		}
		ev := env.waitForAudit("refresh_invalid", "profile_unknown")
		if ev.Metadata["profile"] != "mobile" || ev.Success {
			t.Fatalf("refresh_invalid event = %+v", ev)
		}
		if env.hasSession(env.sidOf(refresh)) {
			t.Fatal("the session of a removed profile survived a refresh")
		}
		_ = access

		if _, err := engine2.Validate(env.ctx(), strictAccess, ModeStrict); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("strict read = %v, want ErrSessionNotFound", err)
		}
		ev = env.waitForAudit("session_invalid", "profile_unknown")
		if ev.Metadata["profile"] != "mobile" {
			t.Fatalf("session_invalid event = %+v", ev)
		}
		if env.hasSession(env.sidOf(strictRefresh)) {
			t.Fatal("the session of a removed profile survived a strict read")
		}

		// The other profile is untouched.
		if _, _, err := engine2.Refresh(env.ctx(), webRefresh); err != nil {
			t.Fatalf("refresh of a surviving profile: %v", err)
		}
	})

	t.Run("removing every profile ends profile sessions", func(t *testing.T) {
		env := newSPEnv(t, nil)
		_, refresh := env.loginAs("web")
		engine2 := env.rebuild(func(c *Config) {
			c.SessionProfiles.Profiles = nil
			c.SessionProfiles.DefaultProfile = ""
			c.SessionProfiles.RememberMeProfile = ""
		})
		if _, _, err := engine2.Refresh(env.ctx(), refresh); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("refresh = %v, want ErrSessionNotFound", err)
		}
		env.waitForAudit("refresh_invalid", "profile_unknown")
	})
}

// Sessions created before profiles were enabled stay legacy: v5 on disk, the
// old TTL behavior, and no profile in their audit events.
func TestSessionProfilesLegacySessionsKeepLegacyBehavior(t *testing.T) {
	env := newSPEnv(t, nil)
	legacy := env.rebuild(func(c *Config) {
		c.SessionProfiles.Profiles = nil
		c.SessionProfiles.DefaultProfile = ""
		c.SessionProfiles.RememberMeProfile = ""
	})
	access, refresh, err := legacy.Login(env.ctx(), rsIdentifier, rsPassword)
	if err != nil {
		t.Fatalf("legacy login: %v", err)
	}
	sid := env.sidOf(refresh)
	assertLegacy := func(step string) {
		t.Helper()
		sess := env.peek(sid)
		if sess.Profile != "" || sess.SchemaVersion != 5 {
			t.Fatalf("%s: session = version %d profile %q, want legacy v5", step, sess.SchemaVersion, sess.Profile)
		}
	}
	assertLegacy("created")
	const lifetime = 7 * spDay

	env.advance(spDay)
	// The profile-enabled engine refreshes it exactly as v0.7.0 would: same
	// PTTL, still v5.
	ttlBefore := env.mr.TTL(env.sessionKey(sid))
	_, next, err := env.engine.Refresh(env.ctx(), refresh)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	assertLegacy("refreshed")
	if got := env.mr.TTL(env.sessionKey(sid)); got != ttlBefore {
		t.Fatalf("a legacy refresh changed the TTL from %v to %v", ttlBefore, got)
	}

	// A strict read applies the legacy sliding reset.
	if _, err := env.engine.Validate(env.ctx(), access, ModeStrict); err != nil {
		t.Fatalf("strict read: %v", err)
	}
	assertLegacy("strict read")
	if got := env.mr.TTL(env.sessionKey(sid)); got != lifetime-spDay {
		t.Fatalf("legacy sliding reset left TTL %v, want %v", got, lifetime-spDay)
	}

	// Introspection shows no profile and no idle expiry.
	info, err := env.engine.GetSessionInfo(env.ctx(), env.tenant, sid)
	if err != nil || info.Profile != "" || info.IdleExpiresAt != 0 {
		t.Fatalf("GetSessionInfo = %+v, %v", info, err)
	}

	// A role switch keeps it legacy.
	res := env.mustSwitch(next, "admin")
	if sess := env.peek(env.sidOf(res.RefreshToken)); sess.Profile != "" || sess.SchemaVersion != 5 {
		t.Fatalf("switched legacy session = %+v", sess)
	}

	// Logout of a legacy session carries no profile.
	if err := env.engine.Logout(env.ctx(), env.sidOf(res.RefreshToken)); err != nil {
		t.Fatalf("logout: %v", err)
	}
	env.engine.Close()
	env.sink.mu.Lock()
	defer env.sink.mu.Unlock()
	for _, ev := range env.sink.events {
		if _, ok := ev.Metadata["profile"]; ok && ev.SessionID == sid {
			t.Fatalf("a legacy session's %s event carries a profile: %v", ev.EventType, ev.Metadata)
		}
	}
}

// Introspection: Profile and IdleExpiresAt on both views.
func TestSessionProfilesIntrospection(t *testing.T) {
	env := newSPEnv(t, nil)
	_, mobRefresh := env.loginAs("mobile")
	_, webRefresh := env.loginAs("web")
	_, agentRefresh := env.loginAs("agent")
	env.advance(10 * time.Hour)

	mobile, err := env.engine.GetSessionInfo(env.ctx(), env.tenant, env.sidOf(mobRefresh))
	if err != nil {
		t.Fatalf("GetSessionInfo: %v", err)
	}
	if mobile.Profile != "mobile" || mobile.IdleExpiresAt != env.clk.Now().Add(90*spDay-10*time.Hour).Unix() {
		t.Fatalf("mobile info = %+v", mobile)
	}
	web, err := env.engine.GetSessionInfo(env.ctx(), env.tenant, env.sidOf(webRefresh))
	if err != nil || web.Profile != "web" || web.IdleExpiresAt != 0 {
		t.Fatalf("web info = %+v, %v", web, err)
	}

	list, err := env.engine.ListActiveSessions(env.ctx(), rsUserID)
	if err != nil || len(list) != 3 {
		t.Fatalf("ListActiveSessions = %v, %v", list, err)
	}
	byProfile := map[string]SessionInfo{}
	for _, info := range list {
		byProfile[info.Profile] = info
	}
	if byProfile["mobile"].IdleExpiresAt != mobile.IdleExpiresAt ||
		byProfile["web"].IdleExpiresAt != 0 ||
		byProfile["agent"].IdleExpiresAt != env.clk.Now().Add(spDay-10*time.Hour).Unix() ||
		byProfile["agent"].ExpiresAt != session.UnboundedExpiresAt {
		t.Fatalf("ListActiveSessions = %+v", byProfile)
	}
	_ = agentRefresh

	// A removed profile no longer lists, and listing deletes nothing.
	engine2 := env.rebuild(func(c *Config) { delete(c.SessionProfiles.Profiles, "mobile") })
	list, err = engine2.ListActiveSessions(env.ctx(), rsUserID)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListActiveSessions after removing a profile = %v, %v", list, err)
	}
	if !env.hasSession(env.sidOf(mobRefresh)) {
		t.Fatal("listing deleted a session")
	}
}

// Audit: the profile is added to the events of a session under a profile and
// to nothing else.
func TestSessionProfilesAuditMetadata(t *testing.T) {
	env, secret, _ := spMFAEnv(t, nil)
	ctx := env.ctxFor("mobile")

	res, err := env.engine.LoginWithResult(ctx, rsIdentifier, rsPassword)
	if err != nil || !res.MFARequired {
		t.Fatalf("step 1: %v", err)
	}
	done, err := env.engine.ConfirmLoginMFA(env.ctx(), res.MFASession, env.totp(secret))
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	_, refresh2, err := env.engine.Refresh(env.ctx(), done.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	switched := env.mustSwitch(refresh2, "admin")
	if err := env.engine.Logout(env.ctx(), env.sidOf(switched.RefreshToken)); err != nil {
		t.Fatalf("logout: %v", err)
	}

	for _, ev := range []string{"mfa_success", "refresh_success", "role_switched", "logout_session"} {
		got := env.waitForAudit(ev, "")
		if got.Metadata["profile"] != "mobile" {
			t.Fatalf("%s metadata = %v, want profile=mobile", ev, got.Metadata)
		}
	}

	// A plain login (no MFA) also reports it.
	env2 := newSPEnv(t, nil)
	env2.loginAs("agent")
	if got := env2.waitForAudit("login_success", ""); got.Metadata["profile"] != "agent" || got.Metadata["identifier"] != rsIdentifier {
		t.Fatalf("login_success metadata = %v", got.Metadata)
	}

	// Logout by access token.
	env3 := newSPEnv(t, nil)
	access, _ := env3.loginAs("web")
	if err := env3.engine.LogoutByAccessToken(env3.ctx(), access); err != nil {
		t.Fatalf("LogoutByAccessToken: %v", err)
	}
	if got := env3.waitForAudit("logout_session", ""); got.Metadata["profile"] != "web" {
		t.Fatalf("logout_session metadata = %v", got.Metadata)
	}
}

func TestSessionProfileErrorSentinels(t *testing.T) {
	cases := []struct {
		name      string
		err       *AuthError
		code      AuthCode
		auditCode AuditErrorCode
	}{
		{"unknown profile", ErrUnknownSessionProfile, CodeAuthUnknownSessionProfile, auditErrUnknownSessionProfile},
		{"profile conflict", ErrSessionProfileConflict, CodeAuthSessionProfileConflict, auditErrSessionProfileConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Code != string(tc.code) || tc.err.Category != CategoryAuthValidation || tc.err.Message == "" {
				t.Fatalf("sentinel = %+v", tc.err)
			}
			if got := auditErrorCode(tc.err); got != tc.auditCode {
				t.Fatalf("audit code = %q, want %q", got, tc.auditCode)
			}
			wrapped := fmt.Errorf("context: %w", tc.err)
			mapped := mapToAuthError(wrapped)
			if !errors.Is(mapped, tc.err) || mapped.Code != tc.err.Code {
				t.Fatalf("mapToAuthError lost the sentinel: %v", mapped)
			}
		})
	}
	if CodeAuthUnknownSessionProfile != "AUTH_UNKNOWN_SESSION_PROFILE" || CodeAuthSessionProfileConflict != "AUTH_SESSION_PROFILE_CONFLICT" {
		t.Fatal("error codes changed")
	}
}

func TestWithSessionProfileContext(t *testing.T) {
	ctx := context.Background()
	if name, ok := SessionProfileFromContext(ctx); ok || name != "" {
		t.Fatalf("empty context = (%q, %v)", name, ok)
	}
	if name, ok := SessionProfileFromContext(WithSessionProfile(ctx, "mobile")); !ok || name != "mobile" {
		t.Fatalf("named context = (%q, %v)", name, ok)
	}
	if name, ok := SessionProfileFromContext(WithSessionProfile(ctx, "")); ok || name != "" {
		t.Fatalf("an empty name must read as none, got (%q, %v)", name, ok)
	}
	// It composes with the tenant and the innermost name wins.
	both := WithSessionProfile(WithTenantID(ctx, "t1"), "web")
	if tenant, _ := TenantIDFromContext(both); tenant != "t1" {
		t.Fatalf("tenant lost: %q", tenant)
	}
	if name, _ := SessionProfileFromContext(WithSessionProfile(both, "agent")); name != "agent" {
		t.Fatalf("innermost name = %q", name)
	}
}
