package goAuth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal/clock"
	"github.com/MrEthical07/goAuth/session"
)

// spProfiles is Dressin's policy plus the variants the tests need. The global
// JWT.AccessTTL is 5m (the test config), so "web" and "agent" prove a profile
// can issue shorter and longer tokens while "mobile" inherits.
func spProfiles() map[string]SessionProfile {
	return map[string]SessionProfile{
		"web":        {AbsoluteLifetime: 15 * spDay, AccessTTL: 2 * time.Minute},
		"mobile":     {IdleTimeout: 90 * spDay, AbsoluteLifetime: 365 * spDay},
		"mobile-use": {IdleTimeout: 90 * spDay, AbsoluteLifetime: 365 * spDay, RenewOnUse: true},
		"agent":      {IdleTimeout: spDay, AllowUnbounded: true, AccessTTL: 10 * time.Minute},
	}
}

// spEnv is an rsEnv configured with session profiles and a controllable
// clock: advance moves session time and the key lifetimes together.
type spEnv struct {
	*rsEnv
	clk *clock.Fake
}

func spConfig(mutate func(*Config)) rsOption {
	return rsConfig(func(c *Config) {
		c.Session.Profiles = spProfiles()
		c.Session.DefaultProfile = "web"
		c.Session.JitterEnabled = false
		c.ValidationMode = ModeHybrid
		c.TOTP.RequireForLogin = true
		c.Account.AutoLogin = true
		if mutate != nil {
			mutate(c)
		}
	})
}

func newSPEnv(t *testing.T, mutate func(*Config), opts ...rsOption) *spEnv {
	t.Helper()
	all := append([]rsOption{spConfig(mutate)}, opts...)
	env := newRSEnv(t, all...)
	// Start at the real time: MFA challenges and TOTP windows are checked
	// against it, and only the days a test advances are fake.
	clk := clock.NewFake(time.Now().Truncate(time.Second))
	t.Cleanup(clock.Set(clk.Now))
	env.mr.SetTime(clk.Now())
	return &spEnv{rsEnv: env, clk: clk}
}

func (e *spEnv) advance(d time.Duration) {
	e.clk.Advance(d)
	e.mr.SetTime(e.clk.Now())
	e.mr.FastForward(d)
}

// ctxFor is the request context naming a profile.
func (e *spEnv) ctxFor(profile string) context.Context {
	if profile == "" {
		return e.ctx()
	}
	return WithSessionProfile(e.ctx(), profile)
}

func (e *spEnv) loginAs(profile string) (access, refresh string) {
	e.t.Helper()
	access, refresh, err := e.engine.Login(e.ctxFor(profile), rsIdentifier, rsPassword)
	if err != nil {
		e.t.Fatalf("Login as %q: %v", profile, err)
	}
	return access, refresh
}

func (e *spEnv) refreshToken(refresh string) (string, string, error) {
	return e.engine.Refresh(e.ctx(), refresh)
}

func (e *spEnv) mustRefresh(refresh string) (access, next string) {
	e.t.Helper()
	access, next, err := e.refreshToken(refresh)
	if err != nil {
		e.t.Fatalf("Refresh: %v", err)
	}
	return access, next
}

func (e *spEnv) ttl(refresh string) time.Duration {
	return e.mr.TTL(e.sessionKey(e.sidOf(refresh)))
}

func (e *spEnv) wantTTL(what, refresh string, want time.Duration) {
	e.t.Helper()
	if got := e.ttl(refresh); got != want {
		e.t.Fatalf("%s: session TTL = %v, want %v", what, got, want)
	}
}

func (e *spEnv) strict(access string) error {
	_, err := e.engine.Validate(e.ctx(), access, ModeStrict)
	return err
}

// AC1a: a fixed profile ends 15 days after login even when refreshed daily.
func TestSessionProfilesAC1aWebFixedFifteenDays(t *testing.T) {
	env := newSPEnv(t, nil)
	_, refresh := env.loginAs("web")
	sid := env.sidOf(refresh)
	env.wantTTL("at login", refresh, 15*spDay)

	for day := 1; day <= 14; day++ {
		env.advance(spDay)
		_, refresh = env.mustRefresh(refresh)
		env.wantTTL("after a daily refresh", refresh, time.Duration(15-day)*spDay)
	}

	env.advance(spDay) // day 15
	if env.hasSession(sid) {
		t.Fatal("the web session outlived its 15 days")
	}
	if _, _, err := env.refreshToken(refresh); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("refresh on day 15 = %v, want ErrSessionNotFound", err)
	}
}

// AC1b: a mobile session refreshed at day 89 survives and its window moves to
// day 179; one left idle for 91 days ends.
func TestSessionProfilesAC1bMobileIdleWindow(t *testing.T) {
	t.Run("refreshed at day 89 survives", func(t *testing.T) {
		env := newSPEnv(t, nil)
		_, refresh := env.loginAs("mobile")
		env.wantTTL("at login", refresh, 90*spDay)

		env.advance(89 * spDay)
		_, refresh = env.mustRefresh(refresh)
		env.wantTTL("after the day-89 refresh", refresh, 90*spDay) // window ends day 179

		env.advance(89 * spDay) // day 178: still inside the moved window
		_, _ = env.mustRefresh(refresh)
	})

	t.Run("the window ends at day 179 without another refresh", func(t *testing.T) {
		env := newSPEnv(t, nil)
		_, refresh := env.loginAs("mobile")
		env.advance(89 * spDay)
		_, refresh = env.mustRefresh(refresh)
		env.advance(90 * spDay) // day 179
		if env.hasSession(env.sidOf(refresh)) {
			t.Fatal("the session outlived its moved idle window")
		}
	})

	t.Run("idle for 91 days ends", func(t *testing.T) {
		env := newSPEnv(t, nil)
		_, refresh := env.loginAs("mobile")
		env.advance(91 * spDay)
		if _, _, err := env.refreshToken(refresh); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("refresh after 91 idle days = %v, want ErrSessionNotFound", err)
		}
	})
}

// AC1c: a mobile session refreshed regularly still ends at day 365.
func TestSessionProfilesAC1cMobileCeiling(t *testing.T) {
	env := newSPEnv(t, nil)
	_, refresh := env.loginAs("mobile")
	sid := env.sidOf(refresh)

	for i := 0; i < 6; i++ { // days 60, 120, ..., 360
		env.advance(60 * spDay)
		_, refresh = env.mustRefresh(refresh)
	}
	// Day 360: five days of ceiling remain, so the window is clamped to them.
	env.wantTTL("after the day-360 refresh", refresh, 5*spDay)

	env.advance(5 * spDay) // day 365
	if env.hasSession(sid) {
		t.Fatal("the mobile session outlived its 365-day ceiling")
	}
	if _, _, err := env.refreshToken(refresh); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("refresh on day 365 = %v, want ErrSessionNotFound", err)
	}
}

// AC2: a replayed refresh token is rejected and deletes the session, for
// every profile.
func TestSessionProfilesAC2RefreshReuseEndsEveryProfile(t *testing.T) {
	for _, profile := range []string{"web", "mobile", "mobile-use", "agent"} {
		t.Run(profile, func(t *testing.T) {
			env := newSPEnv(t, nil)
			access, stale := env.loginAs(profile)
			sid := env.sidOf(stale)
			_, fresh := env.mustRefresh(stale)

			_, _, err := env.refreshToken(stale)
			if !errors.Is(err, ErrRefreshReuse) {
				t.Fatalf("replayed token = %v, want ErrRefreshReuse", err)
			}
			if env.hasSession(sid) {
				t.Fatal("reuse did not delete the session")
			}
			if _, _, err := env.refreshToken(fresh); !errors.Is(err, ErrSessionNotFound) {
				t.Fatalf("the legitimate token after reuse = %v, want ErrSessionNotFound", err)
			}
			if err := env.strict(access); !errors.Is(err, ErrSessionNotFound) {
				t.Fatalf("strict validation after reuse = %v, want ErrSessionNotFound", err)
			}
			env.waitForAudit("refresh_reuse_detected", "")
		})
	}
}

// Sessions of different profiles for one user coexist and age independently.
func TestSessionProfilesConcurrentProfilesCoexist(t *testing.T) {
	env := newSPEnv(t, nil)
	webAccess, webRefresh := env.loginAs("web")
	mobAccess, mobRefresh := env.loginAs("mobile")
	agentAccess, agentRefresh := env.loginAs("agent")

	if ids := env.sessionIDs(); len(ids) != 3 {
		t.Fatalf("sessions = %v, want 3", ids)
	}
	for name, access := range map[string]string{"web": webAccess, "mobile": mobAccess, "agent": agentAccess} {
		if err := env.strict(access); err != nil {
			t.Fatalf("strict validation of %s: %v", name, err)
		}
	}
	env.wantTTL("web", webRefresh, 15*spDay)
	env.wantTTL("mobile", mobRefresh, 90*spDay)
	env.wantTTL("agent", agentRefresh, spDay)

	// After 16 days the web session is over; the mobile one is not.
	env.advance(16 * spDay)
	mobRefresh = func() string { _, r := env.mustRefresh(mobRefresh); return r }()
	if _, _, err := env.refreshToken(webRefresh); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("web refresh = %v, want ErrSessionNotFound", err)
	}
	if _, _, err := env.refreshToken(agentRefresh); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("idle agent refresh = %v, want ErrSessionNotFound", err)
	}
	env.wantTTL("mobile after its refresh", mobRefresh, 90*spDay)
}

// An unbounded profile has no ceiling: its ExpiresAt is the sentinel and only
// inactivity ends it.
func TestSessionProfilesUnboundedHasNoCeiling(t *testing.T) {
	env := newSPEnv(t, nil)
	_, refresh := env.loginAs("agent")
	sess := env.peek(env.sidOf(refresh))
	if sess.ExpiresAt != session.UnboundedExpiresAt || sess.Profile != "agent" {
		t.Fatalf("session = %+v, want the unbounded sentinel", sess)
	}
	for i := 0; i < 3; i++ {
		env.advance(20 * time.Hour)
		_, refresh = env.mustRefresh(refresh)
		env.wantTTL("after a refresh", refresh, spDay)
	}
	info, err := env.engine.GetSessionInfo(env.ctx(), env.tenant, env.sidOf(refresh))
	if err != nil || info.ExpiresAt != session.UnboundedExpiresAt {
		t.Fatalf("GetSessionInfo = %+v, %v", info, err)
	}
}

// Strict reads: without RenewOnUse the key is untouched, and a v6 session
// never receives the legacy sliding reset (TTL = remaining absolute lifetime).
// A naive implementation that fell through to the legacy path would set the
// mobile session's key to the 365 days left before its ceiling.
func TestSessionProfilesStrictReadDoesNotApplyLegacyReset(t *testing.T) {
	env := newSPEnv(t, nil)
	access, refresh := env.loginAs("mobile")
	env.advance(10 * spDay)

	if err := env.strict(access); err != nil {
		t.Fatalf("strict validation: %v", err)
	}
	env.wantTTL("after a strict read without RenewOnUse", refresh, 80*spDay)

	// The fixed web session is untouched too (legacy would reset it to 15d).
	webAccess, webRefresh := env.loginAs("web")
	env.advance(3 * spDay)
	if err := env.strict(webAccess); err != nil {
		t.Fatalf("strict validation: %v", err)
	}
	env.wantTTL("web after a strict read", webRefresh, 12*spDay)
}

func TestSessionProfilesStrictReadRenewOnUse(t *testing.T) {
	env := newSPEnv(t, nil)
	access, refresh := env.loginAs("mobile-use")
	env.advance(80 * spDay)
	env.wantTTL("before the read", refresh, 10*spDay)
	if err := env.strict(access); err != nil {
		t.Fatalf("strict validation: %v", err)
	}
	env.wantTTL("after a strict read with RenewOnUse", refresh, 90*spDay)

	// Hybrid and JWT-only validation never read the session, so they renew
	// nothing.
	env.advance(50 * spDay)
	for _, mode := range []RouteMode{ModeHybrid, ModeJWTOnly} {
		_, _ = env.engine.Validate(env.ctx(), access, mode)
	}
	env.wantTTL("after stateless validation", refresh, 40*spDay)
}

// AC6: N concurrent refreshes of one session at the idle-window boundary and
// at the ceiling boundary give exactly one winner. The losers behave exactly
// as v0.7.0 reuse does, the TTL never passes the ceiling and the session is
// never resurrected. Meaningful under -race.
func TestSessionProfilesAC6ConcurrentRefreshBoundaries(t *testing.T) {
	const workers = 12
	cases := []struct {
		name    string
		profile string
		setup   func(env *spEnv, refresh *string)
	}{
		{"idle boundary", "mobile", func(env *spEnv, _ *string) {
			env.advance(90*spDay - 2*time.Second)
		}},
		{"ceiling boundary", "mobile", func(env *spEnv, refresh *string) {
			for i := 0; i < 5; i++ {
				env.advance(70 * spDay)
				_, *refresh = env.mustRefresh(*refresh)
			}
			env.advance(15*spDay - 2*time.Second)
			_, *refresh = env.mustRefresh(*refresh) // clamped to the 2s left
			env.advance(time.Second)
		}},
		{"fixed ceiling boundary", "web", func(env *spEnv, _ *string) {
			env.advance(15*spDay - 2*time.Second)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newSPEnv(t, nil)
			_, refresh := env.loginAs(tc.profile)
			sid := env.sidOf(refresh)
			tc.setup(env, &refresh)
			if !env.hasSession(sid) {
				t.Fatal("setup left no session to race on")
			}
			sess := env.peek(sid)
			remaining := time.Unix(sess.ExpiresAt, 0).Sub(env.clk.Now())

			var (
				wg      sync.WaitGroup
				start   = make(chan struct{})
				mu      sync.Mutex
				wins    int
				reuse   int
				missing int
				other   []error
			)
			for i := 0; i < workers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					_, _, err := env.engine.Refresh(env.ctx(), refresh)
					mu.Lock()
					defer mu.Unlock()
					switch {
					case err == nil:
						wins++
					case errors.Is(err, ErrRefreshReuse):
						reuse++
					case errors.Is(err, ErrSessionNotFound):
						missing++
					default:
						other = append(other, err)
					}
				}()
			}
			close(start)
			wg.Wait()

			if wins != 1 || len(other) != 0 {
				t.Fatalf("winners = %d (reuse %d, not found %d, other %v), want exactly 1", wins, reuse, missing, other)
			}
			if reuse < 1 || reuse+missing != workers-1 {
				t.Fatalf("losers: %d reuse + %d not found, want %d with at least one reuse detection", reuse, missing, workers-1)
			}
			if env.hasSession(sid) {
				if ttl := env.mr.TTL(env.sessionKey(sid)); ttl > remaining {
					t.Fatalf("TTL %v passes the ceiling (%v left)", ttl, remaining)
				}
			}
			env.advance(remaining + time.Second)
			if env.hasSession(sid) {
				t.Fatal("the session was resurrected past its ceiling")
			}
		})
	}
}

// Profiles behave identically with multi-tenancy on.
func TestSessionProfilesMultiTenant(t *testing.T) {
	env := newSPEnv(t, nil, rsMultiTenant())
	_, refresh := env.loginAs("mobile")
	sess := env.peek(env.sidOf(refresh))
	if sess.Profile != "mobile" || sess.TenantID != "tenant-a" {
		t.Fatalf("session = %+v", sess)
	}
	env.advance(89 * spDay)
	_, refresh = env.mustRefresh(refresh)
	env.wantTTL("after the day-89 refresh", refresh, 90*spDay)

	_, webRefresh := env.loginAs("")
	if got := env.peek(env.sidOf(webRefresh)).Profile; got != "web" {
		t.Fatalf("the default profile = %q, want web", got)
	}
	env.advance(15 * spDay)
	if _, _, err := env.refreshToken(webRefresh); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("web refresh after 15 days = %v, want ErrSessionNotFound", err)
	}
}

// Per-profile access-token lifetimes land in exp; the claim set is the same
// as for a legacy token.
func TestSessionProfilesAccessTokenTTL(t *testing.T) {
	env := newSPEnv(t, nil)
	want := map[string]time.Duration{
		"web":    2 * time.Minute,
		"mobile": 5 * time.Minute, // inherits JWT.AccessTTL
		"agent":  10 * time.Minute,
	}
	legacyClaims := []string{"av", "exp", "iat", "mask", "pv", "rv", "sid", "tid", "uid"}
	for profile, ttl := range want {
		access, refresh := env.loginAs(profile)
		for what, token := range map[string]string{"login": access, "refresh": func() string { a, _ := env.mustRefresh(refresh); return a }()} {
			claims, err := env.engine.jwtManager.ParseAccess(token)
			if err != nil {
				t.Fatalf("%s %s token: %v", profile, what, err)
			}
			if got := claims.ExpiresAt.Sub(claims.IssuedAt.Time); got != ttl {
				t.Fatalf("%s %s token lifetime = %v, want %v", profile, what, got, ttl)
			}
			if keys := jwtClaimKeys(t, token); len(keys) != len(legacyClaims) {
				t.Fatalf("%s %s token claims = %v, want %v", profile, what, keys, legacyClaims)
			}
		}
	}
}
