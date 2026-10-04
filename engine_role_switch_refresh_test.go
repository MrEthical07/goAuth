package goAuth

import (
	"errors"
	"testing"
)

// A switched role survives refresh: Refresh never reads the provider for the
// role, it issues the access token from the stored session.
func TestRefreshAfterSwitchKeepsSwitchedRole(t *testing.T) {
	env := newRSEnv(t)
	_, refresh := env.login()
	sw := env.mustSwitch(refresh, "admin")

	refresh = sw.RefreshToken
	for i := 0; i < 3; i++ {
		access, next, err := env.engine.Refresh(env.ctx(), refresh)
		if err != nil {
			t.Fatalf("refresh %d failed: %v", i, err)
		}
		refresh = next
		res, err := env.validate(access, ModeStrict)
		if err != nil {
			t.Fatalf("validate after refresh %d failed: %v", i, err)
		}
		requireRoleIs(t, res, "admin")
		if !canWrite(env, res) {
			t.Fatalf("refresh %d lost the admin mask", i)
		}
		hybrid, err := env.validate(access, ModeHybrid)
		if err != nil || !canWrite(env, hybrid) {
			t.Fatalf("refresh %d: the refreshed token must carry the admin mask in hybrid too (%v)", i, err)
		}
	}
}

func TestRefreshRoleRecheckRevokedRoleEndsTheSession(t *testing.T) {
	env := newRSEnv(t)
	_, refresh := env.login()
	sw := env.mustSwitch(refresh, "admin")
	sid := env.sidOf(sw.RefreshToken)

	env.up.revoke(rsUserID, "admin")
	failuresBefore := env.metric(MetricRefreshFailure)
	invalidatedBefore := env.metric(MetricSessionInvalidated)

	access, next, err := env.engine.Refresh(env.ctx(), sw.RefreshToken)
	if !errors.Is(err, ErrRoleNotAllowed) {
		t.Fatalf("Refresh with a revoked role = %v, want ErrRoleNotAllowed", err)
	}
	assertBoundaryAuthError(t, err, ErrRoleNotAllowed)
	if access != "" || next != "" {
		t.Fatalf("a refused refresh must not return tokens (%q, %q)", access, next)
	}
	if env.hasSession(sid) {
		t.Fatal("the session must be deleted, with no fallback to the primary role")
	}
	if ids := env.sessionIDs(); len(ids) != 0 {
		t.Fatalf("user index still lists %v", ids)
	}
	if _, _, err := env.engine.Refresh(env.ctx(), sw.RefreshToken); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("the refresh token after revocation = %v, want ErrSessionNotFound", err)
	}
	if got := env.metric(MetricRefreshFailure); got != failuresBefore+2 {
		t.Fatalf("refresh failures = %d, want %d", got, failuresBefore+2)
	}
	if got := env.metric(MetricSessionInvalidated); got != invalidatedBefore+1 {
		t.Fatalf("sessions invalidated = %d, want %d", got, invalidatedBefore+1)
	}
	ev := env.waitForAudit(auditEventRefreshInvalid, "role_revoked")
	if ev.UserID != rsUserID || ev.SessionID != sid || ev.Success {
		t.Fatalf("unexpected role_revoked audit event: %+v", ev)
	}
}

func TestRefreshRoleRecheckProviderErrorNeitherRotatesNorDeletes(t *testing.T) {
	env := newRSEnv(t)
	_, refresh := env.login()
	sid := env.sidOf(refresh)
	before := env.peek(sid)

	env.up.setCanErr(errors.New("provider-db-down"))
	access, next, err := env.engine.Refresh(env.ctx(), refresh)
	if !errors.Is(err, ErrSystemUnavailable) {
		t.Fatalf("Refresh with an unavailable provider = %v, want ErrSystemUnavailable", err)
	}
	if access != "" || next != "" {
		t.Fatal("no tokens may be issued")
	}
	if got := env.peek(sid); !sameSession(t, got, before) {
		t.Fatal("the session must be neither rotated nor deleted on a provider error")
	}
	env.waitForAudit(auditEventRefreshInvalid, "role_check_unavailable")

	// The very same refresh token works on retry.
	env.up.setCanErr(nil)
	if _, _, err := env.engine.Refresh(env.ctx(), refresh); err != nil {
		t.Fatalf("retrying the same refresh token failed: %v", err)
	}
}

func TestRefreshRoleRecheckCoversPrimaryRoleToo(t *testing.T) {
	env := newRSEnv(t)
	_, refresh := env.login()
	sid := env.sidOf(refresh)

	// The session never switched; its primary role is re-checked all the same.
	env.up.revoke(rsUserID, "teacher")
	if _, _, err := env.engine.Refresh(env.ctx(), refresh); !errors.Is(err, ErrRoleNotAllowed) {
		t.Fatalf("Refresh with a revoked primary role = %v, want ErrRoleNotAllowed", err)
	}
	if env.hasSession(sid) {
		t.Fatal("the session must end when its primary role is no longer held")
	}
	if last := env.up.lastCall(); last.role != "teacher" || last.userID != rsUserID || last.tenantID != "0" {
		t.Fatalf("provider saw %+v, want the session's own role, user and tenant", last)
	}
}

func TestRefreshRoleRecheckCostsOneProviderCallPerRefresh(t *testing.T) {
	env := newRSEnv(t)
	_, refresh := env.login()
	if n := env.up.callCount(); n != 0 {
		t.Fatalf("login must not call the provider, saw %d", n)
	}
	for i := 1; i <= 3; i++ {
		_, next, err := env.engine.Refresh(env.ctx(), refresh)
		if err != nil {
			t.Fatalf("refresh %d failed: %v", i, err)
		}
		refresh = next
		if n := env.up.callCount(); n != i {
			t.Fatalf("after %d refreshes the provider was called %d times, want %d", i, n, i)
		}
	}
}

func TestValidationMakesNoProviderCalls(t *testing.T) {
	env := newRSEnv(t)
	access, refresh := env.login()
	sw := env.mustSwitch(refresh, "admin")
	calls := env.up.callCount()

	for _, token := range []string{access, sw.AccessToken} {
		for _, mode := range []RouteMode{ModeStrict, ModeHybrid, ModeJWTOnly, ModeInherit} {
			_, _ = env.validate(token, mode)
		}
	}
	if got := env.up.callCount(); got != calls {
		t.Fatalf("validation called the provider %d time(s)", got-calls)
	}
}

// Missing, expired and mismatching sessions skip the re-check, so reuse
// detection and deletion behave exactly as they do without role switching.
func TestRefreshRoleRecheckIsSkippedWhenRefreshWouldFailAnyway(t *testing.T) {
	t.Run("mismatching token keeps the reuse behavior and skips the provider", func(t *testing.T) {
		env := newRSEnv(t, rsConfig(func(c *Config) { c.SessionHardening.EnableReplayTracking = true }))
		_, r1 := env.login()
		_, _, err := env.engine.Refresh(env.ctx(), r1)
		if err != nil {
			t.Fatalf("first refresh failed: %v", err)
		}
		callsAfterFirst := env.up.callCount()

		if _, _, err := env.engine.Refresh(env.ctx(), r1); !errors.Is(err, ErrRefreshReuse) {
			t.Fatalf("stale token = %v, want ErrRefreshReuse", err)
		}
		if env.up.callCount() != callsAfterFirst {
			t.Fatal("a mismatching token must not reach the provider")
		}
		if env.hasSession(env.sidOf(r1)) {
			t.Fatal("reuse must still delete the session")
		}
		env.waitForAudit(auditEventRefreshReuseDetected, "")
	})

	t.Run("logged-out session", func(t *testing.T) {
		env := newRSEnv(t)
		_, refresh := env.login()
		if err := env.engine.Logout(env.ctx(), env.sidOf(refresh)); err != nil {
			t.Fatalf("logout failed: %v", err)
		}
		if _, _, err := env.engine.Refresh(env.ctx(), refresh); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("refresh = %v, want ErrSessionNotFound", err)
		}
		if n := env.up.callCount(); n != 0 {
			t.Fatalf("the provider was called %d time(s) for a missing session", n)
		}
	})
}

// The reuse outcome of a mismatching token must be indistinguishable from an
// engine that never had role switching.
func TestRefreshReuseUnchangedByRoleSwitchEnablement(t *testing.T) {
	outcome := func(enabled bool) (map[MetricID]uint64, bool, error) {
		env := newRSEnv(t,
			rsConfig(func(c *Config) { c.RoleSwitch.Enabled = enabled }),
			rsConfig(func(c *Config) { c.SessionHardening.EnableReplayTracking = true }),
		)
		_, r1 := env.login()
		if _, _, err := env.engine.Refresh(env.ctx(), r1); err != nil {
			t.Fatalf("first refresh failed: %v", err)
		}
		before := map[MetricID]uint64{}
		for k, v := range env.engine.MetricsSnapshot().Counters {
			before[k] = v
		}
		_, _, err := env.engine.Refresh(env.ctx(), r1)
		delta := map[MetricID]uint64{}
		for k, v := range env.engine.MetricsSnapshot().Counters {
			if v != before[k] {
				delta[k] = v - before[k]
			}
		}
		return delta, env.hasSession(env.sidOf(r1)), err
	}

	offDelta, offAlive, offErr := outcome(false)
	onDelta, onAlive, onErr := outcome(true)

	if !errors.Is(offErr, ErrRefreshReuse) || !errors.Is(onErr, ErrRefreshReuse) {
		t.Fatalf("off=%v on=%v, both want ErrRefreshReuse", offErr, onErr)
	}
	if offAlive || onAlive {
		t.Fatal("the session must be deleted either way")
	}
	if len(offDelta) != len(onDelta) {
		t.Fatalf("metric deltas differ: off=%v on=%v", offDelta, onDelta)
	}
	for id, v := range offDelta {
		if onDelta[id] != v {
			t.Fatalf("metric %v: off +%d, on +%d", id, v, onDelta[id])
		}
	}
}
