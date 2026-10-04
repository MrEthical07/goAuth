package goAuth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Refresh, then a switch presenting the pre-refresh (already rotated) token,
// is refresh-token reuse: the session is revoked exactly as Refresh would.
func TestSwitchRoleAfterRefreshIsReuse(t *testing.T) {
	env := newRSEnv(t, rsConfig(func(c *Config) { c.SessionHardening.EnableReplayTracking = true }))
	_, r1 := env.login()
	sid := env.sidOf(r1)

	_, r2, err := env.engine.Refresh(env.ctx(), r1)
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	reuseBefore := env.metric(MetricRefreshReuseDetected)
	replayBefore := env.metric(MetricReplayDetected)
	invalidatedBefore := env.metric(MetricSessionInvalidated)

	res, err := env.switchRole(r1, "admin", RoleSwitchOptions{})
	if !errors.Is(err, ErrRefreshReuse) {
		t.Fatalf("SwitchRole with a stale token = %v, want ErrRefreshReuse", err)
	}
	if res != nil {
		t.Fatalf("expected no result, got %+v", res)
	}
	if env.hasSession(sid) {
		t.Fatal("reuse must delete the session")
	}
	if _, _, err := env.engine.Refresh(env.ctx(), r2); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("the newer refresh token after reuse = %v, want ErrSessionNotFound", err)
	}
	if ids := env.sessionIDs(); len(ids) != 0 {
		t.Fatalf("user index still lists %v", ids)
	}
	if n, _ := env.engine.sessionStore.TenantSessionCount(context.Background(), env.tenant); n != 0 {
		t.Fatalf("tenant counter = %d after revocation, want 0", n)
	}

	for name, id := range map[string]MetricID{
		"refresh reuse": MetricRefreshReuseDetected,
		"replay":        MetricReplayDetected,
		"invalidated":   MetricSessionInvalidated,
	} {
		before := map[MetricID]uint64{
			MetricRefreshReuseDetected: reuseBefore,
			MetricReplayDetected:       replayBefore,
			MetricSessionInvalidated:   invalidatedBefore,
		}[id]
		if got := env.metric(id); got != before+1 {
			t.Fatalf("%s metric = %d, want %d", name, got, before+1)
		}
	}
	env.waitForAudit(auditEventRefreshReuseDetected, "")
	env.waitForAudit(auditEventRoleSwitchFailed, "reuse_detected")
	if keys := env.keys("arp:*"); len(keys) != 1 || keys[0] != "arp:"+sid {
		t.Fatalf("replay tracking keys = %v, want exactly arp:%s", keys, sid)
	}
}

// With replay tracking off, reuse through a switch does not record an anomaly.
func TestSwitchRoleReuseWithoutReplayTracking(t *testing.T) {
	env := newRSEnv(t, rsConfig(func(c *Config) { c.SessionHardening.EnableReplayTracking = false }))
	_, r1 := env.login()
	if _, _, err := env.engine.Refresh(env.ctx(), r1); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if _, err := env.switchRole(r1, "admin", RoleSwitchOptions{}); !errors.Is(err, ErrRefreshReuse) {
		t.Fatalf("SwitchRole with a stale token = %v, want ErrRefreshReuse", err)
	}
	if keys := env.keys("arp:*"); len(keys) != 0 {
		t.Fatalf("replay tracking is off but %v was written", keys)
	}
}

// A mismatching switch must behave exactly like a mismatching refresh:
// same metrics, same audit event, same deletion.
func TestSwitchRoleReuseMatchesRefreshReuse(t *testing.T) {
	run := func(t *testing.T, stale func(env *rsEnv, r1 string) error) map[MetricID]uint64 {
		env := newRSEnv(t, rsConfig(func(c *Config) { c.SessionHardening.EnableReplayTracking = true }))
		_, r1 := env.login()
		if _, _, err := env.engine.Refresh(env.ctx(), r1); err != nil {
			t.Fatalf("refresh failed: %v", err)
		}
		base := env.engine.MetricsSnapshot().Counters
		before := map[MetricID]uint64{}
		for k, v := range base {
			before[k] = v
		}
		if err := stale(env, r1); !errors.Is(err, ErrRefreshReuse) {
			t.Fatalf("stale call = %v, want ErrRefreshReuse", err)
		}
		delta := map[MetricID]uint64{}
		for k, v := range env.engine.MetricsSnapshot().Counters {
			if v != before[k] {
				delta[k] = v - before[k]
			}
		}
		return delta
	}

	viaRefresh := run(t, func(env *rsEnv, r1 string) error {
		_, _, err := env.engine.Refresh(env.ctx(), r1)
		return err
	})
	viaSwitch := run(t, func(env *rsEnv, r1 string) error {
		_, err := env.switchRole(r1, "admin", RoleSwitchOptions{})
		return err
	})

	// The switch books the limiter check on top; every Refresh-visible
	// metric must match.
	delete(viaSwitch, MetricLimiterCheck)
	if len(viaRefresh) != len(viaSwitch) {
		t.Fatalf("metric deltas differ: refresh=%v switch=%v", viaRefresh, viaSwitch)
	}
	for id, want := range viaRefresh {
		if viaSwitch[id] != want {
			t.Fatalf("metric %v: refresh +%d, switch +%d", id, want, viaSwitch[id])
		}
	}
}

// A switch, then a refresh presenting the pre-switch token: the old session
// no longer exists, so that is not-found (not reuse), and the switched
// session is unaffected.
func TestRefreshAfterSwitchIsNotFoundAndLeavesSwitchedSession(t *testing.T) {
	env := newRSEnv(t)
	_, r1 := env.login()
	sw := env.mustSwitch(r1, "admin")
	newSID := env.sidOf(sw.RefreshToken)
	before := env.peek(newSID)

	if _, _, err := env.engine.Refresh(env.ctx(), r1); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("refresh with the pre-switch token = %v, want ErrSessionNotFound", err)
	}
	if env.metric(MetricRefreshReuseDetected) != 0 {
		t.Fatal("a stale pre-switch token must not be booked as reuse")
	}
	if got := env.peek(newSID); !sameSession(t, got, before) {
		t.Fatal("the switched session was modified by the stale refresh")
	}
	if _, _, err := env.engine.Refresh(env.ctx(), sw.RefreshToken); err != nil {
		t.Fatalf("the switched session's own refresh token must work: %v", err)
	}
}

func assertNoOrphans(t *testing.T, env *rsEnv) {
	t.Helper()
	ids := env.sessionIDs()
	for _, id := range ids {
		if !env.hasSession(id) {
			t.Fatalf("user index lists %s but its session is gone (orphan index entry)", id)
		}
	}
	count, err := env.engine.sessionStore.TenantSessionCount(context.Background(), env.tenant)
	if err != nil {
		t.Fatalf("tenant count: %v", err)
	}
	if count != len(ids) {
		t.Fatalf("tenant counter = %d but %d sessions are live", count, len(ids))
	}
}

// A truly concurrent switch and refresh with the same token: exactly one
// wins the CAS.
func TestSwitchRoleAndRefreshRaceExactlyOneWins(t *testing.T) {
	const rounds = 60
	env := newRSEnv(t)
	ctx := context.Background()

	var switchWins, refreshWins int
	for round := 0; round < rounds; round++ {
		if err := env.engine.LogoutAll(ctx, rsUserID); err != nil {
			t.Fatalf("round %d: logout all: %v", round, err)
		}
		_, r1 := env.login()
		oldSID := env.sidOf(r1)

		var (
			wg                 sync.WaitGroup
			barrier            = make(chan struct{})
			switchRes          *RoleSwitchResult
			switchErr, refrErr error
			refreshRefresh     string
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-barrier
			switchRes, switchErr = env.switchRole(r1, "admin", RoleSwitchOptions{})
		}()
		// Vary the refresh's head start so both orderings occur: the switch
		// does more work before its swap, so without a delay refresh
		// always wins.
		refreshDelay := time.Duration(round%12) * 70 * time.Microsecond
		go func() {
			defer wg.Done()
			<-barrier
			time.Sleep(refreshDelay)
			_, refreshRefresh, refrErr = env.engine.Refresh(env.ctx(), r1)
		}()
		close(barrier)
		wg.Wait()

		switchOK, refreshOK := switchErr == nil, refrErr == nil
		if switchOK == refreshOK {
			t.Fatalf("round %d: switch err=%v refresh err=%v; exactly one must succeed", round, switchErr, refrErr)
		}

		ids := env.sessionIDs()
		if switchOK {
			switchWins++
			// The refresh lost to a session that no longer exists.
			if !errors.Is(refrErr, ErrSessionNotFound) {
				t.Fatalf("round %d: refresh lost to a switch with %v, want ErrSessionNotFound", round, refrErr)
			}
			newSID := env.sidOf(switchRes.RefreshToken)
			if len(ids) != 1 || ids[0] != newSID || env.hasSession(oldSID) {
				t.Fatalf("round %d: after a switch win the live sessions are %v (old %s, new %s)", round, ids, oldSID, newSID)
			}
		} else {
			refreshWins++
			// The switch presented a token the refresh already rotated:
			// reuse, which deletes the session.
			if !errors.Is(switchErr, ErrRefreshReuse) {
				t.Fatalf("round %d: switch lost to a refresh with %v, want ErrRefreshReuse", round, switchErr)
			}
			if switchRes != nil {
				t.Fatalf("round %d: the losing switch returned a result", round)
			}
			if len(ids) != 0 || env.hasSession(oldSID) {
				t.Fatalf("round %d: a reuse must leave no live session, got %v", round, ids)
			}
			if _, _, err := env.engine.Refresh(env.ctx(), refreshRefresh); !errors.Is(err, ErrSessionNotFound) {
				t.Fatalf("round %d: the winner's refresh token must be dead after reuse, got %v", round, err)
			}
		}
		assertNoOrphans(t, env)
	}
	t.Logf("switch won %d rounds, refresh won %d rounds", switchWins, refreshWins)
}

// Two concurrent switches with the same token: exactly one wins.
func TestConcurrentSwitchesExactlyOneWins(t *testing.T) {
	const rounds = 40
	const workers = 4
	env := newRSEnv(t)
	ctx := context.Background()

	for round := 0; round < rounds; round++ {
		if err := env.engine.LogoutAll(ctx, rsUserID); err != nil {
			t.Fatalf("round %d: logout all: %v", round, err)
		}
		_, r1 := env.login()

		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			barrier = make(chan struct{})
			wins    []*RoleSwitchResult
			errs    []error
		)
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-barrier
				res, err := env.switchRole(r1, "admin", RoleSwitchOptions{})
				mu.Lock()
				defer mu.Unlock()
				if err == nil {
					wins = append(wins, res)
				} else {
					errs = append(errs, err)
				}
			}()
		}
		close(barrier)
		wg.Wait()

		if len(wins) != 1 || len(errs) != workers-1 {
			t.Fatalf("round %d: %d wins, %d failures; want exactly one winner (errors: %v)", round, len(wins), len(errs), errs)
		}
		for _, err := range errs {
			if !errors.Is(err, ErrSessionNotFound) {
				t.Fatalf("round %d: a losing switch returned %v, want ErrSessionNotFound", round, err)
			}
		}
		winnerSID := env.sidOf(wins[0].RefreshToken)
		if ids := env.sessionIDs(); len(ids) != 1 || ids[0] != winnerSID {
			t.Fatalf("round %d: live sessions %v, want only %s", round, ids, winnerSID)
		}
		assertNoOrphans(t, env)
	}
}

// Switching and refreshing in the documented serialized order never trips
// reuse: always present the most recently returned token.
func TestSerializedRefreshAndSwitchNeverTripReuse(t *testing.T) {
	env := newRSEnv(t)
	_, refresh := env.login()

	for i := 0; i < 6; i++ {
		_, next, err := env.engine.Refresh(env.ctx(), refresh)
		if err != nil {
			t.Fatalf("step %d: refresh failed: %v", i, err)
		}
		refresh = next
		role := "admin"
		if i%2 == 1 {
			role = "teacher"
		}
		sw := env.mustSwitch(refresh, role)
		refresh = sw.RefreshToken
	}
	if env.metric(MetricRefreshReuseDetected) != 0 {
		t.Fatal("serialized use must never register reuse")
	}
	assertNoOrphans(t, env)
}
