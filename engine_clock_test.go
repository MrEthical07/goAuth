package goAuth

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// manualClock is a Clock a test moves by hand.
type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func newManualClock(start time.Time) *manualClock { return &manualClock{now: start} }

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// clockedEnv is an rsEnv on a manualClock that starts years away from the wall
// clock, so anything that still reads the system time shows up at once.
type clockedEnv struct {
	*rsEnv
	clk *manualClock
}

func newClockedEnv(t *testing.T, start time.Time, opts ...rsOption) *clockedEnv {
	t.Helper()
	clk := newManualClock(start)
	env := newRSEnv(t, append([]rsOption{rsClock(clk)}, opts...)...)
	env.mr.SetTime(start)
	return &clockedEnv{rsEnv: env, clk: clk}
}

// advance moves the clock and Redis by d, as the docs tell a test to.
func (e *clockedEnv) advance(d time.Duration) {
	e.clk.Advance(d)
	e.mr.SetTime(e.clk.Now())
	e.mr.FastForward(d)
}

var clockStart = time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC)

// A session, its access token and the audit trail are all stamped by the
// injected clock, and the token is judged against it.
func TestWithClockDrivesSessionTokensAndAudit(t *testing.T) {
	env := newClockedEnv(t, clockStart)
	access, refresh := env.login()

	sess := env.peek(env.sidOf(refresh))
	if sess.CreatedAt != clockStart.Unix() {
		t.Fatalf("session CreatedAt = %d, want the injected %d", sess.CreatedAt, clockStart.Unix())
	}
	claims, err := env.engine.jwtManager.ParseAccess(access)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	if claims.IssuedAt.Unix() != clockStart.Unix() {
		t.Fatalf("token iat = %d, want the injected %d", claims.IssuedAt.Unix(), clockStart.Unix())
	}
	if _, err := env.engine.Validate(env.ctx(), access, ModeHybrid); err != nil {
		t.Fatalf("Validate before expiry: %v", err)
	}

	// Only the access token lapses: the session is long-lived. The wall clock
	// has not moved.
	env.advance(env.cfg.JWT.AccessTTL + time.Minute)
	if _, err := env.engine.Validate(env.ctx(), access, ModeHybrid); err == nil {
		t.Fatal("an access token past its expiry on the injected clock was accepted")
	}
	if !env.hasSession(env.sidOf(refresh)) {
		t.Fatal("the session must outlive its access token")
	}

	env.engine.Close()
	env.sink.mu.Lock()
	defer env.sink.mu.Unlock()
	if len(env.sink.events) == 0 {
		t.Fatal("no audit events")
	}
	for _, ev := range env.sink.events {
		if ev.Timestamp.Year() != 2031 {
			t.Fatalf("audit event %q stamped %v, want the injected clock's year 2031", ev.EventType, ev.Timestamp)
		}
	}
}

// Two engines in one process with different clocks do not affect each other.
func TestWithClockEnginesAreIndependent(t *testing.T) {
	a := newClockedEnv(t, clockStart)
	b := newClockedEnv(t, clockStart.AddDate(9, 0, 0))
	_, refreshA := a.login()
	accessB, refreshB := b.login()

	a.advance(400 * 24 * time.Hour) // beyond every default session lifetime
	if a.hasSession(a.sidOf(refreshA)) {
		t.Fatal("engine A's session outlived its clock")
	}
	if !b.hasSession(b.sidOf(refreshB)) {
		t.Fatal("engine A's clock ended engine B's session")
	}
	if _, err := b.engine.Validate(b.ctx(), accessB, ModeHybrid); err != nil {
		t.Fatalf("engine B rejected its own fresh token: %v", err)
	}
}

// A challenge's expiry is judged by the injected clock, not by Redis alone: the
// key is still alive in Redis (only the clock moves) but the record has expired.
func TestWithClockChallengeExpiry(t *testing.T) {
	env := &clockedEnv{}
	clk := newManualClock(clockStart)
	ec := newECEnv(t, nil, rsClock(clk))
	env.rsEnv, env.clk = ec.rsEnv, clk
	env.mr.SetTime(clockStart)

	t.Run("password reset", func(t *testing.T) {
		challenge, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
		if err != nil {
			t.Fatalf("RequestPasswordReset: %v", err)
		}
		// Past ResetTTL by the clock, inside it by Redis.
		clk.Advance(env.cfg.PasswordReset.ResetTTL + time.Minute)
		err = env.engine.ConfirmPasswordReset(env.ctx(), challenge, "a-brand-new-password-1")
		if err == nil {
			t.Fatal("an expired reset challenge was accepted")
		}
		if errors.Is(err, ErrSystemUnavailable) {
			t.Fatalf("expected an invalid-challenge refusal, got %v", err)
		}

		fresh, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
		if err != nil {
			t.Fatalf("second RequestPasswordReset: %v", err)
		}
		if err := env.engine.ConfirmPasswordReset(env.ctx(), fresh, "a-brand-new-password-1"); err != nil {
			t.Fatalf("a fresh challenge must redeem: %v", err)
		}
	})
}
