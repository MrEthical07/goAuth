package goAuth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// Regression tests for R2-12 of the v0.8.1 verification audit (run 3): the
// automatic lockout discarded the session-revocation error its lock returned.

// newLockoutAuditEngine is newCreateAccountEngine with an audit sink, strict
// validation (a revoked session stops validating at once) and auto-lockout on.
func newLockoutAuditEngine(t *testing.T, up UserProvider, mutate func(*Config)) (*Engine, *redis.Client, *collectingSink) {
	t.Helper()
	cfg := lockoutTestConfig()
	cfg.ValidationMode = ModeStrict
	cfg.Audit.Enabled = true
	if mutate != nil {
		mutate(&cfg)
	}
	mr, rdb := newTestRedis(t)
	t.Cleanup(mr.Close)
	t.Cleanup(func() { _ = rdb.Close() })
	sink := &collectingSink{}
	engine, err := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"perm.read"}).
		WithRoles(map[string][]string{"member": {}, "admin": {"perm.read"}}).
		WithUserProvider(up).
		WithAuditSink(sink).
		Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	t.Cleanup(engine.Close)
	return engine, rdb, sink
}

// awaitAudit polls for an audit event: the dispatcher forwards from its own goroutine.
func awaitAudit(t *testing.T, sink *collectingSink, eventType, reason string) *AuditEvent {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if ev := sink.find(eventType, reason); ev != nil {
			return ev
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit event %q (reason %q) was never emitted", eventType, reason)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// failAllOnKey fails every command that names key while on, like a Redis outage
// confined to one user's session index.
func failAllOnKey(key string) *keyFailHook { return &keyFailHook{substr: key} }

// wrongPasswords makes n failed attempts, each answered ErrInvalidCredentials.
func wrongPasswords(t *testing.T, engine *Engine, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, _, err := engine.Login(context.Background(), "alice", "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("wrong password %d = %v, want ErrInvalidCredentials", i+1, err)
		}
	}
}

// FAILED-BEFORE (R2-12): the lock committed, the one revocation failed, the
// error was dropped and the locked account's session stayed alive.
func TestAutoLockoutRetriesAFailedSessionRevocation(t *testing.T) {
	up := newHardeningUserProvider(t)
	engine, rdb, sink := newLockoutAuditEngine(t, up, nil)
	ctx := context.Background()

	access, refresh, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatal(err)
	}
	wrongPasswords(t, engine, 2)

	hook := &failOnceOnKey{key: "au:0:u1"}
	hook.armed.Store(true)
	rdb.AddHook(hook)

	// The attempt that crosses the threshold looks like any wrong password.
	if _, _, err := engine.Login(ctx, "alice", "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("threshold attempt = %v, want ErrInvalidCredentials", err)
	}
	if hook.armed.Load() {
		t.Fatal("the injected failure was never reached: the revocation did not run")
	}
	if got := up.users["u1"].Status; got != AccountLocked {
		t.Fatalf("status = %d, want Locked", got)
	}
	requireSessionRevoked(t, engine, access, refresh)

	engine.Close()
	if ev := sink.find(auditEventLoginFailure, "auto_lockout_sessions_not_ended"); ev != nil {
		t.Fatalf("the retry succeeded, but a not-ended audit was emitted: %+v", ev)
	}
	if ev := sink.find(auditEventLoginFailure, "auto_lockout"); ev == nil {
		t.Fatal("the lock was not audited")
	}
}

// FAILED-BEFORE (R2-12): with the revocation failing both times nothing said so.
func TestAutoLockoutAuditsSessionsThatCouldNotBeEnded(t *testing.T) {
	up := newHardeningUserProvider(t)
	engine, rdb, sink := newLockoutAuditEngine(t, up, nil)
	ctx := context.Background()

	if _, _, err := engine.Login(ctx, "alice", "correct-password-123"); err != nil {
		t.Fatal(err)
	}
	wrongPasswords(t, engine, 2)

	hook := failAllOnKey("au:0:u1")
	rdb.AddHook(hook)
	hook.on.Store(true)
	_, _, err := engine.Login(ctx, "alice", "wrong-password")
	hook.on.Store(false)

	// R2-14: still the answer of any wrong password.
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("threshold attempt = %v, want ErrInvalidCredentials", err)
	}
	if got := up.users["u1"].Status; got != AccountLocked {
		t.Fatalf("status = %d, want Locked", got)
	}
	ev := awaitAudit(t, sink, auditEventLoginFailure, "auto_lockout_sessions_not_ended")
	if ev.Success || ev.UserID != "u1" {
		t.Fatalf("audit event = %+v", ev)
	}
	awaitAudit(t, sink, auditEventLoginFailure, "auto_lockout")
}

// A lock whose revocation works does not audit a failure, and is not retried.
func TestAutoLockoutWithWorkingRevocationEmitsNoNotEndedAudit(t *testing.T) {
	up := newHardeningUserProvider(t)
	engine, _, sink := newLockoutAuditEngine(t, up, nil)
	ctx := context.Background()

	access, refresh, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatal(err)
	}
	wrongPasswords(t, engine, 3)
	requireSessionRevoked(t, engine, access, refresh)

	awaitAudit(t, sink, auditEventLoginFailure, "auto_lockout")
	engine.Close()
	if ev := sink.find(auditEventLoginFailure, "auto_lockout_sessions_not_ended"); ev != nil {
		t.Fatalf("unexpected audit event %+v", ev)
	}
}
