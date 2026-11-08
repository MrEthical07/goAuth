package goAuth

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

// Regression tests for R2-16 of the v0.8.1 verification audit (run 3): the
// automatic lockout wrote Locked without checking the account was still Active,
// so an administrator's disable or delete that landed between the login's status
// read and the lock write was overwritten, and a later UnlockAccount made the
// account Active.

// lockRaceProvider hands back the account as the login read it, then lets an
// administrator disable (or delete) it: the moment between the login's status
// read and the lock write. The status the login trusts is the one read by ID
// after the revocation epoch (the identifier lookup only yields the ID). The
// hook runs synchronously right after that read, which places the interleaving
// exactly and needs no goroutine to park.
type lockRaceProvider struct {
	*mockUserProvider
	blockWith atomic.Int32 // 1 + the AccountStatus to write after the next ID read; 0 = off
}

// arm makes the next read by ID be followed by an administrator setting status.
func (p *lockRaceProvider) arm(status AccountStatus) { p.blockWith.Store(int32(status) + 1) }

func (p *lockRaceProvider) afterRead(user UserRecord, err error) (UserRecord, error) {
	if err == nil {
		if status := p.blockWith.Swap(0); status != 0 {
			blockAccount(p.mockUserProvider, AccountStatus(status-1))
		}
	}
	return user, err
}

func (p *lockRaceProvider) GetUserByID(userID string) (UserRecord, error) {
	return p.afterRead(p.mockUserProvider.GetUserByID(userID))
}

func (p *lockRaceProvider) GetUserByIDInTenant(ctx context.Context, tenantID, userID string) (UserRecord, error) {
	return p.afterRead(p.mockUserProvider.GetUserByIDInTenant(ctx, tenantID, userID))
}

// lockRaceCASProvider adds the optional compare-and-set capability and counts it.
type lockRaceCASProvider struct {
	*lockRaceProvider
	calls   atomic.Int64
	applied atomic.Int64
}

func (p *lockRaceCASProvider) UpdateAccountStatusIf(_ context.Context, _, userID string, expected, next AccountStatus) (bool, error) {
	p.calls.Add(1)
	p.mu.Lock()
	defer p.mu.Unlock()
	user := p.users[userID]
	if user.Status != expected {
		return false, nil
	}
	user.Status = next
	user.AccountVersion++
	p.users[userID] = user
	p.applied.Add(1)
	return true, nil
}

func (p *lockRaceProvider) statusWrites() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.updateStatusCalls
}

func (p *lockRaceProvider) status() AccountStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.users["u1"].Status
}

// lockRaceCase is one way the lock can run: with the provider's compare-and-set,
// or by re-reading the status right before the write.
type lockRaceCase struct {
	name string
	// build returns the provider the engine is built over, the plain provider
	// under it, and the compare-and-set counters (nil without the capability).
	build func(t *testing.T) (UserProvider, *lockRaceProvider, *lockRaceCASProvider)
}

func lockRaceCases() []lockRaceCase {
	return []lockRaceCase{
		{"compare-and-set", func(t *testing.T) (UserProvider, *lockRaceProvider, *lockRaceCASProvider) {
			plain := &lockRaceProvider{mockUserProvider: newHardeningUserProvider(t)}
			cas := &lockRaceCASProvider{lockRaceProvider: plain}
			return cas, plain, cas
		}},
		{"re-read", func(t *testing.T) (UserProvider, *lockRaceProvider, *lockRaceCASProvider) {
			plain := &lockRaceProvider{mockUserProvider: newHardeningUserProvider(t)}
			return plain, plain, nil
		}},
	}
}

// FAILED-BEFORE (R2-16): the lock was written over the administrator's status.
func TestAutoLockoutNeverOverwritesABlockedAccount(t *testing.T) {
	for _, tc := range lockRaceCases() {
		for _, blocked := range []AccountStatus{AccountDisabled, AccountDeleted} {
			t.Run(tc.name+"/"+accountStatusName(blocked), func(t *testing.T) {
				up, plain, cas := tc.build(t)
				engine, _, sink := newLockoutAuditEngine(t, up, func(c *Config) { c.Metrics.Enabled = true })
				ctx := context.Background()

				access, refresh, err := engine.Login(ctx, "alice", "correct-password-123")
				if err != nil {
					t.Fatal(err)
				}
				wrongPasswords(t, engine, 2)

				// The login that crosses the threshold reads Active; the administrator
				// blocks the account before its lock is written.
				plain.arm(blocked)
				_, _, err = engine.Login(ctx, "alice", "wrong-password")
				if !errors.Is(err, ErrInvalidCredentials) {
					t.Fatalf("threshold attempt = %v, want ErrInvalidCredentials", err)
				}

				if got := plain.status(); got != blocked {
					t.Fatalf("status = %d, want the administrator's %d", got, blocked)
				}
				if cas != nil {
					if cas.calls.Load() != 1 || cas.applied.Load() != 0 {
						t.Fatalf("UpdateAccountStatusIf calls=%d applied=%d, want 1 and 0", cas.calls.Load(), cas.applied.Load())
					}
				} else if n := plain.statusWrites(); n != 0 {
					t.Fatalf("UpdateAccountStatus called %d times, want none", n)
				}

				// A skipped lock revokes nothing and audits no lock.
				if _, err := engine.Validate(ctx, access, ModeStrict); err != nil {
					t.Fatalf("a skipped lock revoked the session: %v", err)
				}
				if _, _, err := engine.Refresh(ctx, refresh); err != nil {
					t.Fatalf("a skipped lock revoked the refresh token: %v", err)
				}
				engine.Close()
				if ev := sink.find(auditEventLoginFailure, "auto_lockout"); ev != nil {
					t.Fatalf("a skipped lock was audited as a lock: %+v", ev)
				}
				if ev := sink.find(auditEventAccountStatusChange, ""); ev != nil {
					t.Fatalf("a skipped lock emitted an account status change: %+v", ev)
				}
				if n := engine.MetricsSnapshot().Counters[MetricAccountLocked]; n != 0 {
					t.Fatalf("MetricAccountLocked = %d, want 0", n)
				}
				// The attempt is audited as the wrong password it is.
				if ev := sink.find(auditEventLoginFailure, "password_mismatch"); ev == nil {
					t.Fatal("the attempt was not audited as a password mismatch")
				}
			})
		}
	}
}

// With the account still Active the lock is written once, through the provider's
// compare-and-set when it has one, and ends the sessions.
func TestAutoLockoutLocksAnActiveAccount(t *testing.T) {
	for _, tc := range lockRaceCases() {
		t.Run(tc.name, func(t *testing.T) {
			up, plain, cas := tc.build(t)
			engine, _, sink := newLockoutAuditEngine(t, up, func(c *Config) { c.Metrics.Enabled = true })
			ctx := context.Background()

			access, refresh, err := engine.Login(ctx, "alice", "correct-password-123")
			if err != nil {
				t.Fatal(err)
			}
			wrongPasswords(t, engine, 3)

			if got := plain.status(); got != AccountLocked {
				t.Fatalf("status = %d, want Locked", got)
			}
			if cas != nil && (cas.calls.Load() != 1 || cas.applied.Load() != 1) {
				t.Fatalf("UpdateAccountStatusIf calls=%d applied=%d, want 1 and 1", cas.calls.Load(), cas.applied.Load())
			}
			if cas == nil && plain.statusWrites() != 1 {
				t.Fatalf("UpdateAccountStatus called %d times, want 1", plain.statusWrites())
			}
			requireSessionRevoked(t, engine, access, refresh)
			awaitAudit(t, sink, auditEventLoginFailure, "auto_lockout")
			awaitAudit(t, sink, auditEventAccountStatusChange, "")
			if n := engine.MetricsSnapshot().Counters[MetricAccountLocked]; n != 1 {
				t.Fatalf("MetricAccountLocked = %d, want 1", n)
			}
			if _, _, err := engine.Login(ctx, "alice", "correct-password-123"); !errors.Is(err, ErrAccountLocked) {
				t.Fatalf("login after the lock = %v, want ErrAccountLocked", err)
			}
		})
	}
}

func accountStatusName(s AccountStatus) string {
	switch s {
	case AccountDisabled:
		return "disabled"
	case AccountDeleted:
		return "deleted"
	default:
		return "other"
	}
}
