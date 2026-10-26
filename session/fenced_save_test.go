package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fencedSession(tenant, user, sid string) *Session {
	s := testSession()
	s.TenantID = tenant
	s.UserID = user
	s.SessionID = sid
	return s
}

func TestRevocationEpochIsBumpedByEveryDeleteAllAndExpires(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	if epoch, err := store.RevocationEpoch(ctx, "t-1", "u-1"); err != nil || epoch != 0 {
		t.Fatalf("a user nobody revoked has epoch 0, got %d, %v", epoch, err)
	}
	if err := store.DeleteAllForUser(ctx, "t-1", "u-1"); err != nil {
		t.Fatalf("DeleteAllForUser: %v", err)
	}
	if epoch, _ := store.RevocationEpoch(ctx, "t-1", "u-1"); epoch != 1 {
		t.Fatalf("epoch after one delete-all = %d, want 1", epoch)
	}
	if _, err := store.DeleteAllForUserExcept(ctx, "t-1", "u-1", "keep"); err != nil {
		t.Fatalf("DeleteAllForUserExcept: %v", err)
	}
	if epoch, _ := store.RevocationEpoch(ctx, "t-1", "u-1"); epoch != 2 {
		t.Fatalf("epoch after a delete-all that keeps a session = %d, want 2", epoch)
	}
	if ttl := rdb.TTL(ctx, "aue:t-1:u-1").Val(); ttl <= 59*time.Minute || ttl > time.Hour {
		t.Fatalf("epoch TTL = %v, want about an hour", ttl)
	}
	// Other users and other tenants are not affected.
	for _, other := range [][2]string{{"t-1", "u-2"}, {"t-2", "u-1"}} {
		if epoch, _ := store.RevocationEpoch(ctx, other[0], other[1]); epoch != 0 {
			t.Fatalf("%v: epoch %d, want 0", other, epoch)
		}
	}
	// The default tenant is spelled "0" in keys, whichever way it is passed.
	if err := store.DeleteAllForUser(ctx, "", "u-3"); err != nil {
		t.Fatal(err)
	}
	if epoch, _ := store.RevocationEpoch(ctx, "0", "u-3"); epoch != 1 {
		t.Fatalf("default-tenant epoch = %d, want 1", epoch)
	}
}

func TestSaveFencedRefusesAfterARevocation(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	epoch, _ := store.RevocationEpoch(ctx, "t-1", "u-1")
	if err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "s1"), time.Hour, epoch, SaveLimits{}); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if n, _ := store.ActiveSessionCount(ctx, "t-1", "u-1"); n != 1 {
		t.Fatalf("sessions = %d, want 1", n)
	}
	if got := rdb.Get(ctx, "ast:t-1:count").Val(); got != "1" {
		t.Fatalf("tenant counter = %q, want 1", got)
	}

	// A revocation lands after the epoch was read.
	if err := store.DeleteAllForUser(ctx, "t-1", "u-1"); err != nil {
		t.Fatal(err)
	}
	err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "s2"), time.Hour, epoch, SaveLimits{})
	if !errors.Is(err, ErrSessionFenced) {
		t.Fatalf("save under a stale epoch: %v, want ErrSessionFenced", err)
	}
	if n, _ := store.ActiveSessionCount(ctx, "t-1", "u-1"); n != 0 {
		t.Fatalf("a fenced save stored a session: %d", n)
	}
	if rdb.Exists(ctx, "as:t-1:s2").Val() != 0 {
		t.Fatal("a fenced save wrote the session key")
	}

	// With the epoch read again it goes through.
	next, _ := store.RevocationEpoch(ctx, "t-1", "u-1")
	if err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "s3"), time.Hour, next, SaveLimits{}); err != nil {
		t.Fatalf("save under the new epoch: %v", err)
	}
}

func TestSaveFencedEnforcesTheCapsAtomically(t *testing.T) {
	store, _, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	var stored, userLimited atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", fmt.Sprintf("s%d", i)), time.Hour, 0, SaveLimits{MaxPerUser: 3})
			switch {
			case err == nil:
				stored.Add(1)
			case errors.Is(err, ErrUserSessionLimit):
				userLimited.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if stored.Load() != 3 || userLimited.Load() != 17 {
		t.Fatalf("stored %d, refused %d; want exactly the cap (3) stored", stored.Load(), userLimited.Load())
	}
	if n, _ := store.ActiveSessionCount(ctx, "t-1", "u-1"); n != 3 {
		t.Fatalf("user holds %d sessions, want 3", n)
	}

	// The tenant cap is shared by users.
	for i := 0; i < 6; i++ {
		_ = store.SaveFenced(ctx, fencedSession("t-2", fmt.Sprintf("u-%d", i), fmt.Sprintf("x%d", i)), time.Hour, 0, SaveLimits{MaxPerTenant: 4})
	}
	if n, _ := store.TenantSessionCount(ctx, "t-2"); n != 4 {
		t.Fatalf("tenant holds %d sessions, want the cap (4)", n)
	}
	if err := store.SaveFenced(ctx, fencedSession("t-2", "u-9", "x9"), time.Hour, 0, SaveLimits{MaxPerTenant: 4}); !errors.Is(err, ErrTenantSessionLimit) {
		t.Fatalf("over the tenant cap: %v, want ErrTenantSessionLimit", err)
	}

	// ConcurrentLogins is a per-user cap like MaxPerUser.
	for i := 0; i < 2; i++ {
		_ = store.SaveFenced(ctx, fencedSession("t-3", "u-1", fmt.Sprintf("c%d", i)), time.Hour, 0, SaveLimits{ConcurrentLogins: 2})
	}
	if err := store.SaveFenced(ctx, fencedSession("t-3", "u-1", "c9"), time.Hour, 0, SaveLimits{ConcurrentLogins: 2}); !errors.Is(err, ErrUserSessionLimit) {
		t.Fatalf("over the concurrent-login cap: %v, want ErrUserSessionLimit", err)
	}
}

// A tenant counter that drifted upwards (sessions expired on their own) is
// reconciled before the cap refuses.
func TestSaveFencedReconcilesADriftedTenantCounter(t *testing.T) {
	store, _, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	if err := store.SetTenantSessionCount(ctx, "t-1", 50); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "s1"), time.Hour, 0, SaveLimits{MaxPerTenant: 3}); err != nil {
		t.Fatalf("a drifted counter must be reconciled, not refuse: %v", err)
	}
	if n, _ := store.TenantSessionCount(ctx, "t-1"); n != 1 {
		t.Fatalf("counter after reconciliation and save = %d, want 1", n)
	}
}

func TestSaveFencedSingleSessionEndsTheOthersOnlyWhenEverythingPasses(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	for _, sid := range []string{"old1", "old2"} {
		if err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", sid), time.Hour, 0, SaveLimits{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := rdb.Set(ctx, store.assuranceKey("t-1", "old1"), "x", time.Hour).Err(); err != nil {
		t.Fatal(err)
	}

	// A stale epoch refuses and ends nothing.
	staleEpoch, _ := store.RevocationEpoch(ctx, "t-1", "u-1")
	if err := rdb.Incr(ctx, "aue:t-1:u-1").Err(); err != nil {
		t.Fatal(err)
	}
	err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "new"), time.Hour, staleEpoch, SaveLimits{SingleSession: true})
	if !errors.Is(err, ErrSessionFenced) {
		t.Fatalf("got %v, want ErrSessionFenced", err)
	}
	if n, _ := store.ActiveSessionCount(ctx, "t-1", "u-1"); n != 2 {
		t.Fatalf("a refused save ended sessions: %d left, want 2", n)
	}

	// A passing save ends the others, their proof keys, fixes the counter, and
	// does not itself bump the epoch.
	epoch, _ := store.RevocationEpoch(ctx, "t-1", "u-1")
	if err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "new"), time.Hour, epoch, SaveLimits{SingleSession: true, MaxPerUser: 1}); err != nil {
		t.Fatalf("single-session save: %v", err)
	}
	ids, _ := store.ActiveSessionIDs(ctx, "t-1", "u-1")
	if len(ids) != 1 || ids[0] != "new" {
		t.Fatalf("sessions after a single-session login: %v", ids)
	}
	if rdb.Exists(ctx, "as:t-1:old1", "as:t-1:old2", store.assuranceKey("t-1", "old1")).Val() != 0 {
		t.Fatal("the other sessions or their proof keys survived")
	}
	if n, _ := store.TenantSessionCount(ctx, "t-1"); n != 1 {
		t.Fatalf("tenant counter = %d, want 1", n)
	}
	if after, _ := store.RevocationEpoch(ctx, "t-1", "u-1"); after != epoch {
		t.Fatalf("a login replacing the user's sessions moved the epoch: %d -> %d", epoch, after)
	}
}
