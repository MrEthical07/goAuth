package session

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newSessionStoreWithClock is newSessionStoreTest plus the miniredis handle, so
// a test can let sessions expire by TTL with FastForward.
func newSessionStoreWithClock(t *testing.T) (*Store, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis start: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		rdb.Close()
		mr.Close()
	})
	return NewStore(rdb, "as", true, false, 0), mr, rdb
}

func sortedIDs(t *testing.T, store *Store, tenant, user string) []string {
	t.Helper()
	ids, err := store.ActiveSessionIDs(context.Background(), tenant, user)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(ids)
	return ids
}

// C3: the user's set keeps the ID of a session that expired by TTL. It must not
// count toward MaxPerUser or ConcurrentLogins.
func TestSaveFencedCapsCountLiveSessionsOnly(t *testing.T) {
	for _, tc := range []struct {
		name   string
		limits SaveLimits
	}{
		{"MaxPerUser", SaveLimits{MaxPerUser: 1}},
		{"ConcurrentLogins", SaveLimits{ConcurrentLogins: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, mr, _ := newSessionStoreWithClock(t)
			ctx := context.Background()

			if err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "s1"), time.Hour, 0, tc.limits); err != nil {
				t.Fatalf("first save: %v", err)
			}
			if err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "s2"), time.Hour, 0, tc.limits); !errors.Is(err, ErrUserSessionLimit) {
				t.Fatalf("a live session at the cap: %v, want ErrUserSessionLimit", err)
			}

			mr.FastForward(2 * time.Hour) // s1 expires by TTL; its ID stays in the set
			if got := sortedIDs(t, store, "t-1", "u-1"); len(got) != 1 || got[0] != "s1" {
				t.Fatalf("precondition: the set should still hold the expired ID, got %v", got)
			}
			if err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "s3"), time.Hour, 0, tc.limits); err != nil {
				t.Fatalf("a user whose only session expired was refused: %v", err)
			}
			if got := sortedIDs(t, store, "t-1", "u-1"); len(got) != 1 || got[0] != "s3" {
				t.Fatalf("the expired ID should have been pruned, set = %v", got)
			}
		})
	}
}

func TestSaveFencedKeepsTheLiveSessionWhenPruningTheExpiredOne(t *testing.T) {
	store, mr, rdb := newSessionStoreWithClock(t)
	ctx := context.Background()
	limits := SaveLimits{MaxPerUser: 2}

	if err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "old"), time.Hour, 0, limits); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(50 * time.Minute)
	if err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "live"), time.Hour, 0, limits); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(20 * time.Minute) // "old" is gone, "live" has 40 minutes left

	if err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "new"), time.Hour, 0, limits); err != nil {
		t.Fatalf("one live and one expired session at a cap of 2: %v", err)
	}
	got := sortedIDs(t, store, "t-1", "u-1")
	if len(got) != 2 || got[0] != "live" || got[1] != "new" {
		t.Fatalf("set = %v, want [live new]", got)
	}
	if rdb.Exists(ctx, "as:t-1:live").Val() != 1 {
		t.Fatal("the live session was removed")
	}

	// The cap is still enforced against live sessions.
	if err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "third"), time.Hour, 0, limits); !errors.Is(err, ErrUserSessionLimit) {
		t.Fatalf("two live sessions at a cap of 2: %v, want ErrUserSessionLimit", err)
	}
	if rdb.Exists(ctx, "as:t-1:third").Val() != 0 {
		t.Fatal("a refused save wrote its session")
	}
}

func TestLiveSessionCountPrunesOnlyAtTheCap(t *testing.T) {
	store, mr, _ := newSessionStoreWithClock(t)
	ctx := context.Background()

	if err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "s1"), 30*time.Minute, 0, SaveLimits{}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "s2"), time.Hour, 0, SaveLimits{}); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(45 * time.Minute) // s1 expired, s2 live

	// Below the cap the answer cannot change a decision, so nothing is scanned
	// or removed.
	if n, err := store.LiveSessionCount(ctx, "t-1", "u-1", 3); err != nil || n != 2 {
		t.Fatalf("below the cap: %d, %v; want the raw size 2", n, err)
	}
	if got := sortedIDs(t, store, "t-1", "u-1"); len(got) != 2 {
		t.Fatalf("a count below the cap pruned: %v", got)
	}
	// atLeast <= 0 is the raw size too.
	if n, _ := store.LiveSessionCount(ctx, "t-1", "u-1", 0); n != 2 {
		t.Fatalf("no cap: %d, want 2", n)
	}

	// At the cap the dead entry is removed and the live one counted.
	if n, err := store.LiveSessionCount(ctx, "t-1", "u-1", 2); err != nil || n != 1 {
		t.Fatalf("at the cap: %d, %v; want 1 live session", n, err)
	}
	if got := sortedIDs(t, store, "t-1", "u-1"); len(got) != 1 || got[0] != "s2" {
		t.Fatalf("set after pruning = %v, want [s2]", got)
	}

	// Another user, and the default tenant spelling, are separate sets.
	if n, _ := store.LiveSessionCount(ctx, "t-1", "u-2", 1); n != 0 {
		t.Fatalf("an unknown user: %d, want 0", n)
	}
}

// The tenant counter is an estimate with its own reconciliation: pruning a
// user's set does not touch it.
func TestPruningTheUserSetLeavesTheTenantCounterAlone(t *testing.T) {
	store, mr, rdb := newSessionStoreWithClock(t)
	ctx := context.Background()

	if err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "s1"), time.Hour, 0, SaveLimits{}); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(2 * time.Hour)
	if _, err := store.LiveSessionCount(ctx, "t-1", "u-1", 1); err != nil {
		t.Fatal(err)
	}
	if got := rdb.Get(ctx, "ast:t-1:count").Val(); got != "1" {
		t.Fatalf("tenant counter = %q, want it left at 1", got)
	}
}
