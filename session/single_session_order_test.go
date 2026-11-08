package session

import (
	"context"
	"errors"
	"testing"
	"time"
)

// R2-28 residual: every refusal check (epoch, per-user and concurrent caps,
// tenant cap) runs before the single-session purge. A refused save ends
// nothing.
func TestSaveFencedSingleSessionRefusedForTheTenantCapEndsNothing(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	for _, sid := range []string{"old1", "old2"} {
		if err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", sid), time.Hour, 0, SaveLimits{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := rdb.Set(ctx, store.assuranceKey("t-1", "old1"), "proof", time.Hour).Err(); err != nil {
		t.Fatal(err)
	}
	// Four other users' sessions: the tenant holds 6, and even without the
	// user's own two it is at its cap of 4.
	for _, u := range []string{"u-2", "u-3", "u-4", "u-5"} {
		if err := store.SaveFenced(ctx, fencedSession("t-1", u, "s-"+u), time.Hour, 0, SaveLimits{}); err != nil {
			t.Fatal(err)
		}
	}
	limits := SaveLimits{SingleSession: true, MaxPerTenant: 4}
	err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "new"), time.Hour, 0, limits)
	if !errors.Is(err, ErrTenantSessionLimit) {
		t.Fatalf("a full tenant: %v, want ErrTenantSessionLimit", err)
	}
	for _, key := range []string{"as:t-1:old1", "as:t-1:old2", store.assuranceKey("t-1", "old1")} {
		if rdb.Exists(ctx, key).Val() != 1 {
			t.Fatalf("a save refused for the tenant cap ended %s", key)
		}
	}
	if ids := sortedIDs(t, store, "t-1", "u-1"); len(ids) != 2 || ids[0] != "old1" || ids[1] != "old2" {
		t.Fatalf("user's set after a refused save = %v, want [old1 old2]", ids)
	}
	if got := rdb.Get(ctx, "ast:t-1:count").Val(); got != "6" {
		t.Fatalf("tenant counter = %q, a refused save must not change it (want 6)", got)
	}
	if rdb.Exists(ctx, "as:t-1:new").Val() != 0 {
		t.Fatal("a refused save wrote its session")
	}
}

// The user's own sessions do not count against the tenant cap they are about
// to free: a replacement that fits once they are gone is stored, as before.
func TestSaveFencedSingleSessionStillReplacesWhenTheTenantIsFullOfTheUsersOwn(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	for _, sid := range []string{"old1", "old2"} {
		if err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", sid), time.Hour, 0, SaveLimits{}); err != nil {
			t.Fatal(err)
		}
	}
	limits := SaveLimits{SingleSession: true, MaxPerTenant: 2}
	if err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "new"), time.Hour, 0, limits); err != nil {
		t.Fatalf("the tenant is full of the user's own sessions, which the save replaces: %v", err)
	}
	if ids := sortedIDs(t, store, "t-1", "u-1"); len(ids) != 1 || ids[0] != "new" {
		t.Fatalf("user's set = %v, want [new]", ids)
	}
	if rdb.Exists(ctx, "as:t-1:old1", "as:t-1:old2").Val() != 0 {
		t.Fatal("the replaced sessions survived")
	}
	if got := rdb.Get(ctx, "ast:t-1:count").Val(); got != "1" {
		t.Fatalf("tenant counter = %q, want 1", got)
	}
}

// Expired entries in the user's set are not "other sessions": they free no
// tenant slot and are not counted as deleted.
func TestSaveFencedSingleSessionIgnoresExpiredEntriesWhenJudgingTheTenantCap(t *testing.T) {
	store, mr, rdb := newSessionStoreWithClock(t)
	ctx := context.Background()

	if err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "gone"), time.Hour, 0, SaveLimits{}); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(2 * time.Hour) // "gone" expired; the tenant counter still says 1
	if err := store.SaveFenced(ctx, fencedSession("t-1", "u-2", "other"), time.Hour, 0, SaveLimits{}); err != nil {
		t.Fatal(err)
	}
	// Counter 2, one live session of someone else, cap 1: the user's expired
	// entry frees nothing, but the counter is reconciled against a scan and the
	// live count (1) is at the cap, so the save is refused.
	err := store.SaveFenced(ctx, fencedSession("t-1", "u-1", "new"), time.Hour, 0, SaveLimits{SingleSession: true, MaxPerTenant: 1})
	if !errors.Is(err, ErrTenantSessionLimit) {
		t.Fatalf("got %v, want ErrTenantSessionLimit", err)
	}
	if rdb.Exists(ctx, "as:t-1:other").Val() != 1 {
		t.Fatal("another user's session was touched")
	}
}
