package session

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func seedAssurance(t *testing.T, store *Store, sess *Session) {
	t.Helper()
	a := Assurance{MFAAt: 1700000000, MFAMethod: "totp", AuthAt: 1700000000}
	if err := store.SaveAssurance(context.Background(), sess.TenantID, sess.SessionID, a, time.Hour); err != nil {
		t.Fatalf("save assurance: %v", err)
	}
}

func hasAssurance(t *testing.T, store *Store, sess *Session) bool {
	t.Helper()
	a, err := store.GetAssurance(context.Background(), sess.TenantID, sess.SessionID)
	if err != nil {
		t.Fatalf("get assurance: %v", err)
	}
	return a != nil
}

func wantAssuranceGone(t *testing.T, store *Store, sess *Session, path string) {
	t.Helper()
	if hasAssurance(t, store, sess) {
		t.Fatalf("%s: the MFA-proof key survived the deletion of its session", path)
	}
}

func saveFor(t *testing.T, store *Store, tenant, user, id string) *Session {
	t.Helper()
	s := testSession()
	s.TenantID, s.UserID, s.SessionID = tenant, user, id
	if err := store.Save(context.Background(), s, time.Hour); err != nil {
		t.Fatalf("save %s: %v", id, err)
	}
	seedAssurance(t, store, s)
	return s
}

func sessionExists(t *testing.T, rdb *redis.Client, store *Store, tenant, id string) bool {
	t.Helper()
	n, err := rdb.Exists(context.Background(), store.key(tenant, id)).Result()
	if err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func wantCount(t *testing.T, store *Store, tenant string, want int) {
	t.Helper()
	got, err := store.TenantSessionCount(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("tenant counter = %d, want %d", got, want)
	}
}

func TestDeleteAllForUserRemovesOnlyThatUsersSessionsAndProofKeys(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	mine := []*Session{saveFor(t, store, "t-1", "u-1", "a"), saveFor(t, store, "t-1", "u-1", "b"), saveFor(t, store, "t-1", "u-1", "c")}
	otherUser := saveFor(t, store, "t-1", "u-2", "d")
	otherTenant := saveFor(t, store, "t-2", "u-1", "e")
	wantCount(t, store, "t-1", 4)

	if err := store.DeleteAllForUser(ctx, "t-1", "u-1"); err != nil {
		t.Fatal(err)
	}
	for _, s := range mine {
		if sessionExists(t, rdb, store, "t-1", s.SessionID) {
			t.Fatalf("session %s survived", s.SessionID)
		}
		wantAssuranceGone(t, store, s, "DeleteAllForUser")
	}
	if !sessionExists(t, rdb, store, "t-1", otherUser.SessionID) || !hasAssurance(t, store, otherUser) {
		t.Fatal("another user's session or proof key was removed")
	}
	if !sessionExists(t, rdb, store, "t-2", otherTenant.SessionID) || !hasAssurance(t, store, otherTenant) {
		t.Fatal("the same user's session in another tenant was removed")
	}
	wantCount(t, store, "t-1", 1)
	wantCount(t, store, "t-2", 1)
	if n, _ := store.ActiveSessionCount(ctx, "t-1", "u-1"); n != 0 {
		t.Fatalf("user index still holds %d sessions", n)
	}
	if n, _ := rdb.Exists(ctx, store.userKey("t-1", "u-1")).Result(); n != 0 {
		t.Fatal("the user's session set was not removed")
	}
}

func TestDeleteAllForUserCounterReachesZeroAndKeyIsRemoved(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()
	saveFor(t, store, "t-1", "u-1", "a")
	saveFor(t, store, "t-1", "u-1", "b")
	if err := store.DeleteAllForUser(ctx, "t-1", "u-1"); err != nil {
		t.Fatal(err)
	}
	if n, _ := rdb.Exists(ctx, store.tenantCountKey("t-1")).Result(); n != 0 {
		t.Fatal("the counter key should be deleted at zero")
	}
	// Idempotent, and nothing to delete is not an error.
	if err := store.DeleteAllForUser(ctx, "t-1", "u-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteAllForUser(ctx, "t-1", "nobody"); err != nil {
		t.Fatal(err)
	}
}

// The counter is lowered by the sessions actually deleted: members of the set
// whose key has already expired are not counted, and a counter that is lower
// than what is deleted (it was reset, or drifted) never goes negative.
func TestDeleteAllForUserCounterNeverNegative(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	t.Run("stale set members are not counted", func(t *testing.T) {
		saveFor(t, store, "t-1", "u-1", "live")
		if err := rdb.SAdd(ctx, store.userKey("t-1", "u-1"), "expired-1", "expired-2").Err(); err != nil {
			t.Fatal(err)
		}
		saveFor(t, store, "t-1", "u-9", "other") // count 2
		if err := store.DeleteAllForUser(ctx, "t-1", "u-1"); err != nil {
			t.Fatal(err)
		}
		wantCount(t, store, "t-1", 1)
	})

	t.Run("counter lower than the sessions deleted", func(t *testing.T) {
		store, rdb, done := newSessionStoreTest(t)
		defer done()
		for i := 0; i < 3; i++ {
			saveFor(t, store, "t-1", "u-1", fmt.Sprintf("s%d", i))
		}
		if err := store.SetTenantSessionCount(ctx, "t-1", 1); err != nil {
			t.Fatal(err)
		}
		if err := store.DeleteAllForUser(ctx, "t-1", "u-1"); err != nil {
			t.Fatal(err)
		}
		if n, _ := rdb.Exists(ctx, store.tenantCountKey("t-1")).Result(); n != 0 {
			t.Fatal("a counter at or below the number deleted must be removed, not left negative")
		}
		wantCount(t, store, "t-1", 0)
	})

	t.Run("missing counter", func(t *testing.T) {
		store, rdb, done := newSessionStoreTest(t)
		defer done()
		saveFor(t, store, "t-1", "u-1", "a")
		if err := rdb.Del(ctx, store.tenantCountKey("t-1")).Err(); err != nil {
			t.Fatal(err)
		}
		if err := store.DeleteAllForUser(ctx, "t-1", "u-1"); err != nil {
			t.Fatal(err)
		}
		if v, err := rdb.Get(ctx, store.tenantCountKey("t-1")).Result(); err == nil {
			t.Fatalf("counter key created with value %q", v)
		}
	})
}

func TestDeleteAllForUserExceptKeepsOneSessionStoredIndexedAndCounted(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	keep := saveFor(t, store, "t-1", "u-1", "keep")
	gone := []*Session{saveFor(t, store, "t-1", "u-1", "x"), saveFor(t, store, "t-1", "u-1", "y")}
	saveFor(t, store, "t-1", "u-2", "other")

	n, err := store.DeleteAllForUserExcept(ctx, "t-1", "u-1", "keep")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("removed %d sessions, want 2", n)
	}
	if !sessionExists(t, rdb, store, "t-1", "keep") || !hasAssurance(t, store, keep) {
		t.Fatal("the kept session or its proof key was removed")
	}
	for _, s := range gone {
		if sessionExists(t, rdb, store, "t-1", s.SessionID) {
			t.Fatalf("%s survived", s.SessionID)
		}
		wantAssuranceGone(t, store, s, "DeleteAllForUserExcept")
	}
	ids, _ := store.ActiveSessionIDs(ctx, "t-1", "u-1")
	if len(ids) != 1 || ids[0] != "keep" {
		t.Fatalf("user index = %v, want only the kept session", ids)
	}
	wantCount(t, store, "t-1", 2) // keep + the other user's session

	// Calling again removes nothing and keeps counting it.
	if n, err := store.DeleteAllForUserExcept(ctx, "t-1", "u-1", "keep"); err != nil || n != 0 {
		t.Fatalf("second call = %d, %v", n, err)
	}
	wantCount(t, store, "t-1", 2)
}

func TestDeleteAllForUserExceptWithUnknownSessionRemovesEverything(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()
	saveFor(t, store, "t-1", "u-1", "a")
	saveFor(t, store, "t-1", "u-1", "b")
	other := saveFor(t, store, "t-1", "u-2", "theirs")

	// "theirs" belongs to another user, so naming it as the one to keep must
	// not spare anything of u-1's.
	n, err := store.DeleteAllForUserExcept(ctx, "t-1", "u-1", other.SessionID)
	if err != nil || n != 2 {
		t.Fatalf("removed %d, %v; want 2", n, err)
	}
	if !sessionExists(t, rdb, store, "t-1", "theirs") {
		t.Fatal("the other user's session was touched")
	}
	if ids, _ := store.ActiveSessionIDs(ctx, "t-1", "u-1"); len(ids) != 0 {
		t.Fatalf("user index = %v, want empty", ids)
	}
	wantCount(t, store, "t-1", 1)
}
