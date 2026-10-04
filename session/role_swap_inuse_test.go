package session

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// dumpKeyspace captures every key with its value (strings) or members (sets),
// so a test can prove an operation changed nothing.
func dumpKeyspace(t *testing.T, rdb *redis.Client) map[string]string {
	t.Helper()
	ctx := context.Background()
	keys, err := rdb.Keys(ctx, "*").Result()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		typ, err := rdb.Type(ctx, k).Result()
		if err != nil {
			t.Fatalf("type %s: %v", k, err)
		}
		switch typ {
		case "string":
			v, err := rdb.Get(ctx, k).Result()
			if err != nil {
				t.Fatalf("get %s: %v", k, err)
			}
			out[k] = "s:" + v
		case "set":
			m, err := rdb.SMembers(ctx, k).Result()
			if err != nil {
				t.Fatalf("smembers %s: %v", k, err)
			}
			sort.Strings(m)
			out[k] = "m:" + strings.Join(m, ",")
		default:
			out[k] = typ
		}
	}
	return out
}

func requireKeyspaceUnchanged(t *testing.T, before, after map[string]string) {
	t.Helper()
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("keyspace changed:\n before: %v\n after:  %v", before, after)
	}
}

func TestSwapSessionRefusesReplacementIDEqualToOldID(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	old := testSession()
	if err := store.Save(ctx, old, time.Hour); err != nil {
		t.Fatal(err)
	}
	before := dumpKeyspace(t, rdb)

	next := swapTarget(old, old.SessionID)
	if err := store.SwapSession(ctx, old.TenantID, old.SessionID, old.RefreshHash, next, nil); err == nil {
		t.Fatal("a replacement with the old session's ID must be refused")
	}
	requireKeyspaceUnchanged(t, before, dumpKeyspace(t, rdb))
	if _, err := store.RotateRefreshHash(ctx, old.TenantID, old.SessionID, old.RefreshHash, [32]byte{9}); err != nil {
		t.Fatalf("the old session must still be usable: %v", err)
	}
}

func TestSwapSessionRefusesIncompleteReplacement(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	old := testSession()
	if err := store.Save(ctx, old, time.Hour); err != nil {
		t.Fatal(err)
	}
	before := dumpKeyspace(t, rdb)

	for name, mutate := range map[string]func(*Session){
		"empty session id": func(s *Session) { s.SessionID = "" },
		"empty user id":    func(s *Session) { s.UserID = "" },
	} {
		next := swapTarget(old, "sid-new")
		mutate(next)
		if err := store.SwapSession(ctx, old.TenantID, old.SessionID, old.RefreshHash, next, nil); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}
	requireKeyspaceUnchanged(t, before, dumpKeyspace(t, rdb))
}

// The replacement ID names another live session, of the same user or of a
// different one: nothing may change and the old session must keep working.
func TestSwapSessionRefusesOccupiedReplacementID(t *testing.T) {
	cases := map[string]string{
		"same user":      "u-1",
		"different user": "u-other",
	}
	for name, otherUser := range cases {
		t.Run(name, func(t *testing.T) {
			store, rdb, done := newSessionStoreTest(t)
			defer done()
			ctx := context.Background()

			old := testSession()
			if err := store.Save(ctx, old, time.Hour); err != nil {
				t.Fatal(err)
			}
			if err := store.SaveAssurance(ctx, old.TenantID, old.SessionID, Assurance{MFAAt: 1700000000, MFAMethod: "totp", AuthAt: 1700000000}, time.Hour); err != nil {
				t.Fatal(err)
			}

			occupant := testSession()
			occupant.SessionID = "sid-occupied"
			occupant.UserID = otherUser
			occupant.RefreshHash = [32]byte{0x77}
			if err := store.Save(ctx, occupant, time.Hour); err != nil {
				t.Fatal(err)
			}
			if err := store.SaveAssurance(ctx, occupant.TenantID, occupant.SessionID, Assurance{MFAAt: 1700000500, MFAMethod: "backup_code", AuthAt: 1700000500}, time.Hour); err != nil {
				t.Fatal(err)
			}

			before := dumpKeyspace(t, rdb)
			countBefore, _ := store.TenantSessionCount(ctx, old.TenantID)

			next := swapTarget(old, occupant.SessionID)
			err := store.SwapSession(ctx, old.TenantID, old.SessionID, old.RefreshHash, next, &Assurance{MFAAt: 1, MFAMethod: "totp", AuthAt: 1})
			if !errors.Is(err, ErrSessionIDInUse) {
				t.Fatalf("SwapSession = %v, want ErrSessionIDInUse", err)
			}

			requireKeyspaceUnchanged(t, before, dumpKeyspace(t, rdb))
			if countAfter, _ := store.TenantSessionCount(ctx, old.TenantID); countAfter != countBefore {
				t.Fatalf("tenant count %d -> %d", countBefore, countAfter)
			}
			// The old session still refreshes with the same token.
			if _, err := store.RotateRefreshHash(ctx, old.TenantID, old.SessionID, old.RefreshHash, [32]byte{0x55}); err != nil {
				t.Fatalf("the old session must still refresh after a refused swap: %v", err)
			}
		})
	}
}

// A stale refresh hash is checked before the occupied ID: the reuse outcome
// (delete the old session, mismatch) is unchanged.
func TestSwapSessionStaleHashWinsOverOccupiedID(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	old := testSession()
	if err := store.Save(ctx, old, time.Hour); err != nil {
		t.Fatal(err)
	}
	occupant := testSession()
	occupant.SessionID = "sid-occupied"
	occupant.UserID = "u-other"
	if err := store.Save(ctx, occupant, time.Hour); err != nil {
		t.Fatal(err)
	}
	occupantBlob, _ := rdb.Get(ctx, store.key(occupant.TenantID, occupant.SessionID)).Bytes()

	err := store.SwapSession(ctx, old.TenantID, old.SessionID, [32]byte{0x99}, swapTarget(old, occupant.SessionID), nil)
	if !errors.Is(err, ErrRefreshHashMismatch) {
		t.Fatalf("SwapSession = %v, want ErrRefreshHashMismatch", err)
	}
	if _, err := store.Peek(ctx, old.TenantID, old.SessionID); !errors.Is(err, redis.Nil) {
		t.Fatalf("the old session must be deleted on reuse, got %v", err)
	}
	if ids, _ := store.ActiveSessionIDs(ctx, old.TenantID, old.UserID); len(ids) != 0 {
		t.Fatalf("old user's index = %v, want empty", ids)
	}
	got, _ := rdb.Get(ctx, store.key(occupant.TenantID, occupant.SessionID)).Bytes()
	if string(got) != string(occupantBlob) {
		t.Fatal("the occupant must be untouched")
	}
	if n, _ := store.TenantSessionCount(ctx, old.TenantID); n != 1 {
		t.Fatalf("tenant count = %d, want 1 (only the occupant remains)", n)
	}
}
