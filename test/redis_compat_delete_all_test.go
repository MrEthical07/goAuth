//go:build integration
// +build integration

package test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/session"
	"github.com/redis/go-redis/v9"
)

// skipCluster: like the rotation and swap scripts, the atomic delete builds the
// keys of a user's sessions from the IDs in the user's set, so it needs a
// single-node or non-sharded deployment.
func skipCluster(t *testing.T, name string) {
	t.Helper()
	if strings.Contains(name, "cluster") {
		t.Skip("session scripts touch keys in more than one hash slot")
	}
}

func compatSaveWithProof(t *testing.T, store *session.Store, tenant, user, sid string, hash byte) *session.Session {
	t.Helper()
	ctx := context.Background()
	s := makeCompatSession(tenant, user, sid, hashByte(hash))
	if err := store.Save(ctx, s, time.Hour); err != nil {
		t.Fatalf("save %s: %v", sid, err)
	}
	held := session.Assurance{MFAAt: time.Now().Unix(), MFAMethod: "totp", AuthAt: time.Now().Unix()}
	if err := store.SaveAssurance(ctx, tenant, sid, held, time.Hour); err != nil {
		t.Fatalf("save assurance %s: %v", sid, err)
	}
	return s
}

func proofExists(t *testing.T, store *session.Store, s *session.Session) bool {
	t.Helper()
	a, err := store.GetAssurance(context.Background(), s.TenantID, s.SessionID)
	if err != nil {
		t.Fatalf("get assurance: %v", err)
	}
	return a != nil
}

// TestRedisCompat_DeleteAllForUser runs the atomic logout-all script on every
// available backend: it removes the user's sessions and their MFA-proof keys,
// fixes the counter by what it deleted, leaves others alone, and keeps one
// session when asked.
func TestRedisCompat_DeleteAllForUser(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			skipCluster(t, mode.name)
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			store := session.NewStore(rdb, "as", true, false, 0)
			ctx := context.Background()

			mine := []*session.Session{
				compatSaveWithProof(t, store, "t-del", "u-del", "d1", 1),
				compatSaveWithProof(t, store, "t-del", "u-del", "d2", 2),
				compatSaveWithProof(t, store, "t-del", "u-del", "d3", 3),
			}
			other := compatSaveWithProof(t, store, "t-del", "u-other", "o1", 4)
			elsewhere := compatSaveWithProof(t, store, "t-del2", "u-del", "e1", 5)

			// Keep d2: it stays stored, indexed and counted.
			n, err := store.DeleteAllForUserExcept(ctx, "t-del", "u-del", "d2")
			if err != nil || n != 2 {
				t.Fatalf("DeleteAllForUserExcept = %d, %v; want 2", n, err)
			}
			if _, err := store.Peek(ctx, "t-del", "d2"); err != nil {
				t.Fatalf("the kept session is gone: %v", err)
			}
			if !proofExists(t, store, mine[1]) || proofExists(t, store, mine[0]) || proofExists(t, store, mine[2]) {
				t.Fatal("proof keys do not match the sessions that remain")
			}
			if ids, _ := store.ActiveSessionIDs(ctx, "t-del", "u-del"); len(ids) != 1 || ids[0] != "d2" {
				t.Fatalf("user index = %v", ids)
			}
			if c, _ := store.TenantSessionCount(ctx, "t-del"); c != 2 {
				t.Fatalf("tenant counter = %d, want 2 (d2 and the other user's)", c)
			}

			if err := store.DeleteAllForUser(ctx, "t-del", "u-del"); err != nil {
				t.Fatalf("DeleteAllForUser: %v", err)
			}
			if _, err := store.Peek(ctx, "t-del", "d2"); err == nil {
				t.Fatal("d2 survived DeleteAllForUser")
			}
			if proofExists(t, store, mine[1]) {
				t.Fatal("d2's proof key survived")
			}
			if _, err := store.Peek(ctx, "t-del", other.SessionID); err != nil || !proofExists(t, store, other) {
				t.Fatal("another user's session or proof was touched")
			}
			if _, err := store.Peek(ctx, "t-del2", elsewhere.SessionID); err != nil || !proofExists(t, store, elsewhere) {
				t.Fatal("the same user's session in another tenant was touched")
			}
			if c, _ := store.TenantSessionCount(ctx, "t-del"); c != 1 {
				t.Fatalf("tenant counter = %d, want 1", c)
			}
			if c, _ := store.TenantSessionCount(ctx, "t-del2"); c != 1 {
				t.Fatalf("other tenant's counter = %d, want 1", c)
			}

			// A counter that is already lower than what gets deleted is removed, not made negative.
			compatSaveWithProof(t, store, "t-neg", "u-neg", "n1", 6)
			compatSaveWithProof(t, store, "t-neg", "u-neg", "n2", 7)
			if err := store.SetTenantSessionCount(ctx, "t-neg", 1); err != nil {
				t.Fatal(err)
			}
			if err := store.DeleteAllForUser(ctx, "t-neg", "u-neg"); err != nil {
				t.Fatal(err)
			}
			if exists, _ := rdb.Exists(ctx, "ast:t-neg:count").Result(); exists != 0 {
				t.Fatal("the counter key should be deleted at zero")
			}
		})
	}
}

// TestRedisCompat_DeleteAllForUserIsAtomic races saves against the script on
// every available backend: nothing saved before the call survives it, and the
// counter and the user index equal the sessions that exist afterwards.
func TestRedisCompat_DeleteAllForUserIsAtomic(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			skipCluster(t, mode.name)
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			store := session.NewStore(rdb, "as", true, false, 0)
			ctx := context.Background()
			const (
				rounds  = 15
				writers = 8
				tenant  = "t-race"
				user    = "u-race"
			)

			for round := 0; round < rounds; round++ {
				rdb.FlushDB(ctx)
				var before []string
				for i := 0; i < 20; i++ {
					id := fmt.Sprintf("old-%d", i)
					if err := store.Save(ctx, makeCompatSession(tenant, user, id, hashByte(byte(i+1))), time.Hour); err != nil {
						t.Fatal(err)
					}
					before = append(before, id)
				}

				var started, stop atomic.Bool
				var mu sync.Mutex
				var wg sync.WaitGroup
				for w := 0; w < writers; w++ {
					wg.Add(1)
					go func(w int) {
						defer wg.Done()
						for i := 0; !stop.Load(); i++ {
							id := fmt.Sprintf("w%d-%d", w, i)
							if err := store.Save(ctx, makeCompatSession(tenant, user, id, hashByte(byte(w+1))), time.Hour); err != nil {
								t.Errorf("save: %v", err)
								return
							}
							if !started.Load() {
								mu.Lock()
								before = append(before, id)
								mu.Unlock()
							}
						}
					}(w)
				}
				time.Sleep(time.Duration(2+round%4) * time.Millisecond)
				started.Store(true)
				if err := store.DeleteAllForUser(ctx, tenant, user); err != nil {
					t.Fatalf("DeleteAllForUser: %v", err)
				}
				stop.Store(true)
				wg.Wait()

				for _, id := range before {
					if _, err := store.Peek(ctx, tenant, id); err == nil {
						t.Fatalf("round %d: %s existed before the call and survived it", round, id)
					} else if err != redis.Nil {
						t.Fatalf("peek: %v", err)
					}
				}
				live, err := store.EstimateActiveSessions(ctx, tenant)
				if err != nil {
					t.Fatal(err)
				}
				count, _ := store.TenantSessionCount(ctx, tenant)
				indexed, _ := store.ActiveSessionCount(ctx, tenant, user)
				if count != live || indexed != live {
					t.Fatalf("round %d: counter=%d index=%d live=%d", round, count, indexed, live)
				}
			}
		})
	}
}

// TestRedisCompat_SessionEndRemovesProofKey checks, on every backend, that the
// other session-deleting scripts take the MFA-proof key with the session.
func TestRedisCompat_SessionEndRemovesProofKey(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			skipCluster(t, mode.name)
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			store := session.NewStore(rdb, "as", true, false, 0)
			ctx := context.Background()

			s := compatSaveWithProof(t, store, "t-end", "u-end", "x1", 11)
			if err := store.Delete(ctx, s.TenantID, s.SessionID); err != nil {
				t.Fatal(err)
			}
			if proofExists(t, store, s) {
				t.Fatal("Delete left the proof key")
			}

			r := compatSaveWithProof(t, store, "t-end", "u-end", "x2", 12)
			if _, err := store.RotateRefreshHash(ctx, r.TenantID, r.SessionID, hashByte(0x99), hashByte(0x98)); err == nil {
				t.Fatal("expected a reuse failure")
			}
			if proofExists(t, store, r) {
				t.Fatal("refresh-token reuse left the proof key")
			}

			w := compatSaveWithProof(t, store, "t-end", "u-end", "x3", 13)
			next := swapTargetSession(w, "x3-new", hashByte(0x42))
			if err := store.SwapSession(ctx, w.TenantID, w.SessionID, hashByte(0x77), next, nil); err == nil {
				t.Fatal("expected a mismatch failure")
			}
			if proofExists(t, store, w) {
				t.Fatal("a refused swap left the old proof key")
			}
		})
	}
}
