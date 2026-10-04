//go:build integration
// +build integration

package test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/permission"
	"github.com/MrEthical07/goAuth/session"
	"github.com/redis/go-redis/v9"
)

func swapTargetSession(from *session.Session, sid string, refreshHash [32]byte) *session.Session {
	mask := permission.Mask64(0x0F)
	next := *from
	next.SessionID = sid
	next.Role = "admin"
	next.Mask = &mask
	next.RefreshHash = refreshHash
	return &next
}

// TestRedisCompat_SwapSession validates the role-switch swap script across
// backends: the old session is replaced atomically, the lifetime and the
// assurance carry over, and the counters stay consistent.
func TestRedisCompat_SwapSession(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			rdb, cleanup := mode.setup(t)
			defer cleanup()

			store := session.NewStore(rdb, "as", true, false, 0)
			ctx := context.Background()

			old := makeCompatSession("tenant-swap", "user-swap", "sid-old", hashByte(0x41))
			if err := store.Save(ctx, old, time.Hour); err != nil {
				t.Fatalf("save: %v", err)
			}
			held := session.Assurance{MFAAt: time.Now().Unix(), MFAMethod: "totp", AuthAt: time.Now().Unix()}
			if err := store.SaveAssurance(ctx, old.TenantID, old.SessionID, held, time.Hour); err != nil {
				t.Fatalf("save assurance: %v", err)
			}
			countBefore, err := store.TenantSessionCount(ctx, old.TenantID)
			if err != nil {
				t.Fatalf("tenant count: %v", err)
			}

			next := swapTargetSession(old, "sid-new", hashByte(0x42))
			if err := store.SwapSession(ctx, old.TenantID, old.SessionID, old.RefreshHash, next, nil); err != nil {
				t.Fatalf("swap: %v", err)
			}

			if _, err := store.Peek(ctx, old.TenantID, old.SessionID); !errors.Is(err, redis.Nil) {
				t.Fatalf("old session should be gone, got %v", err)
			}
			got, err := store.Peek(ctx, next.TenantID, next.SessionID)
			if err != nil {
				t.Fatalf("new session missing: %v", err)
			}
			if got.Role != "admin" || got.RefreshHash != next.RefreshHash || got.CreatedAt != old.CreatedAt || got.ExpiresAt != old.ExpiresAt {
				t.Fatalf("new session content wrong: %+v", got)
			}
			moved, err := store.GetAssurance(ctx, next.TenantID, next.SessionID)
			if err != nil || moved == nil || *moved != held {
				t.Fatalf("assurance not carried over: %v %v", moved, err)
			}
			if leftover, _ := store.GetAssurance(ctx, old.TenantID, old.SessionID); leftover != nil {
				t.Fatalf("old assurance left behind: %v", leftover)
			}
			if ids, _ := store.ActiveSessionIDs(ctx, old.TenantID, old.UserID); len(ids) != 1 || ids[0] != next.SessionID {
				t.Fatalf("user index = %v, want only the new session", ids)
			}
			if after, _ := store.TenantSessionCount(ctx, old.TenantID); after != countBefore {
				t.Fatalf("tenant counter %d -> %d, want unchanged", countBefore, after)
			}

			// A stale presenter now finds nothing, and a wrong hash deletes.
			err = store.SwapSession(ctx, old.TenantID, old.SessionID, old.RefreshHash, swapTargetSession(old, "sid-x", hashByte(0x43)), nil)
			if !errors.Is(err, redis.Nil) || !errors.Is(err, session.ErrRefreshSessionNotFound) {
				t.Fatalf("swapping a swapped-away session = %v, want not found", err)
			}
			err = store.SwapSession(ctx, next.TenantID, next.SessionID, hashByte(0x99), swapTargetSession(next, "sid-y", hashByte(0x44)), nil)
			if !errors.Is(err, session.ErrRefreshHashMismatch) {
				t.Fatalf("wrong hash = %v, want mismatch", err)
			}
			if _, err := store.Peek(ctx, next.TenantID, next.SessionID); !errors.Is(err, redis.Nil) {
				t.Fatalf("a mismatching swap must delete the session, got %v", err)
			}
			if n, _ := store.TenantSessionCount(ctx, next.TenantID); n != 0 {
				t.Fatalf("tenant counter = %d after revocation, want 0", n)
			}
		})
	}
}

// TestRedisCompat_SwapSessionVersusRotateRace mixes swaps and rotations on
// one session: exactly one operation wins, whatever the backend.
func TestRedisCompat_SwapSessionVersusRotateRace(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			rdb, cleanup := mode.setup(t)
			defer cleanup()

			store := session.NewStore(rdb, "as", true, false, 0)
			ctx := context.Background()

			for round := 0; round < 20; round++ {
				current := hashByte(0x51)
				old := makeCompatSession("tenant-race", "user-race", "sid-race", current)
				if err := store.Save(ctx, old, time.Hour); err != nil {
					t.Fatalf("save: %v", err)
				}

				const workers = 8
				var (
					wg      sync.WaitGroup
					mu      sync.Mutex
					winners int
					barrier = make(chan struct{})
				)
				for i := 0; i < workers; i++ {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						<-barrier
						var err error
						if i%2 == 0 {
							next := swapTargetSession(old, "sid-new-"+string(rune('a'+i)), hashByte(byte(0x60+i)))
							err = store.SwapSession(ctx, old.TenantID, old.SessionID, current, next, nil)
						} else {
							_, err = store.RotateRefreshHash(ctx, old.TenantID, old.SessionID, current, hashByte(byte(0x70+i)))
						}
						if err == nil {
							mu.Lock()
							winners++
							mu.Unlock()
						}
					}(i)
				}
				close(barrier)
				wg.Wait()

				if winners != 1 {
					t.Fatalf("round %d: %d winners, want exactly 1", round, winners)
				}
				ids, _ := store.ActiveSessionIDs(ctx, old.TenantID, old.UserID)
				for _, id := range ids {
					if _, err := store.Peek(ctx, old.TenantID, id); err != nil {
						t.Fatalf("round %d: orphan index entry %s: %v", round, id, err)
					}
				}
				if err := store.DeleteAllForUser(ctx, old.TenantID, old.UserID); err != nil {
					t.Fatalf("cleanup: %v", err)
				}
			}
		})
	}
}

// TestRedisCompat_SwapSessionRefusesOccupiedID validates the replacement-ID
// guard and its check order across backends.
func TestRedisCompat_SwapSessionRefusesOccupiedID(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			rdb, cleanup := mode.setup(t)
			defer cleanup()

			store := session.NewStore(rdb, "as", true, false, 0)
			ctx := context.Background()

			old := makeCompatSession("tenant-inuse", "user-a", "sid-old", hashByte(0x81))
			occupant := makeCompatSession("tenant-inuse", "user-b", "sid-occupied", hashByte(0x82))
			for _, sess := range []*session.Session{old, occupant} {
				if err := store.Save(ctx, sess, time.Hour); err != nil {
					t.Fatalf("save: %v", err)
				}
			}
			countBefore, _ := store.TenantSessionCount(ctx, old.TenantID)
			occupantBefore, err := store.Peek(ctx, occupant.TenantID, occupant.SessionID)
			if err != nil {
				t.Fatalf("peek: %v", err)
			}

			err = store.SwapSession(ctx, old.TenantID, old.SessionID, old.RefreshHash, swapTargetSession(old, occupant.SessionID, hashByte(0x83)), nil)
			if !errors.Is(err, session.ErrSessionIDInUse) {
				t.Fatalf("occupied id = %v, want ErrSessionIDInUse", err)
			}
			if err := store.SwapSession(ctx, old.TenantID, old.SessionID, old.RefreshHash, swapTargetSession(old, old.SessionID, hashByte(0x84)), nil); err == nil {
				t.Fatal("a replacement with the old id must be refused")
			}
			occupantAfter, err := store.Peek(ctx, occupant.TenantID, occupant.SessionID)
			if err != nil || occupantAfter.RefreshHash != occupantBefore.RefreshHash || occupantAfter.UserID != "user-b" {
				t.Fatalf("occupant changed: %+v %v", occupantAfter, err)
			}
			if n, _ := store.TenantSessionCount(ctx, old.TenantID); n != countBefore {
				t.Fatalf("tenant count %d -> %d", countBefore, n)
			}
			if _, err := store.RotateRefreshHash(ctx, old.TenantID, old.SessionID, old.RefreshHash, hashByte(0x85)); err != nil {
				t.Fatalf("the old session must still refresh: %v", err)
			}

			// A stale hash still wins over an occupied id.
			err = store.SwapSession(ctx, old.TenantID, old.SessionID, hashByte(0x99), swapTargetSession(old, occupant.SessionID, hashByte(0x86)), nil)
			if !errors.Is(err, session.ErrRefreshHashMismatch) {
				t.Fatalf("stale hash = %v, want ErrRefreshHashMismatch", err)
			}
			if _, err := store.Peek(ctx, old.TenantID, old.SessionID); !errors.Is(err, redis.Nil) {
				t.Fatalf("reuse must delete the old session, got %v", err)
			}
		})
	}
}
