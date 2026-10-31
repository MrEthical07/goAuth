//go:build integration
// +build integration

package test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal/stores"
	"github.com/redis/go-redis/v9"
)

func compatKeys(t *testing.T, rdb redis.UniversalClient, pattern string) []string {
	t.Helper()
	keys, err := rdb.Keys(context.Background(), pattern).Result()
	if err != nil {
		t.Fatalf("keys %s: %v", pattern, err)
	}
	return keys
}

// The deferred sign-up ticket is read and deleted by one script: of many
// concurrent callers exactly one gets it, on every backend.
func TestRedisCompat_ExternalSignupSingleUse(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			store := stores.NewExternalSignupStore(rdb, "")
			ctx := context.Background()
			record := stores.ExternalSignupRecord{
				Provider: "google", Subject: "sub", Email: "a@example.com", EmailVerified: true,
				ExpiresAt: time.Now().Add(time.Minute).Unix(),
			}
			if err := store.Save(ctx, "tenant1", "handle-g4", record, time.Minute); err != nil {
				t.Fatalf("save: %v", err)
			}
			keys := compatKeys(t, rdb, "axs:*")
			if len(keys) != 1 || strings.Contains(keys[0], "handle-g4") {
				t.Fatalf("keys = %v", keys)
			}
			if ttl := rdb.PTTL(ctx, keys[0]).Val(); ttl <= 0 || ttl > time.Minute {
				t.Fatalf("ticket TTL = %v", ttl)
			}
			if err := store.Save(ctx, "tenant1", "handle-g4", record, time.Minute); err == nil {
				t.Fatal("a colliding handle overwrote the ticket")
			}
			if _, err := store.Take(ctx, "tenant2", "handle-g4"); !errors.Is(err, stores.ErrExternalSignupNotFound) {
				t.Fatalf("take from another tenant = %v", err)
			}

			var wins atomic.Int32
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i := 0; i < 16; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					if _, err := store.Take(ctx, "tenant1", "handle-g4"); err == nil {
						wins.Add(1)
					}
				}()
			}
			close(start)
			wg.Wait()
			if wins.Load() != 1 {
				t.Fatalf("%d callers got the ticket, want 1", wins.Load())
			}
			if n := len(compatKeys(t, rdb, "axs:*")); n != 0 {
				t.Fatalf("%d ticket keys left", n)
			}
		})
	}
}

// The email-verification pointer: written with the record's lifetime, newest
// wins, a tombstone supersedes everything.
func TestRedisCompat_VerificationPointer(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			store := stores.NewEmailVerificationStore(rdb, "")
			ctx := context.Background()

			if st, err := store.PointerState(ctx, "t", "u", "v1"); err != nil || st != stores.PointerAbsent {
				t.Fatalf("no pointer = %v, %v", st, err)
			}
			if err := store.SetCurrent(ctx, "t", "u", "v1", time.Minute); err != nil {
				t.Fatal(err)
			}
			if err := store.SetCurrent(ctx, "t", "u", "v2", time.Minute); err != nil {
				t.Fatal(err)
			}
			if st, _ := store.PointerState(ctx, "t", "u", "v2"); st != stores.PointerCurrent {
				t.Fatalf("newest = %v", st)
			}
			if st, _ := store.PointerState(ctx, "t", "u", "v1"); st != stores.PointerSuperseded {
				t.Fatalf("older = %v", st)
			}
			if ttl := rdb.PTTL(ctx, "aevg:t:u").Val(); ttl <= 0 || ttl > time.Minute {
				t.Fatalf("pointer TTL = %v", ttl)
			}
			if err := store.InvalidateOutstanding(ctx, "t", "u", time.Minute); err != nil {
				t.Fatal(err)
			}
			if st, _ := store.PointerState(ctx, "t", "u", "v2"); st != stores.PointerSuperseded {
				t.Fatalf("after the tombstone = %v", st)
			}
		})
	}
}

// saveEmailChangeUnverifiedLua stores the record, the per-user pointer and the
// flag, and drops the previous challenge together with its flag.
func TestRedisCompat_EmailChangeUnverifiedFlag(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			store := stores.NewEmailChangeStore(rdb, "")
			ctx := context.Background()
			rec := func() *stores.EmailChangeRecord {
				return &stores.EmailChangeRecord{
					UserID: "u1", OldIdentifier: "old@example.com", NewIdentifier: "new@example.com",
					AccountVersion: 1, ExpiresAt: time.Now().Add(time.Minute).Unix(),
				}
			}

			if err := store.SaveUnverified(ctx, "t", "c1", rec(), time.Minute); err != nil {
				t.Fatalf("SaveUnverified: %v", err)
			}
			if flagged, err := store.WasUnverified(ctx, "t", "c1"); err != nil || !flagged {
				t.Fatalf("WasUnverified(c1) = %v, %v", flagged, err)
			}
			if ttl := rdb.PTTL(ctx, "aecu:t:c1").Val(); ttl <= 0 || ttl > time.Minute {
				t.Fatalf("flag TTL = %v", ttl)
			}

			// A second request replaces the first challenge and its flag.
			if err := store.SaveUnverified(ctx, "t", "c2", rec(), time.Minute); err != nil {
				t.Fatal(err)
			}
			if flagged, _ := store.WasUnverified(ctx, "t", "c1"); flagged {
				t.Fatal("the replaced challenge kept its flag")
			}
			if flagged, _ := store.WasUnverified(ctx, "t", "c2"); !flagged {
				t.Fatal("the new challenge has no flag")
			}
			if n := len(compatKeys(t, rdb, "aec:t:*")); n != 1 {
				t.Fatalf("%d challenge records, want 1", n)
			}

			// A verified save has no flag.
			if err := store.Save(ctx, "t", "c3", rec(), time.Minute); err != nil {
				t.Fatal(err)
			}
			if flagged, _ := store.WasUnverified(ctx, "t", "c3"); flagged {
				t.Fatal("a verified challenge is flagged")
			}
		})
	}
}
