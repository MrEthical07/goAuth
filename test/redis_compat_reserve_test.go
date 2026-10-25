//go:build integration
// +build integration

package test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal/stores"
	"github.com/MrEthical07/goAuth/internal/window"
)

// The reserve scripts claim a limiter slot before the guarded work runs. These
// tests run each script against every configured Redis backend (miniredis
// always, real Redis when REDIS_ADDR is set), because the claim has to be one
// atomic step on the server.

func TestRedisCompatWindowReserve(t *testing.T) {
	for _, mode := range redisModes(t) {
		for _, wm := range []struct {
			name string
			mode window.Mode
		}{{"fixed", window.Fixed}, {"sliding", window.Sliding}} {
			t.Run(mode.name+"/"+wm.name, func(t *testing.T) {
				rdb, cleanup := mode.setup(t)
				defer cleanup()
				ctx := context.Background()
				w := window.New(rdb, wm.mode)
				key := "itest:reserve:" + wm.name

				for i := int64(1); i <= 3; i++ {
					count, ok, err := w.Reserve(ctx, key, time.Minute, 3)
					if err != nil || !ok || count != i {
						t.Fatalf("claim %d: count=%d ok=%v err=%v", i, count, ok, err)
					}
				}
				count, ok, err := w.Reserve(ctx, key, time.Minute, 3)
				if err != nil || ok || count != 3 {
					t.Fatalf("expected a refusal at the limit, got count=%d ok=%v err=%v", count, ok, err)
				}
				if got, err := w.Count(ctx, key, time.Minute); err != nil || got != 3 {
					t.Fatalf("a refused claim must not grow the counter, got %d (%v)", got, err)
				}

				if err := w.Release(ctx, key, time.Minute); err != nil {
					t.Fatalf("release: %v", err)
				}
				if _, ok, err := w.Reserve(ctx, key, time.Minute, 3); err != nil || !ok {
					t.Fatalf("expected the released slot to be claimable, got ok=%v err=%v", ok, err)
				}

				if err := w.Reset(ctx, key, time.Minute); err != nil {
					t.Fatalf("reset: %v", err)
				}
				if got, err := w.Count(ctx, key, time.Minute); err != nil || got != 0 {
					t.Fatalf("expected 0 after reset, got %d (%v)", got, err)
				}
			})
		}
	}
}

func TestRedisCompatWindowReserveConcurrentBurst(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			ctx := context.Background()
			w := window.New(rdb, window.Fixed)

			const callers = 100
			const limit = 5
			var claimed atomic.Int64
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i := 0; i < callers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					if _, ok, err := w.Reserve(ctx, "itest:reserve:burst", time.Minute, limit); err == nil && ok {
						claimed.Add(1)
					}
				}()
			}
			close(start)
			wg.Wait()

			if got := claimed.Load(); got != limit {
				t.Fatalf("expected exactly %d claims out of %d concurrent callers, got %d", limit, callers, got)
			}
		})
	}
}

func TestRedisCompatMFAChallengeAttemptScripts(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			ctx := context.Background()
			store := stores.NewMFALoginChallengeStore(rdb, "itest-amc")

			save := func(id string, profile string) {
				t.Helper()
				rec := &stores.MFALoginChallenge{
					UserID:     "u1",
					TenantID:   "t1",
					ExpiresAt:  time.Now().Add(time.Minute).Unix(),
					RememberMe: true,
					Profile:    profile,
				}
				if err := store.Save(ctx, id, rec, time.Minute); err != nil {
					t.Fatalf("save: %v", err)
				}
			}

			// Counting keeps the rest of the record and its TTL, for the
			// plain and the profile-carrying layout.
			for _, profile := range []string{"", "mobile"} {
				id := "count-" + profile
				save(id, profile)
				for want := 1; want <= 3; want++ {
					got, err := store.ReserveAttempt(ctx, id, 3)
					if err != nil || got != want {
						t.Fatalf("%s claim %d: got %d, %v", id, want, got, err)
					}
				}
				rec, err := store.Get(ctx, id)
				if err != nil || rec.Attempts != 3 || rec.UserID != "u1" || rec.TenantID != "t1" || !rec.RememberMe || rec.Profile != profile {
					t.Fatalf("%s: record after claims = %+v, %v", id, rec, err)
				}
				if ttl := rdb.TTL(ctx, "itest-amc:"+id).Val(); ttl <= 0 || ttl > time.Minute {
					t.Fatalf("%s: TTL after claims = %v", id, ttl)
				}
				if _, err := store.ReserveAttempt(ctx, id, 3); !errors.Is(err, stores.ErrMFALoginChallengeExceeded) {
					t.Fatalf("%s: claim past the limit: %v", id, err)
				}
				if rdb.Exists(ctx, "itest-amc:"+id).Val() != 0 {
					t.Fatalf("%s: a claim past the limit must delete the challenge", id)
				}
			}

			// Release gives one back and floors at zero.
			save("rel", "")
			if err := store.ReleaseAttempt(ctx, "rel"); err != nil {
				t.Fatalf("release on a fresh challenge: %v", err)
			}
			for i := 0; i < 2; i++ {
				if _, err := store.ReserveAttempt(ctx, "rel", 2); err != nil {
					t.Fatalf("claim: %v", err)
				}
			}
			if err := store.ReleaseAttempt(ctx, "rel"); err != nil {
				t.Fatalf("release: %v", err)
			}
			if got, err := store.ReserveAttempt(ctx, "rel", 2); err != nil || got != 2 {
				t.Fatalf("claim after release: %d, %v", got, err)
			}

			// Missing and expired.
			if _, err := store.ReserveAttempt(ctx, "missing", 2); !errors.Is(err, stores.ErrMFALoginChallengeNotFound) {
				t.Fatalf("missing: %v", err)
			}
			old := &stores.MFALoginChallenge{UserID: "u1", ExpiresAt: time.Now().Add(-time.Minute).Unix()}
			if err := store.Save(ctx, "old", old, time.Minute); err != nil {
				t.Fatalf("save: %v", err)
			}
			if _, err := store.ReserveAttempt(ctx, "old", 2); !errors.Is(err, stores.ErrMFALoginChallengeExpired) {
				t.Fatalf("expired: %v", err)
			}

			// A concurrent burst is bounded by the limit.
			save("burst", "")
			var granted atomic.Int64
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i := 0; i < 64; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					if _, err := store.ReserveAttempt(ctx, "burst", 5); err == nil {
						granted.Add(1)
					}
				}()
			}
			close(start)
			wg.Wait()
			if got := granted.Load(); got != 5 {
				t.Fatalf("%d concurrent claims granted, want exactly 5", got)
			}
		})
	}
}
