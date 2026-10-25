//go:build integration
// +build integration

package test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
