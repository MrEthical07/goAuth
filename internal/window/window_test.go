package window

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestWindow(t *testing.T, mode Mode) (*Window, *miniredis.Miniredis) {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis run failed: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		_ = rdb.Close()
		mr.Close()
	})
	return New(rdb, mode), mr
}

func TestFixedIncrIsAtomicAndSetsTTL(t *testing.T) {
	w, mr := newTestWindow(t, Fixed)
	ctx := context.Background()

	count, err := w.Incr(ctx, "k", time.Minute)
	if err != nil {
		t.Fatalf("incr failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}
	if ttl := mr.TTL("k"); ttl <= 0 || ttl > time.Minute {
		t.Fatalf("expected TTL in (0, 1m], got %v", ttl)
	}

	if count, err = w.Incr(ctx, "k", time.Minute); err != nil || count != 2 {
		t.Fatalf("expected count 2, got %d (%v)", count, err)
	}
}

func TestFixedCountMissingKeyIsZero(t *testing.T) {
	w, _ := newTestWindow(t, Fixed)

	count, err := w.Count(context.Background(), "missing", time.Minute)
	if err != nil {
		t.Fatalf("count failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 for missing key, got %d", count)
	}
}

func TestZeroWindowIsPlainIncrWithoutTTL(t *testing.T) {
	for _, mode := range []Mode{Fixed, Sliding} {
		w, mr := newTestWindow(t, mode)
		ctx := context.Background()

		if count, err := w.Incr(ctx, "k", 0); err != nil || count != 1 {
			t.Fatalf("mode %d: expected count 1, got %d (%v)", mode, count, err)
		}
		if ttl := mr.TTL("k"); ttl != 0 {
			t.Fatalf("mode %d: expected no TTL, got %v", mode, ttl)
		}
		if count, err := w.Count(ctx, "k", 0); err != nil || count != 1 {
			t.Fatalf("mode %d: expected count 1, got %d (%v)", mode, count, err)
		}
	}
}

// setClock pins the window's clock to a fixed instant.
func setClock(w *Window, at time.Time) {
	w.now = func() time.Time { return at }
}

func TestSlidingWeightedCountAcrossBoundary(t *testing.T) {
	w, _ := newTestWindow(t, Sliding)
	ctx := context.Background()
	windowDur := time.Minute

	// t0 = start of a bucket. Five events land 59s into bucket N.
	t0 := time.UnixMilli(1_700_000_040_000).Truncate(windowDur)
	setClock(w, t0.Add(59*time.Second))
	var count int64
	var err error
	for i := 0; i < 5; i++ {
		count, err = w.Incr(ctx, "k", windowDur)
		if err != nil {
			t.Fatalf("incr failed: %v", err)
		}
	}
	if count != 5 {
		t.Fatalf("expected 5 within one bucket, got %d", count)
	}

	// 1s into bucket N+1: the previous bucket still weighs ~59/60.
	setClock(w, t0.Add(61*time.Second))
	count, err = w.Incr(ctx, "k", windowDur)
	if err != nil {
		t.Fatalf("incr failed: %v", err)
	}
	// 1 + floor(5 * 59000/60000) = 1 + 4 = 5
	if count != 5 {
		t.Fatalf("expected weighted count 5 just after the boundary, got %d", count)
	}

	if count, err = w.Count(ctx, "k", windowDur); err != nil || count != 5 {
		t.Fatalf("expected weighted read 5, got %d (%v)", count, err)
	}

	// Late in bucket N+1 the previous bucket's weight has decayed.
	setClock(w, t0.Add(119*time.Second))
	count, err = w.Count(ctx, "k", windowDur)
	if err != nil {
		t.Fatalf("count failed: %v", err)
	}
	// 1 + floor(5 * 1000/60000) = 1
	if count != 1 {
		t.Fatalf("expected decayed count 1 late in the next bucket, got %d", count)
	}
}

// TestSlidingBlocksBoundaryBurstThatFixedAdmits is the boundary-burst
// regression test: max-out just before a window boundary, then burst just
// after it. Fixed-window counting admits the second burst (2x the limit);
// sliding-window counting rejects it.
func TestSlidingBlocksBoundaryBurstThatFixedAdmits(t *testing.T) {
	const limit = 5
	windowDur := time.Minute
	ctx := context.Background()

	// Fixed: five hits, window expires at the boundary, five more all read 1..5.
	fixed, mr := newTestWindow(t, Fixed)
	for i := 0; i < limit; i++ {
		if _, err := fixed.Incr(ctx, "k", windowDur); err != nil {
			t.Fatalf("fixed incr failed: %v", err)
		}
	}
	mr.FastForward(windowDur + time.Second)
	count, err := fixed.Incr(ctx, "k", windowDur)
	if err != nil {
		t.Fatalf("fixed incr failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("fixed window should have reset at the boundary, got %d", count)
	}

	// Sliding: same pattern stays over the limit right after the boundary.
	sliding, _ := newTestWindow(t, Sliding)
	t0 := time.UnixMilli(1_700_000_040_000).Truncate(windowDur)
	setClock(sliding, t0.Add(59*time.Second))
	for i := 0; i < limit; i++ {
		if _, err := sliding.Incr(ctx, "k", windowDur); err != nil {
			t.Fatalf("sliding incr failed: %v", err)
		}
	}
	setClock(sliding, t0.Add(61*time.Second))
	count, err = sliding.Incr(ctx, "k", windowDur)
	if err != nil {
		t.Fatalf("sliding incr failed: %v", err)
	}
	if count <= limit-1 {
		t.Fatalf("sliding window must retain boundary-burst weight, got %d", count)
	}
}

func TestSlidingBucketKeysHaveTTL(t *testing.T) {
	w, mr := newTestWindow(t, Sliding)
	ctx := context.Background()
	windowDur := time.Minute

	at := time.UnixMilli(1_700_000_040_000)
	setClock(w, at)
	if _, err := w.Incr(ctx, "k", windowDur); err != nil {
		t.Fatalf("incr failed: %v", err)
	}

	curr, _ := slidingBucketKeys("k", at.UnixMilli()/windowDur.Milliseconds())
	if ttl := mr.TTL(curr); ttl <= 0 || ttl > 2*windowDur {
		t.Fatalf("expected bucket TTL in (0, 2m], got %v", ttl)
	}
}

func TestSlidingResetClearsBothBuckets(t *testing.T) {
	w, _ := newTestWindow(t, Sliding)
	ctx := context.Background()
	windowDur := time.Minute

	t0 := time.UnixMilli(1_700_000_040_000).Truncate(windowDur)
	setClock(w, t0.Add(59*time.Second))
	for i := 0; i < 3; i++ {
		if _, err := w.Incr(ctx, "k", windowDur); err != nil {
			t.Fatalf("incr failed: %v", err)
		}
	}
	setClock(w, t0.Add(61*time.Second))
	if _, err := w.Incr(ctx, "k", windowDur); err != nil {
		t.Fatalf("incr failed: %v", err)
	}

	if err := w.Reset(ctx, "k", windowDur); err != nil {
		t.Fatalf("reset failed: %v", err)
	}
	count, err := w.Count(ctx, "k", windowDur)
	if err != nil {
		t.Fatalf("count failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 after reset, got %d", count)
	}
}

func TestErrorsSurfaceWhenRedisDown(t *testing.T) {
	for _, mode := range []Mode{Fixed, Sliding} {
		w, mr := newTestWindow(t, mode)
		mr.Close()

		if _, err := w.Incr(context.Background(), "k", time.Minute); err == nil {
			t.Fatalf("mode %d: expected error with redis down", mode)
		}
		if _, err := w.Count(context.Background(), "k", time.Minute); err == nil {
			t.Fatalf("mode %d: expected error with redis down", mode)
		}
	}
}

func TestReserveClaimsUpToTheLimitAndRefusesWithoutGrowing(t *testing.T) {
	for _, mode := range []Mode{Fixed, Sliding} {
		w, mr := newTestWindow(t, mode)
		ctx := context.Background()

		for i := int64(1); i <= 3; i++ {
			count, ok, err := w.Reserve(ctx, "k", time.Minute, 3)
			if err != nil || !ok || count != i {
				t.Fatalf("mode %d claim %d: count=%d ok=%v err=%v", mode, i, count, ok, err)
			}
		}
		for i := 0; i < 4; i++ {
			count, ok, err := w.Reserve(ctx, "k", time.Minute, 3)
			if err != nil || ok || count != 3 {
				t.Fatalf("mode %d: expected a refusal at 3, got count=%d ok=%v err=%v", mode, count, ok, err)
			}
		}
		if count, err := w.Count(ctx, "k", time.Minute); err != nil || count != 3 {
			t.Fatalf("mode %d: refused claims must not grow the counter, got %d (%v)", mode, count, err)
		}
		if mode == Fixed {
			if ttl := mr.TTL("k"); ttl <= 0 || ttl > time.Minute {
				t.Fatalf("expected the first claim to pin a TTL, got %v", ttl)
			}
		}
	}
}

func TestReserveWithoutWindowNeverExpires(t *testing.T) {
	for _, mode := range []Mode{Fixed, Sliding} {
		w, mr := newTestWindow(t, mode)
		ctx := context.Background()

		if _, ok, err := w.Reserve(ctx, "k", 0, 1); err != nil || !ok {
			t.Fatalf("mode %d: expected the first claim, got ok=%v err=%v", mode, ok, err)
		}
		if _, ok, err := w.Reserve(ctx, "k", 0, 1); err != nil || ok {
			t.Fatalf("mode %d: expected a refusal, got ok=%v err=%v", mode, ok, err)
		}
		if ttl := mr.TTL("k"); ttl != 0 {
			t.Fatalf("mode %d: expected no TTL, got %v", mode, ttl)
		}
	}
}

func TestReserveSlidingCountsThePreviousBucket(t *testing.T) {
	w, _ := newTestWindow(t, Sliding)
	ctx := context.Background()
	windowDur := time.Minute

	t0 := time.UnixMilli(1_700_000_040_000).Truncate(windowDur)
	setClock(w, t0.Add(59*time.Second))
	for i := 0; i < 5; i++ {
		if _, ok, err := w.Reserve(ctx, "k", windowDur, 5); err != nil || !ok {
			t.Fatalf("claim %d: ok=%v err=%v", i, ok, err)
		}
	}

	// One second into the next bucket the previous one still weighs ~59/60
	// (4 of the 5), so only one more claim fits where a fixed window would
	// admit a whole second burst of five.
	setClock(w, t0.Add(61*time.Second))
	if count, ok, err := w.Reserve(ctx, "k", windowDur, 5); err != nil || !ok || count != 5 {
		t.Fatalf("expected one claim after the boundary, got count=%d ok=%v err=%v", count, ok, err)
	}
	if _, ok, err := w.Reserve(ctx, "k", windowDur, 5); err != nil || ok {
		t.Fatalf("expected the boundary burst to be refused, got ok=%v err=%v", ok, err)
	}
}

func TestReserveIsBoundedUnderConcurrency(t *testing.T) {
	for _, mode := range []Mode{Fixed, Sliding} {
		w, _ := newTestWindow(t, mode)
		ctx := context.Background()

		const callers = 64
		const limit = 5
		var wg sync.WaitGroup
		var claimed atomic.Int64
		start := make(chan struct{})
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, ok, err := w.Reserve(ctx, "k", time.Minute, limit); err == nil && ok {
					claimed.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()

		if got := claimed.Load(); got != limit {
			t.Fatalf("mode %d: expected exactly %d claims, got %d", mode, limit, got)
		}
	}
}

func TestReleaseGivesASlotBackAndNeverGoesNegative(t *testing.T) {
	for _, mode := range []Mode{Fixed, Sliding} {
		w, _ := newTestWindow(t, mode)
		ctx := context.Background()

		if err := w.Release(ctx, "k", time.Minute); err != nil {
			t.Fatalf("mode %d: release of a missing key failed: %v", mode, err)
		}
		if count, err := w.Count(ctx, "k", time.Minute); err != nil || count != 0 {
			t.Fatalf("mode %d: release must not create state, got %d (%v)", mode, count, err)
		}

		for i := 0; i < 2; i++ {
			if _, ok, err := w.Reserve(ctx, "k", time.Minute, 2); err != nil || !ok {
				t.Fatalf("mode %d: claim failed: ok=%v err=%v", mode, ok, err)
			}
		}
		if _, ok, _ := w.Reserve(ctx, "k", time.Minute, 2); ok {
			t.Fatalf("mode %d: expected the window to be full", mode)
		}
		if err := w.Release(ctx, "k", time.Minute); err != nil {
			t.Fatalf("mode %d: release failed: %v", mode, err)
		}
		if _, ok, err := w.Reserve(ctx, "k", time.Minute, 2); err != nil || !ok {
			t.Fatalf("mode %d: expected a freed slot, got ok=%v err=%v", mode, ok, err)
		}
	}
}

func TestReserveAndReleaseSurfaceErrorsWhenRedisDown(t *testing.T) {
	for _, mode := range []Mode{Fixed, Sliding} {
		w, mr := newTestWindow(t, mode)
		mr.Close()

		if _, _, err := w.Reserve(context.Background(), "k", time.Minute, 1); err == nil {
			t.Fatalf("mode %d: expected a reserve error with redis down", mode)
		}
		if err := w.Release(context.Background(), "k", time.Minute); err == nil {
			t.Fatalf("mode %d: expected a release error with redis down", mode)
		}
	}
}
