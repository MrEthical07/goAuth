package window

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// NewWithClock moves the sliding window's buckets with the injected time
// source, and a nil source is the wall clock.
func TestNewWithClockDrivesSlidingBuckets(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close(); mr.Close() })

	windowDur := time.Minute
	now := time.UnixMilli(1_700_000_040_000).Truncate(windowDur).Add(59 * time.Second)
	w := NewWithClock(rdb, Sliding, func() time.Time { return now })
	ctx := context.Background()

	var count int64
	for i := 0; i < 5; i++ {
		if count, err = w.Incr(ctx, "k", windowDur); err != nil {
			t.Fatalf("incr: %v", err)
		}
	}
	if count != 5 {
		t.Fatalf("count in one bucket = %d, want 5", count)
	}
	// Two windows later the injected clock has left both buckets behind.
	now = now.Add(2 * windowDur)
	if count, err = w.Count(ctx, "k", windowDur); err != nil || count != 0 {
		t.Fatalf("count after two windows = %d (%v), want 0", count, err)
	}
}

func TestNewWithClockNilIsWallClock(t *testing.T) {
	w := NewWithClock(nil, Fixed, nil)
	if w.now == nil {
		t.Fatal("nil clock must default to the wall clock")
	}
	if d := time.Since(w.now()); d < 0 || d > time.Minute {
		t.Fatalf("default clock is %v away from now", d)
	}
}
