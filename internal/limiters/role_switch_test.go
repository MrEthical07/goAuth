package limiters

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal/window"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newRoleSwitchTestRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return mr, rdb
}

func TestRoleSwitchLimiterReserveAndReset(t *testing.T) {
	for _, mode := range []window.Mode{window.Fixed, window.Sliding} {
		name := "fixed"
		if mode == window.Sliding {
			name = "sliding"
		}
		t.Run(name, func(t *testing.T) {
			_, rdb := newRoleSwitchTestRedis(t)
			l := NewRoleSwitchLimiter(rdb, RoleSwitchConfig{MaxAttempts: 3, Cooldown: time.Minute, WindowMode: mode})
			ctx := context.Background()

			for i := 0; i < 3; i++ {
				if err := l.Reserve(ctx, "t1", "sid-1"); err != nil {
					t.Fatalf("attempt %d should be allowed: %v", i+1, err)
				}
			}
			if err := l.Reserve(ctx, "t1", "sid-1"); !errors.Is(err, ErrRoleSwitchRateLimited) {
				t.Fatalf("4th attempt = %v, want ErrRoleSwitchRateLimited", err)
			}

			// A different session and a different tenant have their own budget.
			if err := l.Reserve(ctx, "t1", "sid-2"); err != nil {
				t.Fatalf("other session should be unaffected: %v", err)
			}
			if err := l.Reserve(ctx, "t2", "sid-1"); err != nil {
				t.Fatalf("other tenant should be unaffected: %v", err)
			}

			if err := l.Reset(ctx, "t1", "sid-1"); err != nil {
				t.Fatalf("reset: %v", err)
			}
			if err := l.Reserve(ctx, "t1", "sid-1"); err != nil {
				t.Fatalf("attempt after reset should be allowed: %v", err)
			}
		})
	}
}

func TestRoleSwitchLimiterDefaults(t *testing.T) {
	_, rdb := newRoleSwitchTestRedis(t)
	l := NewRoleSwitchLimiter(rdb, RoleSwitchConfig{})
	if l.maxAttempts != 10 || l.cooldown != 15*time.Minute {
		t.Fatalf("defaults = %d / %v, want 10 / 15m", l.maxAttempts, l.cooldown)
	}
}

func TestRoleSwitchLimiterBackendFailureIsUnavailable(t *testing.T) {
	mr, rdb := newRoleSwitchTestRedis(t)
	l := NewRoleSwitchLimiter(rdb, RoleSwitchConfig{MaxAttempts: 3, Cooldown: time.Minute})
	mr.Close()

	err := l.Reserve(context.Background(), "t1", "sid-1")
	if !errors.Is(err, ErrRoleSwitchUnavailable) {
		t.Fatalf("Reserve with a dead backend = %v, want ErrRoleSwitchUnavailable", err)
	}
	if errors.Is(err, ErrRoleSwitchRateLimited) {
		t.Fatal("a backend failure must not look like a rate-limit denial")
	}
}
