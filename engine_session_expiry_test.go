package goAuth

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newExpiryEngine is newCreateAccountEngine that also hands back the miniredis
// server, so a test can let sessions expire by TTL with FastForward.
func newExpiryEngine(t *testing.T, cfg Config) (*Engine, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr, rdb := newTestRedis(t)
	engine, err := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"perm.read"}).
		WithRoles(map[string][]string{"member": {}, "admin": {"perm.read"}}).
		WithUserProvider(newHardeningUserProvider(t)).
		Build()
	if err != nil {
		mr.Close()
		t.Fatalf("Build failed: %v", err)
	}
	t.Cleanup(mr.Close)
	return engine, mr, rdb
}

func loginSessionID(t *testing.T, e *Engine, identifier string) string {
	t.Helper()
	_, refresh, err := e.Login(context.Background(), identifier, "correct-password-123")
	if err != nil {
		t.Fatalf("login %s: %v", identifier, err)
	}
	sid, _, err := internal.DecodeRefreshToken(refresh)
	if err != nil {
		t.Fatalf("decode refresh: %v", err)
	}
	return sid
}

func userSessionSet(t *testing.T, rdb *redis.Client, user string) []string {
	t.Helper()
	ids, err := rdb.SMembers(context.Background(), "au:0:"+user).Result()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(ids)
	return ids
}

// C3: a session that expired by TTL left its ID in the user's set, and that ID
// counted toward the per-user caps, so a user with no live session was refused.
func TestExpiredSessionsDoNotCountTowardThePerUserCaps(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*SessionHardeningConfig)
	}{
		{"MaxSessionsPerUser", func(h *SessionHardeningConfig) { h.MaxSessionsPerUser = 1 }},
		{"ConcurrentLoginLimit", func(h *SessionHardeningConfig) { h.ConcurrentLoginLimit = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := accountTestConfig()
			tc.set(&cfg.SessionHardening)
			engine, mr, rdb := newExpiryEngine(t, cfg)

			first := loginSessionID(t, engine, "alice")
			if _, _, err := engine.Login(context.Background(), "alice", "correct-password-123"); !errors.Is(err, ErrSessionLimitExceeded) {
				t.Fatalf("a live session at the cap: %v, want ErrSessionLimitExceeded", err)
			}

			mr.FastForward(cfg.Session.AbsoluteSessionLifetime + time.Hour)
			if rdb.Exists(context.Background(), "as:0:"+first).Val() != 0 {
				t.Fatal("precondition: the first session should have expired")
			}
			second := loginSessionID(t, engine, "alice")

			if got := userSessionSet(t, rdb, "u1"); len(got) != 1 || got[0] != second {
				t.Fatalf("user set = %v, want only the new session %s", got, second)
			}
		})
	}
}

func TestExpiredSessionIsPrunedAndTheLiveOneKeptUnderACapOfTwo(t *testing.T) {
	cfg := accountTestConfig()
	cfg.SessionHardening.MaxSessionsPerUser = 2
	engine, mr, rdb := newExpiryEngine(t, cfg)
	ctx := context.Background()

	old := loginSessionID(t, engine, "alice")
	ttl := mr.TTL("as:0:" + old)
	if ttl <= time.Hour {
		t.Fatalf("session TTL %v is too short for the test", ttl)
	}
	mr.FastForward(ttl - 30*time.Minute)
	live := loginSessionID(t, engine, "alice")
	mr.FastForward(time.Hour) // old is gone; live has most of its life left
	if rdb.Exists(ctx, "as:0:"+old).Val() != 0 || rdb.Exists(ctx, "as:0:"+live).Val() != 1 {
		t.Fatal("precondition: one expired session and one live session")
	}

	third := loginSessionID(t, engine, "alice")
	want := []string{live, third}
	sort.Strings(want)
	if got := userSessionSet(t, rdb, "u1"); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("user set = %v, want the live and the new session %v", got, want)
	}
	if rdb.Exists(ctx, "as:0:"+live).Val() != 1 {
		t.Fatal("the live session was ended")
	}

	// The cap still applies to live sessions.
	if _, _, err := engine.Login(ctx, "alice", "correct-password-123"); !errors.Is(err, ErrSessionLimitExceeded) {
		t.Fatalf("two live sessions at a cap of 2: %v, want ErrSessionLimitExceeded", err)
	}
}
