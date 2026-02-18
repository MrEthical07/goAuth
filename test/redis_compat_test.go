//go:build integration
// +build integration

package test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/permission"
	"github.com/MrEthical07/goAuth/session"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// redisMode describes which Redis backend the compatibility suite is running against.
type redisMode struct {
	name  string
	setup func(t *testing.T) (redis.UniversalClient, func())
}

// redisModes returns the set of Redis backends to test.
// miniredis is always available.
// Real Redis standalone is used when REDIS_ADDR is set (e.g. "127.0.0.1:6379").
func redisModes(t *testing.T) []redisMode {
	t.Helper()
	modes := []redisMode{
		{
			name: "miniredis",
			setup: func(t *testing.T) (redis.UniversalClient, func()) {
				t.Helper()
				mr, err := miniredis.Run()
				if err != nil {
					t.Fatalf("miniredis: %v", err)
				}
				rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
				return rdb, func() { _ = rdb.Close(); mr.Close() }
			},
		},
	}

	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		modes = append(modes, redisMode{
			name: "standalone:" + addr,
			setup: func(t *testing.T) (redis.UniversalClient, func()) {
				t.Helper()
				rdb := redis.NewClient(&redis.Options{Addr: addr})
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := rdb.Ping(ctx).Err(); err != nil {
					t.Skipf("cannot connect to Redis at %s: %v", addr, err)
				}
				// Flush the test DB to avoid state leaking between runs.
				rdb.FlushDB(context.Background())
				return rdb, func() { rdb.FlushDB(context.Background()); _ = rdb.Close() }
			},
		})
	}

	// Cluster mode: when REDIS_CLUSTER_ADDRS is set (comma-separated).
	if addrs := os.Getenv("REDIS_CLUSTER_ADDRS"); addrs != "" {
		modes = append(modes, redisMode{
			name: "cluster",
			setup: func(t *testing.T) (redis.UniversalClient, func()) {
				t.Helper()
				clusterAddrs := splitAddrs(addrs)
				rdb := redis.NewClusterClient(&redis.ClusterOptions{Addrs: clusterAddrs})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := rdb.Ping(ctx).Err(); err != nil {
					t.Skipf("cannot connect to Redis cluster: %v", err)
				}
				return rdb, func() { _ = rdb.Close() }
			},
		})
	}

	// Sentinel mode: when REDIS_SENTINEL_ADDRS and REDIS_SENTINEL_MASTER are set.
	if addrs := os.Getenv("REDIS_SENTINEL_ADDRS"); addrs != "" {
		master := os.Getenv("REDIS_SENTINEL_MASTER")
		if master == "" {
			master = "mymaster"
		}
		modes = append(modes, redisMode{
			name: "sentinel",
			setup: func(t *testing.T) (redis.UniversalClient, func()) {
				t.Helper()
				rdb := redis.NewFailoverClient(&redis.FailoverOptions{
					MasterName:    master,
					SentinelAddrs: splitAddrs(addrs),
				})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := rdb.Ping(ctx).Err(); err != nil {
					t.Skipf("cannot connect to Redis sentinel: %v", err)
				}
				rdb.FlushDB(context.Background())
				return rdb, func() { rdb.FlushDB(context.Background()); _ = rdb.Close() }
			},
		})
	}

	return modes
}

func splitAddrs(s string) []string {
	var addrs []string
	for _, a := range splitComma(s) {
		a = trimSpace(a)
		if a != "" {
			addrs = append(addrs, a)
		}
	}
	return addrs
}

func splitComma(s string) []string {
	result := []string{}
	current := ""
	for _, c := range s {
		if c == ',' {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func makeCompatSession(tenantID, userID, sessionID string, refreshHash [32]byte) *session.Session {
	mask := permission.Mask64(0xFF)
	now := time.Now()
	return &session.Session{
		SessionID:         sessionID,
		UserID:            userID,
		TenantID:          tenantID,
		Role:              "member",
		Mask:              &mask,
		PermissionVersion: 1,
		RoleVersion:       1,
		AccountVersion:    1,
		Status:            0,
		RefreshHash:       refreshHash,
		CreatedAt:         now.Unix(),
		ExpiresAt:         now.Add(time.Hour).Unix(),
	}
}

// TestRedisCompat_RefreshRotation validates that Lua-based rotation works across backends.
func TestRedisCompat_RefreshRotation(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			rdb, cleanup := mode.setup(t)
			defer cleanup()

			store := session.NewStore(rdb, "as", true, false, 0)
			ctx := context.Background()

			oldHash := hashByte(0x01)
			newHash := hashByte(0x02)
			sess := makeCompatSession("tenant1", "user1", "sid-rot", oldHash)

			if err := store.Save(ctx, sess, time.Hour); err != nil {
				t.Fatalf("save: %v", err)
			}

			rotated, err := store.RotateRefreshHash(ctx, "tenant1", "sid-rot", oldHash, newHash)
			if err != nil {
				t.Fatalf("rotate: %v", err)
			}
			if rotated.RefreshHash != newHash {
				t.Error("rotated session should have new refresh hash")
			}

			// Replay detection: reusing old hash should fail.
			_, err = store.RotateRefreshHash(ctx, "tenant1", "sid-rot", oldHash, hashByte(0x03))
			if !errors.Is(err, session.ErrRefreshHashMismatch) {
				t.Errorf("expected ErrRefreshHashMismatch on replay, got %v", err)
			}
		})
	}
}

// TestRedisCompat_DeleteIdempotent validates delete idempotency across backends.
func TestRedisCompat_DeleteIdempotent(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			rdb, cleanup := mode.setup(t)
			defer cleanup()

			store := session.NewStore(rdb, "as", true, false, 0)
			ctx := context.Background()

			sess := makeCompatSession("tenant1", "user1", "sid-del", hashByte(0xAA))
			if err := store.Save(ctx, sess, time.Hour); err != nil {
				t.Fatalf("save: %v", err)
			}

			if err := store.Delete(ctx, "tenant1", "sid-del"); err != nil {
				t.Fatalf("first delete: %v", err)
			}
			if err := store.Delete(ctx, "tenant1", "sid-del"); err != nil {
				t.Fatalf("second delete should be idempotent: %v", err)
			}
		})
	}
}

// TestRedisCompat_StrictValidate validates session Get (strict mode read) across backends.
func TestRedisCompat_StrictValidate(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			rdb, cleanup := mode.setup(t)
			defer cleanup()

			store := session.NewStore(rdb, "as", true, false, 0)
			ctx := context.Background()

			sess := makeCompatSession("tenant1", "user1", "sid-strict", hashByte(0xBB))
			if err := store.Save(ctx, sess, time.Hour); err != nil {
				t.Fatalf("save: %v", err)
			}

			got, err := store.Get(ctx, "tenant1", "sid-strict", time.Hour)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if got.UserID != "user1" {
				t.Errorf("got UserID=%q, want user1", got.UserID)
			}
			if got.SessionID != "sid-strict" {
				t.Errorf("got SessionID=%q, want sid-strict", got.SessionID)
			}
		})
	}
}

// TestRedisCompat_CounterCorrectness validates tenant session counters across backends.
func TestRedisCompat_CounterCorrectness(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			rdb, cleanup := mode.setup(t)
			defer cleanup()

			store := session.NewStore(rdb, "as", true, false, 0)
			ctx := context.Background()

			// Save 3 sessions.
			for i := 0; i < 3; i++ {
				sid := "sid-counter-" + string(rune('a'+i))
				sess := makeCompatSession("tenant-cnt", "user-cnt", sid, hashByte(byte(i+1)))
				if err := store.Save(ctx, sess, time.Hour); err != nil {
					t.Fatalf("save %s: %v", sid, err)
				}
			}

			count, err := store.TenantSessionCount(ctx, "tenant-cnt")
			if err != nil {
				t.Fatalf("count: %v", err)
			}
			if count != 3 {
				t.Errorf("expected count=3, got %d", count)
			}

			// Delete one.
			if err := store.Delete(ctx, "tenant-cnt", "sid-counter-a"); err != nil {
				t.Fatalf("delete: %v", err)
			}

			count, err = store.TenantSessionCount(ctx, "tenant-cnt")
			if err != nil {
				t.Fatalf("count after delete: %v", err)
			}
			if count != 2 {
				t.Errorf("expected count=2 after delete, got %d", count)
			}
		})
	}
}

// TestRedisCompat_ReplayDetectionDeletesSession validates that replay detection
// (hash mismatch) triggers session deletion across backends.
func TestRedisCompat_ReplayDetectionDeletesSession(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			rdb, cleanup := mode.setup(t)
			defer cleanup()

			store := session.NewStore(rdb, "as", true, false, 0)
			ctx := context.Background()

			current := hashByte(0x10)
			wrong := hashByte(0x20)
			next := hashByte(0x30)

			sess := makeCompatSession("tenant-rpl", "user-rpl", "sid-replay", current)
			if err := store.Save(ctx, sess, time.Hour); err != nil {
				t.Fatalf("save: %v", err)
			}

			// Wrong hash → ErrRefreshHashMismatch.
			_, err := store.RotateRefreshHash(ctx, "tenant-rpl", "sid-replay", wrong, next)
			if !errors.Is(err, session.ErrRefreshHashMismatch) {
				t.Fatalf("expected ErrRefreshHashMismatch, got %v", err)
			}

			// Session should be deleted after mismatch.
			_, err = store.Get(ctx, "tenant-rpl", "sid-replay", time.Hour)
			if !errors.Is(err, redis.Nil) {
				t.Errorf("expected session to be deleted after replay, got err=%v", err)
			}
		})
	}
}
