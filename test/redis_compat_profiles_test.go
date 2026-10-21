//go:build integration
// +build integration

package test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/session"
	"github.com/redis/go-redis/v9"
)

// Profile windows for the compatibility suite. They are long enough that no
// key lapses while a test runs, and the checks read the key's PTTL instead of
// waiting for expiry, so the same assertions hold on a backend whose clock
// does not move (miniredis) and on a real Redis.
var compatProfiles = map[string]session.ProfilePolicy{
	"fixed":    {AbsoluteLifetime: 2 * time.Hour},
	"renewing": {IdleTimeout: 100 * time.Second, AbsoluteLifetime: 2 * time.Hour},
	"renewuse": {IdleTimeout: 100 * time.Second, AbsoluteLifetime: 2 * time.Hour, RenewOnUse: true},
	"open":     {IdleTimeout: 100 * time.Second},
}

func compatProfileSession(t *testing.T, store *session.Store, profile, sid string, hash byte) *session.Session {
	t.Helper()
	sess := makeCompatSession("tenant-prof", "user-prof", sid, hashByte(hash))
	expiresAt, ttl, err := store.NewSessionLifetime(profile, time.Now())
	if err != nil {
		t.Fatalf("NewSessionLifetime: %v", err)
	}
	sess.Profile = profile
	sess.ExpiresAt = expiresAt
	if err := store.Save(context.Background(), sess, ttl); err != nil {
		t.Fatalf("save: %v", err)
	}
	return sess
}

func compatPTTL(t *testing.T, rdb redis.UniversalClient, prefix, tenant, sid string) time.Duration {
	t.Helper()
	d, err := rdb.PTTL(context.Background(), prefix+":"+tenant+":"+sid).Result()
	if err != nil {
		t.Fatalf("PTTL: %v", err)
	}
	return d
}

func wantAbout(t *testing.T, what string, got, want, slack time.Duration) {
	t.Helper()
	if got > want || got < want-slack {
		t.Fatalf("%s: TTL = %v, want within %v below %v", what, got, slack, want)
	}
}

// TestRedisCompat_ProfileRefresh validates the profile branch of the refresh
// script across backends.
func TestRedisCompat_ProfileRefresh(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			ctx := context.Background()
			store := session.NewStore(rdb, "as", true, false, 0).WithProfiles(compatProfiles)

			t.Run("renewing refresh renews the idle window", func(t *testing.T) {
				sess := compatProfileSession(t, store, "renewing", "sid-renew", 0x10)
				// Pull the key's life down, then refresh: it is renewed to the idle window.
				if err := rdb.Expire(ctx, "as:tenant-prof:sid-renew", 20*time.Second).Err(); err != nil {
					t.Fatal(err)
				}
				got, err := store.RotateRefreshHash(ctx, sess.TenantID, sess.SessionID, sess.RefreshHash, hashByte(0x11))
				if err != nil || got.Profile != "renewing" || got.SchemaVersion != session.ProfileSchemaVersion {
					t.Fatalf("rotate = %+v, %v", got, err)
				}
				wantAbout(t, "after refresh", compatPTTL(t, rdb, "as", "tenant-prof", "sid-renew"), 100*time.Second, 3*time.Second)
			})

			t.Run("fixed refresh keeps the TTL", func(t *testing.T) {
				sess := compatProfileSession(t, store, "fixed", "sid-fixed", 0x20)
				if err := rdb.Expire(ctx, "as:tenant-prof:sid-fixed", 500*time.Second).Err(); err != nil {
					t.Fatal(err)
				}
				if _, err := store.RotateRefreshHash(ctx, sess.TenantID, sess.SessionID, sess.RefreshHash, hashByte(0x21)); err != nil {
					t.Fatalf("rotate: %v", err)
				}
				wantAbout(t, "after refresh", compatPTTL(t, rdb, "as", "tenant-prof", "sid-fixed"), 500*time.Second, 3*time.Second)
			})

			t.Run("the window is clamped to the ceiling", func(t *testing.T) {
				sess := makeCompatSession("tenant-prof", "user-prof", "sid-clamp", hashByte(0x30))
				sess.Profile = "renewing"
				sess.ExpiresAt = time.Now().Add(40 * time.Second).Unix()
				if err := store.Save(ctx, sess, time.Hour); err != nil {
					t.Fatal(err)
				}
				if _, err := store.RotateRefreshHash(ctx, sess.TenantID, sess.SessionID, sess.RefreshHash, hashByte(0x31)); err != nil {
					t.Fatalf("rotate: %v", err)
				}
				// 100s idle window, 40s of ceiling: the key gets at most 40s.
				got := compatPTTL(t, rdb, "as", "tenant-prof", "sid-clamp")
				if got > 40*time.Second || got < 35*time.Second {
					t.Fatalf("TTL = %v, want about 40s", got)
				}
			})

			t.Run("an unbounded profile renews without a ceiling", func(t *testing.T) {
				sess := compatProfileSession(t, store, "open", "sid-open", 0x40)
				if sess.ExpiresAt != session.UnboundedExpiresAt {
					t.Fatalf("ExpiresAt = %d", sess.ExpiresAt)
				}
				if _, err := store.RotateRefreshHash(ctx, sess.TenantID, sess.SessionID, sess.RefreshHash, hashByte(0x41)); err != nil {
					t.Fatalf("rotate: %v", err)
				}
				wantAbout(t, "after refresh", compatPTTL(t, rdb, "as", "tenant-prof", "sid-open"), 100*time.Second, 3*time.Second)
			})

			t.Run("a passed ceiling deletes and reads as expired", func(t *testing.T) {
				sess := makeCompatSession("tenant-prof", "user-prof", "sid-late", hashByte(0x50))
				sess.Profile = "renewing"
				sess.ExpiresAt = time.Now().Add(time.Second).Unix()
				if err := store.Save(ctx, sess, time.Hour); err != nil {
					t.Fatal(err)
				}
				time.Sleep(2100 * time.Millisecond)
				before, _ := store.TenantSessionCount(ctx, sess.TenantID)
				_, err := store.RotateRefreshHash(ctx, sess.TenantID, sess.SessionID, sess.RefreshHash, hashByte(0x51))
				if !errors.Is(err, redis.Nil) || !errors.Is(err, session.ErrRefreshSessionExpired) {
					t.Fatalf("rotate = %v, want expired", err)
				}
				if _, err := store.Peek(ctx, sess.TenantID, sess.SessionID); !errors.Is(err, redis.Nil) {
					t.Fatalf("the session survived: %v", err)
				}
				if after, _ := store.TenantSessionCount(ctx, sess.TenantID); after != before-1 {
					t.Fatalf("tenant count %d -> %d, want one fewer", before, after)
				}
			})

			t.Run("a shortened ceiling already passed deletes", func(t *testing.T) {
				sess := compatProfileSession(t, store, "renewing", "sid-short", 0x60)
				sess.CreatedAt = time.Now().Add(-30 * time.Second).Unix()
				if err := store.Save(ctx, sess, time.Hour); err != nil {
					t.Fatal(err)
				}
				short := session.NewStore(rdb, "as", true, false, 0).WithProfiles(map[string]session.ProfilePolicy{
					"renewing": {IdleTimeout: 10 * time.Second, AbsoluteLifetime: 20 * time.Second},
				})
				_, err := short.RotateRefreshHash(ctx, sess.TenantID, sess.SessionID, sess.RefreshHash, hashByte(0x61))
				if !errors.Is(err, session.ErrRefreshSessionExpired) {
					t.Fatalf("rotate = %v, want expired", err)
				}
			})

			t.Run("an unknown profile deletes with the reason", func(t *testing.T) {
				sess := compatProfileSession(t, store, "renewing", "sid-gone", 0x70)
				other := session.NewStore(rdb, "as", true, false, 0).WithProfiles(map[string]session.ProfilePolicy{
					"fixed": {AbsoluteLifetime: time.Hour},
				})
				_, err := other.RotateRefreshHash(ctx, sess.TenantID, sess.SessionID, sess.RefreshHash, hashByte(0x71))
				if !errors.Is(err, session.ErrRefreshSessionExpired) || !errors.Is(err, session.ErrProfileUnknown) || session.EndedProfileName(err) != "renewing" {
					t.Fatalf("rotate = %v, want expired + unknown profile \"renewing\"", err)
				}
				if _, err := store.Peek(ctx, sess.TenantID, sess.SessionID); !errors.Is(err, redis.Nil) {
					t.Fatalf("the session survived: %v", err)
				}
			})

			t.Run("reuse deletes", func(t *testing.T) {
				sess := compatProfileSession(t, store, "renewing", "sid-reuse", 0x80)
				if _, err := store.RotateRefreshHash(ctx, sess.TenantID, sess.SessionID, sess.RefreshHash, hashByte(0x81)); err != nil {
					t.Fatalf("rotate: %v", err)
				}
				_, err := store.RotateRefreshHash(ctx, sess.TenantID, sess.SessionID, sess.RefreshHash, hashByte(0x82))
				if !errors.Is(err, session.ErrRefreshHashMismatch) {
					t.Fatalf("replay = %v, want mismatch", err)
				}
				if _, err := store.Peek(ctx, sess.TenantID, sess.SessionID); !errors.Is(err, redis.Nil) {
					t.Fatalf("reuse must delete the session: %v", err)
				}
			})

			t.Run("legacy sessions take the old path", func(t *testing.T) {
				legacy := makeCompatSession("tenant-prof", "user-prof", "sid-legacy", hashByte(0x90))
				if err := store.Save(ctx, legacy, time.Hour); err != nil {
					t.Fatal(err)
				}
				if err := rdb.Expire(ctx, "as:tenant-prof:sid-legacy", 300*time.Second).Err(); err != nil {
					t.Fatal(err)
				}
				got, err := store.RotateRefreshHash(ctx, legacy.TenantID, legacy.SessionID, legacy.RefreshHash, hashByte(0x91))
				if err != nil || got.SchemaVersion != session.CurrentSchemaVersion || got.Profile != "" {
					t.Fatalf("rotate = %+v, %v", got, err)
				}
				wantAbout(t, "legacy TTL", compatPTTL(t, rdb, "as", "tenant-prof", "sid-legacy"), 300*time.Second, 3*time.Second)
			})
		})
	}
}

// TestRedisCompat_ProfileStrictRead validates strict-read renewal across
// backends.
func TestRedisCompat_ProfileStrictRead(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			ctx := context.Background()
			store := session.NewStore(rdb, "as", true, false, 0).WithProfiles(compatProfiles)

			for _, tc := range []struct {
				profile string
				want    time.Duration
			}{
				{"renewuse", 100 * time.Second}, // renewed to the idle window
				{"renewing", 20 * time.Second},  // untouched
				{"fixed", 20 * time.Second},     // untouched
			} {
				sess := compatProfileSession(t, store, tc.profile, "sid-"+tc.profile, 0xA0)
				if err := rdb.Expire(ctx, "as:tenant-prof:sid-"+tc.profile, 20*time.Second).Err(); err != nil {
					t.Fatal(err)
				}
				if _, err := store.Get(ctx, sess.TenantID, sess.SessionID, 7*24*time.Hour); err != nil {
					t.Fatalf("%s: Get: %v", tc.profile, err)
				}
				wantAbout(t, tc.profile+" after a strict read", compatPTTL(t, rdb, "as", "tenant-prof", "sid-"+tc.profile), tc.want, 3*time.Second)
			}

			// A removed profile ends the session.
			sess := compatProfileSession(t, store, "renewing", "sid-removed", 0xB0)
			other := session.NewStore(rdb, "as", true, false, 0).WithProfiles(map[string]session.ProfilePolicy{"fixed": {AbsoluteLifetime: time.Hour}})
			if _, err := other.Get(ctx, sess.TenantID, sess.SessionID, time.Hour); !errors.Is(err, redis.Nil) || !errors.Is(err, session.ErrProfileUnknown) {
				t.Fatalf("Get of a removed profile = %v", err)
			}
			if _, err := store.Peek(ctx, sess.TenantID, sess.SessionID); !errors.Is(err, redis.Nil) {
				t.Fatalf("the session survived: %v", err)
			}
		})
	}
}

// TestRedisCompat_ProfileSwap validates the swap script's profile branch
// across backends.
func TestRedisCompat_ProfileSwap(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			ctx := context.Background()
			store := session.NewStore(rdb, "as", true, false, 0).WithProfiles(compatProfiles)

			old := compatProfileSession(t, store, "renewing", "sid-old", 0xC0)
			held := session.Assurance{MFAAt: time.Now().Unix(), MFAMethod: "totp", AuthAt: time.Now().Unix()}
			if err := store.SaveAssurance(ctx, old.TenantID, old.SessionID, held, time.Hour); err != nil {
				t.Fatal(err)
			}
			if err := rdb.Expire(ctx, "as:tenant-prof:sid-old", 20*time.Second).Err(); err != nil {
				t.Fatal(err)
			}

			next := swapTargetSession(old, "sid-new", hashByte(0xC1))
			next.SchemaVersion = 0
			if err := store.SwapSession(ctx, old.TenantID, old.SessionID, old.RefreshHash, next, nil); err != nil {
				t.Fatalf("swap: %v", err)
			}
			got, err := store.Peek(ctx, next.TenantID, next.SessionID)
			if err != nil || got.Profile != "renewing" || got.CreatedAt != old.CreatedAt || got.ExpiresAt != old.ExpiresAt || got.Role != "admin" {
				t.Fatalf("swapped session = %+v, %v", got, err)
			}
			wantAbout(t, "swapped session (a switch renews the idle window)", compatPTTL(t, rdb, "as", "tenant-prof", "sid-new"), 100*time.Second, 3*time.Second)
			if moved, err := store.GetAssurance(ctx, next.TenantID, next.SessionID); err != nil || moved == nil || *moved != held {
				t.Fatalf("assurance not carried over: %v %v", moved, err)
			}
			assuranceTTL, _ := rdb.PTTL(ctx, "asa:tenant-prof:sid-new").Result()
			if assuranceTTL < time.Hour {
				t.Fatalf("assurance TTL = %v, want the session's remaining ceiling (~2h)", assuranceTTL)
			}

			// A swap cannot change the profile.
			bad := swapTargetSession(next, "sid-bad", hashByte(0xC2))
			bad.SchemaVersion = 0
			bad.Profile = "fixed"
			if err := store.SwapSession(ctx, next.TenantID, next.SessionID, next.RefreshHash, bad, nil); !errors.Is(err, session.ErrRefreshSessionCorrupt) {
				t.Fatalf("swap with another profile = %v, want ErrRefreshSessionCorrupt", err)
			}

			// A removed profile ends the session at the swap.
			other := session.NewStore(rdb, "as", true, false, 0).WithProfiles(map[string]session.ProfilePolicy{"fixed": {AbsoluteLifetime: time.Hour}})
			gone := swapTargetSession(next, "sid-gone", hashByte(0xC3))
			gone.SchemaVersion = 0
			err = other.SwapSession(ctx, next.TenantID, next.SessionID, next.RefreshHash, gone, nil)
			if !errors.Is(err, session.ErrRefreshSessionExpired) || !errors.Is(err, session.ErrProfileUnknown) {
				t.Fatalf("swap of a removed profile = %v", err)
			}
			if _, err := store.Peek(ctx, next.TenantID, next.SessionID); !errors.Is(err, redis.Nil) {
				t.Fatalf("the session survived: %v", err)
			}
		})
	}
}

// TestRedisCompat_ProfileConcurrentRefresh checks that concurrent refreshes of
// one profile session have exactly one winner on every backend.
func TestRedisCompat_ProfileConcurrentRefresh(t *testing.T) {
	for _, mode := range redisModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			rdb, cleanup := mode.setup(t)
			defer cleanup()
			ctx := context.Background()
			store := session.NewStore(rdb, "as", true, false, 0).WithProfiles(compatProfiles)

			sess := compatProfileSession(t, store, "renewing", "sid-race", 0xD0)
			const workers = 16
			var (
				wg      sync.WaitGroup
				start   = make(chan struct{})
				mu      sync.Mutex
				winners int
			)
			for i := 0; i < workers; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					_, err := store.RotateRefreshHash(ctx, sess.TenantID, sess.SessionID, sess.RefreshHash, hashByte(byte(0xE0+i)))
					if err == nil {
						mu.Lock()
						winners++
						mu.Unlock()
					}
				}(i)
			}
			close(start)
			wg.Wait()
			if winners != 1 {
				t.Fatalf("winners = %d, want exactly 1", winners)
			}
		})
	}
}
