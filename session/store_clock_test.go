package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal/clock"
	"github.com/MrEthical07/goAuth/permission"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func clockTestStore(t *testing.T, profiles map[string]ProfilePolicy) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close(); mr.Close() })
	return NewStore(rdb, "as", true, false, 0).WithProfiles(profiles), mr
}

func saveProfiled(t *testing.T, s *Store, id, profile string, at time.Time) *Session {
	t.Helper()
	expiresAt, ttl, err := s.NewSessionLifetime(profile, at)
	if err != nil {
		t.Fatalf("NewSessionLifetime: %v", err)
	}
	mask := permission.Mask64(1)
	sess := &Session{
		SessionID: id, UserID: "u-1", TenantID: "t-1", Role: "member", Mask: &mask,
		RefreshHash: [32]byte{1}, CreatedAt: at.Unix(), ExpiresAt: expiresAt, Profile: profile,
	}
	if err := s.Save(context.Background(), sess, ttl); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return sess
}

// WithClock is per store: two stores in one process, one of them on top of a
// package clock set somewhere else entirely, never see each other's time.
func TestStoreWithClockIsPerStore(t *testing.T) {
	// The package default points at the year 2000 and must not matter to a
	// store that carries its own clock.
	t.Cleanup(clock.Set(func() time.Time { return time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC) }))

	profiles := map[string]ProfilePolicy{"short": {AbsoluteLifetime: 10 * day}}
	a, mrA := clockTestStore(t, profiles)
	b, mrB := clockTestStore(t, profiles)
	clkA := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	clkB := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	a.WithClock(clkA)
	b.WithClock(clkB)
	mrA.SetTime(clkA.Now())
	mrB.SetTime(clkB.Now())

	saveProfiled(t, a, "s-a", "short", clkA.Now())
	saveProfiled(t, b, "s-b", "short", clkB.Now())

	// Only A's clock and Redis move past the ceiling.
	clkA.Advance(11 * day)
	mrA.SetTime(clkA.Now())
	mrA.FastForward(11 * day)

	ctx := context.Background()
	if _, err := a.GetReadOnly(ctx, "t-1", "s-a"); !errors.Is(err, redis.Nil) {
		t.Fatalf("A past its ceiling: err = %v, want redis.Nil", err)
	}
	if _, err := b.GetReadOnly(ctx, "t-1", "s-b"); err != nil {
		t.Fatalf("B on its own clock must still see its session: %v", err)
	}
}

// A store without WithClock keeps following the package default, and a nil
// clock restores it.
func TestStoreWithoutClockUsesPackageDefault(t *testing.T) {
	fixed := time.Date(2029, 5, 6, 7, 8, 9, 0, time.UTC)
	t.Cleanup(clock.Set(func() time.Time { return fixed }))

	s, _ := clockTestStore(t, nil)
	if got := s.now(); !got.Equal(fixed) {
		t.Fatalf("default store time = %v, want package clock %v", got, fixed)
	}
	own := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	s.WithClock(clock.NewFake(own))
	if got := s.now(); !got.Equal(own) {
		t.Fatalf("store time = %v, want its own %v", got, own)
	}
	s.WithClock(nil)
	if got := s.now(); !got.Equal(fixed) {
		t.Fatalf("after WithClock(nil) time = %v, want package clock %v", got, fixed)
	}
}

// The store stays comparable with == after WithClock.
func TestStoreStaysComparable(t *testing.T) {
	a, _ := clockTestStore(t, nil)
	a.WithClock(clock.NewFake(time.Unix(1, 0)))
	b := *a
	if *a != b {
		t.Fatal("a copy of a store must compare equal to it")
	}
}
