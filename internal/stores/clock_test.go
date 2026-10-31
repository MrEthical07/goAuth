package stores

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func clockTestRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close(); mr.Close() })
	return rdb, mr
}

// A record whose expiry is compared against the injected clock, not the wall
// clock: a clock five minutes past the record's expiry refuses it, while the
// wall clock (and the unmoved Redis TTL) still consider it alive.
func TestStoresCompareExpiryWithInjectedClock(t *testing.T) {
	rdb, _ := clockTestRedis(t)
	ctx := context.Background()
	wall := time.Now()
	hash := [32]byte{7}

	t.Run("password reset", func(t *testing.T) {
		now := wall
		s := NewPasswordResetStore(rdb, "apr").WithClock(func() time.Time { return now })
		rec := &PasswordResetRecord{UserID: "u", SecretHash: hash, ExpiresAt: wall.Add(time.Minute).Unix()}
		enc, err := encodePasswordResetRecord(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := rdb.Set(ctx, s.key("t", "r1"), enc, time.Hour).Err(); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get(ctx, "t", "r1"); err != nil {
			t.Fatalf("Get before expiry: %v", err)
		}
		now = wall.Add(6 * time.Minute)
		if _, err := s.Get(ctx, "t", "r1"); !errors.Is(err, ErrResetNotFound) {
			t.Fatalf("Get after the injected clock passed expiry = %v, want ErrResetNotFound", err)
		}
	})

	t.Run("mfa login", func(t *testing.T) {
		now := wall
		s := NewMFALoginChallengeStore(rdb, "amc").WithClock(func() time.Time { return now })
		const id = "c1"
		rec := &MFALoginChallenge{UserID: "u", TenantID: "t", ExpiresAt: wall.Add(time.Minute).Unix()}
		if err := s.Save(ctx, id, rec, time.Hour); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if _, err := s.Get(ctx, id); err != nil {
			t.Fatalf("Get before expiry: %v", err)
		}
		now = wall.Add(6 * time.Minute)
		if _, err := s.Get(ctx, id); !errors.Is(err, ErrMFALoginChallengeExpired) {
			t.Fatalf("Get after the injected clock passed expiry = %v, want ErrMFALoginChallengeExpired", err)
		}
	})
}

func TestStoresDefaultToWallClock(t *testing.T) {
	rdb, _ := clockTestRedis(t)
	for name, now := range map[string]func() time.Time{
		"reset":        NewPasswordResetStore(rdb, "").now,
		"verification": NewEmailVerificationStore(rdb, "").now,
		"mfa":          NewMFALoginChallengeStore(rdb, "").now,
		"emailchange":  NewEmailChangeStore(rdb, "").now,
	} {
		if d := time.Since(now()); d < -time.Second || d > time.Minute {
			t.Errorf("%s: default clock is %v from the wall clock", name, d)
		}
	}
}
