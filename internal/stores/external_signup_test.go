package stores

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func signupRecord(expires time.Time) ExternalSignupRecord {
	return ExternalSignupRecord{
		Provider: "google", Subject: "sub-1", Email: "a@example.com", EmailVerified: true,
		DisplayName: "A", ExpiresAt: expires.Unix(),
	}
}

func TestExternalSignupStoreRoundTripAndSingleUse(t *testing.T) {
	rdb, mr := clockTestRedis(t)
	s := NewExternalSignupStore(rdb, "")
	ctx := context.Background()
	now := time.Now()

	if err := s.Save(ctx, "t1", "handle-1", signupRecord(now.Add(time.Minute)), time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}
	for _, key := range mr.Keys() {
		if strings.Contains(key, "handle-1") {
			t.Fatalf("the handle names a key: %s", key)
		}
		if !strings.HasPrefix(key, "axs:t1:") || len(key) != len("axs:t1:")+64 {
			t.Fatalf("key = %q, want axs:<tenant>:<64 hex>", key)
		}
	}
	rec, err := s.Take(ctx, "t1", "handle-1")
	if err != nil || rec.Provider != "google" || rec.Subject != "sub-1" || rec.Email != "a@example.com" || !rec.EmailVerified || rec.DisplayName != "A" {
		t.Fatalf("Take = %+v, %v", rec, err)
	}
	if _, err := s.Take(ctx, "t1", "handle-1"); !errors.Is(err, ErrExternalSignupNotFound) {
		t.Fatalf("second Take = %v, want ErrExternalSignupNotFound", err)
	}
}

func TestExternalSignupStoreTenantsAreSeparate(t *testing.T) {
	rdb, _ := clockTestRedis(t)
	s := NewExternalSignupStore(rdb, "")
	ctx := context.Background()
	if err := s.Save(ctx, "t1", "h", signupRecord(time.Now().Add(time.Minute)), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Take(ctx, "t2", "h"); !errors.Is(err, ErrExternalSignupNotFound) {
		t.Fatalf("Take from another tenant = %v", err)
	}
	if err := s.Delete(ctx, "t2", "h"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Take(ctx, "t1", "h"); err != nil {
		t.Fatalf("the owner's ticket was affected by the other tenant: %v", err)
	}
}

func TestExternalSignupStoreExpiryUsesTheClockAndConsumes(t *testing.T) {
	rdb, mr := clockTestRedis(t)
	now := time.Now()
	s := NewExternalSignupStore(rdb, "").WithClock(func() time.Time { return now })
	ctx := context.Background()
	if err := s.Save(ctx, "t", "h", signupRecord(now.Add(time.Minute)), time.Hour); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := s.Take(ctx, "t", "h"); !errors.Is(err, ErrExternalSignupNotFound) {
		t.Fatalf("Take after the clock passed expiry = %v", err)
	}
	if len(mr.Keys()) != 0 {
		t.Fatalf("an expired ticket was left behind: %v", mr.Keys())
	}
}

func TestExternalSignupStoreRefusesCollisionsAndCorruptRecords(t *testing.T) {
	rdb, mr := clockTestRedis(t)
	s := NewExternalSignupStore(rdb, "")
	ctx := context.Background()
	rec := signupRecord(time.Now().Add(time.Minute))
	if err := s.Save(ctx, "t", "h", rec, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, "t", "h", rec, time.Minute); !errors.Is(err, ErrExternalSignupUnavailable) {
		t.Fatalf("a colliding handle = %v, want a refusal", err)
	}

	key := mr.Keys()[0]
	if err := mr.Set(key, "{not json"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Take(ctx, "t", "h"); !errors.Is(err, ErrExternalSignupNotFound) {
		t.Fatalf("a corrupt ticket = %v", err)
	}
	if len(mr.Keys()) != 0 {
		t.Fatal("a corrupt ticket survived being taken")
	}
}

func TestExternalSignupStoreConcurrentTakeHasOneWinner(t *testing.T) {
	rdb, _ := clockTestRedis(t)
	s := NewExternalSignupStore(rdb, "")
	ctx := context.Background()
	if err := s.Save(ctx, "t", "h", signupRecord(time.Now().Add(time.Minute)), time.Minute); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := s.Take(ctx, "t", "h"); err == nil {
				wins.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d callers got the ticket, want exactly 1", wins.Load())
	}
}

func TestVerificationPointerStates(t *testing.T) {
	rdb, mr := clockTestRedis(t)
	s := NewEmailVerificationStore(rdb, "")
	ctx := context.Background()

	if st, err := s.PointerState(ctx, "t", "u", "v1"); err != nil || st != PointerAbsent {
		t.Fatalf("no pointer = %v, %v", st, err)
	}
	if err := s.SetCurrent(ctx, "t", "u", "v1", time.Hour); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.PointerState(ctx, "t", "u", "v1"); st != PointerCurrent {
		t.Fatalf("current record = %v", st)
	}
	if st, _ := s.PointerState(ctx, "t", "u", "v0"); st != PointerSuperseded {
		t.Fatalf("older record = %v", st)
	}
	if err := s.InvalidateOutstanding(ctx, "t", "u", time.Hour); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.PointerState(ctx, "t", "u", "v1"); st != PointerSuperseded {
		t.Fatalf("after the tombstone = %v", st)
	}
	if !mr.Exists("aevg:t:u") {
		t.Fatalf("pointer key is not aevg:<tenant>:<user>: %v", mr.Keys())
	}
	if ttl := mr.TTL("aevg:t:u"); ttl <= 0 || ttl > time.Hour {
		t.Fatalf("pointer TTL = %v", ttl)
	}
}
