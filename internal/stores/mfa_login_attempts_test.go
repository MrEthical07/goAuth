package stores

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newAttemptStore(t *testing.T) (*MFALoginChallengeStore, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		_ = rdb.Close()
		mr.Close()
	})
	return NewMFALoginChallengeStore(rdb, "amc"), mr
}

func saveChallenge(t *testing.T, s *MFALoginChallengeStore, id string, record *MFALoginChallenge) {
	t.Helper()
	if record.ExpiresAt == 0 {
		record.ExpiresAt = time.Now().Add(time.Minute).Unix()
	}
	if err := s.Save(context.Background(), id, record, time.Minute); err != nil {
		t.Fatalf("save: %v", err)
	}
}

func TestReserveAttemptCountsUpToTheLimitAndDeletesPastIt(t *testing.T) {
	s, mr := newAttemptStore(t)
	ctx := context.Background()
	saveChallenge(t, s, "c1", &MFALoginChallenge{UserID: "u1", TenantID: "t1", RememberMe: true})

	for want := 1; want <= 3; want++ {
		got, err := s.ReserveAttempt(ctx, "c1", 3)
		if err != nil || got != want {
			t.Fatalf("claim %d: got %d, %v", want, got, err)
		}
	}
	record, err := s.Get(ctx, "c1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if record.Attempts != 3 || record.UserID != "u1" || record.TenantID != "t1" || !record.RememberMe {
		t.Fatalf("the claim must only move the attempt counter, got %+v", record)
	}
	if ttl := mr.TTL("amc:c1"); ttl <= 0 || ttl > time.Minute {
		t.Fatalf("the claim must keep the record's TTL, got %v", ttl)
	}

	if _, err := s.ReserveAttempt(ctx, "c1", 3); !errors.Is(err, ErrMFALoginChallengeExceeded) {
		t.Fatalf("claim past the limit: %v, want ErrMFALoginChallengeExceeded", err)
	}
	if mr.Exists("amc:c1") {
		t.Fatal("a claim past the limit must delete the challenge")
	}
	if _, err := s.ReserveAttempt(ctx, "c1", 3); !errors.Is(err, ErrMFALoginChallengeNotFound) {
		t.Fatalf("claim on a deleted challenge: %v, want ErrMFALoginChallengeNotFound", err)
	}
}

// The counter sits at the same offset in every record version, including the
// one that carries a session profile.
func TestReserveAttemptHandlesEveryRecordVersion(t *testing.T) {
	s, _ := newAttemptStore(t)
	ctx := context.Background()
	saveChallenge(t, s, "plain", &MFALoginChallenge{UserID: "u1", TenantID: "t1"})
	saveChallenge(t, s, "profiled", &MFALoginChallenge{UserID: "u1", TenantID: "t1", Profile: "mobile"})

	for _, id := range []string{"plain", "profiled"} {
		if got, err := s.ReserveAttempt(ctx, id, 5); err != nil || got != 1 {
			t.Fatalf("%s: got %d, %v", id, got, err)
		}
		record, err := s.Get(ctx, id)
		if err != nil || record.Attempts != 1 {
			t.Fatalf("%s: %+v, %v", id, record, err)
		}
	}
	record, _ := s.Get(ctx, "profiled")
	if record.Profile != "mobile" || record.UserID != "u1" {
		t.Fatalf("the profile record was damaged: %+v", record)
	}
}

func TestReserveAttemptReportsMissingAndExpired(t *testing.T) {
	s, mr := newAttemptStore(t)
	ctx := context.Background()

	if _, err := s.ReserveAttempt(ctx, "nope", 3); !errors.Is(err, ErrMFALoginChallengeNotFound) {
		t.Fatalf("missing: %v", err)
	}

	saveChallenge(t, s, "old", &MFALoginChallenge{UserID: "u1", ExpiresAt: time.Now().Add(-time.Minute).Unix()})
	if _, err := s.ReserveAttempt(ctx, "old", 3); !errors.Is(err, ErrMFALoginChallengeExpired) {
		t.Fatalf("expired: %v", err)
	}
	if mr.Exists("amc:old") {
		t.Fatal("an expired challenge must be deleted")
	}
}

func TestReleaseAttemptGivesAClaimBackAndNeverGoesNegative(t *testing.T) {
	s, _ := newAttemptStore(t)
	ctx := context.Background()
	saveChallenge(t, s, "c1", &MFALoginChallenge{UserID: "u1"})

	if err := s.ReleaseAttempt(ctx, "c1"); err != nil {
		t.Fatalf("release on a fresh challenge: %v", err)
	}
	if got, err := s.ReserveAttempt(ctx, "c1", 2); err != nil || got != 1 {
		t.Fatalf("claim after a no-op release: %d, %v", got, err)
	}
	if got, err := s.ReserveAttempt(ctx, "c1", 2); err != nil || got != 2 {
		t.Fatalf("second claim: %d, %v", got, err)
	}
	if err := s.ReleaseAttempt(ctx, "c1"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if got, err := s.ReserveAttempt(ctx, "c1", 2); err != nil || got != 2 {
		t.Fatalf("claim after a release: %d, %v", got, err)
	}
	if err := s.ReleaseAttempt(ctx, "missing"); err != nil {
		t.Fatalf("release on a missing challenge: %v", err)
	}
}

func TestReserveAttemptIsBoundedUnderConcurrency(t *testing.T) {
	s, _ := newAttemptStore(t)
	ctx := context.Background()
	saveChallenge(t, s, "c1", &MFALoginChallenge{UserID: "u1"})

	const callers, limit = 64, 5
	var granted atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := s.ReserveAttempt(ctx, "c1", limit); err == nil {
				granted.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := granted.Load(); got != limit {
		t.Fatalf("%d of %d concurrent claims were granted, want exactly %d", got, callers, limit)
	}
}

// RecordFailure keeps its contract on top of the same script: the failure that
// uses up the budget reports it and removes the challenge.
func TestRecordFailureReportsTheFailureThatUsesUpTheBudget(t *testing.T) {
	s, mr := newAttemptStore(t)
	ctx := context.Background()
	saveChallenge(t, s, "c1", &MFALoginChallenge{UserID: "u1"})

	for i := 1; i <= 2; i++ {
		if exceeded, err := s.RecordFailure(ctx, "c1", 3); err != nil || exceeded {
			t.Fatalf("failure %d: exceeded=%v err=%v", i, exceeded, err)
		}
	}
	if exceeded, err := s.RecordFailure(ctx, "c1", 3); err != nil || !exceeded {
		t.Fatalf("failure 3: exceeded=%v err=%v", exceeded, err)
	}
	if mr.Exists("amc:c1") {
		t.Fatal("the challenge must be deleted once the budget is used up")
	}
	if _, err := s.RecordFailure(ctx, "c1", 3); !errors.Is(err, ErrMFALoginChallengeNotFound) {
		t.Fatalf("failure on a deleted challenge: %v", err)
	}
}
