package stores

import (
	"context"
	"testing"
	"time"
)

func TestChallengeEpochRoundTripsAndGoesWithTheChallenge(t *testing.T) {
	s, mr := newAttemptStore(t)
	ctx := context.Background()

	if _, ok, err := s.Epoch(ctx, "c1"); err != nil || ok {
		t.Fatalf("a challenge without an epoch: ok=%v err=%v", ok, err)
	}
	saveChallenge(t, s, "c1", &MFALoginChallenge{UserID: "u1", TenantID: "0"})
	if err := s.SaveEpoch(ctx, "c1", 7, time.Minute); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := s.Epoch(ctx, "c1"); err != nil || !ok || got != 7 {
		t.Fatalf("epoch = %d ok=%v err=%v, want 7", got, ok, err)
	}
	if ttl := mr.TTL("amc:c1:ep"); ttl <= 0 || ttl > time.Minute {
		t.Fatalf("epoch TTL = %v, want within the challenge's", ttl)
	}
	// The challenge's own record is untouched by the companion.
	if rec, err := s.Get(ctx, "c1"); err != nil || rec.UserID != "u1" {
		t.Fatalf("challenge: %+v, %v", rec, err)
	}
	if deleted, err := s.Delete(ctx, "c1"); err != nil || !deleted {
		t.Fatalf("delete: %v %v", deleted, err)
	}
	if mr.Exists("amc:c1:ep") {
		t.Fatal("the epoch outlived its challenge")
	}
}
