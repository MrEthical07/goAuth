package flows

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeClock is a clock a test moves by hand; sleeping on it advances it.
type fakeClock struct {
	t      time.Time
	sleeps int
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }
func (c *fakeClock) sleep(_ context.Context, d time.Duration) error {
	c.sleeps++
	c.t = c.t.Add(d)
	return nil
}

const testFloor = 30 * time.Millisecond

func resetDepsFor(clock *fakeClock, lookup func(context.Context, string) (PasswordResetUser, error)) PasswordResetDeps {
	errInvalid := errors.New("invalid")
	return PasswordResetDeps{
		Enabled:             true,
		Strategy:            0,
		ResetTTL:            time.Minute,
		Now:                 clock.now,
		EnumerationFloor:    func() time.Duration { return testFloor },
		SleepFor:            clock.sleep,
		CheckRequestLimiter: func(context.Context, string, string) error { return nil },
		MapLimiterError:     func(err error) error { return err },
		GetUserByIdentifier: func(ctx context.Context, id string) (PasswordResetUser, error) {
			clock.advance(120 * time.Microsecond) // the provider lookup
			return lookup(ctx, id)
		},
		HashPassword: func(string) (string, error) { return "", nil },
		SaveResetRecord: func(context.Context, string, string, PasswordResetStoreRecord, time.Duration) error {
			clock.advance(200 * time.Microsecond) // the Redis write
			return nil
		},
		GenerateChallenge: func(int, int) (string, string, [32]byte, error) { return "id", "challenge", [32]byte{}, nil },
		Errors:            PasswordResetErrors{PasswordResetInvalid: errInvalid},
	}
}

// FAILED-BEFORE (R2-19): the randomized delay ran only on the unknown-identifier
// branch, so a registered identifier answered in a fraction of a millisecond
// and an unknown one after 20-40 ms. Every branch now takes the same floor
// from request entry.
func TestPasswordResetRequestEveryBranchTakesTheSameFloor(t *testing.T) {
	notFound := errors.New("not found")
	for name, lookup := range map[string]func(context.Context, string) (PasswordResetUser, error){
		"registered": func(context.Context, string) (PasswordResetUser, error) {
			return PasswordResetUser{UserID: "u1"}, nil
		},
		"unknown": func(context.Context, string) (PasswordResetUser, error) {
			return PasswordResetUser{}, notFound
		},
	} {
		clock := newFakeClock()
		start := clock.now()
		challenge, err := RunRequestPasswordReset(context.Background(), "alice", resetDepsFor(clock, lookup))
		if err != nil || challenge != "challenge" {
			t.Fatalf("%s: %q, %v", name, challenge, err)
		}
		if elapsed := clock.now().Sub(start); elapsed != testFloor {
			t.Fatalf("%s: the request took %v, want exactly the floor %v", name, elapsed, testFloor)
		}
	}
}

// Work that is already slower than the floor is not padded further.
func TestEnumerationFloorDoesNotPadSlowWork(t *testing.T) {
	clock := newFakeClock()
	deps := resetDepsFor(clock, func(context.Context, string) (PasswordResetUser, error) {
		clock.advance(testFloor * 2)
		return PasswordResetUser{UserID: "u1"}, nil
	})
	start := clock.now()
	if _, err := RunRequestPasswordReset(context.Background(), "alice", deps); err != nil {
		t.Fatal(err)
	}
	if clock.sleeps != 0 {
		t.Fatalf("slept %d times on a request that already took longer than the floor", clock.sleeps)
	}
	if elapsed := clock.now().Sub(start); elapsed < testFloor*2 {
		t.Fatalf("elapsed %v", elapsed)
	}
}

func TestEnumerationFloorEndsWithTheContext(t *testing.T) {
	clock := newFakeClock()
	deps := resetDepsFor(clock, func(context.Context, string) (PasswordResetUser, error) {
		return PasswordResetUser{}, errors.New("not found")
	})
	deps.SleepFor = func(ctx context.Context, d time.Duration) error { return context.Canceled }
	if _, err := RunRequestPasswordReset(context.Background(), "alice", deps); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

func verificationDepsFor(clock *fakeClock, user EmailVerificationUser, lookupErr error) EmailVerificationDeps {
	return EmailVerificationDeps{
		Enabled:             true,
		ActiveStatus:        0,
		VerificationTTL:     time.Minute,
		Now:                 clock.now,
		EnumerationFloor:    func() time.Duration { return testFloor },
		SleepFor:            clock.sleep,
		CheckRequestLimiter: func(context.Context, string, string) error { return nil },
		MapLimiterError:     func(err error) error { return err },
		AccountStatusError: func(status uint8) error {
			if status == 2 {
				return errors.New("disabled")
			}
			return nil
		},
		GetUserByIdentifier: func(context.Context, string) (EmailVerificationUser, error) {
			clock.advance(120 * time.Microsecond)
			return user, lookupErr
		},
		SaveVerificationRecord: func(context.Context, string, string, EmailVerificationStoreRecord, time.Duration) error {
			clock.advance(200 * time.Microsecond)
			return nil
		},
		GenerateChallenge: func(int, int, string) (string, string, [32]byte, error) {
			return "id", "challenge", [32]byte{}, nil
		},
	}
}

// FAILED-BEFORE (R2-19): the same for email verification, where an already
// verified account was faster still than a pending one.
func TestEmailVerificationRequestEveryBranchTakesTheSameFloor(t *testing.T) {
	for name, tc := range map[string]struct {
		user      EmailVerificationUser
		lookupErr error
	}{
		"pending":        {user: EmailVerificationUser{UserID: "u1", Status: 1}},
		"already active": {user: EmailVerificationUser{UserID: "u1", Status: 0}},
		"not verifiable": {user: EmailVerificationUser{UserID: "u1", Status: 2}},
		"unknown":        {lookupErr: errors.New("not found")},
	} {
		clock := newFakeClock()
		start := clock.now()
		challenge, err := RunRequestEmailVerification(context.Background(), "alice", verificationDepsFor(clock, tc.user, tc.lookupErr))
		if err != nil || challenge != "challenge" {
			t.Fatalf("%s: %q, %v", name, challenge, err)
		}
		if elapsed := clock.now().Sub(start); elapsed != testFloor {
			t.Fatalf("%s: the request took %v, want exactly the floor %v", name, elapsed, testFloor)
		}
	}
}
