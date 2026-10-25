package goAuth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Regression tests for the limiter findings of the v0.8.0 security audit
// (run 2). Each one is labelled FAILED-BEFORE with the finding ID: it fails on
// the commit the audit was run against and passes with the fix.

// gatedProvider wraps the shared test provider for the burst tests. Lookups can
// be parked on a gate so a test controls when verification may start, folding
// makes the lookup case-insensitive (the provider shape the audit assumed for
// the spelling findings), and the counters are safe under -race.
type gatedProvider struct {
	*mockUserProvider
	fold    bool
	gate    chan struct{}
	lookups atomic.Int64
}

func newGatedProvider(t *testing.T, fold bool) *gatedProvider {
	t.Helper()
	return &gatedProvider{mockUserProvider: newHardeningUserProvider(t), fold: fold}
}

func (p *gatedProvider) GetUserByIdentifier(identifier string) (UserRecord, error) {
	p.lookups.Add(1)
	if p.gate != nil {
		<-p.gate
	}
	key := identifier
	if p.fold {
		key = strings.ToLower(identifier)
	}
	id, ok := p.byIdentifier[key]
	if !ok {
		return UserRecord{}, errors.New("not found")
	}
	return p.users[id], nil
}

// burst runs n calls released together and returns their errors in call order.
// While gate is non-nil the calls that reach the provider stay parked until
// every call that is going to be refused up front has returned (or the
// deadline passes, which is what happens when nothing refuses them).
func burst(t *testing.T, n, wantRefused int, gate chan struct{}, call func(i int) error) []error {
	t.Helper()
	type result struct {
		i   int
		err error
	}
	out := make(chan result, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func(i int) {
			<-start
			out <- result{i, call(i)}
		}(i)
	}
	close(start)

	errs := make([]error, n)
	got := 0
	deadline := time.After(3 * time.Second)
collect:
	for got < wantRefused {
		select {
		case r := <-out:
			errs[r.i] = r.err
			got++
		case <-deadline:
			break collect
		}
	}
	if gate != nil {
		close(gate)
	}
	for ; got < n; got++ {
		r := <-out
		errs[r.i] = r.err
	}
	return errs
}

func countErrs(errs []error, targets ...error) (matched int) {
	for _, err := range errs {
		for _, target := range targets {
			if errors.Is(err, target) {
				matched++
				break
			}
		}
	}
	return matched
}

// FAILED-BEFORE (R2-05): the login gate read the failure counter, verified the
// password and only then recorded the failure, so every request in a burst saw
// a count below the limit and ran Argon2.
func TestLoginConcurrentBurstBoundedByMaxLoginAttempts(t *testing.T) {
	cfg := accountTestConfig()
	up := newGatedProvider(t, false)
	up.gate = make(chan struct{})
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	const n = 40
	max := cfg.Security.MaxLoginAttempts
	errs := burst(t, n, n-max, up.gate, func(i int) error {
		_, _, err := engine.Login(context.Background(), "alice", fmt.Sprintf("wrong-password-%d", i))
		return err
	})

	if got := up.lookups.Load(); got != int64(max) {
		t.Fatalf("%d of %d concurrent logins reached verification, want exactly MaxLoginAttempts (%d)", got, n, max)
	}
	if got := countErrs(errs, ErrInvalidCredentials); got != max {
		t.Fatalf("%d logins were verified and rejected, want %d (errors: %v)", got, max, errs)
	}
	if got := countErrs(errs, ErrLoginRateLimited); got != n-max {
		t.Fatalf("%d logins were rate limited, want %d", got, n-max)
	}
}

// The sequential behavior is unchanged: the sixth attempt is the first one
// refused, and the password is not verified for it.
func TestLoginSequentialAttemptsRefusedAtTheSameNumber(t *testing.T) {
	cfg := accountTestConfig()
	up := newGatedProvider(t, false)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()
	for i := 1; i <= cfg.Security.MaxLoginAttempts; i++ {
		if _, _, err := engine.Login(ctx, "alice", "wrong-password-123"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v, want ErrInvalidCredentials", i, err)
		}
	}
	if _, _, err := engine.Login(ctx, "alice", "wrong-password-123"); !errors.Is(err, ErrLoginRateLimited) {
		t.Fatalf("attempt %d: %v, want ErrLoginRateLimited", cfg.Security.MaxLoginAttempts+1, err)
	}
	if got := up.lookups.Load(); got != int64(cfg.Security.MaxLoginAttempts) {
		t.Fatalf("the refused attempt reached verification: %d lookups", got)
	}
}

// A correct password is bounded by the same budget: a guess hidden in the
// sixth position is not evaluated.
func TestLoginCorrectPasswordAfterTheBudgetIsRefused(t *testing.T) {
	cfg := accountTestConfig()
	up := newGatedProvider(t, false)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()
	for i := 0; i < cfg.Security.MaxLoginAttempts; i++ {
		_, _, _ = engine.Login(ctx, "alice", "wrong-password-123")
	}
	if _, _, err := engine.Login(ctx, "alice", "correct-password-123"); !errors.Is(err, ErrLoginRateLimited) {
		t.Fatalf("a correct password past the budget got %v, want ErrLoginRateLimited", err)
	}
}

// A good login clears the budget it claimed.
func TestLoginSuccessResetsTheClaim(t *testing.T) {
	cfg := accountTestConfig()
	up := newGatedProvider(t, false)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := context.Background()
	for round := 0; round < 3; round++ {
		for i := 0; i < cfg.Security.MaxLoginAttempts-1; i++ {
			_, _, _ = engine.Login(ctx, "alice", "wrong-password-123")
		}
		if _, _, err := engine.Login(ctx, "alice", "correct-password-123"); err != nil {
			t.Fatalf("round %d: login failed: %v", round, err)
		}
	}
	if attempts, err := engine.GetLoginAttempts(ctx, "alice"); err != nil || attempts != 0 {
		t.Fatalf("GetLoginAttempts = %d, %v; a good login must leave nothing behind", attempts, err)
	}
}
