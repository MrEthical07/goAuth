package goAuth

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/redis/go-redis/v9"
)

// Regression tests for R2-13 of the v0.8.0 security audit (run 2): confirming
// an email address re-enabled an account that was blocked after the
// verification had read it.

func pendingUserProvider() *mockUserProvider {
	return &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {UserID: "u1", Identifier: "alice", TenantID: "0", Status: AccountPendingVerification, AccountVersion: 1},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}
}

func statusOf(up *mockUserProvider) AccountStatus {
	up.mu.Lock()
	defer up.mu.Unlock()
	return up.users["u1"].Status
}

func blockAccount(up *mockUserProvider, status AccountStatus) {
	up.mu.Lock()
	defer up.mu.Unlock()
	user := up.users["u1"]
	user.Status = status
	user.AccountVersion++
	up.users["u1"] = user
}

// blockingReadProvider hands back the account as it was, and blocks it right
// after: the moment between the verification reading the account and writing
// its status.
type blockingReadProvider struct {
	*mockUserProvider
	armed atomic.Bool
}

func (p *blockingReadProvider) snapshotThenBlock(read func() (UserRecord, error)) (UserRecord, error) {
	user, err := read()
	if err == nil && p.armed.CompareAndSwap(true, false) {
		blockAccount(p.mockUserProvider, AccountDisabled)
	}
	return user, err
}

func (p *blockingReadProvider) GetUserByID(userID string) (UserRecord, error) {
	return p.snapshotThenBlock(func() (UserRecord, error) { return p.mockUserProvider.GetUserByID(userID) })
}

func (p *blockingReadProvider) GetUserByIDInTenant(ctx context.Context, tenantID, userID string) (UserRecord, error) {
	return p.snapshotThenBlock(func() (UserRecord, error) {
		return p.mockUserProvider.GetUserByIDInTenant(ctx, tenantID, userID)
	})
}

// casStatusProvider adds the optional compare-and-set capability.
type casStatusProvider struct {
	*blockingReadProvider
	calls   atomic.Int64
	applied atomic.Int64
}

func (p *casStatusProvider) UpdateAccountStatusIf(_ context.Context, _, userID string, expected, next AccountStatus) (bool, error) {
	p.calls.Add(1)
	p.mu.Lock()
	defer p.mu.Unlock()
	user := p.users[userID]
	if user.Status != expected {
		return false, nil
	}
	user.Status = next
	user.AccountVersion++
	p.users[userID] = user
	p.applied.Add(1)
	return true, nil
}

// newVerificationEngine is the hand-built test engine with the provider
// capability detection Build performs.
func newVerificationEngine(t *testing.T, rdb *redis.Client, up UserProvider, cfg EmailVerificationConfig) *Engine {
	t.Helper()
	engine := newTestEmailVerificationEngine(t, rdb, up, cfg)
	if cas, ok := up.(AccountStatusCASUpdater); ok {
		engine.statusCAS = cas
	}
	return engine
}

// Build detects the capability on its own.
func TestBuildDetectsTheAccountStatusCASCapability(t *testing.T) {
	cfg := verificationLoginConfig(ModeStrict)
	base := newHardeningUserProvider(t)
	up := &casStatusProvider{blockingReadProvider: &blockingReadProvider{mockUserProvider: base}}
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	if engine.statusCAS == nil {
		t.Fatal("Build did not pick up AccountStatusCASUpdater")
	}

	plain, _, done2 := newCreateAccountEngine(t, cfg, newHardeningUserProvider(t))
	defer done2()
	if plain.statusCAS != nil {
		t.Fatal("a provider without the capability got one")
	}
}

func requestVerification(t *testing.T, engine *Engine) string {
	t.Helper()
	challenge, err := engine.RequestEmailVerification(context.Background(), "alice")
	if err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	return challenge
}

// FAILED-BEFORE (R2-13): without compare-and-set, the account is read again
// right before the write and only a pending one is activated.
func TestVerificationDoesNotReenableAnAccountBlockedMeanwhile(t *testing.T) {
	for _, strategy := range []VerificationStrategyType{VerificationToken, VerificationUUID} {
		_, rdb := newTestRedis(t)
		base := pendingUserProvider()
		up := &blockingReadProvider{mockUserProvider: base}
		engine := newVerificationEngine(t, rdb, up, testEmailVerificationConfig(strategy))

		challenge := requestVerification(t, engine)
		// Arm only now, so the request's own reads do not trigger it. The
		// confirm reads the account (and gets the pending copy), then the
		// account is disabled before the write.
		up.armed.Store(true)
		err := engine.ConfirmEmailVerification(context.Background(), challenge)
		if !errors.Is(err, ErrAccountDisabled) {
			t.Fatalf("strategy %v: confirm: %v, want ErrAccountDisabled", strategy, err)
		}
		if got := statusOf(base); got != AccountDisabled {
			t.Fatalf("strategy %v: the account is %v, want it to stay disabled", strategy, got)
		}
	}
}

// FAILED-BEFORE (R2-13): with compare-and-set the write is exact, however late
// the status changed.
func TestVerificationUsesCompareAndSetWhenTheProviderOffersIt(t *testing.T) {
	_, rdb := newTestRedis(t)
	base := pendingUserProvider()
	up := &casStatusProvider{blockingReadProvider: &blockingReadProvider{mockUserProvider: base}}
	engine := newVerificationEngine(t, rdb, up, testEmailVerificationConfig(VerificationToken))

	challenge := requestVerification(t, engine)
	up.armed.Store(true)
	err := engine.ConfirmEmailVerification(context.Background(), challenge)
	if !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("confirm: %v, want ErrAccountDisabled", err)
	}
	if up.calls.Load() != 1 || up.applied.Load() != 0 {
		t.Fatalf("compare-and-set calls=%d applied=%d, want one call that did not apply", up.calls.Load(), up.applied.Load())
	}
	if got := statusOf(base); got != AccountDisabled {
		t.Fatalf("the account is %v, want it to stay disabled", got)
	}
}

// Controls: the ordinary transition still happens, with and without the
// capability, and it still ends the user's sessions.
func TestVerificationStillActivatesAPendingAccount(t *testing.T) {
	for _, withCAS := range []bool{false, true} {
		_, rdb := newTestRedis(t)
		base := pendingUserProvider()
		inner := &blockingReadProvider{mockUserProvider: base}
		var up UserProvider = inner
		var cas *casStatusProvider
		if withCAS {
			cas = &casStatusProvider{blockingReadProvider: inner}
			up = cas
		}
		engine := newVerificationEngine(t, rdb, up, testEmailVerificationConfig(VerificationToken))

		challenge := requestVerification(t, engine)
		if err := engine.ConfirmEmailVerification(context.Background(), challenge); err != nil {
			t.Fatalf("withCAS=%v: confirm: %v", withCAS, err)
		}
		if got := statusOf(base); got != AccountActive {
			t.Fatalf("withCAS=%v: status %v, want active", withCAS, got)
		}
		if withCAS && cas.applied.Load() != 1 {
			t.Fatalf("the compare-and-set did not apply: %d", cas.applied.Load())
		}
		if user := base.users["u1"]; user.AccountVersion != 2 {
			t.Fatalf("withCAS=%v: account version %d, want 2", withCAS, user.AccountVersion)
		}
	}
}

func TestVerificationOfAnAlreadyActiveAccountIsANoOp(t *testing.T) {
	_, rdb := newTestRedis(t)
	base := pendingUserProvider()
	up := &casStatusProvider{blockingReadProvider: &blockingReadProvider{mockUserProvider: base}}
	engine := newVerificationEngine(t, rdb, up, testEmailVerificationConfig(VerificationToken))

	challenge := requestVerification(t, engine)
	base.mu.Lock()
	user := base.users["u1"]
	user.Status = AccountActive
	base.users["u1"] = user
	base.mu.Unlock()

	if err := engine.ConfirmEmailVerification(context.Background(), challenge); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if up.calls.Load() != 0 {
		t.Fatalf("an active account was written to: %d calls", up.calls.Load())
	}
}
