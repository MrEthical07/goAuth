package goAuth

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/MrEthical07/goAuth/password"
)

// Regression tests for R2-07 of the v0.8.0 security audit (run 2): the
// rehash-on-login upgrade overwrote a password that changed after the login
// read the account.

const (
	rehashOldPassword = "correct-password-123"
	rehashNewPassword = "another-password-456"
)

// weakHashOf hashes pw with parameters the engine's own hasher considers
// outdated, so a login with it triggers the upgrade.
func weakHashOf(t *testing.T, pw string) string {
	t.Helper()
	h, err := password.NewArgon2(password.Config{
		Memory:      32768,
		Time:        2,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := h.Hash(pw)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func rehashConfig() Config {
	cfg := accountTestConfig()
	cfg.Password.UpgradeOnLogin = true
	return cfg
}

func newRehashProvider(t *testing.T) *mockUserProvider {
	up := newHardeningUserProvider(t)
	changeUser(up, func(u *UserRecord) { u.PasswordHash = weakHashOf(t, rehashOldPassword) })
	return up
}

func storedHash(up *mockUserProvider) string {
	up.mu.Lock()
	defer up.mu.Unlock()
	return up.users["u1"].PasswordHash
}

// requirePasswordIs fails unless pw verifies against the stored hash and other
// does not.
func requirePasswordIs(t *testing.T, engine *Engine, up *mockUserProvider, pw, other string) {
	t.Helper()
	hash := storedHash(up)
	if ok, err := engine.verifyHash(pw, hash); err != nil || !ok {
		t.Fatalf("the stored hash does not verify the password that should be in force (err=%v)", err)
	}
	if ok, _ := engine.verifyHash(other, hash); ok {
		t.Fatal("the stored hash verifies the password that was replaced")
	}
}

// rehashProvider can stage a concurrent change at the moment the engine writes
// or re-reads.
type rehashProvider struct {
	*mockUserProvider
	beforeWrite func()
	readArmed   atomic.Bool
	onArmedRead func()
}

func (p *rehashProvider) UpdatePasswordHash(userID, newHash string) error {
	if p.beforeWrite != nil {
		p.beforeWrite()
	}
	return p.mockUserProvider.UpdatePasswordHash(userID, newHash)
}

func (p *rehashProvider) GetUserByID(userID string) (UserRecord, error) {
	if p.readArmed.CompareAndSwap(true, false) && p.onArmedRead != nil {
		p.onArmedRead()
	}
	return p.mockUserProvider.GetUserByID(userID)
}

func (p *rehashProvider) GetUserByIDInTenant(ctx context.Context, tenantID, userID string) (UserRecord, error) {
	if p.readArmed.CompareAndSwap(true, false) && p.onArmedRead != nil {
		p.onArmedRead()
	}
	return p.mockUserProvider.GetUserByIDInTenant(ctx, tenantID, userID)
}

// casRehashProvider adds the optional compare-and-swap capability.
type casRehashProvider struct {
	*rehashProvider
	casCalls atomic.Int64
	applied  atomic.Int64
}

func (p *casRehashProvider) CompareAndSwapPasswordHash(_ context.Context, _, userID, expectedOld, next string) (bool, error) {
	p.casCalls.Add(1)
	if p.beforeWrite != nil {
		p.beforeWrite()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	user := p.users[userID]
	if user.PasswordHash != expectedOld {
		return false, nil
	}
	user.PasswordHash = next
	p.users[userID] = user
	p.applied.Add(1)
	return true, nil
}

func setPasswordTo(t *testing.T, up *mockUserProvider, pw string) {
	changeUser(up, func(u *UserRecord) { u.PasswordHash = weakHashOf(t, pw) })
}

// Control: an ordinary login still upgrades the hash.
func TestRehashUpgradeStillHappensOnAnOrdinaryLogin(t *testing.T) {
	cfg := rehashConfig()
	up := newRehashProvider(t)
	before := storedHash(up)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	if _, _, err := engine.Login(context.Background(), "alice", rehashOldPassword); err != nil {
		t.Fatal(err)
	}
	if storedHash(up) == before {
		t.Fatal("the hash was not upgraded")
	}
	requirePasswordIs(t, engine, up, rehashOldPassword, rehashNewPassword)
}

// FAILED-BEFORE (R2-07): a password change that landed while the login was
// verifying was overwritten by the upgrade, which re-hashed the OLD password
// over the new hash.
func TestRehashUpgradeDoesNotOverwriteAPasswordChangedDuringLogin(t *testing.T) {
	cfg := rehashConfig()
	up := newRehashProvider(t)
	engine, _ := newAuditEngine(t, cfg, up)
	p := installLoginParker(engine, up.users["u1"].PasswordHash)

	outcome := parkedLogin(t, engine, p, rehashOldPassword)
	// The change is a plain provider write so it does not depend on the
	// engine's own revocation; whatever the login decides, the new password
	// must be the one in force.
	setPasswordTo(t, up, rehashNewPassword)
	p.release()
	<-outcome

	requirePasswordIs(t, engine, up, rehashNewPassword, rehashOldPassword)
}

// FAILED-BEFORE (R2-07): with a provider that offers compare-and-swap the
// upgrade is exact, however late the change lands.
func TestRehashUpgradeUsesCompareAndSwapWhenTheProviderOffersIt(t *testing.T) {
	cfg := rehashConfig()
	base := &rehashProvider{mockUserProvider: newRehashProvider(t)}
	up := &casRehashProvider{rehashProvider: base}
	base.beforeWrite = func() { setPasswordTo(t, base.mockUserProvider, rehashNewPassword) }
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	if _, _, err := engine.Login(context.Background(), "alice", rehashOldPassword); err != nil {
		t.Fatalf("login: %v", err)
	}
	if up.casCalls.Load() != 1 || up.applied.Load() != 0 {
		t.Fatalf("compare-and-swap calls=%d applied=%d, want 1 call that did not apply", up.casCalls.Load(), up.applied.Load())
	}
	requirePasswordIs(t, engine, base.mockUserProvider, rehashNewPassword, rehashOldPassword)
}

func TestRehashUpgradeAppliesThroughCompareAndSwap(t *testing.T) {
	cfg := rehashConfig()
	base := &rehashProvider{mockUserProvider: newRehashProvider(t)}
	before := storedHash(base.mockUserProvider)
	up := &casRehashProvider{rehashProvider: base}
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	if _, _, err := engine.Login(context.Background(), "alice", rehashOldPassword); err != nil {
		t.Fatal(err)
	}
	if up.applied.Load() != 1 || storedHash(base.mockUserProvider) == before {
		t.Fatalf("the upgrade was not applied (applied=%d)", up.applied.Load())
	}
	requirePasswordIs(t, engine, base.mockUserProvider, rehashOldPassword, rehashNewPassword)
}

// FAILED-BEFORE (R2-07): without compare-and-swap the account is re-read right
// before the write and the upgrade is skipped if the hash is no longer the
// verified one.
func TestRehashUpgradeRereadsTheUserWithoutCompareAndSwap(t *testing.T) {
	cfg := rehashConfig()
	up := &rehashProvider{mockUserProvider: newRehashProvider(t)}
	up.onArmedRead = func() { setPasswordTo(t, up.mockUserProvider, rehashNewPassword) }
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	// Arm the change for the first by-ID read after the password was verified.
	real := engine.verifyHashFn
	engine.verifyHashFn = func(pw, encoded string) (bool, error) {
		var ok bool
		var err error
		if real != nil {
			ok, err = real(pw, encoded)
		} else {
			ok, err = engine.passwordHash.Verify(pw, encoded)
		}
		if ok {
			up.readArmed.Store(true)
		}
		return ok, err
	}

	if _, _, err := engine.Login(context.Background(), "alice", rehashOldPassword); err != nil {
		t.Fatalf("login: %v", err)
	}
	requirePasswordIs(t, engine, up.mockUserProvider, rehashNewPassword, rehashOldPassword)
}

// FAILED-BEFORE (R2-07): the upgrade ran before the login was known to
// succeed, so a login refused afterwards (here by the session cap) had already
// rewritten the hash.
func TestRehashUpgradeWaitsForTheLoginToSucceed(t *testing.T) {
	cfg := rehashConfig()
	cfg.SessionHardening.MaxSessionsPerUser = 1
	up := newRehashProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := context.Background()

	if _, _, err := engine.Login(ctx, "alice", rehashOldPassword); err != nil {
		t.Fatal(err)
	}
	// The first login upgraded the hash; make it outdated again.
	setPasswordTo(t, up, rehashOldPassword)
	before := storedHash(up)

	if _, _, err := engine.Login(ctx, "alice", rehashOldPassword); !errors.Is(err, ErrSessionLimitExceeded) {
		t.Fatalf("second login: %v, want ErrSessionLimitExceeded", err)
	}
	if storedHash(up) != before {
		t.Fatal("a refused login upgraded the hash")
	}
}
