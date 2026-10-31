package test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	goAuth "github.com/MrEthical07/goAuth"
	"github.com/MrEthical07/goAuth/password"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// This file is the acceptance test for Builder.WithClock, written against the
// public API only, the way an application's own test suite would use it: an
// engine on a manual clock plus miniredis, walked through months of session
// life in milliseconds.

const (
	clockDay      = 24 * time.Hour
	clockUser     = "alice@example.com"
	clockPassword = "correct-horse-battery"
)

// manualClock is a goAuth.Clock the test moves by hand.
type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// clockRig is an engine built WithClock over miniredis.
type clockRig struct {
	t      *testing.T
	engine *goAuth.Engine
	clk    *manualClock
	mr     *miniredis.Miniredis
}

// advance moves the engine's clock and Redis by the same amount: the clock
// does not move Redis, and key lifetimes are Redis's own time.
func (r *clockRig) advance(d time.Duration) {
	r.clk.advance(d)
	r.mr.SetTime(r.clk.Now())
	r.mr.FastForward(d)
}

func (r *clockRig) loginAs(profile string) (access, refresh string) {
	r.t.Helper()
	ctx := goAuth.WithSessionProfile(context.Background(), profile)
	access, refresh, err := r.engine.Login(ctx, clockUser, clockPassword)
	if err != nil {
		r.t.Fatalf("Login as %s: %v", profile, err)
	}
	return access, refresh
}

func newClockRig(t *testing.T, start time.Time) *clockRig {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	mr.SetTime(start)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close(); mr.Close() })

	cfg := goAuth.DefaultConfig()
	cfg.Password.Memory = 8 * 1024
	cfg.Password.Time = 1
	cfg.Password.Parallelism = 1
	cfg.Security.ProductionMode = false
	cfg.Session.JitterEnabled = false
	cfg.ValidationMode = goAuth.ModeStrict
	cfg.JWT.AccessTTL = time.Hour
	cfg.SessionProfiles.Profiles = map[string]goAuth.SessionProfile{
		"web": {AbsoluteLifetime: 15 * clockDay},
		"mobile": {
			IdleTimeout:      90 * clockDay,
			AbsoluteLifetime: 365 * clockDay,
			RenewOnUse:       true,
		},
	}
	cfg.SessionProfiles.DefaultProfile = "web"

	hasher, err := password.NewArgon2(password.Config{
		Memory: cfg.Password.Memory, Time: cfg.Password.Time, Parallelism: cfg.Password.Parallelism,
		SaltLength: cfg.Password.SaltLength, KeyLength: cfg.Password.KeyLength,
	})
	if err != nil {
		t.Fatalf("argon2: %v", err)
	}
	hash, err := hasher.Hash(clockPassword)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	provider := newClockProvider()
	provider.put(goAuth.UserRecord{
		UserID: "user-1", Identifier: clockUser, PasswordHash: hash, Role: "member",
		Status: goAuth.AccountActive, PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
	})

	clk := &manualClock{now: start}
	engine, err := goAuth.New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"user.read"}).
		WithRoles(map[string][]string{"member": {"user.read"}}).
		WithUserProvider(provider).
		WithClock(clk).
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(engine.Close)
	return &clockRig{t: t, engine: engine, clk: clk, mr: mr}
}

// The mobile profile (90-day idle window, 365-day ceiling, renew on use),
// refreshed every 60 days: the refresh at day 360 succeeds and the session ends
// at day 365, with refresh and strict validation both refusing it.
func TestWithClockMobileSessionReachesItsCeiling(t *testing.T) {
	rig := newClockRig(t, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	ctx := context.Background()
	_, refresh := rig.loginAs("mobile")

	for day := 60; day <= 360; day += 60 {
		rig.advance(60 * clockDay)
		var err error
		if _, refresh, err = rig.engine.Refresh(ctx, refresh); err != nil {
			t.Fatalf("refresh at day %d: %v", day, err)
		}
	}

	// Ten minutes before the ceiling the session is alive; a refresh there
	// hands out an access token that outlives the ceiling.
	rig.advance(4*clockDay + 23*time.Hour + 50*time.Minute)
	access, refreshLast, err := rig.engine.Refresh(ctx, refresh)
	if err != nil {
		t.Fatalf("refresh just before the ceiling: %v", err)
	}
	if _, err := rig.engine.Validate(ctx, access, goAuth.ModeStrict); err != nil {
		t.Fatalf("strict validation just before the ceiling: %v", err)
	}

	// Twenty minutes later it is day 365 and ten minutes. The access token has
	// forty minutes left, so only the session can refuse it.
	rig.advance(20 * time.Minute)
	if _, err := rig.engine.Validate(ctx, access, goAuth.ModeStrict); err == nil {
		t.Fatal("strict validation accepted a session past its 365-day ceiling")
	}
	if _, _, err := rig.engine.Refresh(ctx, refreshLast); !errors.Is(err, goAuth.ErrSessionNotFound) {
		t.Fatalf("refresh past the ceiling = %v, want ErrSessionNotFound", err)
	}
}

// No refresh for 91 days ends a mobile session by idle.
func TestWithClockMobileSessionEndsByIdle(t *testing.T) {
	rig := newClockRig(t, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	ctx := context.Background()
	_, refresh := rig.loginAs("mobile")

	rig.advance(91 * clockDay)
	if _, _, err := rig.engine.Refresh(ctx, refresh); !errors.Is(err, goAuth.ErrSessionNotFound) {
		t.Fatalf("refresh after 91 idle days = %v, want ErrSessionNotFound", err)
	}
	if infos, err := rig.engine.ListActiveSessions(ctx, "user-1"); err != nil || len(infos) != 0 {
		t.Fatalf("active sessions = %d (%v), want 0", len(infos), err)
	}
}

// A session refreshed inside its idle window keeps going: the same 91 days,
// split in two, do not end it.
func TestWithClockRefreshRestartsTheIdleWindow(t *testing.T) {
	rig := newClockRig(t, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	ctx := context.Background()
	_, refresh := rig.loginAs("mobile")

	rig.advance(60 * clockDay)
	_, refresh, err := rig.engine.Refresh(ctx, refresh)
	if err != nil {
		t.Fatalf("refresh at day 60: %v", err)
	}
	rig.advance(31 * clockDay)
	if _, _, err := rig.engine.Refresh(ctx, refresh); err != nil {
		t.Fatalf("refresh at day 91 after a refresh at day 60: %v", err)
	}
}

// ---------------------------------------------------------------------------
// In-memory user provider
// ---------------------------------------------------------------------------

type clockProvider struct {
	mu      sync.RWMutex
	byID    map[string]goAuth.UserRecord
	byIdent map[string]string
}

func newClockProvider() *clockProvider {
	return &clockProvider{byID: map[string]goAuth.UserRecord{}, byIdent: map[string]string{}}
}

func (p *clockProvider) put(u goAuth.UserRecord) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.byID[u.UserID] = u
	p.byIdent[u.Identifier] = u.UserID
}

var errClockNotFound = errors.New("user not found")

func (p *clockProvider) GetUserByIdentifier(identifier string) (goAuth.UserRecord, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	id, ok := p.byIdent[identifier]
	if !ok {
		return goAuth.UserRecord{}, errClockNotFound
	}
	return p.byID[id], nil
}

func (p *clockProvider) GetUserByID(userID string) (goAuth.UserRecord, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	u, ok := p.byID[userID]
	if !ok {
		return goAuth.UserRecord{}, errClockNotFound
	}
	return u, nil
}

func (p *clockProvider) UpdatePasswordHash(userID, newHash string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	u, ok := p.byID[userID]
	if !ok {
		return errClockNotFound
	}
	u.PasswordHash = newHash
	p.byID[userID] = u
	return nil
}

func (p *clockProvider) CreateUser(context.Context, goAuth.CreateUserInput) (goAuth.UserRecord, error) {
	return goAuth.UserRecord{}, errors.New("not used")
}

func (p *clockProvider) UpdateAccountStatus(_ context.Context, userID string, status goAuth.AccountStatus) (goAuth.UserRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	u, ok := p.byID[userID]
	if !ok {
		return goAuth.UserRecord{}, errClockNotFound
	}
	u.Status = status
	p.byID[userID] = u
	return u, nil
}

func (p *clockProvider) GetTOTPSecret(context.Context, string) (*goAuth.TOTPRecord, error) {
	return nil, errors.New("totp not configured")
}
func (p *clockProvider) EnableTOTP(context.Context, string, []byte) error { return nil }
func (p *clockProvider) DisableTOTP(context.Context, string) error        { return nil }
func (p *clockProvider) MarkTOTPVerified(context.Context, string) error   { return nil }
func (p *clockProvider) UpdateTOTPLastUsedCounter(context.Context, string, int64) error {
	return nil
}
func (p *clockProvider) GetBackupCodes(context.Context, string) ([]goAuth.BackupCodeRecord, error) {
	return nil, nil
}
func (p *clockProvider) ReplaceBackupCodes(context.Context, string, []goAuth.BackupCodeRecord) error {
	return nil
}
func (p *clockProvider) ConsumeBackupCode(context.Context, string, [32]byte) (bool, error) {
	return false, nil
}
