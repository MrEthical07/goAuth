// Package main demonstrates goAuth session profiles: one engine serving a web
// client whose sessions last a fixed 15 days from login, and a mobile client
// whose sessions stay alive for 90 days of inactivity (every successful
// refresh restarts that window) up to a 365-day ceiling.
//
// It runs a short scripted walkthrough against miniredis (no external Redis
// needed) and an in-memory user provider stub:
//
//	go run ./examples/session-profiles
//
// The walkthrough logs a user in as "web" and as "mobile", lists the sessions
// with their expiry fields, refreshes the mobile session to show its idle
// window move, and shows that an unknown profile is refused before any work.
//
// The profile is always chosen by the server (here, from which client
// application's endpoint the request arrived on), never from a header or body
// field the client controls: see profileFor.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	goAuth "github.com/MrEthical07/goAuth"
	"github.com/MrEthical07/goAuth/password"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

const (
	userEmail    = "alice@example.com"
	userPassword = "correct-horse"
)

// client identifies which of your applications a request came from. In a real
// service this is decided by the route or the authenticated API client, not by
// anything the end user can set.
type client int

const (
	webApp client = iota
	mobileApp
)

// profileFor maps a trusted server-side signal to a session profile name.
func profileFor(c client) string {
	if c == mobileApp {
		return "mobile"
	}
	return "web"
}

func main() {
	if err := run(os.Stdout); err != nil {
		// The error is not printed: it can wrap a failed login, and nothing
		// derived from credentials should reach a log. TestWalkthroughRuns
		// reports the full error when this fails.
		log.Fatal("session-profiles example failed; run its test for details")
	}
}

func run(w io.Writer) error {
	mr, err := miniredis.Run()
	if err != nil {
		return err
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	cfg := goAuth.DefaultConfig()
	// Cheap Argon2 settings keep the demo fast; keep the defaults in production.
	cfg.Password.Memory = 8 * 1024
	cfg.Password.Time = 1
	cfg.Password.Parallelism = 1
	cfg.Security.ProductionMode = false

	cfg.SessionProfiles.Profiles = map[string]goAuth.SessionProfile{
		// web: fixed. Ends 15 days after login however often it is refreshed.
		"web": {AbsoluteLifetime: 15 * 24 * time.Hour},
		// mobile: renewing. Ends after 90 days without a successful refresh,
		// and never later than 365 days after login. RenewOnUse also restarts
		// the window when a ModeStrict route validates the session.
		"mobile": {
			IdleTimeout:      90 * 24 * time.Hour,
			AbsoluteLifetime: 365 * 24 * time.Hour,
			RenewOnUse:       true,
		},
	}
	cfg.SessionProfiles.DefaultProfile = "web"
	cfg.Session.JitterEnabled = false

	hasher, err := password.NewArgon2(password.Config{
		Memory: cfg.Password.Memory, Time: cfg.Password.Time, Parallelism: cfg.Password.Parallelism,
		SaltLength: cfg.Password.SaltLength, KeyLength: cfg.Password.KeyLength,
	})
	if err != nil {
		return err
	}
	hash, err := hasher.Hash(userPassword)
	if err != nil {
		return err
	}
	provider := newStubProvider()
	provider.put(goAuth.UserRecord{
		UserID: "user-1", Identifier: userEmail, PasswordHash: hash, Role: "admin",
		Status: goAuth.AccountActive, PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
	})

	engine, err := goAuth.New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"user.read"}).
		WithRoles(map[string][]string{"admin": {"user.read"}}).
		WithUserProvider(provider).
		Build()
	if err != nil {
		return err
	}
	defer engine.Close()

	login := func(c client) (access, refresh string, err error) {
		ctx := goAuth.WithSessionProfile(context.Background(), profileFor(c))
		return engine.Login(ctx, userEmail, userPassword)
	}

	// 1. Log in from both clients: two concurrent sessions, two profiles.
	_, webRefresh, err := login(webApp)
	if err != nil {
		return fmt.Errorf("web login: %w", err)
	}
	_, mobileRefresh, err := login(mobileApp)
	if err != nil {
		return fmt.Errorf("mobile login: %w", err)
	}
	fmt.Fprintln(w, "logged in as web and as mobile")

	// 2. List them. ExpiresAt is the hard ceiling; IdleExpiresAt is when a
	// renewing session lapses unless it is used first (zero for fixed ones).
	ctx := context.Background()
	if err := printSessions(ctx, w, engine, "after login"); err != nil {
		return err
	}

	// 3. Refresh the mobile session. Its idle window restarts from now; the
	// ceiling does not move. (The web session has no idle window to renew.)
	time.Sleep(1100 * time.Millisecond)
	if _, mobileRefresh, err = engine.Refresh(ctx, mobileRefresh); err != nil {
		return fmt.Errorf("mobile refresh: %w", err)
	}
	if _, webRefresh, err = engine.Refresh(ctx, webRefresh); err != nil {
		return fmt.Errorf("web refresh: %w", err)
	}
	fmt.Fprintln(w, "refreshed both sessions: the mobile idle window moved, the ceilings did not")
	if err := printSessions(ctx, w, engine, "after refresh"); err != nil {
		return err
	}
	_, _ = webRefresh, mobileRefresh

	// 4. A profile name that is not configured is refused before any password
	// is verified or any limiter is touched.
	_, _, err = engine.Login(goAuth.WithSessionProfile(ctx, "kiosk"), userEmail, userPassword)
	if !errors.Is(err, goAuth.ErrUnknownSessionProfile) {
		return fmt.Errorf("expected ErrUnknownSessionProfile, got %v", err)
	}
	fmt.Fprintln(w, "login with an unknown profile: refused with ErrUnknownSessionProfile")
	return nil
}

func printSessions(ctx context.Context, w io.Writer, engine *goAuth.Engine, label string) error {
	infos, err := engine.ListActiveSessions(ctx, "user-1")
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "sessions %s:\n", label)
	for _, profile := range []string{"mobile", "web"} {
		for _, info := range infos {
			if info.Profile != profile {
				continue
			}
			created := time.Unix(info.CreatedAt, 0)
			fmt.Fprintf(w, "  %-6s ceiling +%s", info.Profile, days(time.Unix(info.ExpiresAt, 0).Sub(created)))
			if info.IdleExpiresAt != 0 {
				fmt.Fprintf(w, ", idle window ends %s after login", time.Unix(info.IdleExpiresAt, 0).Sub(created))
			} else {
				fmt.Fprint(w, ", fixed (no idle window)")
			}
			fmt.Fprintln(w)
		}
	}
	return nil
}

// days renders a duration as whole days.
func days(d time.Duration) string {
	return fmt.Sprintf("%dd", int((d+time.Minute)/(24*time.Hour)))
}

// ---------------------------------------------------------------------------
// In-memory user provider stub
// ---------------------------------------------------------------------------

type stubProvider struct {
	mu      sync.RWMutex
	byID    map[string]goAuth.UserRecord
	byIdent map[string]string
}

func newStubProvider() *stubProvider {
	return &stubProvider{byID: map[string]goAuth.UserRecord{}, byIdent: map[string]string{}}
}

func (p *stubProvider) put(u goAuth.UserRecord) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.byID[u.UserID] = u
	p.byIdent[u.Identifier] = u.UserID
}

var errNotFound = errors.New("user not found")

func (p *stubProvider) GetUserByIdentifier(identifier string) (goAuth.UserRecord, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	id, ok := p.byIdent[identifier]
	if !ok {
		return goAuth.UserRecord{}, errNotFound
	}
	return p.byID[id], nil
}

func (p *stubProvider) GetUserByID(userID string) (goAuth.UserRecord, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	u, ok := p.byID[userID]
	if !ok {
		return goAuth.UserRecord{}, errNotFound
	}
	return u, nil
}

func (p *stubProvider) UpdatePasswordHash(userID, newHash string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	u, ok := p.byID[userID]
	if !ok {
		return errNotFound
	}
	u.PasswordHash = newHash
	p.byID[userID] = u
	return nil
}

func (p *stubProvider) CreateUser(_ context.Context, input goAuth.CreateUserInput) (goAuth.UserRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	u := goAuth.UserRecord{
		UserID: "user-new", Identifier: input.Identifier, PasswordHash: input.PasswordHash, Role: input.Role,
		Status: input.Status, PermissionVersion: input.PermissionVersion, RoleVersion: input.RoleVersion,
		AccountVersion: input.AccountVersion,
	}
	p.byID[u.UserID] = u
	p.byIdent[u.Identifier] = u.UserID
	return u, nil
}

func (p *stubProvider) UpdateAccountStatus(_ context.Context, userID string, status goAuth.AccountStatus) (goAuth.UserRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	u, ok := p.byID[userID]
	if !ok {
		return goAuth.UserRecord{}, errNotFound
	}
	u.Status = status
	p.byID[userID] = u
	return u, nil
}

// MFA is not used in this walkthrough.
func (p *stubProvider) GetTOTPSecret(context.Context, string) (*goAuth.TOTPRecord, error) {
	return nil, errors.New("totp not configured")
}
func (p *stubProvider) EnableTOTP(context.Context, string, []byte) error { return nil }
func (p *stubProvider) DisableTOTP(context.Context, string) error        { return nil }
func (p *stubProvider) MarkTOTPVerified(context.Context, string) error   { return nil }
func (p *stubProvider) UpdateTOTPLastUsedCounter(context.Context, string, int64) error {
	return nil
}
func (p *stubProvider) GetBackupCodes(context.Context, string) ([]goAuth.BackupCodeRecord, error) {
	return nil, nil
}
func (p *stubProvider) ReplaceBackupCodes(context.Context, string, []goAuth.BackupCodeRecord) error {
	return nil
}
func (p *stubProvider) ConsumeBackupCode(context.Context, string, [32]byte) (bool, error) {
	return false, nil
}
