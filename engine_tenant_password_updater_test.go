package goAuth

import (
	"context"
	"errors"
	"testing"

	"github.com/MrEthical07/goAuth/password"
)

// tenantPasswordWrite records one UpdatePasswordHashInTenant call.
type tenantPasswordWrite struct {
	tenantID string
	userID   string
	hash     string
}

// tenantUpdaterProvider is a TenantAwareUserProvider that also implements
// TenantAwarePasswordUpdater and records every write on either path.
type tenantUpdaterProvider struct {
	tenantMockProvider

	inTenantWrites []tenantPasswordWrite
	inTenantErr    error
}

func newTenantUpdaterProvider() *tenantUpdaterProvider {
	return &tenantUpdaterProvider{tenantMockProvider: *newTenantMockProvider()}
}

func (p *tenantUpdaterProvider) UpdatePasswordHashInTenant(ctx context.Context, tenantID, userID, newHash string) error {
	p.inTenantWrites = append(p.inTenantWrites, tenantPasswordWrite{tenantID: tenantID, userID: userID, hash: newHash})
	if p.inTenantErr != nil {
		return p.inTenantErr
	}
	user, ok := p.users[userID]
	if !ok || user.TenantID != tenantID {
		return errors.New("not found")
	}
	user.PasswordHash = newHash
	p.users[userID] = user
	return nil
}

// legacyWriteCount reports how many times the tenant-blind writer ran.
func legacyWriteCount(up UserProvider) int {
	switch p := up.(type) {
	case *tenantUpdaterProvider:
		return p.updatePasswordCalls
	case *tenantMockProvider:
		return p.updatePasswordCalls
	}
	return -1
}

func inTenantWrites(up UserProvider) []tenantPasswordWrite {
	if p, ok := up.(*tenantUpdaterProvider); ok {
		return p.inTenantWrites
	}
	return nil
}

type passwordWriter interface {
	UserProvider
	addUser(UserRecord)
}

// passwordWriterCase is one provider/mode combination a writer is run under.
type passwordWriterCase struct {
	name        string
	multiTenant bool
	newProvider func() passwordWriter
	// wantInTenant is true when the tenant-aware writer must be used.
	wantInTenant bool
}

// userTenant is the tenant a test user lives in: a real tenant when
// multi-tenancy is on, the default tenant otherwise.
func (tc passwordWriterCase) userTenant() string {
	if tc.multiTenant {
		return "tenant-a"
	}
	return "0"
}

func passwordWriterCases() []passwordWriterCase {
	return []passwordWriterCase{
		{
			name:         "multi-tenant with updater uses the tenant-aware writer",
			multiTenant:  true,
			newProvider:  func() passwordWriter { return newTenantUpdaterProvider() },
			wantInTenant: true,
		},
		{
			name:         "multi-tenant without updater keeps the legacy writer",
			multiTenant:  true,
			newProvider:  func() passwordWriter { return newTenantMockProvider() },
			wantInTenant: false,
		},
		{
			name:         "single-tenant ignores the updater and keeps the legacy writer",
			multiTenant:  false,
			newProvider:  func() passwordWriter { return newTenantUpdaterProvider() },
			wantInTenant: false,
		},
	}
}

func buildPasswordWriterEngine(t *testing.T, tc passwordWriterCase, up UserProvider, mutate func(*Config)) (*Engine, func()) {
	t.Helper()

	mr, rdb := newTestRedis(t)
	cfg := accountTestConfig()
	cfg.MultiTenant.Enabled = tc.multiTenant
	if mutate != nil {
		mutate(&cfg)
	}

	engine, err := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"perm.read"}).
		WithRoles(map[string][]string{"member": {}, "admin": {"perm.read"}}).
		WithUserProvider(up).
		Build()
	if err != nil {
		mr.Close()
		t.Fatalf("Build failed: %v", err)
	}
	return engine, func() { mr.Close() }
}

func assertPasswordWriteRouting(t *testing.T, tc passwordWriterCase, up UserProvider, wantTenant, wantUser string) {
	t.Helper()

	writes := inTenantWrites(up)
	legacy := legacyWriteCount(up)

	if tc.wantInTenant {
		if len(writes) != 1 {
			t.Fatalf("tenant-aware writer calls = %d, want 1", len(writes))
		}
		if writes[0].tenantID != wantTenant || writes[0].userID != wantUser {
			t.Fatalf("tenant-aware write = (%q, %q), want (%q, %q)", writes[0].tenantID, writes[0].userID, wantTenant, wantUser)
		}
		if legacy != 0 {
			t.Fatalf("legacy writer ran %d time(s) alongside the tenant-aware writer", legacy)
		}
		return
	}

	if len(writes) != 0 {
		t.Fatalf("tenant-aware writer ran %d time(s) where the legacy path was expected", len(writes))
	}
	if legacy != 1 {
		t.Fatalf("legacy writer calls = %d, want 1", legacy)
	}
}

func TestChangePasswordUsesTenantAwareWriter(t *testing.T) {
	hasher := newTestHasher(t)
	oldHash, err := hasher.Hash("old-password-123")
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	for _, tc := range passwordWriterCases() {
		t.Run(tc.name, func(t *testing.T) {
			up := tc.newProvider()
			up.addUser(UserRecord{
				UserID: "user-a", Identifier: "alice@example.com", TenantID: tc.userTenant(),
				PasswordHash: oldHash, Status: AccountActive, Role: "member",
				PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
			})
			engine, done := buildPasswordWriterEngine(t, tc, up, nil)
			defer done()

			ctx := context.Background()
			if tc.multiTenant {
				ctx = WithTenantID(ctx, "tenant-a")
			}

			if err := engine.ChangePassword(ctx, "user-a", "old-password-123", "new-password-456"); err != nil {
				t.Fatalf("ChangePassword failed: %v", err)
			}

			assertPasswordWriteRouting(t, tc, up, "tenant-a", "user-a")
		})
	}
}

func TestPasswordResetConfirmUsesTenantAwareWriter(t *testing.T) {
	for _, tc := range passwordWriterCases() {
		t.Run(tc.name, func(t *testing.T) {
			up := tc.newProvider()
			up.addUser(UserRecord{
				UserID: "user-a", Identifier: "alice@example.com", TenantID: tc.userTenant(),
				Status: AccountActive, Role: "member",
				PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
			})
			engine, done := buildPasswordWriterEngine(t, tc, up, func(cfg *Config) {
				cfg.PasswordReset.Enabled = true
				cfg.PasswordReset.Strategy = ResetToken
			})
			defer done()

			ctx := context.Background()
			if tc.multiTenant {
				ctx = WithTenantID(ctx, "tenant-a")
			}

			challenge, err := engine.RequestPasswordReset(ctx, "alice@example.com")
			if err != nil {
				t.Fatalf("RequestPasswordReset failed: %v", err)
			}
			if challenge == "" {
				t.Fatal("expected a reset challenge")
			}
			if err := engine.ConfirmPasswordReset(ctx, challenge, "brand-new-password-1"); err != nil {
				t.Fatalf("ConfirmPasswordReset failed: %v", err)
			}

			assertPasswordWriteRouting(t, tc, up, "tenant-a", "user-a")
		})
	}
}

func TestRehashOnLoginUsesTenantAwareWriter(t *testing.T) {
	// A hash produced with weaker parameters than the engine's, so the
	// upgrade-on-login branch fires after the password verifies.
	weak, err := password.NewArgon2(password.Config{
		Memory: 8192, Time: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})
	if err != nil {
		t.Fatalf("NewArgon2 failed: %v", err)
	}
	weakHash, err := weak.Hash("login-password-123")
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	for _, tc := range passwordWriterCases() {
		t.Run(tc.name, func(t *testing.T) {
			up := tc.newProvider()
			up.addUser(UserRecord{
				UserID: "user-a", Identifier: "alice@example.com", TenantID: tc.userTenant(),
				PasswordHash: weakHash, Status: AccountActive, Role: "member",
				PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
			})
			engine, done := buildPasswordWriterEngine(t, tc, up, nil)
			defer done()

			ctx := context.Background()
			if tc.multiTenant {
				ctx = WithTenantID(ctx, "tenant-a")
			}

			if _, _, err := engine.Login(ctx, "alice@example.com", "login-password-123"); err != nil {
				t.Fatalf("Login failed: %v", err)
			}

			assertPasswordWriteRouting(t, tc, up, "tenant-a", "user-a")
		})
	}
}

// A tenant-aware write failure keeps the same error mapping as the legacy
// writer: an opaque provider error collapses to ErrSystemInternal.
func TestChangePasswordTenantAwareWriterErrorMapping(t *testing.T) {
	hasher := newTestHasher(t)
	oldHash, err := hasher.Hash("old-password-123")
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	up := newTenantUpdaterProvider()
	up.inTenantErr = errors.New("provider-db-write-failed")
	up.addUser(UserRecord{
		UserID: "user-a", Identifier: "alice@example.com", TenantID: "tenant-a",
		PasswordHash: oldHash, Status: AccountActive, Role: "member",
		PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
	})
	engine, done := buildPasswordWriterEngine(t, passwordWriterCase{multiTenant: true}, up, nil)
	defer done()

	ctx := WithTenantID(context.Background(), "tenant-a")
	err = engine.ChangePassword(ctx, "user-a", "old-password-123", "new-password-456")
	assertBoundaryAuthError(t, err, ErrSystemInternal)
}
