package goAuth

import (
	"context"
	"errors"
	"testing"
)

// newTenantBackupCodeEngine builds a multi-tenant engine with one user in
// each of tenant-a and tenant-b and a full backup-code set for user-a.
func newTenantBackupCodeEngine(t *testing.T) (*Engine, *tenantMockProvider, *collectingSink, []string, func()) {
	t.Helper()

	mr, rdb := newTestRedis(t)

	up := newTenantMockProvider()
	up.addUser(UserRecord{
		UserID: "user-a", Identifier: "a@example.com", TenantID: "tenant-a",
		Status: AccountActive, Role: "member",
		PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
	})
	up.addUser(UserRecord{
		UserID: "user-b", Identifier: "b@example.com", TenantID: "tenant-b",
		Status: AccountActive, Role: "member",
		PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
	})

	cfg := totpTestConfig()
	cfg.MultiTenant.Enabled = true
	cfg.Audit.Enabled = true
	cfg.TOTP.BackupCodeMaxAttempts = 3

	sink := &collectingSink{}
	engine, err := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"perm.read"}).
		WithRoles(map[string][]string{"member": {}, "admin": {"perm.read"}}).
		WithUserProvider(up).
		WithAuditSink(sink).
		Build()
	if err != nil {
		mr.Close()
		t.Fatalf("Build failed: %v", err)
	}

	codes, err := engine.GenerateBackupCodes(WithTenantID(context.Background(), "tenant-a"), "user-a")
	if err != nil {
		mr.Close()
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}

	return engine, up, sink, codes, func() { mr.Close() }
}

// user-a lives in tenant-a. A tenant-b caller, whether through the context
// tenant or the explicit tenantID argument, must get not-found without the
// provider's ConsumeBackupCode ever being reached.
func TestVerifyBackupCodeRejectsForeignTenantUserID(t *testing.T) {
	ctxB := WithTenantID(context.Background(), "tenant-b")

	cases := []struct {
		name   string
		ignore bool
		verify func(e *Engine, code string) error
	}{
		{
			name: "VerifyBackupCode/context tenant",
			verify: func(e *Engine, code string) error {
				return e.VerifyBackupCode(ctxB, "user-a", code)
			},
		},
		{
			name: "VerifyBackupCodeInTenant/explicit tenant",
			verify: func(e *Engine, code string) error {
				return e.VerifyBackupCodeInTenant(context.Background(), "tenant-b", "user-a", code)
			},
		},
		{
			name:   "VerifyBackupCode/provider ignores tenant predicate",
			ignore: true,
			verify: func(e *Engine, code string) error {
				return e.VerifyBackupCode(ctxB, "user-a", code)
			},
		},
		{
			name:   "VerifyBackupCodeInTenant/provider ignores tenant predicate",
			ignore: true,
			verify: func(e *Engine, code string) error {
				return e.VerifyBackupCodeInTenant(context.Background(), "tenant-b", "user-a", code)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine, up, sink, codes, done := newTenantBackupCodeEngine(t)
			defer done()
			up.ignoreTenantScope = tc.ignore

			// A genuine, unconsumed code of the foreign user: the strongest
			// probe, because a tenant-blind consume would accept it.
			err := tc.verify(engine, codes[0])
			if !errors.Is(err, ErrUserNotFound) {
				t.Fatalf("expected ErrUserNotFound, got %v", err)
			}
			if up.consumeBackupCodeCalls != 0 {
				t.Fatalf("provider ConsumeBackupCode called %d times, want 0", up.consumeBackupCodeCalls)
			}

			// The code was neither consumed nor burned: its owner can still
			// use it from their own tenant.
			up.ignoreTenantScope = false
			ctxA := WithTenantID(context.Background(), "tenant-a")
			if err := engine.VerifyBackupCode(ctxA, "user-a", codes[0]); err != nil {
				t.Fatalf("owner could not use the code after a foreign attempt: %v", err)
			}

			engine.Close()

			event := sink.find(auditEventBackupCodeFailed, "user_not_found")
			if event == nil {
				t.Fatal("expected a backup_code_failed audit event with reason user_not_found")
			}
			if event.Success || event.UserID != "user-a" || event.TenantID != "tenant-b" {
				t.Fatalf("unexpected audit event: %+v", *event)
			}
		})
	}
}

func TestVerifyBackupCodeSameTenantUnchanged(t *testing.T) {
	ctxA := WithTenantID(context.Background(), "tenant-a")

	cases := []struct {
		name   string
		verify func(e *Engine, code string) error
	}{
		{
			name: "VerifyBackupCode",
			verify: func(e *Engine, code string) error {
				return e.VerifyBackupCode(ctxA, "user-a", code)
			},
		},
		{
			name: "VerifyBackupCodeInTenant",
			verify: func(e *Engine, code string) error {
				return e.VerifyBackupCodeInTenant(context.Background(), "tenant-a", "user-a", code)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine, up, _, codes, done := newTenantBackupCodeEngine(t)
			defer done()

			if err := tc.verify(engine, codes[0]); err != nil {
				t.Fatalf("same-tenant verify failed: %v", err)
			}
			if up.consumeBackupCodeCalls != 1 {
				t.Fatalf("ConsumeBackupCode calls = %d, want 1", up.consumeBackupCodeCalls)
			}
			if err := tc.verify(engine, codes[0]); !errors.Is(err, ErrBackupCodeInvalid) {
				t.Fatalf("expected replay to be invalid, got %v", err)
			}
			if err := tc.verify(engine, "WRONG-CODE"); !errors.Is(err, ErrBackupCodeInvalid) {
				t.Fatalf("expected wrong code to be invalid, got %v", err)
			}
		})
	}
}

// A foreign-tenant attempt counts toward the backup-code limiter, so probing
// ids across tenants is throttled the same way guessing codes is. The limiter
// is keyed by (tenant, user), so the owner is not locked out by the probing.
func TestVerifyBackupCodeCrossTenantAttemptsCountTowardLimiter(t *testing.T) {
	engine, up, _, codes, done := newTenantBackupCodeEngine(t)
	defer done()

	ctxB := WithTenantID(context.Background(), "tenant-b")

	// BackupCodeMaxAttempts is 3: three probes are recorded as not-found.
	for i := 1; i <= 3; i++ {
		if err := engine.VerifyBackupCode(ctxB, "user-a", codes[0]); !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("probe %d: expected ErrUserNotFound, got %v", i, err)
		}
	}
	if err := engine.VerifyBackupCode(ctxB, "user-a", codes[0]); !errors.Is(err, ErrBackupCodeRateLimited) {
		t.Fatalf("expected rate limited after the cap, got %v", err)
	}
	if up.consumeBackupCodeCalls != 0 {
		t.Fatalf("provider ConsumeBackupCode called %d times, want 0", up.consumeBackupCodeCalls)
	}

	ctxA := WithTenantID(context.Background(), "tenant-a")
	if err := engine.VerifyBackupCode(ctxA, "user-a", codes[0]); err != nil {
		t.Fatalf("owner was locked out by foreign-tenant probing: %v", err)
	}
}

// With multi-tenancy off, VerifyBackupCode must not add a user lookup: the
// provider sees exactly the calls it saw in v0.6.0.
func TestVerifyBackupCodeSingleTenantMakesNoExtraProviderCall(t *testing.T) {
	cfg := totpTestConfig()
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := context.Background()

	codes, err := engine.GenerateBackupCodes(ctx, "u1")
	if err != nil {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}

	lookupsBefore := up.getByIDCalls
	consumeBefore := up.consumeBackupCodeCalls

	if err := engine.VerifyBackupCode(ctx, "u1", codes[0]); err != nil {
		t.Fatalf("VerifyBackupCode failed: %v", err)
	}
	if err := engine.VerifyBackupCodeInTenant(ctx, "0", "u1", "WRONG-CODE"); !errors.Is(err, ErrBackupCodeInvalid) {
		t.Fatalf("expected ErrBackupCodeInvalid, got %v", err)
	}
	// An id that resolves to no user is still just a failed code attempt.
	if err := engine.VerifyBackupCode(ctx, "ghost", codes[1]); !errors.Is(err, ErrBackupCodeInvalid) {
		t.Fatalf("expected ErrBackupCodeInvalid for an unknown id, got %v", err)
	}

	if got := up.getByIDCalls - lookupsBefore; got != 0 {
		t.Fatalf("single-tenant verify made %d user lookups, want 0", got)
	}
	if got := up.consumeBackupCodeCalls - consumeBefore; got != 3 {
		t.Fatalf("ConsumeBackupCode calls = %d, want 3", got)
	}
}
