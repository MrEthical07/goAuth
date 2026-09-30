package goAuth

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
)

// tenantWebAuthnProvider is a tenant-aware user provider that also stores
// WebAuthn credentials and counts every credential call, so tests can assert
// the provider was never reached for a foreign-tenant user.
type tenantWebAuthnProvider struct {
	*tenantMockProvider

	mu          sync.Mutex
	credentials map[string][]WebAuthnCredential

	getCalls    int
	removeCalls int
}

func newTenantWebAuthnProvider() *tenantWebAuthnProvider {
	return &tenantWebAuthnProvider{
		tenantMockProvider: newTenantMockProvider(),
		credentials:        map[string][]WebAuthnCredential{},
	}
}

func (p *tenantWebAuthnProvider) GetWebAuthnCredentials(_ context.Context, userID string) ([]WebAuthnCredential, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.getCalls++
	out := make([]WebAuthnCredential, len(p.credentials[userID]))
	copy(out, p.credentials[userID])
	return out, nil
}

func (p *tenantWebAuthnProvider) AddWebAuthnCredential(_ context.Context, userID string, credential WebAuthnCredential) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.credentials[userID] = append(p.credentials[userID], credential)
	return nil
}

func (p *tenantWebAuthnProvider) UpdateWebAuthnCredentialSignCount(_ context.Context, _ string, _ []byte, _ uint32) error {
	return nil
}

func (p *tenantWebAuthnProvider) RemoveWebAuthnCredential(_ context.Context, userID string, credentialID []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.removeCalls++
	records := p.credentials[userID]
	for i := range records {
		if bytes.Equal(records[i].CredentialID, credentialID) {
			p.credentials[userID] = append(records[:i], records[i+1:]...)
			return nil
		}
	}
	return errors.New("credential not found")
}

func (p *tenantWebAuthnProvider) counts() (get, remove int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.getCalls, p.removeCalls
}

var _ WebAuthnCredentialProvider = (*tenantWebAuthnProvider)(nil)

var tenantWebAuthnCredentialID = []byte("credential-of-user-a")

// newTenantWebAuthnEngine builds a multi-tenant engine with one user in each
// of tenant-a and tenant-b and a stored credential for user-a.
func newTenantWebAuthnEngine(t *testing.T) (*Engine, *tenantWebAuthnProvider, func()) {
	t.Helper()

	up := newTenantWebAuthnProvider()
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
	up.credentials["user-a"] = []WebAuthnCredential{{CredentialID: tenantWebAuthnCredentialID}}

	cfg := webauthnTestConfig()
	cfg.MultiTenant.Enabled = true

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	return engine, up, done
}

// user-a lives in tenant-a; every call below is made under tenant-b. The
// credential provider must never be reached.
func TestWebAuthnListAndRemoveRejectForeignTenantUserID(t *testing.T) {
	ctxB := WithTenantID(context.Background(), "tenant-b")

	cases := []struct {
		name   string
		ignore bool
		call   func(e *Engine) error
	}{
		{
			name: "ListWebAuthnCredentials",
			call: func(e *Engine) error {
				_, err := e.ListWebAuthnCredentials(ctxB, "user-a")
				return err
			},
		},
		{
			name: "RemoveWebAuthnCredential",
			call: func(e *Engine) error {
				return e.RemoveWebAuthnCredential(ctxB, "user-a", tenantWebAuthnCredentialID)
			},
		},
		{
			name:   "ListWebAuthnCredentials/provider ignores tenant predicate",
			ignore: true,
			call: func(e *Engine) error {
				_, err := e.ListWebAuthnCredentials(ctxB, "user-a")
				return err
			},
		},
		{
			name:   "RemoveWebAuthnCredential/provider ignores tenant predicate",
			ignore: true,
			call: func(e *Engine) error {
				return e.RemoveWebAuthnCredential(ctxB, "user-a", tenantWebAuthnCredentialID)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine, up, done := newTenantWebAuthnEngine(t)
			defer done()
			up.ignoreTenantScope = tc.ignore

			if err := tc.call(engine); !errors.Is(err, ErrUserNotFound) {
				t.Fatalf("expected ErrUserNotFound, got %v", err)
			}
			if get, remove := up.counts(); get != 0 || remove != 0 {
				t.Fatalf("credential provider reached for a foreign-tenant user: get=%d remove=%d", get, remove)
			}
			if len(up.credentials["user-a"]) != 1 {
				t.Fatal("foreign-tenant call changed user-a's credentials")
			}
		})
	}
}

func TestWebAuthnListAndRemoveSameTenantUnchanged(t *testing.T) {
	ctxA := WithTenantID(context.Background(), "tenant-a")

	t.Run("ListWebAuthnCredentials", func(t *testing.T) {
		engine, up, done := newTenantWebAuthnEngine(t)
		defer done()

		list, err := engine.ListWebAuthnCredentials(ctxA, "user-a")
		if err != nil {
			t.Fatalf("same-tenant list failed: %v", err)
		}
		if len(list) != 1 || !bytes.Equal(list[0].CredentialID, tenantWebAuthnCredentialID) {
			t.Fatalf("unexpected credentials: %+v", list)
		}
		if get, _ := up.counts(); get != 1 {
			t.Fatalf("GetWebAuthnCredentials calls = %d, want 1", get)
		}
	})

	t.Run("RemoveWebAuthnCredential", func(t *testing.T) {
		engine, up, done := newTenantWebAuthnEngine(t)
		defer done()

		if err := engine.RemoveWebAuthnCredential(ctxA, "user-a", tenantWebAuthnCredentialID); err != nil {
			t.Fatalf("same-tenant remove failed: %v", err)
		}
		if _, remove := up.counts(); remove != 1 {
			t.Fatalf("RemoveWebAuthnCredential calls = %d, want 1", remove)
		}
		if err := engine.RemoveWebAuthnCredential(ctxA, "user-a", tenantWebAuthnCredentialID); !errors.Is(err, ErrWebAuthnCredentialNotFound) {
			t.Fatalf("expected ErrWebAuthnCredentialNotFound on second remove, got %v", err)
		}
	})
}

// The disabled and empty-argument checks come before tenant resolution, so
// they keep their v0.6.0 errors and cost no user lookup.
func TestWebAuthnListAndRemoveEarlyChecksPrecedeTenantLookup(t *testing.T) {
	engine, up, done := newTenantWebAuthnEngine(t)
	defer done()
	ctxA := WithTenantID(context.Background(), "tenant-a")

	if _, err := engine.ListWebAuthnCredentials(ctxA, ""); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("empty userID: expected ErrUserNotFound, got %v", err)
	}
	if err := engine.RemoveWebAuthnCredential(ctxA, "", tenantWebAuthnCredentialID); !errors.Is(err, ErrWebAuthnCredentialNotFound) {
		t.Fatalf("empty userID: expected ErrWebAuthnCredentialNotFound, got %v", err)
	}
	if err := engine.RemoveWebAuthnCredential(ctxA, "user-a", nil); !errors.Is(err, ErrWebAuthnCredentialNotFound) {
		t.Fatalf("empty credentialID: expected ErrWebAuthnCredentialNotFound, got %v", err)
	}
	if up.tenantIDCalls != 0 {
		t.Fatalf("early-return paths made %d tenant lookups, want 0", up.tenantIDCalls)
	}

	cfg := webauthnTestConfig()
	cfg.WebAuthn.Enabled = false
	cfg.WebAuthn.RequireForLogin = false
	cfg.MultiTenant.Enabled = true
	disabledUP := newTenantWebAuthnProvider()
	disabled, _, disabledDone := newCreateAccountEngine(t, cfg, disabledUP)
	defer disabledDone()
	if _, err := disabled.ListWebAuthnCredentials(ctxA, "user-a"); !errors.Is(err, ErrWebAuthnDisabled) {
		t.Fatalf("disabled list: expected ErrWebAuthnDisabled, got %v", err)
	}
	if err := disabled.RemoveWebAuthnCredential(ctxA, "user-a", tenantWebAuthnCredentialID); !errors.Is(err, ErrWebAuthnDisabled) {
		t.Fatalf("disabled remove: expected ErrWebAuthnDisabled, got %v", err)
	}
	if disabledUP.tenantIDCalls != 0 {
		t.Fatalf("disabled surface made %d tenant lookups, want 0", disabledUP.tenantIDCalls)
	}
}

// With multi-tenancy off, list and remove must not add a user lookup.
func TestWebAuthnListAndRemoveSingleTenantMakeNoExtraProviderCall(t *testing.T) {
	cfg := webauthnTestConfig()
	up := newWebAuthnMockProvider(t)
	up.credentials["u1"] = []WebAuthnCredential{{CredentialID: []byte("cred-1")}}
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := context.Background()

	lookupsBefore := up.getByIDCalls

	list, err := engine.ListWebAuthnCredentials(ctx, "u1")
	if err != nil || len(list) != 1 {
		t.Fatalf("list: got %d credentials, err=%v", len(list), err)
	}
	// An id that resolves to no user is passed straight to the provider, as
	// it always was.
	if list, err := engine.ListWebAuthnCredentials(ctx, "ghost"); err != nil || len(list) != 0 {
		t.Fatalf("list of an unknown id: got %d credentials, err=%v", len(list), err)
	}
	if err := engine.RemoveWebAuthnCredential(ctx, "u1", []byte("cred-1")); err != nil {
		t.Fatalf("remove failed: %v", err)
	}

	if got := up.getByIDCalls - lookupsBefore; got != 0 {
		t.Fatalf("single-tenant list/remove made %d user lookups, want 0", got)
	}
}
