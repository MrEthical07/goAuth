package goAuth

import (
	"errors"
	"testing"
)

// A provider or database failure during the account lookup says nothing
// about the session: it is "unavailable" (503), never "session not found"
// (401, which a client treats as a logout). The session is untouched and the
// same refresh token works once the provider recovers.
func TestSwitchRoleLookupOutageIsUnavailable(t *testing.T) {
	modes := map[string][]rsOption{
		"single-tenant (GetUserByID)":        nil,
		"multi-tenant (GetUserByIDInTenant)": {rsMultiTenant()},
	}
	for name, opts := range modes {
		t.Run(name, func(t *testing.T) {
			env := newRSEnv(t, opts...)
			_, refresh := env.login()
			sid := env.sidOf(refresh)
			before := env.peek(sid)
			callsBefore := env.up.callCount()

			env.up.setLookupErr(errors.New("provider-db-down"))
			res, err := env.switchRole(refresh, "admin", RoleSwitchOptions{})
			if !errors.Is(err, ErrSystemUnavailable) {
				t.Fatalf("SwitchRole during a lookup outage = %v, want ErrSystemUnavailable", err)
			}
			if errors.Is(err, ErrSessionNotFound) {
				t.Fatal("a provider outage must not look like a logout")
			}
			if res != nil {
				t.Fatalf("expected no result, got %+v", res)
			}
			assertBoundaryAuthError(t, err, ErrSystemUnavailable)
			if got := env.peek(sid); !sameSession(t, got, before) {
				t.Fatal("the session must be untouched")
			}
			if env.up.callCount() != callsBefore {
				t.Fatal("CanAssumeRole must not be reached when the account lookup failed")
			}
			env.waitForAudit(auditEventRoleSwitchFailed, "unavailable")

			// The same refresh token works once the provider recovers.
			env.up.setLookupErr(nil)
			env.mustSwitch(refresh, "admin")
		})
	}
}

// A genuinely missing account, or a record from another tenant, still means
// the session is no longer usable.
func TestSwitchRoleMissingOrForeignAccountIsSessionNotFound(t *testing.T) {
	t.Run("single-tenant: provider reports ErrUserNotFound", func(t *testing.T) {
		env := newRSEnv(t)
		_, refresh := env.login()
		env.up.typedNotFound = true
		delete(env.up.users, rsUserID)
		if _, err := env.switchRole(refresh, "admin", RoleSwitchOptions{}); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("SwitchRole = %v, want ErrSessionNotFound", err)
		}
		if !env.hasSession(env.sidOf(refresh)) {
			t.Fatal("a missing account must not delete the session")
		}
	})

	t.Run("multi-tenant: provider reports ErrUserNotFound", func(t *testing.T) {
		env := newRSEnv(t, rsMultiTenant())
		_, refresh := env.login()
		env.up.typedNotFound = true
		delete(env.up.users, rsUserID)
		if _, err := env.switchRole(refresh, "admin", RoleSwitchOptions{}); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("SwitchRole = %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("multi-tenant: record from another tenant (backstop returns ErrUserNotFound)", func(t *testing.T) {
		env := newRSEnv(t, rsMultiTenant())
		_, refresh := env.login()
		env.up.ignoreTenantScope = true
		user := env.up.users[rsUserID]
		user.TenantID = "tenant-b"
		env.up.users[rsUserID] = user
		if _, err := env.switchRole(refresh, "admin", RoleSwitchOptions{}); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("SwitchRole = %v, want ErrSessionNotFound", err)
		}
	})
}

// The tenant-mismatch backstop must keep returning ErrUserNotFound, since
// the switch relies on it to tell "foreign record" from "provider failure".
func TestLookupUserByIDInTenantMismatchIsErrUserNotFound(t *testing.T) {
	env := newRSEnv(t, rsMultiTenant())
	env.up.ignoreTenantScope = true
	user := env.up.users[rsUserID]
	user.TenantID = "tenant-b"
	env.up.users[rsUserID] = user

	_, err := env.engine.lookupUserByIDInTenant(env.ctx(), "tenant-a", rsUserID)
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("lookup = %v, want ErrUserNotFound", err)
	}
}
