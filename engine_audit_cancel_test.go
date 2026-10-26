package goAuth

import (
	"errors"
	"strings"
	"testing"
)

// Regression tests for R2-26 of the v0.8.0 security audit (run 2): a pending
// change-email challenge survived password reset, password change and
// LogoutAll, so recovery did not evict a staged email change.

func requirePendingChange(t *testing.T, env *ecEnv, wantPending bool) {
	t.Helper()
	if got := len(env.changeKeys()) > 0; got != wantPending {
		t.Fatalf("pending email change = %v, want %v (keys %v)", got, wantPending, env.changeKeys())
	}
}

// FAILED-BEFORE (R2-26): each of these left the staged change redeemable.
func TestRecoveryCancelsAPendingEmailChange(t *testing.T) {
	cases := map[string]func(t *testing.T, env *ecEnv){
		"password reset": func(t *testing.T, env *ecEnv) {
			code, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
			if err != nil {
				t.Fatal(err)
			}
			if err := env.engine.ConfirmPasswordReset(env.ctx(), code, "brand-new-password-9"); err != nil {
				t.Fatalf("ConfirmPasswordReset: %v", err)
			}
		},
		"password change": func(t *testing.T, env *ecEnv) {
			if err := env.engine.ChangePassword(env.ctx(), rsUserID, rsPassword, "brand-new-password-9"); err != nil {
				t.Fatalf("ChangePassword: %v", err)
			}
		},
		"LogoutAll": func(t *testing.T, env *ecEnv) {
			if err := env.engine.LogoutAll(env.ctx(), rsUserID); err != nil {
				t.Fatalf("LogoutAll: %v", err)
			}
		},
		"LogoutAllInTenant": func(t *testing.T, env *ecEnv) {
			if err := env.engine.LogoutAllInTenant(env.ctx(), "0", rsUserID); err != nil {
				t.Fatalf("LogoutAllInTenant: %v", err)
			}
		},
	}
	for name, recover := range cases {
		t.Run(name, func(t *testing.T) {
			env := newECEnv(t, nil)
			env.login()
			req := env.mustRequest(ecNewEmail)
			requirePendingChange(t, env, true)

			recover(t, env)

			requirePendingChange(t, env, false)
			if _, err := env.confirm(req, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
				t.Fatalf("confirming the staged change after recovery: %v, want ErrEmailChangeInvalid", err)
			}
			ev := env.waitForAudit(auditEventEmailChangeCancelled, "recovery")
			if ev.UserID != rsUserID {
				t.Fatalf("audit event for %q, want %q", ev.UserID, rsUserID)
			}
			if got := env.user(rsUserID).Identifier; got != rsIdentifier {
				t.Fatalf("the identifier changed to %q", got)
			}
		})
	}
}

// Recovery of one account leaves another account's staged change alone, and a
// recovery with nothing staged audits nothing.
func TestRecoveryCancelsOnlyTheRecoveredUsersChange(t *testing.T) {
	env := newECEnv(t, nil)
	env.addOther("u2", "other@example.com")
	mine := env.mustRequest(ecNewEmail)
	theirs, err := env.engine.RequestEmailChange(env.ctx(), "u2", "other-new@example.com")
	if err != nil {
		t.Fatal(err)
	}

	if err := env.engine.LogoutAll(env.ctx(), "u2"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.engine.ConfirmEmailChange(env.ctx(), theirs.VerificationID, theirs.Code, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
		t.Fatalf("u2's staged change survived u2's LogoutAll: %v", err)
	}
	env.mustConfirm(mine, ConfirmEmailChangeOptions{})
	if n := env.auditCount(auditEventEmailChangeCancelled); n != 1 {
		t.Fatalf("%d cancel events, want exactly the one for u2", n)
	}
}

// FAILED-BEFORE (R2-26): the recovery must not fail, or look failed, because the
// staged change could not be cancelled; the failure is logged and audited.
func TestACancelFailureDoesNotFailTheRecovery(t *testing.T) {
	env := newECEnv(t, nil)
	env.login()
	env.mustRequest(ecNewEmail)

	hook := &failOnceOnKey{key: "aecp:0:" + rsUserID}
	hook.armed.Store(true)
	env.rdb.AddHook(hook)

	if err := env.engine.LogoutAll(env.ctx(), rsUserID); err != nil {
		t.Fatalf("LogoutAll failed because the cancel did: %v", err)
	}
	env.waitForAudit(auditEventEmailChangeFailure, "recovery")
	if hook.armed.Load() {
		t.Fatal("the cancel never reached Redis, so the failure path was not exercised")
	}
	requirePendingChange(t, env, true)
	if !env.logs.Contains("pending email change could not be cancelled") {
		t.Fatal("the failure was not logged")
	}
}

// FAILED-BEFORE (R2-26 review): a bare LogoutAll(userID) only names the request's
// tenant, but without tenant-scoped lookups the challenge lives under the user's
// own tenant.
func TestRecoveryFindsAChallengeStoredUnderTheUsersOwnTenant(t *testing.T) {
	env := newECEnv(t, nil)
	u := env.user(rsUserID)
	u.TenantID = "7"
	env.setUser(u)
	req := env.mustRequest(ecNewEmail)
	if len(env.changeKeys()) == 0 {
		t.Fatal("no staged change")
	}
	for _, k := range env.changeKeys() {
		if !strings.Contains(k, ":7:") {
			t.Fatalf("the challenge is not stored under the user's own tenant: %v", env.changeKeys())
		}
	}

	if err := env.engine.LogoutAll(env.ctx(), rsUserID); err != nil {
		t.Fatalf("LogoutAll: %v", err)
	}
	requirePendingChange(t, env, false)
	if _, err := env.confirm(req, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
		t.Fatalf("confirming after recovery: %v, want ErrEmailChangeInvalid", err)
	}
}
