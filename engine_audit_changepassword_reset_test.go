package goAuth

import (
	"context"
	"errors"
	"testing"
)

const cpNewPassword = "owner-new-password-9"

// newChangePasswordResetEnv is an engine with password reset enabled (OTP
// strategy) and one Active user who owns rsPassword.
func newChangePasswordResetEnv(t *testing.T, opts ...rsOption) *rsEnv {
	t.Helper()
	all := append([]rsOption{rsConfig(func(c *Config) {
		c.PasswordReset = testResetConfig(ResetOTP)
	})}, opts...)
	return newRSEnv(t, all...)
}

func (env *rsEnv) setRecordTenant(tenant string) {
	env.t.Helper()
	env.up.mu.Lock()
	defer env.up.mu.Unlock()
	u := env.up.users[rsUserID]
	u.TenantID = tenant
	env.up.users[rsUserID] = u
}

func (env *rsEnv) loginWith(ctx context.Context, password string) error {
	_, _, err := env.engine.Login(ctx, rsIdentifier, password)
	return err
}

// FAILED-BEFORE (R2-25 / C1): ChangePassword never wrote the reset tombstone,
// so a reset code requested before the owner changed the password was still
// redeemable afterwards and replaced the owner's new password.
func TestChangePasswordSupersedesOutstandingResetCodes(t *testing.T) {
	env := newChangePasswordResetEnv(t)
	ctx := env.ctx()

	earlier, err := env.engine.RequestPasswordReset(ctx, rsIdentifier)
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if err := env.engine.ChangePassword(ctx, rsUserID, rsPassword, cpNewPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	err = env.engine.ConfirmPasswordReset(ctx, earlier, "attacker-password-1")
	if !errors.Is(err, ErrPasswordResetInvalid) {
		t.Fatalf("a code issued before the password change = %v, want ErrPasswordResetInvalid", err)
	}
	if err := env.loginWith(ctx, cpNewPassword); err != nil {
		t.Fatalf("the owner's new password no longer works: %v", err)
	}
	if err := env.loginWith(ctx, "attacker-password-1"); err == nil {
		t.Fatal("the redeemed code's password was set")
	}
}

// A code requested after the change is the owner's again and redeems: the
// tombstone is a write-order fence, not a lock.
func TestChangePasswordLeavesLaterResetCodesValid(t *testing.T) {
	env := newChangePasswordResetEnv(t)
	ctx := env.ctx()

	if err := env.engine.ChangePassword(ctx, rsUserID, rsPassword, cpNewPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	later, err := env.engine.RequestPasswordReset(ctx, rsIdentifier)
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if err := env.engine.ConfirmPasswordReset(ctx, later, "after-change-password-1"); err != nil {
		t.Fatalf("a code requested after the change must redeem: %v", err)
	}
}

// The record's tenant differs from the context's while MultiTenant is off: the
// reset record lives under the record tenant, and the tombstone must reach it.
func TestChangePasswordSupersedesResetCodesUnderTheRecordTenant(t *testing.T) {
	env := newChangePasswordResetEnv(t)
	env.setRecordTenant("record-tenant")
	ctx := env.ctx()

	earlier, err := env.engine.RequestPasswordReset(ctx, rsIdentifier)
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if !env.mr.Exists("aprg:record-tenant:" + rsUserID) {
		t.Fatalf("the reset pointer was not written under the record tenant: %v", env.keys("aprg:*"))
	}
	if err := env.engine.ChangePassword(ctx, rsUserID, rsPassword, cpNewPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	for _, tenant := range []string{env.tenant, "record-tenant"} {
		if !env.mr.Exists("aprg:" + tenant + ":" + rsUserID) {
			t.Errorf("no tombstone under tenant %q: %v", tenant, env.keys("aprg:*"))
		}
	}

	// Redeemed in the record's tenant, where the code lives.
	err = env.engine.ConfirmPasswordReset(WithTenantID(context.Background(), "record-tenant"), earlier, "attacker-password-1")
	if !errors.Is(err, ErrPasswordResetInvalid) {
		t.Fatalf("a code under the record tenant = %v, want ErrPasswordResetInvalid", err)
	}
}

// Multi-tenant: the tombstone lands in the request's tenant only, which is
// where the session revocation looks too.
func TestChangePasswordSupersedesResetCodesMultiTenant(t *testing.T) {
	env := newChangePasswordResetEnv(t, rsMultiTenant())
	ctx := env.ctx()

	earlier, err := env.engine.RequestPasswordReset(ctx, rsIdentifier)
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if err := env.engine.ChangePassword(ctx, rsUserID, rsPassword, cpNewPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if err := env.engine.ConfirmPasswordReset(ctx, earlier, "attacker-password-1"); !errors.Is(err, ErrPasswordResetInvalid) {
		t.Fatalf("a code issued before the password change = %v, want ErrPasswordResetInvalid", err)
	}
}

// With password reset disabled the change writes nothing for it.
func TestChangePasswordWritesNoResetPointerWhileResetIsDisabled(t *testing.T) {
	env := newRSEnv(t)
	if err := env.engine.ChangePassword(env.ctx(), rsUserID, rsPassword, cpNewPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if got := env.keys("aprg:*"); len(got) != 0 {
		t.Fatalf("reset pointers written while password reset is disabled: %v", got)
	}
}

// The password change is done once the hash is written: a tombstone that cannot
// be written is logged and audited, and the change still succeeds.
func TestChangePasswordSurvivesAResetTombstoneFailure(t *testing.T) {
	env := newChangePasswordResetEnv(t)
	ctx := env.ctx()
	hook := &keyFailHook{substr: "aprg:"}
	env.rdb.AddHook(hook)

	hook.on.Store(true)
	err := env.engine.ChangePassword(ctx, rsUserID, rsPassword, cpNewPassword)
	hook.on.Store(false)
	if err != nil {
		t.Fatalf("ChangePassword with an unwritable tombstone = %v, want nil", err)
	}
	if err := env.loginWith(ctx, cpNewPassword); err != nil {
		t.Fatalf("the new password does not work: %v", err)
	}
	ev := env.waitForAudit(auditEventPasswordChangeFailure, "reset_invalidation_failed")
	if ev.Success {
		t.Fatalf("audit event = %+v, want a failure event", ev)
	}
	if env.auditCount(auditEventPasswordChangeSuccess) != 1 {
		t.Fatalf("the change must still audit its success")
	}
}
