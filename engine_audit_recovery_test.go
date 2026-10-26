package goAuth

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Regression tests for the recovery findings of the v0.8.0 security audit
// (run 2): R2-02 and the backup codes that survive a TOTP disable. Each is
// labelled FAILED-BEFORE with the finding ID.

// seedBackupCode stores a backup code for the user straight in the provider, the
// state an account is in when codes were minted before the fix.
func seedBackupCode(t *testing.T, env *rsEnv, code string) {
	t.Helper()
	rec := []BackupCodeRecord{{Hash: backupCodeHash(rsUserID, canonicalizeBackupCode(code))}}
	if err := env.up.ReplaceBackupCodes(context.Background(), rsUserID, rec); err != nil {
		t.Fatalf("seed backup code: %v", err)
	}
}

// FAILED-BEFORE (R2-02 variant A): an account without TOTP minted codes for
// itself and used one as the second factor of a RequireMFA step-up.
func TestBackupCodesAreNotMintedForAnAccountWithoutTOTP(t *testing.T) {
	env := newRSEnv(t, stepUpAdminRequiresMFA(0))
	if _, err := env.engine.GenerateBackupCodes(env.ctx(), rsUserID); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Fatalf("GenerateBackupCodes without TOTP: %v, want ErrTOTPNotConfigured", err)
	}
	if _, err := env.engine.RegenerateBackupCodes(env.ctx(), rsUserID, "123456"); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Fatalf("RegenerateBackupCodes without TOTP: %v, want ErrTOTPNotConfigured", err)
	}
	if env.up.mockUserProvider.replaceBackupCodesCalls != 0 {
		t.Fatal("codes were stored for an account without TOTP")
	}
}

// FAILED-BEFORE (R2-02 variant A): the backup_code branch of the step-up did not
// require an enrolled authenticator the way the totp branch does. Codes that
// exist for an account without TOTP (minted by an earlier version) prove
// nothing about its owner.
func TestStepUpBackupCodeNeedsAnEnrolledAuthenticator(t *testing.T) {
	env := newRSEnv(t, stepUpAdminRequiresMFA(0))
	_, refresh := env.login()
	seedBackupCode(t, env, "ABCD-EFGH")

	_, err := env.switchRole(refresh, "admin", RoleSwitchOptions{MFAType: "backup_code", MFACode: "ABCD-EFGH"})
	if !errors.Is(err, ErrTOTPNotConfigured) {
		t.Fatalf("step-up with a backup code and no TOTP: %v, want ErrTOTPNotConfigured", err)
	}
	if _, err := env.switchRole(refresh, "admin", RoleSwitchOptions{MFAType: "totp", MFACode: "123456"}); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Fatalf("control: the totp branch: %v, want ErrTOTPNotConfigured", err)
	}
}

// FAILED-BEFORE (R2-02 variants B and C): an enrolled account with no codes on
// file (never generated, or all used) let a password-only session holder mint
// codes and pass the step-up without the authenticator.
func TestFirstBackupCodesNeedTheMinutesAfterTOTPSetup(t *testing.T) {
	env := newRSEnv(t, stepUpAdminRequiresMFA(0))
	secret := env.enableTOTP()
	_, refresh := env.login() // a password-only session

	// Inside the window the user who just enrolled gets their codes, once.
	codes, err := env.engine.GenerateBackupCodes(env.ctx(), rsUserID)
	if err != nil {
		t.Fatalf("GenerateBackupCodes right after setup: %v", err)
	}
	if _, err := env.engine.GenerateBackupCodes(env.ctx(), rsUserID); !errors.Is(err, ErrBackupCodeRegenerationRequiresTOTP) {
		t.Fatalf("second Generate: %v, want ErrBackupCodeRegenerationRequiresTOTP", err)
	}

	// Variant C: the codes are used up; Generate must not reopen.
	for _, c := range codes {
		if err := env.engine.VerifyBackupCode(env.ctx(), rsUserID, c); err != nil {
			t.Fatalf("consume: %v", err)
		}
	}
	if _, err := env.engine.GenerateBackupCodes(env.ctx(), rsUserID); !errors.Is(err, ErrBackupCodeRegenerationRequiresTOTP) {
		t.Fatalf("Generate after the codes were used up: %v, want ErrBackupCodeRegenerationRequiresTOTP", err)
	}

	// Regenerate with the authenticator still works, and the codes it returns
	// are real.
	more, err := env.engine.RegenerateBackupCodes(env.ctx(), rsUserID, codeForOffset(t, secret, env.cfg.TOTP, 1))
	if err != nil || len(more) == 0 {
		t.Fatalf("RegenerateBackupCodes with a TOTP code: %v", err)
	}
	if _, err := env.switchRole(refresh, "admin", RoleSwitchOptions{MFAType: "backup_code", MFACode: more[0]}); err != nil {
		t.Fatalf("a code obtained with the authenticator must still satisfy the step-up: %v", err)
	}
}

// FAILED-BEFORE (R2-02 variant B): later than ten minutes after setup, with no
// codes on file, a session holder cannot mint any.
func TestBackupCodeGenerationClosesTenMinutesAfterSetup(t *testing.T) {
	env := newRSEnv(t, stepUpAdminRequiresMFA(0))
	env.enableTOTP()
	_, refresh := env.login()

	env.mr.FastForward(11 * time.Minute)
	if _, err := env.engine.GenerateBackupCodes(env.ctx(), rsUserID); !errors.Is(err, ErrBackupCodeRegenerationRequiresTOTP) {
		t.Fatalf("Generate eleven minutes after setup: %v, want ErrBackupCodeRegenerationRequiresTOTP", err)
	}
	if _, err := env.switchRole(refresh, "admin", RoleSwitchOptions{MFAType: "backup_code", MFACode: "ABCD-EFGH"}); err == nil {
		t.Fatal("an invented backup code satisfied the step-up")
	}
	if _, err := env.engine.RegenerateBackupCodes(env.ctx(), rsUserID, "000000"); err == nil {
		t.Fatal("Regenerate accepted a wrong TOTP code")
	}
}

// FAILED-BEFORE (R2-02 variant D): with RequireForLogin, a session holder minted
// codes and later logged in with the password and a code, never needing TOTP.
func TestMintedBackupCodesDoNotReplaceTheAuthenticatorAtLogin(t *testing.T) {
	env := newRSEnv(t, rsConfig(func(c *Config) { c.TOTP.RequireForLogin = true }))
	secret := env.enableTOTP()
	env.mr.FastForward(11 * time.Minute)
	if _, _, err := env.engine.LoginWithTOTP(env.ctx(), rsIdentifier, rsPassword, env.totpCode(secret)); err != nil {
		t.Fatalf("LoginWithTOTP: %v", err)
	}

	if _, err := env.engine.GenerateBackupCodes(env.ctx(), rsUserID); !errors.Is(err, ErrBackupCodeRegenerationRequiresTOTP) {
		t.Fatalf("Generate by a session holder: %v, want ErrBackupCodeRegenerationRequiresTOTP", err)
	}
	if _, _, err := env.engine.LoginWithBackupCode(env.ctx(), rsIdentifier, rsPassword, "ABCD-EFGH"); err == nil {
		t.Fatal("password plus an invented backup code logged in")
	}
}

// The marker is scoped to the tenant and the user, and a disable removes it.
func TestBackupSetupGrantIsScopedAndRevoked(t *testing.T) {
	env := newRSEnv(t, stepUpAdminRequiresMFA(0))
	ctx := context.Background()
	store := env.engine.backupGrants

	if err := store.Grant(ctx, "tenant-a", "u1", time.Minute); err != nil {
		t.Fatal(err)
	}
	if ok, _ := store.Consume(ctx, "tenant-b", "u1"); ok {
		t.Fatal("a grant for tenant-a was usable in tenant-b")
	}
	if ok, _ := store.Consume(ctx, "tenant-a", "u2"); ok {
		t.Fatal("a grant for u1 was usable by u2")
	}
	if ok, _ := store.Consume(ctx, "tenant-a", "u1"); !ok {
		t.Fatal("the grant was not usable by its owner")
	}
	if ok, _ := store.Consume(ctx, "tenant-a", "u1"); ok {
		t.Fatal("the grant was usable twice")
	}
	// The default tenant is spelled the same either way.
	if err := store.Grant(ctx, "", "u1", time.Minute); err != nil {
		t.Fatal(err)
	}
	if ok, _ := store.Consume(ctx, "0", "u1"); !ok {
		t.Fatal("the default tenant spelled \"\" and \"0\" must be one tenant")
	}
}

// FAILED-BEFORE (R2-02 follow-on): backup codes outlived DisableTOTP, so a code
// minted for the old authenticator worked once the user enrolled a new one.
func TestDisableTOTPClearsTheBackupCodes(t *testing.T) {
	env := newRSEnv(t, rsConfig(func(c *Config) { c.TOTP.RequireForLogin = true }))
	env.enableTOTP()
	codes, err := env.engine.GenerateBackupCodes(env.ctx(), rsUserID)
	if err != nil {
		t.Fatal(err)
	}

	if err := env.engine.DisableTOTP(env.ctx(), rsUserID); err != nil {
		t.Fatalf("DisableTOTP: %v", err)
	}
	if left, _ := env.up.GetBackupCodes(env.ctx(), rsUserID); len(left) != 0 {
		t.Fatalf("%d backup codes survived DisableTOTP", len(left))
	}

	// A new authenticator, later: the old codes must not come back to life.
	secret := env.enableTOTP()
	if err := env.engine.VerifyBackupCode(env.ctx(), rsUserID, codes[0]); !errors.Is(err, ErrBackupCodeInvalid) {
		t.Fatalf("a code from before the disable: %v, want ErrBackupCodeInvalid", err)
	}
	if _, _, err := env.engine.LoginWithBackupCode(env.ctx(), rsIdentifier, rsPassword, codes[1]); err == nil {
		t.Fatal("a code from before the disable logged in")
	}
	// The new enrolment hands out a fresh set the normal way.
	if _, err := env.engine.GenerateBackupCodes(env.ctx(), rsUserID); err != nil {
		t.Fatalf("Generate after re-enrolment: %v", err)
	}
	_ = secret
}
