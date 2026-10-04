package goAuth

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/session"
)

func stepUpAdminRequiresMFA(maxAge time.Duration) rsOption {
	return rsConfig(func(c *Config) {
		c.RoleSwitch.StepUp = map[string]RoleStepUpPolicy{"admin": {RequireMFA: true, MaxAge: maxAge}}
		// Keep the attempt limiter out of the way of tests that exercise
		// the factors' own limiters.
		c.RoleSwitch.MaxAttempts = 50
	})
}

func stepUpAdminRecentAuth(maxAge time.Duration) rsOption {
	return rsConfig(func(c *Config) {
		c.RoleSwitch.StepUp = map[string]RoleStepUpPolicy{"admin": {MaxAge: maxAge}}
		c.RoleSwitch.MaxAttempts = 50
	})
}

func (env *rsEnv) enableTOTP() string {
	env.t.Helper()
	return enableUserTOTP(env.t, env.engine, rsUserID, env.cfg)
}

func (env *rsEnv) totpCode(secret string) string {
	env.t.Helper()
	return codeForNow(env.t, secret, env.cfg.TOTP)
}

func (env *rsEnv) assurance(sid string) *session.Assurance {
	env.t.Helper()
	a, err := env.engine.sessionStore.GetAssurance(context.Background(), env.tenant, sid)
	if err != nil {
		env.t.Fatalf("GetAssurance(%s): %v", sid, err)
	}
	return a
}

// backdate rewrites a session's creation time, keeping everything else
// (including its refresh secret and absolute expiry) as stored.
func (env *rsEnv) backdate(sid string, age time.Duration) {
	env.t.Helper()
	sess := env.peek(sid)
	sess.CreatedAt = time.Now().Add(-age).Unix()
	if err := env.engine.sessionStore.Save(context.Background(), sess, time.Hour); err != nil {
		env.t.Fatalf("re-save: %v", err)
	}
}

func (env *rsEnv) setAssurance(sid string, a session.Assurance) {
	env.t.Helper()
	if err := env.engine.sessionStore.SaveAssurance(context.Background(), env.tenant, sid, a, time.Hour); err != nil {
		env.t.Fatalf("SaveAssurance: %v", err)
	}
}

func requireStepUp(t *testing.T, res *RoleSwitchResult, err error, wantFactors []string) {
	t.Helper()
	if !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("SwitchRole = %v, want ErrStepUpRequired", err)
	}
	assertBoundaryAuthError(t, err, ErrStepUpRequired)
	if res == nil {
		t.Fatal("ErrStepUpRequired must come with a result listing the factors")
	}
	if !res.StepUpRequired {
		t.Fatalf("StepUpRequired = false in %+v", res)
	}
	if res.AccessToken != "" || res.RefreshToken != "" || res.Role != "" {
		t.Fatalf("a step-up result must carry no tokens or role: %+v", res)
	}
	if res.StepUpFactors == nil || !reflect.DeepEqual(res.StepUpFactors, wantFactors) {
		t.Fatalf("StepUpFactors = %#v, want %#v", res.StepUpFactors, wantFactors)
	}
}

func TestStepUpRequiredForPasswordOnlySession(t *testing.T) {
	t.Run("user with totp and backup codes", func(t *testing.T) {
		env := newRSEnv(t, stepUpAdminRequiresMFA(0))
		env.enableTOTP()
		if _, err := env.engine.GenerateBackupCodes(context.Background(), rsUserID); err != nil {
			t.Fatalf("GenerateBackupCodes: %v", err)
		}
		access, refresh := env.login()
		sid := env.sidOf(refresh)
		before := env.peek(sid)

		res, err := env.switchRole(refresh, "admin", RoleSwitchOptions{})
		requireStepUp(t, res, err, []string{"totp", "backup_code"})

		// Nothing switched and nothing was spent.
		if got := env.peek(sid); !sameSession(t, got, before) {
			t.Fatal("a step-up demand must leave the session untouched")
		}
		if _, err := env.validate(access, ModeStrict); err != nil {
			t.Fatalf("the old access token must still work: %v", err)
		}
		if _, _, err := env.engine.Refresh(env.ctx(), refresh); err != nil {
			t.Fatalf("the refresh token must not be spent by a step-up demand: %v", err)
		}
		env.waitForAudit(auditEventRoleSwitchFailed, "step_up_required")
	})

	t.Run("user with totp but no backup codes", func(t *testing.T) {
		env := newRSEnv(t, stepUpAdminRequiresMFA(0))
		env.enableTOTP()
		_, refresh := env.login()
		res, err := env.switchRole(refresh, "admin", RoleSwitchOptions{})
		requireStepUp(t, res, err, []string{"totp"})
	})

	t.Run("user with no second factor is offered none", func(t *testing.T) {
		env := newRSEnv(t, stepUpAdminRequiresMFA(0))
		_, refresh := env.login()
		res, err := env.switchRole(refresh, "admin", RoleSwitchOptions{})
		requireStepUp(t, res, err, []string{})
	})

	t.Run("a target role without a policy needs no proof", func(t *testing.T) {
		env := newRSEnv(t, rsConfig(func(c *Config) {
			c.RoleSwitch.StepUp = map[string]RoleStepUpPolicy{"teacher": {RequireMFA: true}}
		}))
		_, refresh := env.login()
		env.mustSwitch(refresh, "admin")
	})

	t.Run("unsupported inline factors do not satisfy the policy", func(t *testing.T) {
		env := newRSEnv(t, stepUpAdminRequiresMFA(0))
		env.enableTOTP()
		_, refresh := env.login()
		for name, opts := range map[string]RoleSwitchOptions{
			"unknown type":          {MFAType: "sms", MFACode: "123456"},
			"webauthn inline":       {MFAType: "webauthn", MFACode: "{}"},
			"type without code":     {MFAType: "totp"},
			"password for mfa role": {Password: rsPassword},
		} {
			res, err := env.switchRole(refresh, "admin", opts)
			if !errors.Is(err, ErrStepUpRequired) || res == nil || !res.StepUpRequired {
				t.Fatalf("%s: SwitchRole = (%+v, %v), want ErrStepUpRequired", name, res, err)
			}
		}
	})
}

// Every path that issues a session after a second factor stores an
// assurance, and a switch then needs no inline proof.
func TestStepUpAssuranceWrittenOnEveryMFALoginPath(t *testing.T) {
	paths := []struct {
		name   string
		method string
		login  func(t *testing.T, env *rsEnv, secret string, backup []string) string
	}{
		{"ConfirmLoginMFA", "totp", func(t *testing.T, env *rsEnv, secret string, _ []string) string {
			result, err := env.engine.LoginWithResult(env.ctx(), rsIdentifier, rsPassword)
			if err != nil || !result.MFARequired {
				t.Fatalf("LoginWithResult = (%+v, %v)", result, err)
			}
			done, err := env.engine.ConfirmLoginMFA(env.ctx(), result.MFASession, env.totpCode(secret))
			if err != nil {
				t.Fatalf("ConfirmLoginMFA: %v", err)
			}
			return done.RefreshToken
		}},
		{"ConfirmLoginMFAWithType totp", "totp", func(t *testing.T, env *rsEnv, secret string, _ []string) string {
			result, err := env.engine.LoginWithResult(env.ctx(), rsIdentifier, rsPassword)
			if err != nil {
				t.Fatalf("LoginWithResult: %v", err)
			}
			done, err := env.engine.ConfirmLoginMFAWithType(env.ctx(), result.MFASession, env.totpCode(secret), "totp")
			if err != nil {
				t.Fatalf("ConfirmLoginMFAWithType: %v", err)
			}
			return done.RefreshToken
		}},
		{"ConfirmLoginMFAWithType backup", "backup_code", func(t *testing.T, env *rsEnv, _ string, backup []string) string {
			result, err := env.engine.LoginWithResult(env.ctx(), rsIdentifier, rsPassword)
			if err != nil {
				t.Fatalf("LoginWithResult: %v", err)
			}
			done, err := env.engine.ConfirmLoginMFAWithType(env.ctx(), result.MFASession, backup[0], "backup")
			if err != nil {
				t.Fatalf("ConfirmLoginMFAWithType: %v", err)
			}
			return done.RefreshToken
		}},
		{"LoginWithTOTP", "totp", func(t *testing.T, env *rsEnv, secret string, _ []string) string {
			_, refresh, err := env.engine.LoginWithTOTP(env.ctx(), rsIdentifier, rsPassword, env.totpCode(secret))
			if err != nil {
				t.Fatalf("LoginWithTOTP: %v", err)
			}
			return refresh
		}},
		{"LoginWithBackupCode", "backup_code", func(t *testing.T, env *rsEnv, _ string, backup []string) string {
			_, refresh, err := env.engine.LoginWithBackupCode(env.ctx(), rsIdentifier, rsPassword, backup[0])
			if err != nil {
				t.Fatalf("LoginWithBackupCode: %v", err)
			}
			return refresh
		}},
	}

	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			env := newRSEnv(t, stepUpAdminRequiresMFA(0), rsConfig(func(c *Config) { c.TOTP.RequireForLogin = true }))
			secret := env.enableTOTP()
			backup, err := env.engine.GenerateBackupCodes(context.Background(), rsUserID)
			if err != nil {
				t.Fatalf("GenerateBackupCodes: %v", err)
			}

			refresh := p.login(t, env, secret, backup)
			sid := env.sidOf(refresh)
			held := env.assurance(sid)
			if held == nil || held.MFAMethod != p.method || held.MFAAt == 0 || held.AuthAt != held.MFAAt {
				t.Fatalf("assurance after %s = %+v, want method %q", p.name, held, p.method)
			}
			if ttl, _ := env.rdb.PTTL(context.Background(), "asa:"+env.tenant+":"+sid).Result(); ttl <= 0 {
				t.Fatalf("the assurance key must carry a TTL, got %v", ttl)
			}

			sw, err := env.switchRole(refresh, "admin", RoleSwitchOptions{})
			if err != nil {
				t.Fatalf("an MFA-established session must switch without inline proof: %v", err)
			}
			moved := env.assurance(env.sidOf(sw.RefreshToken))
			if moved == nil || *moved != *held {
				t.Fatalf("assurance after the switch = %+v, want %+v carried over", moved, held)
			}
			if old := env.assurance(sid); old != nil {
				t.Fatalf("the old session's assurance must be moved, found %+v", old)
			}
			ev := env.waitForAudit(auditEventRoleSwitched, "")
			if ev.Metadata["step_up"] != "session_assurance" {
				t.Fatalf("role_switched step_up = %q, want session_assurance", ev.Metadata["step_up"])
			}
		})
	}
}

func TestStepUpInlineTOTP(t *testing.T) {
	env := newRSEnv(t, stepUpAdminRequiresMFA(0))
	secret := env.enableTOTP()
	_, refresh := env.login()

	sw, err := env.switchRole(refresh, "admin", RoleSwitchOptions{MFAType: "totp", MFACode: env.totpCode(secret)})
	if err != nil {
		t.Fatalf("SwitchRole with an inline TOTP proof failed: %v", err)
	}
	if sw.Role != "admin" || sw.StepUpRequired {
		t.Fatalf("unexpected result %+v", sw)
	}
	held := env.assurance(env.sidOf(sw.RefreshToken))
	if held == nil || held.MFAMethod != "totp" || held.MFAAt == 0 {
		t.Fatalf("the new session must carry the inline proof as its assurance, got %+v", held)
	}
	ev := env.waitForAudit(auditEventRoleSwitched, "")
	if ev.Metadata["step_up"] != "totp" {
		t.Fatalf("role_switched step_up = %q, want totp", ev.Metadata["step_up"])
	}

	// The assurance now satisfies the policy on later switches.
	back := env.mustSwitch(sw.RefreshToken, "teacher")
	again := env.mustSwitch(back.RefreshToken, "admin")
	if env.assurance(env.sidOf(again.RefreshToken)) == nil {
		t.Fatal("the assurance must follow the session through repeated switches")
	}
}

func TestStepUpInlineBackupCode(t *testing.T) {
	env := newRSEnv(t, stepUpAdminRequiresMFA(0))
	env.enableTOTP()
	codes, err := env.engine.GenerateBackupCodes(context.Background(), rsUserID)
	if err != nil {
		t.Fatalf("GenerateBackupCodes: %v", err)
	}
	_, refresh := env.login()

	sw, err := env.switchRole(refresh, "admin", RoleSwitchOptions{MFAType: "backup_code", MFACode: codes[0]})
	if err != nil {
		t.Fatalf("SwitchRole with an inline backup code failed: %v", err)
	}
	held := env.assurance(env.sidOf(sw.RefreshToken))
	if held == nil || held.MFAMethod != "backup_code" {
		t.Fatalf("assurance = %+v, want method backup_code", held)
	}

	// The code was consumed: it cannot prove anything twice.
	back := env.mustSwitch(sw.RefreshToken, "teacher")
	env.setAssurance(env.sidOf(back.RefreshToken), session.Assurance{})
	if _, err := env.switchRole(back.RefreshToken, "admin", RoleSwitchOptions{MFAType: "backup_code", MFACode: codes[0]}); !errors.Is(err, ErrBackupCodeInvalid) {
		t.Fatalf("reusing a backup code = %v, want ErrBackupCodeInvalid", err)
	}
}

func TestStepUpWrongInlineTOTPUsesTheTOTPLimiter(t *testing.T) {
	env := newRSEnv(t, stepUpAdminRequiresMFA(0))
	env.enableTOTP()
	_, refresh := env.login()
	sid := env.sidOf(refresh)
	before := env.peek(sid)

	res, err := env.switchRole(refresh, "admin", RoleSwitchOptions{MFAType: "totp", MFACode: "000000"})
	if !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("a wrong inline code = %v, want ErrTOTPInvalid", err)
	}
	if res != nil {
		t.Fatalf("a failed proof must not carry a result, got %+v", res)
	}
	if got := env.peek(sid); !sameSession(t, got, before) {
		t.Fatal("a failed proof must leave the session untouched")
	}

	failuresBefore := env.metric(MetricTOTPFailure)
	limited := false
	for i := 0; i < 15 && !limited; i++ {
		_, err := env.switchRole(refresh, "admin", RoleSwitchOptions{MFAType: "totp", MFACode: "000000"})
		limited = errors.Is(err, ErrTOTPRateLimited)
	}
	if !limited {
		t.Fatal("repeated wrong inline codes never hit the TOTP limiter")
	}
	if env.metric(MetricTOTPFailure) <= failuresBefore {
		t.Fatal("inline failures must count as TOTP failures")
	}
	env.waitForAudit(auditEventRoleSwitchFailed, "step_up_required")
}

// The shared TOTP verifier treats "TOTP not enabled" as nothing to verify.
// That must never turn into a valid step-up proof.
func TestStepUpInlineTOTPWithoutEnrolledTOTPIsNotAProof(t *testing.T) {
	env := newRSEnv(t, stepUpAdminRequiresMFA(0))
	_, refresh := env.login()
	sid := env.sidOf(refresh)

	res, err := env.switchRole(refresh, "admin", RoleSwitchOptions{MFAType: "totp", MFACode: "123456"})
	if !errors.Is(err, ErrTOTPNotConfigured) {
		t.Fatalf("an inline TOTP code from a user without TOTP = %v, want ErrTOTPNotConfigured", err)
	}
	if res != nil {
		t.Fatalf("unexpected result %+v", res)
	}
	if !env.hasSession(sid) || env.peek(sid).Role != "teacher" {
		t.Fatal("the session must be unchanged")
	}
	if keys := env.keys("asa:*"); len(keys) != 0 {
		t.Fatalf("no assurance may be recorded for an unproven factor: %v", keys)
	}
}

func TestStepUpMaxAge(t *testing.T) {
	env := newRSEnv(t, stepUpAdminRequiresMFA(10*time.Minute))
	env.enableTOTP()
	_, refresh := env.login()
	sid := env.sidOf(refresh)

	env.setAssurance(sid, session.Assurance{MFAAt: time.Now().Add(-time.Hour).Unix(), MFAMethod: "totp", AuthAt: time.Now().Add(-time.Hour).Unix()})
	res, err := env.switchRole(refresh, "admin", RoleSwitchOptions{})
	requireStepUp(t, res, err, []string{"totp"})

	env.setAssurance(sid, session.Assurance{MFAAt: time.Now().Add(-time.Minute).Unix(), MFAMethod: "totp", AuthAt: time.Now().Add(-time.Minute).Unix()})
	if _, err := env.switchRole(refresh, "admin", RoleSwitchOptions{}); err != nil {
		t.Fatalf("a fresh assurance must satisfy the policy: %v", err)
	}
}

func TestStepUpRecentAuthenticationWithPassword(t *testing.T) {
	t.Run("a fresh login satisfies the policy on its own", func(t *testing.T) {
		env := newRSEnv(t, stepUpAdminRecentAuth(5*time.Minute))
		_, refresh := env.login()
		env.mustSwitch(refresh, "admin")
	})

	t.Run("an old session must re-confirm the password", func(t *testing.T) {
		env := newRSEnv(t, stepUpAdminRecentAuth(5*time.Minute))
		_, refresh := env.login()
		sid := env.sidOf(refresh)
		env.backdate(sid, time.Hour)

		res, err := env.switchRole(refresh, "admin", RoleSwitchOptions{})
		requireStepUp(t, res, err, []string{"password"})

		sw, err := env.switchRole(refresh, "admin", RoleSwitchOptions{Password: rsPassword})
		if err != nil {
			t.Fatalf("an inline password must satisfy a recent-authentication policy: %v", err)
		}
		held := env.assurance(env.sidOf(sw.RefreshToken))
		if held == nil || held.AuthAt == 0 || held.MFAAt != 0 {
			t.Fatalf("a password proof records recent authentication, never an MFA assurance: %+v", held)
		}
		ev := env.waitForAudit(auditEventRoleSwitched, "")
		if ev.Metadata["step_up"] != "password" {
			t.Fatalf("role_switched step_up = %q, want password", ev.Metadata["step_up"])
		}

		// The recorded proof keeps later switches within the window.
		back := env.mustSwitch(sw.RefreshToken, "teacher")
		env.mustSwitch(back.RefreshToken, "admin")
	})

	t.Run("a wrong password is counted by the password-verify limiter", func(t *testing.T) {
		env := newRSEnv(t, stepUpAdminRecentAuth(5*time.Minute))
		_, refresh := env.login()
		env.backdate(env.sidOf(refresh), time.Hour)

		var last error
		sawInvalid := false
		for i := 0; i < 10; i++ {
			res, err := env.switchRole(refresh, "admin", RoleSwitchOptions{Password: "wrong-password-xyz"})
			if res != nil {
				t.Fatalf("a failed proof must not carry a result: %+v", res)
			}
			last = err
			if errors.Is(err, ErrInvalidCredentials) {
				sawInvalid = true
			}
			if errors.Is(err, ErrPasswordVerifyRateLimited) {
				break
			}
		}
		if !sawInvalid {
			t.Fatal("wrong passwords never surfaced ErrInvalidCredentials")
		}
		if !errors.Is(last, ErrPasswordVerifyRateLimited) {
			t.Fatalf("repeated wrong passwords ended with %v, want ErrPasswordVerifyRateLimited", last)
		}
	})

	t.Run("a second factor also satisfies a recent-authentication policy", func(t *testing.T) {
		env := newRSEnv(t, stepUpAdminRecentAuth(5*time.Minute))
		secret := env.enableTOTP()
		_, refresh := env.login()
		env.backdate(env.sidOf(refresh), time.Hour)
		if _, err := env.switchRole(refresh, "admin", RoleSwitchOptions{MFAType: "totp", MFACode: env.totpCode(secret)}); err != nil {
			t.Fatalf("an inline TOTP proof must satisfy recent authentication: %v", err)
		}
	})
}

func TestStepUpPasswordProofKeepsAnExistingMFAAssurance(t *testing.T) {
	env := newRSEnv(t, stepUpAdminRecentAuth(5*time.Minute))
	_, refresh := env.login()
	sid := env.sidOf(refresh)
	env.backdate(sid, time.Hour)
	mfaAt := time.Now().Add(-30 * time.Minute).Unix()
	env.setAssurance(sid, session.Assurance{MFAAt: mfaAt, MFAMethod: "totp", AuthAt: mfaAt})

	sw, err := env.switchRole(refresh, "admin", RoleSwitchOptions{Password: rsPassword})
	if err != nil {
		t.Fatalf("SwitchRole failed: %v", err)
	}
	held := env.assurance(env.sidOf(sw.RefreshToken))
	if held == nil || held.MFAAt != mfaAt || held.MFAMethod != "totp" || held.AuthAt <= mfaAt {
		t.Fatalf("a password proof must refresh AuthAt without discarding the MFA assurance: %+v", held)
	}
}

func TestStepUpNoPolicyNeverWritesAssurance(t *testing.T) {
	t.Run("no step-up configured", func(t *testing.T) {
		env := newRSEnv(t, rsConfig(func(c *Config) { c.TOTP.RequireForLogin = true }))
		secret := env.enableTOTP()
		_, refresh, err := env.engine.LoginWithTOTP(env.ctx(), rsIdentifier, rsPassword, env.totpCode(secret))
		if err != nil {
			t.Fatalf("LoginWithTOTP: %v", err)
		}
		sw := env.mustSwitch(refresh, "admin")
		env.mustSwitch(sw.RefreshToken, "teacher")
		if keys := env.keys("asa:*"); len(keys) != 0 {
			t.Fatalf("no step-up policy is configured but an assurance was written: %v", keys)
		}
	})

	t.Run("step-up configured but role switching disabled", func(t *testing.T) {
		env := newRSEnv(t, stepUpAdminRequiresMFA(0), rsConfig(func(c *Config) {
			c.TOTP.RequireForLogin = true
			c.RoleSwitch.Enabled = false
		}))
		secret := env.enableTOTP()
		if _, _, err := env.engine.LoginWithTOTP(env.ctx(), rsIdentifier, rsPassword, env.totpCode(secret)); err != nil {
			t.Fatalf("LoginWithTOTP: %v", err)
		}
		if keys := env.keys("asa:*"); len(keys) != 0 {
			t.Fatalf("role switching is disabled but an assurance was written: %v", keys)
		}
	})

	t.Run("password login never records an MFA assurance", func(t *testing.T) {
		env := newRSEnv(t, stepUpAdminRequiresMFA(0))
		env.login()
		if keys := env.keys("asa:*"); len(keys) != 0 {
			t.Fatalf("a password-only login wrote %v", keys)
		}
	})
}

// A session created before step-up was configured has no assurance, so a
// RequireMFA policy asks for the factor.
func TestStepUpSessionWithoutAssuranceIsAskedForMFA(t *testing.T) {
	env := newRSEnv(t, stepUpAdminRequiresMFA(0), rsConfig(func(c *Config) { c.TOTP.RequireForLogin = true }))
	secret := env.enableTOTP()
	_, refresh, err := env.engine.LoginWithTOTP(env.ctx(), rsIdentifier, rsPassword, env.totpCode(secret))
	if err != nil {
		t.Fatalf("LoginWithTOTP: %v", err)
	}
	sid := env.sidOf(refresh)
	if env.assurance(sid) == nil {
		t.Fatal("setup: the MFA login should have written an assurance")
	}
	if err := env.rdb.Del(context.Background(), "asa:"+env.tenant+":"+sid).Err(); err != nil {
		t.Fatalf("del: %v", err)
	}
	res, err := env.switchRole(refresh, "admin", RoleSwitchOptions{})
	requireStepUp(t, res, err, []string{"totp"})
}
