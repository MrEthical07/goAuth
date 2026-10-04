package goAuth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSwitchRoleAuditsSuccess(t *testing.T) {
	env := newRSEnv(t)
	_, refresh := env.login()
	oldSID := env.sidOf(refresh)

	sw := env.mustSwitch(refresh, "admin")
	newSID := env.sidOf(sw.RefreshToken)

	ev := env.waitForAudit(auditEventRoleSwitched, "")
	if !ev.Success || ev.Error != "" {
		t.Fatalf("a successful switch must audit as success without an error: %+v", ev)
	}
	if ev.UserID != rsUserID || ev.TenantID != "0" || ev.SessionID != newSID {
		t.Fatalf("event identity wrong: %+v", ev)
	}
	want := map[string]string{
		"from_role":      "teacher",
		"to_role":        "admin",
		"old_session_id": oldSID,
		"new_session_id": newSID,
	}
	for k, v := range want {
		if ev.Metadata[k] != v {
			t.Fatalf("metadata[%q] = %q, want %q (all: %v)", k, ev.Metadata[k], v, ev.Metadata)
		}
	}
	if _, ok := ev.Metadata["step_up"]; ok {
		t.Fatalf("no step-up policy applied, but step_up = %q", ev.Metadata["step_up"])
	}
	if env.auditCount(auditEventRoleSwitchFailed) != 0 {
		t.Fatal("a successful switch must not emit role_switch_failed")
	}
}

// Every failure emits role_switch_failed with its reason, the public error
// code, and no success flag.
func TestSwitchRoleAuditsEveryFailureReason(t *testing.T) {
	type scenario struct {
		reason    string
		wantErr   error
		wantCode  AuditErrorCode
		configure []rsOption
		run       func(env *rsEnv) error
	}
	switchTo := func(env *rsEnv, refresh, role string, opts RoleSwitchOptions) error {
		_, err := env.switchRole(refresh, role, opts)
		return err
	}

	scenarios := []scenario{
		{
			reason: "disabled", wantErr: ErrRoleSwitchDisabled, wantCode: auditErrRoleSwitchDisabled,
			configure: []rsOption{rsConfig(func(c *Config) { c.RoleSwitch.Enabled = false })},
			run: func(env *rsEnv) error {
				_, refresh := env.login()
				return switchTo(env, refresh, "admin", RoleSwitchOptions{})
			},
		},
		{
			reason: "invalid_session", wantErr: ErrRefreshInvalid, wantCode: auditErrInvalidToken,
			run: func(env *rsEnv) error {
				return switchTo(env, "not-a-refresh-token", "admin", RoleSwitchOptions{})
			},
		},
		{
			reason: "invalid_session", wantErr: ErrSessionNotFound, wantCode: auditErrSessionNotFound,
			run: func(env *rsEnv) error {
				_, refresh := env.login()
				if err := env.engine.Logout(env.ctx(), env.sidOf(refresh)); err != nil {
					t.Fatalf("logout: %v", err)
				}
				return switchTo(env, refresh, "admin", RoleSwitchOptions{})
			},
		},
		{
			reason: "reuse_detected", wantErr: ErrRefreshReuse, wantCode: auditErrRefreshReuse,
			run: func(env *rsEnv) error {
				_, r1 := env.login()
				if _, _, err := env.engine.Refresh(env.ctx(), r1); err != nil {
					t.Fatalf("refresh: %v", err)
				}
				return switchTo(env, r1, "admin", RoleSwitchOptions{})
			},
		},
		{
			reason: "same_role", wantErr: ErrRoleSwitchSameRole, wantCode: auditErrRoleSwitchSameRole,
			run: func(env *rsEnv) error {
				_, refresh := env.login()
				return switchTo(env, refresh, "teacher", RoleSwitchOptions{})
			},
		},
		{
			reason: "not_allowed", wantErr: ErrRoleNotAllowed, wantCode: auditErrRoleNotAllowed,
			run: func(env *rsEnv) error {
				_, refresh := env.login()
				env.up.revoke(rsUserID, "admin")
				return switchTo(env, refresh, "admin", RoleSwitchOptions{})
			},
		},
		{
			reason: "not_allowed", wantErr: ErrRoleNotAllowed, wantCode: auditErrRoleNotAllowed,
			run: func(env *rsEnv) error {
				_, refresh := env.login()
				return switchTo(env, refresh, "ghost", RoleSwitchOptions{})
			},
		},
		{
			reason: "step_up_required", wantErr: ErrStepUpRequired, wantCode: auditErrStepUpRequired,
			configure: []rsOption{stepUpAdminRequiresMFA(0)},
			run: func(env *rsEnv) error {
				_, refresh := env.login()
				return switchTo(env, refresh, "admin", RoleSwitchOptions{})
			},
		},
		{
			reason: "step_up_required", wantErr: ErrTOTPInvalid, wantCode: auditErrTOTPInvalid,
			configure: []rsOption{stepUpAdminRequiresMFA(0)},
			run: func(env *rsEnv) error {
				env.enableTOTP()
				_, refresh := env.login()
				return switchTo(env, refresh, "admin", RoleSwitchOptions{MFAType: "totp", MFACode: "000000"})
			},
		},
		{
			reason: "rate_limited", wantErr: ErrRoleSwitchRateLimited, wantCode: auditErrRoleSwitchRateLimited,
			configure: []rsOption{rsConfig(func(c *Config) {
				c.RoleSwitch.MaxAttempts = 1
				c.RoleSwitch.Cooldown = time.Minute
			})},
			run: func(env *rsEnv) error {
				_, refresh := env.login()
				_ = switchTo(env, refresh, "teacher", RoleSwitchOptions{})
				return switchTo(env, refresh, "teacher", RoleSwitchOptions{})
			},
		},
		{
			reason: "account_status", wantErr: ErrAccountDisabled, wantCode: auditErrAccountDisabled,
			run: func(env *rsEnv) error {
				_, refresh := env.login()
				user := env.up.users[rsUserID]
				user.Status = AccountDisabled
				env.up.users[rsUserID] = user
				return switchTo(env, refresh, "admin", RoleSwitchOptions{})
			},
		},
		{
			reason: "unavailable", wantErr: ErrSystemUnavailable, wantCode: auditErrInternal,
			run: func(env *rsEnv) error {
				_, refresh := env.login()
				env.up.setCanErr(errors.New("provider-db-down"))
				return switchTo(env, refresh, "admin", RoleSwitchOptions{})
			},
		},
		{
			reason: "invalid_session", wantErr: ErrDeviceBindingRejected, wantCode: auditErrDeviceBindingRejected,
			configure: []rsOption{rsConfig(func(c *Config) {
				c.DeviceBinding.Enabled = true
				c.DeviceBinding.EnforceIPBinding = true
				c.DeviceBinding.DetectIPChange = true
			})},
			run: func(env *rsEnv) error {
				login := WithClientIP(context.Background(), "203.0.113.7")
				_, refresh, err := env.engine.Login(login, rsIdentifier, rsPassword)
				if err != nil {
					t.Fatalf("login: %v", err)
				}
				_, err = env.engine.SwitchRole(WithClientIP(context.Background(), "198.51.100.9"), refresh, "admin", RoleSwitchOptions{})
				return err
			},
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.reason+"/"+sc.wantErr.Error(), func(t *testing.T) {
			env := newRSEnv(t, sc.configure...)
			err := sc.run(env)
			if !errors.Is(err, sc.wantErr) {
				t.Fatalf("SwitchRole = %v, want %v", err, sc.wantErr)
			}

			ev := env.waitForAudit(auditEventRoleSwitchFailed, sc.reason)
			if ev.Success {
				t.Fatalf("a failure must not audit as success: %+v", ev)
			}
			if ev.Error != string(sc.wantCode) {
				t.Fatalf("audit error code = %q, want %q", ev.Error, sc.wantCode)
			}
			if env.auditCount(auditEventRoleSwitched) != 0 {
				t.Fatal("a failed switch must not emit role_switched")
			}
		})
	}
}

// A reused token books the existing reuse audit event as well, exactly once.
func TestSwitchRoleReuseEmitsTheRefreshReuseEvent(t *testing.T) {
	env := newRSEnv(t)
	_, r1 := env.login()
	if _, _, err := env.engine.Refresh(env.ctx(), r1); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, err := env.switchRole(r1, "admin", RoleSwitchOptions{}); !errors.Is(err, ErrRefreshReuse) {
		t.Fatalf("SwitchRole = %v", err)
	}
	env.waitForAudit(auditEventRefreshReuseDetected, "")
	env.waitForAudit(auditEventRoleSwitchFailed, "reuse_detected")
	if n := env.auditCount(auditEventRefreshReuseDetected); n != 1 {
		t.Fatalf("refresh_reuse_detected emitted %d times, want 1", n)
	}
}
