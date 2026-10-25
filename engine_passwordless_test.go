package goAuth

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

const (
	plUserID     = "ext1"
	plIdentifier = "external@example.com"
)

// plEnv is an rsEnv that also holds an account with no password, the shape
// external sign-in creates.
type plEnv struct {
	*rsEnv
	hashes *atomic.Int64
}

func newPLEnv(t *testing.T, opts ...rsOption) *plEnv {
	t.Helper()
	env := newRSEnv(t, opts...)
	env.up.addUser(UserRecord{
		UserID: plUserID, Identifier: plIdentifier, TenantID: env.tenant,
		PasswordHash: "", Status: AccountActive, Role: "teacher",
		PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
	})
	env.up.grant(plUserID, "teacher", "admin")

	// Count Argon2 verifications instead of timing them.
	n := &atomic.Int64{}
	real := env.engine.passwordHash.Verify
	env.engine.verifyHashFn = func(password, hash string) (bool, error) {
		n.Add(1)
		return real(password, hash)
	}
	return &plEnv{rsEnv: env, hashes: n}
}

// count runs fn and returns how many Argon2 verifications it performed.
func (env *plEnv) count(fn func()) int64 {
	before := env.hashes.Load()
	fn()
	return env.hashes.Load() - before
}

func plLimiterCfg(c *Config) {
	c.Security.EnableLoginFailureLimiter = true
	c.Security.MaxLoginAttempts = 3
	c.Security.LoginCooldownDuration = time.Minute
}

// Password login against an account with no password costs one Argon2
// verification, like a wrong password and like an unknown identifier, and
// fails with the same error.
//
// FAILED-BEFORE: the empty hash failed to parse and returned at once, a
// timing oracle for password-less accounts.
func TestPasswordlessLoginRunsDummyVerification(t *testing.T) {
	env := newPLEnv(t, rsConfig(plLimiterCfg))
	ctx := env.ctx()

	cases := []struct {
		name     string
		identity string
		password string
		reason   string
	}{
		{"wrong password", rsIdentifier, "wrong-password-123", "password_mismatch"},
		{"password-less account", plIdentifier, "any-password-123", "password_not_set"},
		{"unknown identifier", "nobody@example.com", "any-password-123", "user_not_found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			n := env.count(func() { _, _, err = env.engine.Login(ctx, tc.identity, tc.password) })
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("Login = %v, want ErrInvalidCredentials", err)
			}
			if n != 1 {
				t.Fatalf("%d Argon2 verifications, want exactly 1", n)
			}
			ev := env.waitForAudit(auditEventLoginFailure, tc.reason)
			if ev.Error != string(auditErrInvalidCredentials) {
				t.Fatalf("audit error = %q", ev.Error)
			}
		})
	}
}

// Whatever password is offered, including none, an account without one never
// logs in.
//
// ALREADY-TRUE: an empty hash never verified; pinned here.
func TestPasswordlessAccountNeverLogsIn(t *testing.T) {
	env := newPLEnv(t)
	for _, pw := range []string{"", "x", rsPassword, "correct-password-123", "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="} {
		if _, _, err := env.engine.Login(env.ctx(), plIdentifier, pw); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("Login(%q) = %v, want ErrInvalidCredentials", pw, err)
		}
	}
}

// A password-less account is counted by the login limiter, and by
// auto-lockout, exactly like an account with a wrong password: both give the
// same sequence of errors, so the response never reveals which kind it is.
//
// NEW-API.
func TestPasswordlessLoginIsLimitedLikeAWrongPassword(t *testing.T) {
	sequence := func(env *plEnv, identity string, n int) []string {
		var out []string
		for i := 0; i < n; i++ {
			_, _, err := env.engine.Login(env.ctx(), identity, "wrong-password-123")
			out = append(out, spbErr(err))
		}
		return out
	}

	t.Run("login limiter", func(t *testing.T) {
		env := newPLEnv(t, rsConfig(plLimiterCfg))
		withPassword := sequence(env, rsIdentifier, 6)
		without := sequence(env, plIdentifier, 6)
		if len(withPassword) != len(without) {
			t.Fatal("unequal sequences")
		}
		for i := range withPassword {
			if withPassword[i] != without[i] {
				t.Fatalf("attempt %d: with a password %s, without %s", i+1, withPassword[i], without[i])
			}
		}
		if without[3] == without[0] {
			t.Fatalf("the limiter never engaged: %v", without)
		}
		attempts, err := env.engine.GetLoginAttempts(env.ctx(), plIdentifier)
		if err != nil || attempts < 3 {
			t.Fatalf("GetLoginAttempts = %d, %v; password-less attempts must be counted", attempts, err)
		}
	})

	t.Run("auto lockout", func(t *testing.T) {
		env := newPLEnv(t, rsConfig(func(c *Config) {
			plLimiterCfg(c)
			c.Security.MaxLoginAttempts = 50
			c.Security.AutoLockoutEnabled = true
			c.Security.AutoLockoutThreshold = 2
			c.Security.AutoLockoutDuration = time.Hour
		}))
		withPassword := sequence(env, rsIdentifier, 3)
		without := sequence(env, plIdentifier, 3)
		for i := range withPassword {
			if withPassword[i] != without[i] {
				t.Fatalf("attempt %d: with a password %s, without %s", i+1, withPassword[i], without[i])
			}
		}
		if without[1] != spbErr(ErrInvalidCredentials) {
			t.Fatalf("sequence = %v; the attempt that locks the account is answered like any other", without)
		}
	})
}

// ChangePassword and VerifyPassword have nothing to verify for an account
// without a password. They fail with ErrPasswordNotSet after one dummy
// verification, and the attempt still counts toward the password-verify limiter.
//
// FAILED-BEFORE: both returned ErrInvalidCredentials without any Argon2 work.
func TestPasswordlessChangeAndVerifyPassword(t *testing.T) {
	calls := map[string]func(env *plEnv) error{
		"VerifyPassword": func(env *plEnv) error {
			return env.engine.VerifyPassword(env.ctx(), plUserID, "any-password-123")
		},
		"ChangePassword": func(env *plEnv) error {
			return env.engine.ChangePassword(env.ctx(), plUserID, "any-password-123", "brand-new-password-1")
		},
	}
	events := map[string]string{"VerifyPassword": auditEventPasswordVerifyFailure, "ChangePassword": auditEventPasswordChangeFailure}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			env := newPLEnv(t, rsConfig(plLimiterCfg))
			var err error
			n := env.count(func() { err = call(env) })
			if !errors.Is(err, ErrPasswordNotSet) {
				t.Fatalf("%s = %v, want ErrPasswordNotSet", name, err)
			}
			var ae *AuthError
			if !errors.As(err, &ae) || ae.Code != string(CodeAuthPasswordNotSet) || ae.Category != CategoryAuthState {
				t.Fatalf("error = %+v", err)
			}
			if n != 1 {
				t.Fatalf("%d Argon2 verifications, want exactly 1 (the dummy)", n)
			}
			env.waitForAudit(events[name], "password_not_set")

			// The attempt was counted: the limiter engages after MaxLoginAttempts.
			if got := env.mr.Exists("rl:pwdverify:fail:" + env.tenant + ":" + plUserID); !got {
				t.Fatal("the attempt was not counted by the password-verify limiter")
			}
			var last error
			for i := 0; i < 3; i++ {
				last = call(env)
			}
			if !errors.Is(last, ErrPasswordVerifyRateLimited) {
				t.Fatalf("after repeated attempts = %v, want ErrPasswordVerifyRateLimited", last)
			}
		})
	}
}

// An account with a password is untouched by the guard.
//
// ALREADY-TRUE.
func TestPasswordSetAccountsKeepTheirBehavior(t *testing.T) {
	env := newPLEnv(t)
	ctx := env.ctx()
	var err error
	if n := env.count(func() { err = env.engine.VerifyPassword(ctx, rsUserID, rsPassword) }); err != nil || n != 1 {
		t.Fatalf("VerifyPassword = %v after %d verifications", err, n)
	}
	if err := env.engine.VerifyPassword(ctx, rsUserID, "wrong-password-123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password = %v, want ErrInvalidCredentials", err)
	}
	if err := env.engine.ChangePassword(ctx, rsUserID, rsPassword, "brand-new-password-1"); err != nil {
		t.Fatalf("ChangePassword = %v", err)
	}
}

// A disabled account is reported as disabled before any password question.
//
// ALREADY-TRUE.
func TestPasswordlessDisabledAccountReportsStatusFirst(t *testing.T) {
	env := newPLEnv(t)
	user := env.up.users[plUserID]
	user.Status = AccountDisabled
	env.up.users[plUserID] = user
	if err := env.engine.VerifyPassword(env.ctx(), plUserID, "x"); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("VerifyPassword = %v, want ErrAccountDisabled", err)
	}
}

// A recent-authentication step-up offers "password" only to an account that
// has one, and a password proof from one that does not fails with
// ErrPasswordNotSet.
//
// FAILED-BEFORE: the factor list always named "password".
func TestStepUpFactorsOmitPasswordForPasswordlessAccounts(t *testing.T) {
	env := newPLEnv(t, stepUpAdminRecentAuth(5*time.Minute))
	ctx := env.ctx()

	user := env.up.users[plUserID]
	_, refresh, err := env.engine.issueSessionTokens(ctx, user, false)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	env.backdate(env.sidOf(refresh), time.Hour)

	res, err := env.switchRole(refresh, "admin", RoleSwitchOptions{})
	requireStepUp(t, res, err, []string{})

	res, err = env.switchRole(refresh, "admin", RoleSwitchOptions{Password: "any-password-123"})
	if res != nil || !errors.Is(err, ErrPasswordNotSet) {
		t.Fatalf("password proof without a password = %+v, %v; want ErrPasswordNotSet", res, err)
	}

	// An account with a password still gets the factor.
	_, refresh2 := env.login()
	env.backdate(env.sidOf(refresh2), time.Hour)
	res, err = env.switchRole(refresh2, "admin", RoleSwitchOptions{})
	requireStepUp(t, res, err, []string{"password"})
}

// Password reset sets the first password; afterwards the account behaves like
// any other.
//
// ALREADY-TRUE: the reset flow never read the old hash; pinned here.
func TestPasswordResetSetsAFirstPassword(t *testing.T) {
	env := newPLEnv(t, rsConfig(func(c *Config) { c.PasswordReset = testResetConfig(ResetToken) }))
	ctx := context.Background()

	challenge, err := env.engine.RequestPasswordReset(ctx, plIdentifier)
	if err != nil || challenge == "" {
		t.Fatalf("RequestPasswordReset = %q, %v", challenge, err)
	}
	if err := env.engine.ConfirmPasswordReset(ctx, challenge, "first-password-123"); err != nil {
		t.Fatalf("ConfirmPasswordReset = %v", err)
	}
	if env.up.users[plUserID].PasswordHash == "" {
		t.Fatal("the reset did not store a password")
	}
	if _, _, err := env.engine.Login(ctx, plIdentifier, "first-password-123"); err != nil {
		t.Fatalf("Login with the first password = %v", err)
	}
	if err := env.engine.VerifyPassword(ctx, plUserID, "first-password-123"); err != nil {
		t.Fatalf("VerifyPassword after the reset = %v", err)
	}
	if err := env.engine.ChangePassword(ctx, plUserID, "first-password-123", "second-password-123"); err != nil {
		t.Fatalf("ChangePassword after the reset = %v", err)
	}
}
