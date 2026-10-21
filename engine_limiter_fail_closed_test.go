package goAuth

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// limiterBreaker makes the limiter backend fail while leaving every other
// Redis key (sessions, challenges, TOTP state) alone: any command that names an
// "rl:" key fails with a connection-style error. Every limiter in goAuth keeps
// its counters under that prefix.
type limiterBreaker struct {
	mode   atomic.Int32 // breakOff, breakAll, breakReads or breakWrites
	filter atomic.Value // when set to a string, only limiter keys containing it break
}

const (
	breakOff int32 = iota
	breakAll
	breakReads  // GET: the "is this caller already limited" checks
	breakWrites // everything else: counting, reserving, resetting
)

var errLimiterBackendDown = errors.New("limiter backend down")

func (b *limiterBreaker) DialHook(next redis.DialHook) redis.DialHook { return next }

func (b *limiterBreaker) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if b.breaks(cmd.Args()) {
			return errLimiterBackendDown
		}
		return next(ctx, cmd)
	}
}

func (b *limiterBreaker) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, cmd := range cmds {
			if b.breaks(cmd.Args()) {
				return errLimiterBackendDown
			}
		}
		return next(ctx, cmds)
	}
}

func (b *limiterBreaker) breaks(args []interface{}) bool {
	mode := b.mode.Load()
	if mode == breakOff || len(args) == 0 {
		return false
	}
	only, _ := b.filter.Load().(string)
	touches := false
	for _, a := range args[1:] {
		if s, ok := a.(string); ok && strings.Contains(s, "rl:") && strings.Contains(s, only) {
			touches = true
			break
		}
	}
	if !touches {
		return false
	}
	name, _ := args[0].(string)
	isRead := strings.EqualFold(name, "get")
	switch mode {
	case breakReads:
		return isRead
	case breakWrites:
		return !isRead
	}
	return true
}

func (b *limiterBreaker) set(mode int32) { b.mode.Store(mode) }

func limiterFailClosedConfig(closed bool) rsOption {
	return rsConfig(func(c *Config) {
		c.Security.LimiterFailClosed = closed
		c.Security.EnableLoginFailureLimiter = true
		c.EmailVerification = testEmailVerificationConfig(VerificationOTP)
		c.PasswordReset = testResetConfig(ResetOTP)
		c.RoleSwitch.MaxAttempts = 50
		c.TOTP.EnforceReplayProtection = false
		c.EmailChange = EmailChangeConfig{Enabled: true, Strategy: VerificationOTP, OTPDigits: 6, VerificationTTL: 10 * time.Minute, MaxAttempts: 3, RequestMaxAttempts: 50}
	})
}

// limiterPath is one place a request is gated on a limiter. prep runs with the
// backend healthy and returns the call to make once it is broken.
type limiterPath struct {
	name  string
	scope string // the limiter_fail_open event's scope
	mode  int32
	prep  func(t *testing.T, env *rsEnv) func() error
	// wantOpen reports whether, with the flag off, the outcome is one the
	// request would have had without any outage.
	wantOpen func(err error) bool
}

func isNil(err error) bool { return err == nil }

func isCode(code AuthCode) func(error) bool {
	return func(err error) bool {
		var ae *AuthError
		return errors.As(err, &ae) && ae.Code == string(code)
	}
}

func limiterPaths() []limiterPath {
	const newPassword = "another-password-789"
	return []limiterPath{
		{name: "login: check", scope: "login", mode: breakReads, wantOpen: isNil,
			prep: func(t *testing.T, env *rsEnv) func() error {
				return func() error { _, _, err := env.engine.Login(env.ctx(), rsIdentifier, rsPassword); return err }
			}},
		{name: "login: failure counter", scope: "login", mode: breakWrites, wantOpen: isCode(CodeAuthInvalidCredentials),
			prep: func(t *testing.T, env *rsEnv) func() error {
				return func() error { _, _, err := env.engine.Login(env.ctx(), rsIdentifier, "wrong-password-1"); return err }
			}},
		{name: "login: unknown identifier counter", scope: "login", mode: breakWrites, wantOpen: isCode(CodeAuthInvalidCredentials),
			prep: func(t *testing.T, env *rsEnv) func() error {
				return func() error { _, _, err := env.engine.Login(env.ctx(), "nobody@example.com", rsPassword); return err }
			}},
		{name: "login: empty password counter", scope: "login", mode: breakWrites, wantOpen: isCode(CodeAuthInvalidCredentials),
			prep: func(t *testing.T, env *rsEnv) func() error {
				return func() error { _, _, err := env.engine.Login(env.ctx(), rsIdentifier, ""); return err }
			}},
		{name: "password verify: VerifyPassword", scope: "password_verify", mode: breakAll, wantOpen: isNil,
			prep: func(t *testing.T, env *rsEnv) func() error {
				return func() error { return env.engine.VerifyPassword(env.ctx(), rsUserID, rsPassword) }
			}},
		{name: "password verify: ChangePassword", scope: "password_verify", mode: breakAll, wantOpen: isNil,
			prep: func(t *testing.T, env *rsEnv) func() error {
				return func() error { return env.engine.ChangePassword(env.ctx(), rsUserID, rsPassword, newPassword) }
			}},
		{name: "totp: check", scope: "totp", mode: breakReads, wantOpen: isNil,
			prep: func(t *testing.T, env *rsEnv) func() error {
				secret := env.enableTOTP()
				return func() error { return env.engine.VerifyTOTP(env.ctx(), rsUserID, env.totpCode(secret)) }
			}},
		{name: "totp: failure counter", scope: "totp", mode: breakWrites, wantOpen: isCode(CodeAuthTOTPInvalid),
			prep: func(t *testing.T, env *rsEnv) func() error {
				env.enableTOTP()
				return func() error { return env.engine.VerifyTOTP(env.ctx(), rsUserID, "000000") }
			}},
		{name: "backup code: check", scope: "backup_code", mode: breakReads, wantOpen: isNil,
			prep: func(t *testing.T, env *rsEnv) func() error {
				env.enableTOTP()
				codes, err := env.engine.GenerateBackupCodes(env.ctx(), rsUserID)
				if err != nil {
					t.Fatalf("GenerateBackupCodes: %v", err)
				}
				return func() error { return env.engine.VerifyBackupCode(env.ctx(), rsUserID, codes[0]) }
			}},
		{name: "backup code: failure counter", scope: "backup_code", mode: breakWrites, wantOpen: isCode(CodeAuthMFABackupInvalid),
			prep: func(t *testing.T, env *rsEnv) func() error {
				env.enableTOTP()
				if _, err := env.engine.GenerateBackupCodes(env.ctx(), rsUserID); err != nil {
					t.Fatalf("GenerateBackupCodes: %v", err)
				}
				return func() error { return env.engine.VerifyBackupCode(env.ctx(), rsUserID, "AAAAA-BBBBB") }
			}},
		{name: "role switch", scope: "role_switch", mode: breakAll, wantOpen: isNil,
			prep: func(t *testing.T, env *rsEnv) func() error {
				_, refresh := env.login()
				return func() error { _, err := env.switchRole(refresh, "admin", RoleSwitchOptions{}); return err }
			}},
		{name: "account creation", scope: "account_creation", mode: breakAll, wantOpen: isNil,
			prep: func(t *testing.T, env *rsEnv) func() error {
				return func() error {
					_, err := env.engine.CreateAccount(env.ctx(), CreateAccountRequest{Identifier: "fresh@example.com", Password: "brand-new-password-1"})
					return err
				}
			}},
		{name: "email verification: request", scope: "email_verification_request", mode: breakAll, wantOpen: isNil,
			prep: func(t *testing.T, env *rsEnv) func() error {
				return func() error { _, err := env.engine.RequestEmailVerification(env.ctx(), rsIdentifier); return err }
			}},
		{name: "email verification: confirm", scope: "email_verification_confirm", mode: breakAll, wantOpen: isCode(CodeAuthVerificationInvalid),
			prep: func(t *testing.T, env *rsEnv) func() error {
				challenge, err := env.engine.RequestEmailVerification(env.ctx(), rsIdentifier)
				if err != nil {
					t.Fatalf("RequestEmailVerification: %v", err)
				}
				parts := strings.SplitN(challenge, ":", 3)
				if len(parts) != 3 {
					t.Fatalf("unexpected challenge %q", challenge)
				}
				return func() error { return env.engine.ConfirmEmailVerificationCode(env.ctx(), parts[1], parts[2]) }
			}},
		{name: "email change: request", scope: "email_change", mode: breakAll, wantOpen: isNil,
			prep: func(t *testing.T, env *rsEnv) func() error {
				return func() error {
					_, err := env.engine.RequestEmailChange(env.ctx(), rsUserID, "fresh.address@example.com")
					return err
				}
			}},
		{name: "password reset: request", scope: "password_reset_request", mode: breakAll, wantOpen: isNil,
			prep: func(t *testing.T, env *rsEnv) func() error {
				return func() error { _, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier); return err }
			}},
		{name: "password reset: confirm", scope: "password_reset_confirm", mode: breakAll, wantOpen: isNil,
			prep: func(t *testing.T, env *rsEnv) func() error {
				challenge, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
				if err != nil {
					t.Fatalf("RequestPasswordReset: %v", err)
				}
				return func() error { return env.engine.ConfirmPasswordReset(env.ctx(), challenge, newPassword) }
			}},
	}
}

func newLimiterEnv(t *testing.T, closed bool) (*rsEnv, *limiterBreaker) {
	t.Helper()
	env := newRSEnv(t, limiterFailClosedConfig(closed))
	br := &limiterBreaker{}
	env.rdb.AddHook(br)
	return env, br
}

func isSystemError(err error) bool {
	var ae *AuthError
	return errors.As(err, &ae) && ae.Category == CategorySystem
}

// With Security.LimiterFailClosed on, a limiter backend error on any limiter
// path refuses the request with a system error (503) instead of letting it
// through. Off (the default) the outcome is what it would have been with a
// healthy limiter.
//
// NEW-API (Security.LimiterFailClosed); the off rows are ALREADY-TRUE.
func TestLimiterFailClosedTurnsOutageIntoSystemError(t *testing.T) {
	for _, p := range limiterPaths() {
		t.Run(p.name+"/closed", func(t *testing.T) {
			env, br := newLimiterEnv(t, true)
			call := p.prep(t, env)
			br.set(p.mode)
			err := call()
			if err == nil || !isSystemError(err) {
				t.Fatalf("with the limiter down and LimiterFailClosed on, got %v, want a system error", err)
			}
			var ae *AuthError
			if !errors.As(err, &ae) || ae.Code == "" {
				t.Fatalf("expected a canonical AuthError, got %T", err)
			}
			ev := waitForLimiterEvent(t, env, p.scope)
			if ev.Metadata["fail_closed"] != "true" || ev.Metadata["policy"] != "fail_closed" {
				t.Fatalf("event metadata = %v, want fail_closed=true", ev.Metadata)
			}
			if env.metric(MetricLimiterFailOpen) == 0 {
				t.Fatal("the limiter failure metric was not counted")
			}
		})
		t.Run(p.name+"/open", func(t *testing.T) {
			env, br := newLimiterEnv(t, false)
			call := p.prep(t, env)
			br.set(p.mode)
			err := call()
			if !p.wantOpen(err) {
				t.Fatalf("with the limiter down and the default fail-open, got %v", err)
			}
			if isSystemError(err) {
				t.Fatalf("fail-open must not surface a system error, got %v", err)
			}
			ev := waitForLimiterEvent(t, env, p.scope)
			if _, ok := ev.Metadata["fail_closed"]; ok || ev.Metadata["policy"] != "fail_open" {
				t.Fatalf("event metadata = %v, want the unchanged fail_open event", ev.Metadata)
			}
		})
	}
}

func waitForLimiterEvent(t *testing.T, env *rsEnv, scope string) *AuditEvent {
	t.Helper()
	env.engine.Close() // flush the asynchronous dispatcher
	env.sink.mu.Lock()
	defer env.sink.mu.Unlock()
	for i := range env.sink.events {
		ev := env.sink.events[i]
		if ev.EventType == auditEventLimiterFailOpen && ev.Metadata["scope"] == scope {
			return &ev
		}
	}
	t.Fatalf("no %s event with scope %q was emitted", auditEventLimiterFailOpen, scope)
	return nil
}

// A rate-limit denial blocks whatever the flag says; the flag only changes what
// an outage means.
func TestLimiterFailClosedDoesNotChangeDenials(t *testing.T) {
	for _, closed := range []bool{false, true} {
		env := newRSEnv(t, limiterFailClosedConfig(closed), rsConfig(func(c *Config) {
			c.Security.MaxLoginAttempts = 2
		}))
		for i := 0; i < 3; i++ {
			_, _, _ = env.engine.Login(env.ctx(), rsIdentifier, "wrong-password-1")
		}
		if _, _, err := env.engine.Login(env.ctx(), rsIdentifier, rsPassword); !errors.Is(err, ErrLoginRateLimited) {
			t.Fatalf("closed=%v: a denied caller must stay denied, got %v", closed, err)
		}
	}
}

// A reset runs after the request already succeeded and only removes counts, so
// a failed reset never blocks, flag or no flag.
func TestLimiterFailClosedNeverBlocksOnCleanup(t *testing.T) {
	env, br := newLimiterEnv(t, true)
	br.set(breakAll)
	// Prepare a successful login with only the cleanup (reset) broken: let the
	// check and the reads through, fail the writes once the check is past.
	br.set(breakWrites)
	if _, _, err := env.engine.Login(env.ctx(), rsIdentifier, rsPassword); err != nil {
		t.Fatalf("a failing limiter reset after a good login must not fail the login: %v", err)
	}
	ev := waitForLimiterEvent(t, env, "login")
	if _, ok := ev.Metadata["fail_closed"]; ok {
		t.Fatalf("a cleanup failure is not a fail-closed decision: %v", ev.Metadata)
	}
}
