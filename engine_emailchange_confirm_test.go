package goAuth

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal/stores"
	"github.com/MrEthical07/goAuth/session"
	"github.com/redis/go-redis/v9"
)

// All tests in this file are NEW-API (ConfirmEmailChange, CancelEmailChange).

func TestConfirmEmailChangeSuccess(t *testing.T) {
	env := newECEnv(t, nil)
	_, refreshA := env.login()
	_, refreshB := env.login()
	_, refreshC := env.login()
	sidA, sidB, sidC := env.sidOf(refreshA), env.sidOf(refreshB), env.sidOf(refreshC)
	env.setAssurance(sidB, session.Assurance{MFAAt: time.Now().Unix(), MFAMethod: "totp", AuthAt: time.Now().Unix()})

	req := env.mustRequest(ecNewEmail)
	res := env.mustConfirm(req, ConfirmEmailChangeOptions{KeepSessionID: sidA})

	if res.UserID != rsUserID || res.OldEmail != rsIdentifier || res.NewEmail != ecNewEmail || !res.SessionsRevoked {
		t.Fatalf("result = %+v", res)
	}
	got := env.user(rsUserID)
	if got.Identifier != ecNewEmail {
		t.Fatalf("identifier = %q, want %q", got.Identifier, ecNewEmail)
	}
	if got.AccountVersion != 2 {
		t.Fatalf("AccountVersion = %d, want it bumped to 2", got.AccountVersion)
	}
	if env.up.updateIdentifierCalls != 1 {
		t.Fatalf("UpdateIdentifier called %d times", env.up.updateIdentifierCalls)
	}

	// Every session but the one named is gone, with its proof key; the kept
	// session is counted and still validates.
	if !env.hasSession(sidA) || env.hasSession(sidB) || env.hasSession(sidC) {
		t.Fatalf("sessions after the change: A=%v B=%v C=%v", env.hasSession(sidA), env.hasSession(sidB), env.hasSession(sidC))
	}
	if ids := env.sessionIDs(); len(ids) != 1 || ids[0] != sidA {
		t.Fatalf("user index = %v", ids)
	}
	if keys := env.keys("asa:*"); len(keys) != 0 {
		t.Fatalf("MFA-proof keys left behind: %v", keys)
	}
	if n, _ := env.engine.sessionStore.TenantSessionCount(context.Background(), env.tenant); n != 1 {
		t.Fatalf("tenant counter = %d, want 1", n)
	}
	if keys := env.changeKeys(); len(keys) != 0 {
		t.Fatalf("the challenge outlived its use: %v", keys)
	}

	// One use only.
	if _, err := env.confirm(req, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
		t.Fatalf("a second confirm = %v, want ErrEmailChangeInvalid", err)
	}

	ev := env.waitForAudit(auditEventEmailChangeConfirmed, "")
	if !ev.Success || ev.Metadata["new_email"] != "n***@example.com" || ev.Metadata["sessions_revoked"] != "true" {
		t.Fatalf("audit = %+v", ev)
	}
}

func TestConfirmEmailChangeSessionRules(t *testing.T) {
	t.Run("no session named: everything is revoked", func(t *testing.T) {
		env := newECEnv(t, nil)
		_, r1 := env.login()
		_, r2 := env.login()
		env.mustConfirm(env.mustRequest(ecNewEmail), ConfirmEmailChangeOptions{})
		if env.hasSession(env.sidOf(r1)) || env.hasSession(env.sidOf(r2)) {
			t.Fatal("a session survived an email change that named none to keep")
		}
	})

	t.Run("another user's session is ignored and untouched", func(t *testing.T) {
		env := newECEnv(t, nil)
		env.addOther("u2", "second@example.com")
		_, mine := env.login()
		otherSID := env.plantSession("u2")

		env.mustConfirm(env.mustRequest(ecNewEmail), ConfirmEmailChangeOptions{KeepSessionID: otherSID})
		if env.hasSession(env.sidOf(mine)) {
			t.Fatal("naming another user's session spared the caller's own sessions")
		}
		if !env.hasSession(otherSID) {
			t.Fatal("the other user's session was revoked")
		}
	})

	t.Run("an unknown or expired session is ignored", func(t *testing.T) {
		env := newECEnv(t, nil)
		_, mine := env.login()
		expired := env.plantSession(rsUserID)
		sess := env.peek(expired)
		sess.ExpiresAt = time.Now().Add(-time.Minute).Unix()
		if err := env.engine.sessionStore.Save(context.Background(), sess, time.Hour); err != nil {
			t.Fatal(err)
		}
		req := env.mustRequest(ecNewEmail)
		env.mustConfirm(req, ConfirmEmailChangeOptions{KeepSessionID: expired})
		if env.hasSession(env.sidOf(mine)) {
			t.Fatal("an expired KeepSessionID spared the other sessions")
		}
		env2 := newECEnv(t, nil)
		_, mine2 := env2.login()
		env2.mustConfirm(env2.mustRequest(ecNewEmail), ConfirmEmailChangeOptions{KeepSessionID: "does-not-exist"})
		if env2.hasSession(env2.sidOf(mine2)) {
			t.Fatal("an unknown KeepSessionID spared the other sessions")
		}
	})

	t.Run("KeepOtherSessions leaves everything alone", func(t *testing.T) {
		env := newECEnv(t, func(c *EmailChangeConfig) { c.KeepOtherSessions = true })
		_, r1 := env.login()
		_, r2 := env.login()
		res := env.mustConfirm(env.mustRequest(ecNewEmail), ConfirmEmailChangeOptions{})
		if res.SessionsRevoked {
			t.Fatal("SessionsRevoked = true with KeepOtherSessions")
		}
		if !env.hasSession(env.sidOf(r1)) || !env.hasSession(env.sidOf(r2)) {
			t.Fatal("KeepOtherSessions revoked a session")
		}
		if !hasLintCode(env.cfg.Lint(), "email_change_keeps_other_sessions") {
			t.Fatal("expected the email_change_keeps_other_sessions lint note")
		}
	})

	t.Run("revocation failure reports both the change and the error", func(t *testing.T) {
		env := newECEnv(t, nil)
		env.login()
		req := env.mustRequest(ecNewEmail)
		// Break only the user's session index; the challenge store, the marker
		// and the provider keep working.
		hook := &keyFailHook{substr: "au:"}
		env.rdb.AddHook(hook)
		hook.on.Store(true)

		res, err := env.confirm(req, ConfirmEmailChangeOptions{})
		if !errors.Is(err, ErrSessionInvalidationFailed) {
			t.Fatalf("err = %v, want ErrSessionInvalidationFailed", err)
		}
		if res == nil || res.NewEmail != ecNewEmail || res.OldEmail != rsIdentifier || res.SessionsRevoked {
			t.Fatalf("the change happened, so the result must say so: %+v", res)
		}
		if got := env.user(rsUserID); got.Identifier != ecNewEmail {
			t.Fatal("the identifier did not change")
		}
		ev := env.waitForAudit(auditEventEmailChangeConfirmed, "")
		if ev.Metadata["sessions_revoked"] != "false" {
			t.Fatalf("audit = %+v", ev)
		}
	})
}

// keyFailHook fails every Redis command that names a key containing substr,
// while on.
type keyFailHook struct {
	substr string
	on     atomic.Bool
}

func (h *keyFailHook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *keyFailHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if h.on.Load() {
			for _, a := range cmd.Args()[1:] {
				if s, ok := a.(string); ok && strings.Contains(s, h.substr) {
					return errors.New("redis down for " + h.substr)
				}
			}
		}
		return next(ctx, cmd)
	}
}

func (h *keyFailHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func hasLintCode(res LintResult, code string) bool {
	for _, w := range res {
		if w.Code == code {
			return true
		}
	}
	return false
}

// plantSession stores a session for userID directly.
func (env *ecEnv) plantSession(userID string) string {
	env.t.Helper()
	sess := env.peek(env.sidOf(func() string { _, r := env.login(); return r }()))
	sess.UserID = userID
	sess.SessionID = "planted-" + userID
	if err := env.engine.sessionStore.Save(context.Background(), sess, time.Hour); err != nil {
		env.t.Fatalf("plant session: %v", err)
	}
	return sess.SessionID
}

func TestConfirmEmailChangeWrongCodes(t *testing.T) {
	t.Run("attempts are counted and the challenge dies at the limit", func(t *testing.T) {
		env := newECEnv(t, nil) // MaxAttempts 3
		req := env.mustRequest(ecNewEmail)
		wrong := wrongOTP(req.Code)

		for i := 1; i < 3; i++ {
			if _, err := env.engine.ConfirmEmailChange(env.ctx(), req.VerificationID, wrong, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
				t.Fatalf("attempt %d = %v", i, err)
			}
			if len(env.changeKeys()) == 0 {
				t.Fatalf("the challenge died after %d of 3 attempts", i)
			}
		}
		if _, err := env.engine.ConfirmEmailChange(env.ctx(), req.VerificationID, wrong, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
			t.Fatalf("third attempt = %v", err)
		}
		if keys := env.changeKeys(); len(keys) != 0 {
			t.Fatalf("the challenge survived its last attempt: %v", keys)
		}
		// Even the right code is dead now.
		if _, err := env.confirm(req, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
			t.Fatalf("the right code after the limit = %v", err)
		}
		env.waitForAudit(auditEventEmailChangeFailure, "attempts")
		if got := env.user(rsUserID); got.Identifier != rsIdentifier {
			t.Fatal("the identifier changed without a correct code")
		}
	})

	t.Run("a correct code after wrong ones still works", func(t *testing.T) {
		env := newECEnv(t, nil)
		req := env.mustRequest(ecNewEmail)
		_, _ = env.engine.ConfirmEmailChange(env.ctx(), req.VerificationID, wrongOTP(req.Code), ConfirmEmailChangeOptions{})
		env.mustConfirm(req, ConfirmEmailChangeOptions{})
	})

	t.Run("malformed input is invalid", func(t *testing.T) {
		env := newECEnv(t, nil)
		req := env.mustRequest(ecNewEmail)
		for _, c := range []struct{ id, code string }{
			{"", req.Code}, {req.VerificationID, ""}, {"no-colon", req.Code},
			{req.VerificationID, "12ab56"}, {req.VerificationID, "123"}, {":x", req.Code}, {"0:", req.Code},
		} {
			if _, err := env.engine.ConfirmEmailChange(env.ctx(), c.id, c.code, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
				t.Fatalf("ConfirmEmailChange(%q, %q) = %v", c.id, c.code, err)
			}
		}
		env.mustConfirm(req, ConfirmEmailChangeOptions{}) // none of that burned the challenge
	})

	t.Run("unknown challenge", func(t *testing.T) {
		env := newECEnv(t, nil)
		_, err := env.engine.ConfirmEmailChange(env.ctx(), env.tenant+":"+strings.Repeat("A", 22), "123456", ConfirmEmailChangeOptions{})
		requireCode(t, err, CodeAuthEmailChangeInvalid)
	})
}

func wrongOTP(code string) string {
	b := []byte(code)
	if b[0] == '9' {
		b[0] = '0'
	} else {
		b[0]++
	}
	return string(b)
}

func TestConfirmEmailChangeExpiry(t *testing.T) {
	t.Run("the key lifetime ends the challenge", func(t *testing.T) {
		env := newECEnv(t, nil)
		req := env.mustRequest(ecNewEmail)
		env.mr.FastForward(11 * time.Minute)
		if _, err := env.confirm(req, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
			t.Fatalf("confirm after expiry = %v", err)
		}
		if got := env.user(rsUserID); got.Identifier != rsIdentifier {
			t.Fatal("an expired challenge changed the identifier")
		}
	})

	t.Run("a record past its own expiry is refused as expired and deleted", func(t *testing.T) {
		env := newECEnv(t, nil)
		req := env.mustRequest(ecNewEmail)
		_, rawID, _ := strings.Cut(req.VerificationID, ":")
		hash, err := parseEmailVerificationChallengeCode(VerificationOTP, rawID, req.Code, 6)
		if err != nil {
			t.Fatal(err)
		}
		stale := &stores.EmailChangeRecord{
			UserID: rsUserID, OldIdentifier: rsIdentifier, NewIdentifier: ecNewEmail, AccountVersion: 1,
			SecretHash: hash, ExpiresAt: time.Now().Add(-time.Minute).Unix(), Strategy: int(VerificationOTP),
		}
		if err := env.engine.emailChangeStore.Save(context.Background(), env.tenant, rawID, stale, time.Hour); err != nil {
			t.Fatal(err)
		}
		if _, err := env.confirm(req, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
			t.Fatalf("= %v", err)
		}
		env.waitForAudit(auditEventEmailChangeFailure, "expired")
		if keys := env.changeKeys(); len(keys) != 0 {
			t.Fatalf("an expired challenge was left in place: %v", keys)
		}
	})
}

func TestConfirmEmailChangeStale(t *testing.T) {
	t.Run("the account version moved after the request", func(t *testing.T) {
		env := newECEnv(t, nil)
		req := env.mustRequest(ecNewEmail)
		u := env.user(rsUserID)
		u.AccountVersion++
		env.setUser(u)

		_, err := env.confirm(req, ConfirmEmailChangeOptions{})
		requireCode(t, err, CodeAuthEmailChangeStale)
		if env.up.updateIdentifierCalls != 0 {
			t.Fatal("the provider was asked to change a stale request")
		}
		if got := env.user(rsUserID); got.Identifier != rsIdentifier {
			t.Fatal("a stale request changed the identifier")
		}
		env.waitForAudit(auditEventEmailChangeFailure, "stale")
		if keys := env.changeKeys(); len(keys) != 0 {
			t.Fatalf("a stale challenge was left in place: %v", keys)
		}
		if _, err := env.confirm(req, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
			t.Fatalf("retrying a stale challenge = %v", err)
		}
	})

	t.Run("the provider's compare-and-set loses a race", func(t *testing.T) {
		env := newECEnv(t, nil)
		req := env.mustRequest(ecNewEmail)
		env.up.beforeUpdateIdentifier = func() {
			// Another writer changes the email between the engine's re-load and
			// the provider's compare-and-set.
			env.up.mu.Lock()
			u := env.up.users[rsUserID]
			u.Identifier = "someone.else@example.com"
			env.up.users[rsUserID] = u
			env.up.mu.Unlock()
		}
		_, err := env.confirm(req, ConfirmEmailChangeOptions{})
		requireCode(t, err, CodeAuthEmailChangeStale)
		if got := env.user(rsUserID); got.Identifier != "someone.else@example.com" {
			t.Fatalf("identifier = %q", got.Identifier)
		}
	})

	t.Run("the status changed after the request", func(t *testing.T) {
		env := newECEnv(t, nil)
		req := env.mustRequest(ecNewEmail)
		u := env.user(rsUserID)
		u.Status = AccountDisabled
		env.setUser(u)
		_, err := env.confirm(req, ConfirmEmailChangeOptions{})
		if !errors.Is(err, ErrAccountDisabled) {
			t.Fatalf("= %v", err)
		}
		env.waitForAudit(auditEventEmailChangeFailure, "status")
	})

	t.Run("the user is gone", func(t *testing.T) {
		env := newECEnv(t, nil)
		req := env.mustRequest(ecNewEmail)
		env.up.mu.Lock()
		delete(env.up.users, rsUserID)
		env.up.mu.Unlock()
		if _, err := env.confirm(req, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
			t.Fatalf("= %v", err)
		}
	})
}

func TestConfirmEmailChangeUniquenessIsEnforcedAtConfirm(t *testing.T) {
	env := newECEnv(t, nil)
	req := env.mustRequest("Taken@Example.com") // the request does not mind
	env.addOther("u-taken", "taken@example.com")

	_, err := env.confirm(req, ConfirmEmailChangeOptions{})
	ae := requireCode(t, err, CodeAuthEmailInUse)
	if ae.Category != CategoryAuthState {
		t.Fatalf("category = %s", ae.Category)
	}
	if !errors.Is(err, ErrEmailInUse) {
		t.Fatalf("err = %v", err)
	}
	if got := env.user(rsUserID); got.Identifier != rsIdentifier || got.AccountVersion != 1 {
		t.Fatalf("a refused change touched the account: %+v", got)
	}
	env.waitForAudit(auditEventEmailChangeFailure, "in_use")
	if _, err := env.confirm(req, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
		t.Fatalf("the challenge must be spent after the refusal, got %v", err)
	}
}

func TestConfirmEmailChangeProviderFailures(t *testing.T) {
	t.Run("an unexpected provider error is an outage", func(t *testing.T) {
		env := newECEnv(t, nil)
		req := env.mustRequest(ecNewEmail)
		env.up.updateIdentifierErr = errors.New("db down")
		_, err := env.confirm(req, ConfirmEmailChangeOptions{})
		ae := requireCode(t, err, CodeSystemUnavailable)
		if ae.Category != CategorySystem {
			t.Fatalf("category = %s", ae.Category)
		}
		env.waitForAudit(auditEventEmailChangeFailure, "unavailable")
		if got := env.user(rsUserID); got.Identifier != rsIdentifier {
			t.Fatal("identifier changed despite the provider error")
		}
	})

	t.Run("a provider that reports not-found is invalid", func(t *testing.T) {
		env := newECEnv(t, nil)
		req := env.mustRequest(ecNewEmail)
		env.up.updateIdentifierErr = ErrUserNotFound
		if _, err := env.confirm(req, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
			t.Fatalf("= %v", err)
		}
	})

	t.Run("the user lookup failing is an outage", func(t *testing.T) {
		env := newECEnv(t, nil)
		req := env.mustRequest(ecNewEmail)
		env.up.setLookupErr(errors.New("db down"))
		_, err := env.confirm(req, ConfirmEmailChangeOptions{})
		requireCode(t, err, CodeSystemUnavailable)
	})
}

func TestCancelEmailChange(t *testing.T) {
	env := newECEnv(t, nil)
	req := env.mustRequest(ecNewEmail)

	if err := env.engine.CancelEmailChange(env.ctx(), rsUserID); err != nil {
		t.Fatalf("CancelEmailChange: %v", err)
	}
	if keys := env.changeKeys(); len(keys) != 0 {
		t.Fatalf("cancel left %v", keys)
	}
	if _, err := env.confirm(req, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
		t.Fatalf("confirm after cancel = %v", err)
	}
	// Idempotent, and a user with nothing pending is fine.
	for _, id := range []string{rsUserID, rsUserID, "nobody", ""} {
		if err := env.engine.CancelEmailChange(env.ctx(), id); err != nil {
			t.Fatalf("CancelEmailChange(%q) = %v", id, err)
		}
	}
	// Cancelling one user's change leaves another's alone.
	env.addOther("u2", "second@example.com")
	mine := env.mustRequest(ecNewEmail)
	if _, err := env.engine.RequestEmailChange(env.ctx(), "u2", "other@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := env.engine.CancelEmailChange(env.ctx(), "u2"); err != nil {
		t.Fatal(err)
	}
	env.mustConfirm(mine, ConfirmEmailChangeOptions{})
}

func TestEmailChangeStrategies(t *testing.T) {
	for name, strategy := range map[string]VerificationStrategyType{"token": VerificationToken, "uuid": VerificationUUID, "otp": VerificationOTP} {
		t.Run(name, func(t *testing.T) {
			env := newECEnv(t, func(c *EmailChangeConfig) {
				c.Strategy = strategy
				if strategy != VerificationOTP {
					c.VerificationTTL = time.Hour
					c.MaxAttempts = 8
				}
			})
			req := env.mustRequest(ecNewEmail)
			if strategy == VerificationOTP && len(req.Code) != 6 {
				t.Fatalf("code = %q", req.Code)
			}
			if strategy != VerificationOTP && len(req.Code) < 20 {
				t.Fatalf("a %s code should be long, got %q", name, req.Code)
			}
			if _, err := env.engine.ConfirmEmailChange(env.ctx(), req.VerificationID, req.Code+"x", ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
				t.Fatalf("a mangled code = %v", err)
			}
			env.mustConfirm(req, ConfirmEmailChangeOptions{})
		})
	}
	t.Run("a strategy change between request and confirm does not match", func(t *testing.T) {
		env := newECEnv(t, nil)
		req := env.mustRequest(ecNewEmail)
		env.engine.config.EmailChange.Strategy = VerificationToken
		if _, err := env.confirm(req, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
			t.Fatalf("= %v", err)
		}
	})
}

func TestEmailChangePasswordlessUser(t *testing.T) {
	env := newECEnv(t, nil)
	u := env.user(rsUserID)
	u.PasswordHash = ""
	env.setUser(u)

	req := env.mustRequest(ecNewEmail)
	res := env.mustConfirm(req, ConfirmEmailChangeOptions{})
	if res.NewEmail != ecNewEmail {
		t.Fatalf("result = %+v", res)
	}
	if got := env.user(rsUserID); got.Identifier != ecNewEmail || got.PasswordHash != "" {
		t.Fatalf("account = %+v", got)
	}
}
