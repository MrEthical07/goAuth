package goAuth

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/MrEthical07/goAuth/internal"
)

// requireCode asserts err is an AuthError with the given code.
func requireCode(t *testing.T, err error, code AuthCode) *AuthError {
	t.Helper()
	ae := requireAuthError(t, err)
	if ae.Code != string(code) {
		t.Fatalf("error code = %s (%v), want %s", ae.Code, err, code)
	}
	return ae
}

// link stores an existing link, as if the account had linked it earlier.
func (env *extEnv) link(provider, subject, userID string) {
	env.t.Helper()
	env.up.emu.Lock()
	defer env.up.emu.Unlock()
	env.up.links[extKey(env.tenant, provider, subject)] = extLink{
		userID:   userID,
		identity: ExternalIdentity{Provider: provider, Subject: subject},
	}
}

func (env *extEnv) sessionOf(refresh string) (userID, profile string) {
	env.t.Helper()
	sid, _, err := internal.DecodeRefreshToken(refresh)
	if err != nil {
		env.t.Fatalf("decode refresh token: %v", err)
	}
	sess, err := env.engine.sessionStore.Peek(context.Background(), env.tenant, sid)
	if err != nil {
		env.t.Fatalf("peek session: %v", err)
	}
	return sess.UserID, sess.Profile
}

func (env *extEnv) mustLogin(spec extTokenSpec) *LoginResult {
	env.t.Helper()
	res, err := env.login(spec)
	if err != nil {
		env.t.Fatalf("LoginWithExternalIdentity: %v", err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		env.t.Fatalf("no tokens in %+v", res)
	}
	return res
}

// The account-resolution matrix: every branch of the algorithm.
//
// NEW-API.
func TestExternalLoginResolutionMatrix(t *testing.T) {
	t.Run("identity already linked signs in as that account", func(t *testing.T) {
		env := newExtEnv(t)
		env.link("google", "sub-linked", extLocalUserID)

		// No email in the token at all: the link alone suffices (Sign in with
		// Apple omits the email after the first sign-in).
		res := env.mustLogin(extTokenSpec{sub: "sub-linked"})
		if res.NewAccount || res.LinkedIdentity || res.MFARequired {
			t.Fatalf("result flags = %+v", res)
		}
		if uid, _ := env.sessionOf(res.RefreshToken); uid != extLocalUserID {
			t.Fatalf("session belongs to %q", uid)
		}
		auth, err := env.engine.Validate(env.ctx(), res.AccessToken, ModeStrict)
		if err != nil || auth.UserID != extLocalUserID {
			t.Fatalf("Validate = %+v, %v", auth, err)
		}
		if env.up.creates != 0 || env.up.linksMade != 0 {
			t.Fatalf("an existing link created %d accounts and %d links", env.up.creates, env.up.linksMade)
		}
	})

	t.Run("verified email, auto-link on, active account: linked", func(t *testing.T) {
		env := newExtEnv(t, extAutoLink())
		res := env.mustLogin(extTokenSpec{sub: "sub-new", email: extLocalEmail, verified: true})
		if !res.LinkedIdentity || res.NewAccount {
			t.Fatalf("result flags = %+v", res)
		}
		if uid, ok := env.up.linkedTo(env.tenant, "google", "sub-new"); !ok || uid != extLocalUserID {
			t.Fatalf("link = %q, %v", uid, ok)
		}
		if uid, _ := env.sessionOf(res.RefreshToken); uid != extLocalUserID {
			t.Fatalf("session belongs to %q", uid)
		}
		ev := env.waitForAudit(auditEventExternalLinked, "")
		if ev.UserID != extLocalUserID || ev.Metadata["provider"] != "google" || ev.Metadata["via"] != "verified_email" {
			t.Fatalf("external_identity_linked = %+v", ev)
		}

		// The next sign-in finds the link; nothing is linked again.
		again := env.mustLogin(extTokenSpec{sub: "sub-new"})
		if again.LinkedIdentity || env.up.linksMade != 1 {
			t.Fatalf("second sign-in: flags %+v, links made %d", again, env.up.linksMade)
		}
	})

	t.Run("matching account pending verification: refused, not linked", func(t *testing.T) {
		for name, opt := range map[string]extOption{"auto-link on": extAutoLink(), "auto-link off": extConfig(func(*Config) {})} {
			t.Run(name, func(t *testing.T) {
				env := newExtEnv(t, opt)
				env.addLocal(UserRecord{UserID: "pend1", Identifier: "pending@example.com", PasswordHash: "x", Status: AccountPendingVerification})
				_, err := env.login(extTokenSpec{sub: "sub-p", email: "pending@example.com", verified: true})
				requireCode(t, err, CodeAuthExternalLinkRequiresVerify)
				if !errors.Is(err, ErrExternalLinkRequiresVerification) || env.up.linkCount() != 0 {
					t.Fatalf("err = %v, links = %d", err, env.up.linkCount())
				}
				env.waitForAudit(auditEventExternalLoginFailure, "link_requires_verification")
			})
		}
	})

	t.Run("matching account disabled, locked or deleted: that status error, not linked", func(t *testing.T) {
		cases := map[AccountStatus]*AuthError{AccountDisabled: ErrAccountDisabled, AccountLocked: ErrAccountLocked, AccountDeleted: ErrAccountDeleted}
		for status, want := range cases {
			env := newExtEnv(t, extAutoLink())
			env.addLocal(UserRecord{UserID: "bad1", Identifier: "bad@example.com", PasswordHash: "x", Status: status})
			_, err := env.login(extTokenSpec{sub: "sub-b", email: "bad@example.com", verified: true})
			if !errors.Is(err, want) {
				t.Fatalf("status %d: err = %v, want %v", status, err, want)
			}
			if env.up.linkCount() != 0 {
				t.Fatalf("status %d: an unusable account was linked", status)
			}
			env.waitForAudit(auditEventExternalLoginFailure, "account_status")
		}
	})

	t.Run("linked account that is disabled: its status error", func(t *testing.T) {
		env := newExtEnv(t)
		env.addLocal(UserRecord{UserID: "off1", Identifier: "off@example.com", PasswordHash: "x", Status: AccountDisabled})
		env.link("google", "sub-off", "off1")
		_, err := env.login(extTokenSpec{sub: "sub-off"})
		if !errors.Is(err, ErrAccountDisabled) {
			t.Fatalf("err = %v, want ErrAccountDisabled", err)
		}
		env.waitForAudit(auditEventExternalLoginFailure, "account_status")
	})

	t.Run("matching account, auto-link off: link required, not linked", func(t *testing.T) {
		env := newExtEnv(t)
		_, err := env.login(extTokenSpec{sub: "sub-r", email: extLocalEmail, verified: true})
		requireCode(t, err, CodeAuthExternalLinkRequired)
		if !errors.Is(err, ErrExternalAccountLinkRequired) || env.up.linkCount() != 0 {
			t.Fatalf("err = %v, links = %d", err, env.up.linkCount())
		}
		env.waitForAudit(auditEventExternalLoginFailure, "link_required")
	})

	t.Run("no account, sign-up on: created password-less, linked, signed in", func(t *testing.T) {
		env := newExtEnv(t, extSignup())
		token, nonce := env.idp.token(extTokenSpec{sub: "sub-s", email: "fresh@example.com", verified: true})
		res, err := env.engine.LoginWithExternalIdentity(env.ctx(), "google", token, ExternalLoginOptions{Nonce: nonce, DisplayName: "  Fresh Person "})
		if err != nil {
			t.Fatalf("sign-up: %v", err)
		}
		if !res.NewAccount || res.LinkedIdentity {
			t.Fatalf("result flags = %+v", res)
		}
		in := env.up.lastCreate
		if in.PasswordHash != "" || in.Identifier != "fresh@example.com" || in.Role != "member" ||
			in.Status != AccountActive || in.TenantID != env.tenant ||
			in.PermissionVersion != 1 || in.RoleVersion != 1 || in.AccountVersion != 1 {
			t.Fatalf("CreateUserInput = %+v", in)
		}
		id := env.up.lastIdentity
		if id.Provider != "google" || id.Subject != "sub-s" || id.Email != "fresh@example.com" || !id.EmailVerified || id.DisplayName != "Fresh Person" || id.LinkedAt.IsZero() {
			t.Fatalf("identity = %+v", id)
		}
		if uid, ok := env.up.linkedTo(env.tenant, "google", "sub-s"); !ok || uid != res.NewUserID(env) {
			t.Fatalf("link = %q, %v", uid, ok)
		}
		ev := env.waitForAudit(auditEventAccountCreationSuccess, "")
		if ev.Metadata["method"] != "external" || ev.Metadata["role"] != "member" || ev.Metadata["identifier"] != "fresh@example.com" {
			t.Fatalf("account_creation_success = %+v", ev)
		}
		if env.metric(MetricAccountCreationSuccess) != 1 {
			t.Fatal("account creation metric not counted")
		}
	})

	t.Run("no account, sign-up off: not found", func(t *testing.T) {
		env := newExtEnv(t)
		_, err := env.login(extTokenSpec{sub: "sub-n", email: "nobody@example.com", verified: true})
		requireCode(t, err, CodeAuthExternalAccountNotFound)
		if env.up.creates != 0 {
			t.Fatal("an account was created with sign-up off")
		}
		env.waitForAudit(auditEventExternalLoginFailure, "account_not_found")
	})

	t.Run("email not verified or missing: email unverified, nothing used", func(t *testing.T) {
		for name, spec := range map[string]extTokenSpec{
			"verified false":       {sub: "u1", email: extLocalEmail, verified: false},
			"verified string":      {sub: "u2", email: extLocalEmail, verified: "false"},
			"verified claim empty": {sub: "u3", email: extLocalEmail},
			"no email":             {sub: "u4"},
		} {
			t.Run(name, func(t *testing.T) {
				// Both knobs on: even then an unverified email is never used.
				env := newExtEnv(t, extAutoLink(), extSignup())
				_, err := env.login(spec)
				requireCode(t, err, CodeAuthExternalEmailUnverified)
				if env.up.linkCount() != 0 || env.up.creates != 0 {
					t.Fatalf("links %d, creates %d", env.up.linkCount(), env.up.creates)
				}
				env.waitForAudit(auditEventExternalLoginFailure, "email_unverified")
			})
		}
	})

	t.Run("email_verified as the string true is accepted", func(t *testing.T) {
		env := newExtEnv(t, extAutoLink())
		res := env.mustLogin(extTokenSpec{provider: "apple", sub: "apple-sub", email: extLocalEmail, verified: "true", private: "false"})
		if !res.LinkedIdentity {
			t.Fatalf("result = %+v", res)
		}
	})

	t.Run("a provider failure is a service error, not a not-found", func(t *testing.T) {
		env := newExtEnv(t, extSignup())
		env.up.getErr = errors.New("database down")
		_, err := env.login(extTokenSpec{sub: "sub-x", email: "x@example.com", verified: true})
		requireCode(t, err, CodeSystemUnavailable)
		if env.up.creates != 0 {
			t.Fatal("an account was created while the identity lookup was failing")
		}
	})
}

// NewUserID is the ID of the account the sign-in created: the one account
// beyond the seeded one.
func (r *LoginResult) NewUserID(env *extEnv) string {
	uid, _ := env.sessionOf(r.RefreshToken)
	return uid
}

// A concurrent first sign-in of the same person produces exactly one account.
//
// NEW-API.
func TestExternalLoginConcurrentFirstSignUp(t *testing.T) {
	env := newExtEnv(t, extSignup())
	before := env.up.userCount()

	const n = 8
	results := make(chan *LoginResult, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		token, nonce := env.idp.token(extTokenSpec{sub: "sub-race", email: "race@example.com", verified: true})
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			res, err := env.engine.LoginWithExternalIdentity(env.ctx(), "google", token, ExternalLoginOptions{Nonce: nonce})
			if err != nil {
				errs <- err
				return
			}
			results <- res
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Fatalf("a concurrent sign-in failed: %v", err)
	}
	created, users := 0, map[string]bool{}
	for res := range results {
		if res.NewAccount {
			created++
		}
		uid, _ := env.sessionOf(res.RefreshToken)
		users[uid] = true
	}
	if created != 1 || len(users) != 1 {
		t.Fatalf("%d sign-ins created accounts, %d distinct users signed in; want 1 and 1", created, len(users))
	}
	if got := env.up.userCount() - before; got != 1 {
		t.Fatalf("%d accounts were created, want exactly 1", got)
	}
	if env.up.linkCount() != 1 {
		t.Fatalf("%d links exist, want 1", env.up.linkCount())
	}
}

// When creation loses to a concurrent winner, the resolution runs once more.
//
// NEW-API.
func TestExternalLoginDuplicateEmailReResolvesOnce(t *testing.T) {
	winner := func(p *extMockProvider) {
		// Between our lookup and our create, someone registers the address.
		p.beforeCreate = nil
		p.addUser(UserRecord{
			UserID: "winner", Identifier: "dup@example.com", TenantID: "0", PasswordHash: "x",
			Status: AccountActive, Role: "member", PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
		})
	}

	t.Run("the second pass finds the account: link required", func(t *testing.T) {
		env := newExtEnv(t, extSignup())
		env.up.beforeCreate = winner
		_, err := env.login(extTokenSpec{sub: "sub-d", email: "dup@example.com", verified: true})
		requireCode(t, err, CodeAuthExternalLinkRequired)
		if env.up.creates != 1 {
			t.Fatalf("create calls = %d, want 1", env.up.creates)
		}
	})

	t.Run("the second pass finds the account: auto-linked", func(t *testing.T) {
		env := newExtEnv(t, extSignup(), extAutoLink())
		env.up.beforeCreate = winner
		res := env.mustLogin(extTokenSpec{sub: "sub-d", email: "dup@example.com", verified: true})
		if !res.LinkedIdentity || res.NewAccount {
			t.Fatalf("result flags = %+v", res)
		}
		if uid, _ := env.sessionOf(res.RefreshToken); uid != "winner" {
			t.Fatalf("signed in as %q", uid)
		}
	})

	t.Run("a duplicate that persists is retried once, then reported", func(t *testing.T) {
		env := newExtEnv(t, extSignup())
		env.up.createErr = ErrProviderDuplicateIdentifier
		_, err := env.login(extTokenSpec{sub: "sub-d", email: "ghost@example.com", verified: true})
		requireCode(t, err, CodeAuthAccountExists)
		if env.up.creates != 2 {
			t.Fatalf("create calls = %d, want exactly 2 (one retry)", env.up.creates)
		}
		env.waitForAudit(auditEventExternalLoginFailure, "account_exists")
	})

	t.Run("an identity-in-use conflict is retried once, then reported", func(t *testing.T) {
		env := newExtEnv(t, extSignup())
		env.up.createErr = ErrExternalIdentityInUse
		_, err := env.login(extTokenSpec{sub: "sub-d", email: "ghost@example.com", verified: true})
		requireCode(t, err, CodeAuthExternalIdentityInUse)
		if env.up.creates != 2 {
			t.Fatalf("create calls = %d, want exactly 2", env.up.creates)
		}
	})

	t.Run("auto-link losing to another account is retried once", func(t *testing.T) {
		env := newExtEnv(t, extAutoLink())
		env.up.linkErr = ErrExternalIdentityInUse
		_, err := env.login(extTokenSpec{sub: "sub-d", email: extLocalEmail, verified: true})
		requireCode(t, err, CodeAuthExternalIdentityInUse)
		if env.up.linksMade != 2 {
			t.Fatalf("link calls = %d, want exactly 2", env.up.linksMade)
		}
	})

	t.Run("another provider error is not retried", func(t *testing.T) {
		env := newExtEnv(t, extSignup())
		env.up.createErr = errors.New("disk full")
		_, err := env.login(extTokenSpec{sub: "sub-d", email: "ghost@example.com", verified: true})
		requireCode(t, err, CodeSystemUnavailable)
		if env.up.creates != 1 {
			t.Fatalf("create calls = %d, want 1", env.up.creates)
		}
	})
}
