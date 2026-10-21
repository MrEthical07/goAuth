package goAuth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal"
)

func extMFA() extOption {
	return extConfig(func(c *Config) { c.TOTP.RequireForLogin = true })
}

func extProfiles() extOption {
	return extConfig(func(c *Config) {
		c.SessionProfiles.Profiles = spProfiles()
		c.SessionProfiles.DefaultProfile = "web"
		c.SessionProfiles.RememberMeProfile = "mobile"
		c.Session.JitterEnabled = false
	})
}

// With a second factor required, an external sign-in is the first step; the
// unchanged ConfirmLoginMFA finishes it.
//
// NEW-API.
func TestExternalLoginThenMFA(t *testing.T) {
	env := newExtEnv(t, extMFA())
	env.link("google", "sub-mfa", extLocalUserID)
	secret := enableUserTOTP(t, env.engine, extLocalUserID, env.cfg)

	res, err := env.login(extTokenSpec{sub: "sub-mfa"})
	if err != nil {
		t.Fatalf("first step: %v", err)
	}
	if !res.MFARequired || res.MFASession == "" || res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatalf("expected an MFA challenge and no tokens: %+v", res)
	}
	if res.MFAType != "totp" || len(res.MFATypes) != 1 {
		t.Fatalf("MFA types = %q %v", res.MFAType, res.MFATypes)
	}
	ids, _ := env.engine.sessionStore.ActiveSessionIDs(context.Background(), env.tenant, extLocalUserID)
	if len(ids) != 0 {
		t.Fatalf("a session exists before the second factor: %v", ids)
	}
	env.waitForAudit(auditEventMFARequired, "")
	if ev := env.waitForAudit(auditEventExternalLoginSuccess, ""); ev.Metadata["mfa_required"] != "true" {
		t.Fatalf("external_login_success = %+v", ev)
	}

	if _, err := env.engine.ConfirmLoginMFA(env.ctx(), res.MFASession, "000000"); !errors.Is(err, ErrMFALoginInvalid) {
		t.Fatalf("wrong code = %v", err)
	}
	done, err := env.engine.ConfirmLoginMFA(env.ctx(), res.MFASession, codeForOffset(t, secret, env.cfg.TOTP, 1))
	if err != nil || done.AccessToken == "" || done.RefreshToken == "" {
		t.Fatalf("second step: %+v, %v", done, err)
	}
	if uid, _ := env.sessionOf(done.RefreshToken); uid != extLocalUserID {
		t.Fatalf("session belongs to %q", uid)
	}
}

// A user without TOTP is not asked for MFA just because it is required for
// those who have it.
//
// ALREADY-TRUE for password login; NEW-API for external.
func TestExternalLoginWithoutEnrolledTOTPIssuesTokens(t *testing.T) {
	env := newExtEnv(t, extMFA())
	env.link("google", "sub-nomfa", extLocalUserID)
	res := env.mustLogin(extTokenSpec{sub: "sub-nomfa"})
	if res.MFARequired {
		t.Fatalf("result = %+v", res)
	}
}

// The session profile is chosen up front, honoured, and survives the MFA hop.
//
// NEW-API.
func TestExternalLoginSessionProfiles(t *testing.T) {
	t.Run("default, explicit and remember-me profiles", func(t *testing.T) {
		env := newExtEnv(t, extProfiles())
		env.link("google", "sub-p", extLocalUserID)

		res := env.mustLogin(extTokenSpec{sub: "sub-p"})
		if _, profile := env.sessionOf(res.RefreshToken); profile != "web" {
			t.Fatalf("default profile = %q, want web", profile)
		}

		token, nonce := env.idp.token(extTokenSpec{sub: "sub-p"})
		res, err := env.engine.LoginWithExternalIdentity(WithSessionProfile(env.ctx(), "mobile"), "google", token, ExternalLoginOptions{Nonce: nonce})
		if err != nil {
			t.Fatalf("mobile profile: %v", err)
		}
		if _, profile := env.sessionOf(res.RefreshToken); profile != "mobile" {
			t.Fatalf("explicit profile = %q, want mobile", profile)
		}

		token, nonce = env.idp.token(extTokenSpec{sub: "sub-p"})
		res, err = env.engine.LoginWithExternalIdentity(env.ctx(), "google", token, ExternalLoginOptions{Nonce: nonce, RememberMe: true})
		if err != nil {
			t.Fatalf("remember me: %v", err)
		}
		if _, profile := env.sessionOf(res.RefreshToken); profile != "mobile" {
			t.Fatalf("remember-me profile = %q, want mobile", profile)
		}

		env.waitForAudit(auditEventLoginSuccess, "")
		found := false
		for _, ev := range env.events(auditEventExternalLoginSuccess) {
			if ev.Metadata["profile"] == "mobile" {
				found = true
			}
		}
		if !found {
			t.Fatal("external_login_success carries no profile")
		}
	})

	t.Run("an unknown or conflicting profile is refused before any work", func(t *testing.T) {
		env := newExtEnv(t, extProfiles())
		env.link("google", "sub-p", extLocalUserID)
		token, nonce := env.idp.token(extTokenSpec{sub: "sub-p"})
		fetchesBefore := env.idp.fetches.Load()
		env.cmds.reset()

		_, err := env.engine.LoginWithExternalIdentity(WithSessionProfile(env.ctx(), "nope"), "google", token, ExternalLoginOptions{Nonce: nonce})
		requireCode(t, err, CodeAuthUnknownSessionProfile)
		_, err = env.engine.LoginWithExternalIdentity(WithSessionProfile(env.ctx(), "mobile"), "google", token, ExternalLoginOptions{Nonce: nonce, RememberMe: true})
		requireCode(t, err, CodeAuthSessionProfileConflict)

		if got := env.idp.fetches.Load(); got != fetchesBefore {
			t.Fatalf("a refused profile still fetched keys (%d)", got-fetchesBefore)
		}
		if names := env.cmds.names(); len(names) != 0 {
			t.Fatalf("a refused profile still sent Redis commands: %v", names)
		}
		env.waitForAudit(auditEventExternalLoginFailure, "session_profile")

		// The refused attempts did not use up the token.
		if _, err := env.engine.LoginWithExternalIdentity(env.ctx(), "google", token, ExternalLoginOptions{Nonce: nonce}); err != nil {
			t.Fatalf("the token was consumed by a refused attempt: %v", err)
		}
	})

	t.Run("survives MFA", func(t *testing.T) {
		env := newExtEnv(t, extProfiles(), extMFA())
		env.link("google", "sub-p", extLocalUserID)
		secret := enableUserTOTP(t, env.engine, extLocalUserID, env.cfg)

		token, nonce := env.idp.token(extTokenSpec{sub: "sub-p"})
		res, err := env.engine.LoginWithExternalIdentity(WithSessionProfile(env.ctx(), "mobile"), "google", token, ExternalLoginOptions{Nonce: nonce})
		if err != nil || !res.MFARequired {
			t.Fatalf("step 1: %+v, %v", res, err)
		}
		done, err := env.engine.ConfirmLoginMFA(env.ctx(), res.MFASession, codeForOffset(t, secret, env.cfg.TOTP, 1))
		if err != nil {
			t.Fatalf("step 2: %v", err)
		}
		if _, profile := env.sessionOf(done.RefreshToken); profile != "mobile" {
			t.Fatalf("profile after MFA = %q, want mobile", profile)
		}
	})
}

// Session hardening applies to an external sign-in as to any login.
//
// NEW-API.
func TestExternalLoginSessionHardening(t *testing.T) {
	env := newExtEnv(t, extConfig(func(c *Config) { c.SessionHardening.MaxSessionsPerUser = 1 }))
	env.link("google", "sub-h", extLocalUserID)
	env.mustLogin(extTokenSpec{sub: "sub-h"})
	_, err := env.login(extTokenSpec{sub: "sub-h"})
	requireCode(t, err, CodeAuthSessionLimitExceeded)
	env.waitForAudit(auditEventLoginFailure, "session_hardening")

	single := newExtEnv(t, extConfig(func(c *Config) { c.SessionHardening.EnforceSingleSession = true }))
	single.link("google", "sub-h", extLocalUserID)
	first := single.mustLogin(extTokenSpec{sub: "sub-h"})
	second := single.mustLogin(extTokenSpec{sub: "sub-h"})
	if _, _, err := single.engine.Refresh(single.ctx(), first.RefreshToken); err == nil {
		t.Fatal("the first session survived a single-session login")
	}
	if _, _, err := single.engine.Refresh(single.ctx(), second.RefreshToken); err != nil {
		t.Fatalf("the newest session was lost: %v", err)
	}
}

// A linked account that has not verified its email is held back exactly as a
// password login would.
//
// NEW-API.
func TestExternalLoginRequireVerifiedForLogin(t *testing.T) {
	env := newExtEnv(t, extConfig(func(c *Config) {
		c.EmailVerification.Enabled = true
		c.EmailVerification.Strategy = VerificationToken
		c.EmailVerification.RequireForLogin = true
	}))
	env.addLocal(UserRecord{UserID: "pend1", Identifier: "pending@example.com", PasswordHash: "x", Status: AccountPendingVerification})
	env.link("google", "sub-v", "pend1")
	_, err := env.login(extTokenSpec{sub: "sub-v"})
	requireCode(t, err, CodeAuthVerificationRequired)
	env.waitForAudit(auditEventLoginFailure, "pending_verification")
}

// RememberMe means what it means for a password login.
//
// NEW-API.
func TestExternalLoginRememberMeLifetime(t *testing.T) {
	env := newExtEnv(t, extConfig(func(c *Config) {
		c.JWT.RefreshTTL = 12 * time.Hour
		c.Session.AbsoluteSessionLifetime = 12 * time.Hour
		c.Session.MaxSessionDuration = 72 * time.Hour
	}))
	env.link("google", "sub-r", extLocalUserID)

	lifetime := func(rememberMe bool) time.Duration {
		token, nonce := env.idp.token(extTokenSpec{sub: "sub-r"})
		res, err := env.engine.LoginWithExternalIdentity(env.ctx(), "google", token, ExternalLoginOptions{Nonce: nonce, RememberMe: rememberMe})
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		sid, _, _ := internal.DecodeRefreshToken(res.RefreshToken)
		sess, err := env.engine.sessionStore.Peek(context.Background(), env.tenant, sid)
		if err != nil {
			t.Fatalf("peek: %v", err)
		}
		return time.Duration(sess.ExpiresAt-sess.CreatedAt) * time.Second
	}
	short, long := lifetime(false), lifetime(true)
	if short != 12*time.Hour || long != 72*time.Hour {
		t.Fatalf("lifetimes = %v / %v, want 12h / 72h", short, long)
	}
}

// Tenants are isolated: an identity linked in one is unknown in another, and
// a provider that ignores the tenant is caught by the record backstop.
//
// NEW-API.
func TestExternalLoginMultiTenant(t *testing.T) {
	inTenant := func(env *extEnv, tenant string) context.Context { return WithTenantID(context.Background(), tenant) }

	t.Run("an identity linked in tenant A is not found in tenant B", func(t *testing.T) {
		env := newExtEnv(t, extMultiTenant())
		env.link("google", "sub-t", extLocalUserID)

		token, nonce := env.idp.token(extTokenSpec{sub: "sub-t"})
		if _, err := env.engine.LoginWithExternalIdentity(inTenant(env, "tenant-a"), "google", token, ExternalLoginOptions{Nonce: nonce}); err != nil {
			t.Fatalf("tenant A: %v", err)
		}
		token, nonce = env.idp.token(extTokenSpec{sub: "sub-t"})
		_, err := env.engine.LoginWithExternalIdentity(inTenant(env, "tenant-b"), "google", token, ExternalLoginOptions{Nonce: nonce})
		requireCode(t, err, CodeAuthExternalEmailUnverified)
	})

	t.Run("the same email in tenant B is not tenant A's account", func(t *testing.T) {
		env := newExtEnv(t, extMultiTenant(), extAutoLink())
		token, nonce := env.idp.token(extTokenSpec{sub: "sub-t2", email: extLocalEmail, verified: true})
		_, err := env.engine.LoginWithExternalIdentity(inTenant(env, "tenant-b"), "google", token, ExternalLoginOptions{Nonce: nonce})
		requireCode(t, err, CodeAuthExternalAccountNotFound)
		if env.up.linkCount() != 0 {
			t.Fatal("a cross-tenant account was linked")
		}
	})

	t.Run("sign-up lands in the request tenant", func(t *testing.T) {
		env := newExtEnv(t, extMultiTenant(), extSignup())
		token, nonce := env.idp.token(extTokenSpec{sub: "sub-t3", email: "new@example.com", verified: true})
		res, err := env.engine.LoginWithExternalIdentity(inTenant(env, "tenant-b"), "google", token, ExternalLoginOptions{Nonce: nonce})
		if err != nil || !res.NewAccount {
			t.Fatalf("sign-up in tenant B: %+v, %v", res, err)
		}
		if env.up.lastCreate.TenantID != "tenant-b" {
			t.Fatalf("account created in tenant %q", env.up.lastCreate.TenantID)
		}
		if _, ok := env.up.linkedTo("tenant-b", "google", "sub-t3"); !ok {
			t.Fatal("identity not linked in tenant B")
		}
		if _, ok := env.up.linkedTo("tenant-a", "google", "sub-t3"); ok {
			t.Fatal("identity leaked into tenant A")
		}
	})

	t.Run("sign-up without an explicit tenant is refused", func(t *testing.T) {
		env := newExtEnv(t, extMultiTenant(), extSignup())
		token, nonce := env.idp.token(extTokenSpec{sub: "sub-t4", email: "new@example.com", verified: true})
		_, err := env.engine.LoginWithExternalIdentity(context.Background(), "google", token, ExternalLoginOptions{Nonce: nonce})
		requireCode(t, err, CodeAuthAccountCreationInvalid)
		if env.up.creates != 0 {
			t.Fatal("an account was created without a tenant")
		}
	})

	t.Run("a provider that ignores the tenant is caught", func(t *testing.T) {
		env := newExtEnv(t, extMultiTenant())
		env.link("google", "sub-t5", extLocalUserID) // linked in tenant-a
		env.up.ignoreLinkTenant = true               // but returned for any tenant

		token, nonce := env.idp.token(extTokenSpec{sub: "sub-t5"})
		_, err := env.engine.LoginWithExternalIdentity(inTenant(env, "tenant-b"), "google", token, ExternalLoginOptions{Nonce: nonce})
		requireCode(t, err, CodeAuthExternalEmailUnverified)
		if ids, _ := env.engine.sessionStore.ActiveSessionIDs(context.Background(), "tenant-b", extLocalUserID); len(ids) != 0 {
			t.Fatalf("a cross-tenant session was issued: %v", ids)
		}
	})
}
