package goAuth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Section 2.4 of the design: how a change interacts with tenants, external
// identities and the challenges that already exist for the old address.

func TestEmailChangeMultiTenant(t *testing.T) {
	setup := func(t *testing.T) *ecEnv {
		env := newECEnv(t, nil, rsMultiTenant())
		env.up.addUser(UserRecord{
			UserID: "ub", Identifier: "bee@example.com", TenantID: "tenant-b",
			Status: AccountActive, Role: "member", PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1,
		})
		return env
	}
	inB := func(env *ecEnv) context.Context { return WithTenantID(context.Background(), "tenant-b") }

	t.Run("the challenge carries its tenant and is stored under it", func(t *testing.T) {
		env := setup(t)
		req := env.mustRequest(ecNewEmail)
		if !strings.HasPrefix(req.VerificationID, "tenant-a:") {
			t.Fatalf("VerificationID = %q", req.VerificationID)
		}
		if keys := env.keys("aec:tenant-a:*"); len(keys) != 1 {
			t.Fatalf("keys = %v", env.keys("aec*"))
		}
		if keys := env.keys("rl:emailchange:tenant-a:*"); len(keys) != 1 {
			t.Fatalf("limiter keys = %v", env.keys("rl:*"))
		}
	})

	t.Run("a challenge from tenant A is unusable in tenant B", func(t *testing.T) {
		env := setup(t)
		req := env.mustRequest(ecNewEmail)

		// Claimed from tenant B's context: refused without consuming anything.
		if _, err := env.engine.ConfirmEmailChange(inB(env), req.VerificationID, req.Code, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
			t.Fatalf("confirm from tenant B = %v", err)
		}
		// The id rewritten to point at tenant B finds nothing.
		_, rawID, _ := strings.Cut(req.VerificationID, ":")
		if _, err := env.engine.ConfirmEmailChange(inB(env), "tenant-b:"+rawID, req.Code, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
			t.Fatalf("confirm with a rewritten tenant = %v", err)
		}
		if _, err := env.engine.ConfirmEmailChange(env.ctx(), "tenant-b:"+rawID, req.Code, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
			t.Fatalf("confirm with a rewritten tenant from tenant A = %v", err)
		}
		// None of that spent tenant A's challenge, and it did not touch B's user.
		if got := env.user("ub"); got.Identifier != "bee@example.com" || got.AccountVersion != 1 {
			t.Fatalf("tenant B's user changed: %+v", got)
		}
		env.mustConfirm(req, ConfirmEmailChangeOptions{})
		if got := env.user(rsUserID); got.Identifier != ecNewEmail {
			t.Fatalf("tenant A's user = %+v", got)
		}
	})

	t.Run("a confirm without a tenant in context uses the one the id carries", func(t *testing.T) {
		env := setup(t)
		req := env.mustRequest(ecNewEmail)
		if _, err := env.engine.ConfirmEmailChange(context.Background(), req.VerificationID, req.Code, ConfirmEmailChangeOptions{}); err != nil {
			t.Fatalf("confirm without a tenant: %v", err)
		}
	})

	t.Run("a user of another tenant is not found, and a provider that ignores the tenant is caught", func(t *testing.T) {
		env := setup(t)
		if _, err := env.engine.RequestEmailChange(inB(env), rsUserID, ecNewEmail); !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("request for another tenant's user = %v", err)
		}
		env.up.ignoreTenantScope = true // the provider forgets its WHERE clause
		if _, err := env.engine.RequestEmailChange(inB(env), rsUserID, ecNewEmail); !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("the engine's backstop let a foreign-tenant user through: %v", err)
		}
		if keys := env.changeKeys(); len(keys) != 0 {
			t.Fatalf("stored %v", keys)
		}
	})

	t.Run("sessions are revoked in the user's tenant only", func(t *testing.T) {
		env := setup(t)
		_, a := env.login()
		other := "planted-b"
		sessB := env.peek(env.sidOf(a))
		sessB.UserID, sessB.TenantID, sessB.SessionID = "ub", "tenant-b", other
		if err := env.engine.sessionStore.Save(context.Background(), sessB, time.Hour); err != nil {
			t.Fatal(err)
		}
		env.mustConfirm(env.mustRequest(ecNewEmail), ConfirmEmailChangeOptions{})
		if env.hasSession(env.sidOf(a)) {
			t.Fatal("the user's session survived")
		}
		if _, err := env.engine.sessionStore.Peek(context.Background(), "tenant-b", other); err != nil {
			t.Fatalf("a session of tenant B was revoked: %v", err)
		}
	})
}

func TestEmailChangeLeavesExternalIdentitiesLinkedAndAutoLinksTheNewAddress(t *testing.T) {
	env := newExtEnv(t, extAutoLink(), extSignup(), extConfig(func(c *Config) {
		c.EmailChange = EmailChangeConfig{Enabled: true, Strategy: VerificationOTP, MaxAttempts: 3, VerificationTTL: 10 * time.Minute}
		c.EmailVerification.Strategy = VerificationToken
	}))
	env.link("google", "sub-linked", extLocalUserID)

	req, err := env.engine.RequestEmailChange(env.ctx(), extLocalUserID, "moved@example.com")
	if err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	if _, err := env.engine.ConfirmEmailChange(env.ctx(), req.VerificationID, req.Code, ConfirmEmailChangeOptions{}); err != nil {
		t.Fatalf("ConfirmEmailChange: %v", err)
	}

	// The link is (provider, subject); the email moved and the link did not.
	if uid, ok := env.up.linkedTo(env.tenant, "google", "sub-linked"); !ok || uid != extLocalUserID {
		t.Fatalf("the external link did not survive: %v %v", uid, ok)
	}
	res, err := env.login(extTokenSpec{sub: "sub-linked", email: "anything@else.example", verified: true})
	if err != nil {
		t.Fatalf("signing in through the surviving link: %v", err)
	}
	if uid, _ := env.sessionOf(res.RefreshToken); uid != extLocalUserID {
		t.Fatalf("signed in as %s", uid)
	}

	// Auto-link now matches the NEW address, which is proven, and no longer the old.
	res, err = env.login(extTokenSpec{sub: "sub-second", email: "moved@example.com", verified: true})
	if err != nil {
		t.Fatalf("auto-link on the new address: %v", err)
	}
	if uid, _ := env.sessionOf(res.RefreshToken); uid != extLocalUserID || !res.LinkedIdentity || res.NewAccount {
		t.Fatalf("expected the new address to auto-link to the existing account, got %+v as %s", res, uid)
	}
	res, err = env.login(extTokenSpec{sub: "sub-third", email: extLocalEmail, verified: true})
	if err != nil {
		t.Fatalf("the old address is a free address now: %v", err)
	}
	if uid, _ := env.sessionOf(res.RefreshToken); uid == extLocalUserID || !res.NewAccount {
		t.Fatalf("the old address still resolved to the moved account: %+v as %s", res, uid)
	}
}

// With the feature off (the default) nothing about email change reaches Redis:
// no key, no command, and none of the other flows reads a marker.
func TestEmailChangeOffTouchesNothing(t *testing.T) {
	env := newRSEnv(t, rsConfig(func(c *Config) {
		c.EmailVerification = testEmailVerificationConfig(VerificationOTP)
		c.PasswordReset = testResetConfig(ResetOTP)
	}))
	env.cmds.reset()

	_, refresh := env.login()
	reset, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.engine.ConfirmPasswordReset(env.ctx(), reset, "brand-new-password-9"); err != nil {
		t.Fatalf("ConfirmPasswordReset: %v", err)
	}
	if _, err := env.engine.RequestEmailVerification(env.ctx(), rsIdentifier); err != nil {
		t.Fatal(err)
	}
	_ = env.engine.Logout(env.ctx(), env.sidOf(refresh))
	_ = env.engine.LogoutAll(env.ctx(), rsUserID)

	if env.cmds.touches("aec:") || env.cmds.touches("aeci:") || env.cmds.touches("emailchange") {
		t.Fatalf("email-change keys were touched with the feature off: %v", env.cmds.names())
	}
	if keys := env.keys("aec*"); len(keys) != 0 {
		t.Fatalf("keys = %v", keys)
	}
	if env.engine.emailChangeStore != nil || env.engine.emailChangeLimiter != nil || env.engine.emailChangeProvider != nil {
		t.Fatal("email-change state was allocated with the feature off")
	}
}
