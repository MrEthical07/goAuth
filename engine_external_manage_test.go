package goAuth

import (
	"context"
	"errors"
	"testing"
)

// linkToken signs a token for the link API and returns it with its nonce.
func (env *extEnv) linkToken(spec extTokenSpec) (string, string) {
	env.t.Helper()
	return env.idp.token(spec)
}

func (env *extEnv) mustLink(userID string, spec extTokenSpec) *ExternalIdentity {
	env.t.Helper()
	if spec.provider == "" {
		spec.provider = "google"
	}
	token, nonce := env.linkToken(spec)
	id, err := env.engine.LinkExternalIdentity(env.ctx(), userID, spec.provider, token, nonce)
	if err != nil {
		env.t.Fatalf("LinkExternalIdentity: %v", err)
	}
	return id
}

// NEW-API.
func TestLinkExternalIdentity(t *testing.T) {
	t.Run("links, stores what the provider reported, and audits", func(t *testing.T) {
		env := newExtEnv(t)
		// Linking does not need a verified email: the user is authenticated.
		id := env.mustLink(extLocalUserID, extTokenSpec{sub: "sub-l", email: "other@example.com", verified: false})
		if id.Provider != "google" || id.Subject != "sub-l" || id.Email != "other@example.com" || id.EmailVerified || id.LinkedAt.IsZero() {
			t.Fatalf("identity = %+v", id)
		}
		if uid, ok := env.up.linkedTo(env.tenant, "google", "sub-l"); !ok || uid != extLocalUserID {
			t.Fatalf("link = %q, %v", uid, ok)
		}
		ev := env.waitForAudit(auditEventExternalLinked, "")
		if ev.UserID != extLocalUserID || ev.Metadata["provider"] != "google" || ev.Metadata["via"] != "link" {
			t.Fatalf("external_identity_linked = %+v", ev)
		}

		// The user can now sign in with it.
		if _, err := env.login(extTokenSpec{sub: "sub-l"}); err != nil {
			t.Fatalf("sign-in with a linked identity: %v", err)
		}
	})

	t.Run("stores the Apple private-relay flag", func(t *testing.T) {
		env := newExtEnv(t)
		id := env.mustLink(extLocalUserID, extTokenSpec{provider: "apple", sub: "apple-sub", email: "x@privaterelay.appleid.com", verified: "true", private: "true"})
		if !id.EmailVerified || !id.IsPrivateEmail {
			t.Fatalf("identity = %+v", id)
		}
	})

	t.Run("linking the same identity again is idempotent", func(t *testing.T) {
		env := newExtEnv(t)
		env.mustLink(extLocalUserID, extTokenSpec{sub: "sub-i"})
		env.mustLink(extLocalUserID, extTokenSpec{sub: "sub-i"})
		if env.up.linksMade != 1 || env.up.linkCount() != 1 {
			t.Fatalf("link calls %d, links %d", env.up.linksMade, env.up.linkCount())
		}
		if got := len(env.events(auditEventExternalLinked)); got != 1 {
			t.Fatalf("%d link events for an idempotent link", got)
		}
	})

	t.Run("an identity linked to another user is in use", func(t *testing.T) {
		env := newExtEnv(t)
		env.addLocal(UserRecord{UserID: "u2", Identifier: "u2@example.com", PasswordHash: "x", Status: AccountActive})
		env.link("google", "sub-taken", "u2")
		token, nonce := env.linkToken(extTokenSpec{sub: "sub-taken"})
		_, err := env.engine.LinkExternalIdentity(env.ctx(), extLocalUserID, "google", token, nonce)
		requireCode(t, err, CodeAuthExternalIdentityInUse)
		if uid, _ := env.up.linkedTo(env.tenant, "google", "sub-taken"); uid != "u2" {
			t.Fatalf("the link moved to %q", uid)
		}
		env.waitForAudit(auditEventExternalLinkFailure, "identity_in_use")
	})

	t.Run("the provider's own conflict is reported the same way", func(t *testing.T) {
		env := newExtEnv(t)
		env.up.linkErr = ErrExternalIdentityInUse
		token, nonce := env.linkToken(extTokenSpec{sub: "sub-c"})
		_, err := env.engine.LinkExternalIdentity(env.ctx(), extLocalUserID, "google", token, nonce)
		requireCode(t, err, CodeAuthExternalIdentityInUse)
	})

	t.Run("the token is verified like a sign-in: nonce, replay, signature", func(t *testing.T) {
		env := newExtEnv(t)
		token, nonce := env.linkToken(extTokenSpec{sub: "sub-v"})
		_, err := env.engine.LinkExternalIdentity(env.ctx(), extLocalUserID, "google", token, "wrong")
		requireCode(t, err, CodeAuthExternalTokenInvalid)
		if _, err := env.engine.LinkExternalIdentity(env.ctx(), extLocalUserID, "google", token, nonce); err != nil {
			t.Fatalf("link: %v", err)
		}
		_, err = env.engine.LinkExternalIdentity(env.ctx(), extLocalUserID, "google", token, nonce)
		requireCode(t, err, CodeAuthExternalTokenReplayed)
		bad := token[:len(token)-6] + "AAAAAA"
		_, err = env.engine.LinkExternalIdentity(env.ctx(), extLocalUserID, "google", bad, nonce)
		requireCode(t, err, CodeAuthExternalTokenInvalid)
		env.waitForAudit(auditEventExternalLinkFailure, "token_replayed")
	})

	t.Run("unknown provider, unknown user, unusable account", func(t *testing.T) {
		env := newExtEnv(t)
		token, nonce := env.linkToken(extTokenSpec{sub: "sub-u"})
		_, err := env.engine.LinkExternalIdentity(env.ctx(), extLocalUserID, "nope", token, nonce)
		requireCode(t, err, CodeAuthExternalProviderUnknown)

		token, nonce = env.linkToken(extTokenSpec{sub: "sub-u"})
		_, err = env.engine.LinkExternalIdentity(env.ctx(), "no-such-user", "google", token, nonce)
		requireCode(t, err, CodeAuthAccountNotFound)
		token, nonce = env.linkToken(extTokenSpec{sub: "sub-u"})
		_, err = env.engine.LinkExternalIdentity(env.ctx(), "", "google", token, nonce)
		requireCode(t, err, CodeAuthAccountNotFound)

		env.addLocal(UserRecord{UserID: "off", Identifier: "off@example.com", PasswordHash: "x", Status: AccountDisabled})
		token, nonce = env.linkToken(extTokenSpec{sub: "sub-u2"})
		_, err = env.engine.LinkExternalIdentity(env.ctx(), "off", "google", token, nonce)
		if !errors.Is(err, ErrAccountDisabled) {
			t.Fatalf("disabled account = %v", err)
		}
		if env.up.linkCount() != 0 {
			t.Fatal("an unusable account was linked")
		}
	})

	t.Run("an account pending email verification cannot be linked", func(t *testing.T) {
		// Sign-in is allowed for pending accounts unless RequireForLogin is
		// set, so a pre-registered address can have a session.
		env := newExtEnv(t)
		env.addLocal(UserRecord{UserID: "pend1", Identifier: "pending@example.com", PasswordHash: "x", Status: AccountPendingVerification})
		token, nonce := env.linkToken(extTokenSpec{sub: "sub-pend"})
		_, err := env.engine.LinkExternalIdentity(env.ctx(), "pend1", "google", token, nonce)
		requireCode(t, err, CodeAuthExternalLinkRequiresVerify)
		if env.up.linkCount() != 0 {
			t.Fatal("a pending account was linked")
		}
		env.waitForAudit(auditEventExternalLinkFailure, "link_requires_verification")
	})

	t.Run("the user is resolved in the request tenant", func(t *testing.T) {
		env := newExtEnv(t, extMultiTenant())
		token, nonce := env.linkToken(extTokenSpec{sub: "sub-t"})
		other := WithTenantID(context.Background(), "tenant-b")
		_, err := env.engine.LinkExternalIdentity(other, extLocalUserID, "google", token, nonce)
		requireCode(t, err, CodeAuthAccountNotFound)
		if env.up.linkCount() != 0 {
			t.Fatal("a user of another tenant was linked")
		}
	})

	t.Run("the identity limiter applies", func(t *testing.T) {
		env := newExtEnv(t, extLimit(2))
		for i := 0; i < 2; i++ {
			token, nonce := env.linkToken(extTokenSpec{sub: "sub-rl"})
			_, err := env.engine.LinkExternalIdentity(env.ctx(), "no-such-user", "google", token, nonce)
			requireCode(t, err, CodeAuthAccountNotFound)
		}
		token, nonce := env.linkToken(extTokenSpec{sub: "sub-rl"})
		_, err := env.engine.LinkExternalIdentity(env.ctx(), extLocalUserID, "google", token, nonce)
		requireCode(t, err, CodeAuthExternalLoginRateLimited)
	})
}

// NEW-API.
func TestUnlinkExternalIdentity(t *testing.T) {
	t.Run("a user with a password can drop their only identity", func(t *testing.T) {
		env := newExtEnv(t)
		env.mustLink(extLocalUserID, extTokenSpec{sub: "sub-1"})
		if err := env.engine.UnlinkExternalIdentity(env.ctx(), extLocalUserID, "google", "sub-1"); err != nil {
			t.Fatalf("Unlink: %v", err)
		}
		if _, ok := env.up.linkedTo(env.tenant, "google", "sub-1"); ok {
			t.Fatal("the link survived")
		}
		ev := env.waitForAudit(auditEventExternalUnlinked, "")
		if ev.UserID != extLocalUserID || ev.Metadata["provider"] != "google" {
			t.Fatalf("external_identity_unlinked = %+v", ev)
		}
		// The identity no longer signs in.
		if _, err := env.login(extTokenSpec{sub: "sub-1"}); err == nil {
			t.Fatal("an unlinked identity still signs in")
		}
	})

	t.Run("a password-less user cannot drop their only identity", func(t *testing.T) {
		env := newExtEnv(t, extSignup())
		res := env.mustLogin(extTokenSpec{sub: "sub-only", email: "only@example.com", verified: true})
		uid, _ := env.sessionOf(res.RefreshToken)

		err := env.engine.UnlinkExternalIdentity(env.ctx(), uid, "google", "sub-only")
		requireCode(t, err, CodeAuthLastLoginMethod)
		if !errors.Is(err, ErrLastLoginMethod) {
			t.Fatalf("err = %v", err)
		}
		if _, ok := env.up.linkedTo(env.tenant, "google", "sub-only"); !ok {
			t.Fatal("the last identity was removed")
		}
		if env.up.unlinks != 0 {
			t.Fatal("the provider was asked to remove the last identity")
		}
	})

	t.Run("a password-less user can drop one of two identities", func(t *testing.T) {
		env := newExtEnv(t, extSignup())
		res := env.mustLogin(extTokenSpec{sub: "sub-a", email: "two@example.com", verified: true})
		uid, _ := env.sessionOf(res.RefreshToken)
		env.mustLink(uid, extTokenSpec{provider: "apple", sub: "apple-a"})

		if err := env.engine.UnlinkExternalIdentity(env.ctx(), uid, "google", "sub-a"); err != nil {
			t.Fatalf("Unlink: %v", err)
		}
		// Now the Apple identity is the last one.
		requireCode(t, env.engine.UnlinkExternalIdentity(env.ctx(), uid, "apple", "apple-a"), CodeAuthLastLoginMethod)
	})

	t.Run("a password set by reset makes the last identity removable", func(t *testing.T) {
		env := newExtEnv(t, extSignup())
		res := env.mustLogin(extTokenSpec{sub: "sub-pw", email: "pw@example.com", verified: true})
		uid, _ := env.sessionOf(res.RefreshToken)
		user := env.up.users[uid]
		user.PasswordHash = env.up.users[extLocalUserID].PasswordHash
		env.up.users[uid] = user
		if err := env.engine.UnlinkExternalIdentity(env.ctx(), uid, "google", "sub-pw"); err != nil {
			t.Fatalf("Unlink: %v", err)
		}
	})

	t.Run("unlinking what is not linked succeeds and changes nothing", func(t *testing.T) {
		env := newExtEnv(t)
		if err := env.engine.UnlinkExternalIdentity(env.ctx(), extLocalUserID, "google", "never-linked"); err != nil {
			t.Fatalf("Unlink: %v", err)
		}
		if env.up.unlinks != 0 || len(env.events(auditEventExternalUnlinked)) != 0 {
			t.Fatal("a no-op unlink changed state or was audited")
		}
	})

	t.Run("another user's identity cannot be unlinked", func(t *testing.T) {
		env := newExtEnv(t)
		env.addLocal(UserRecord{UserID: "u2", Identifier: "u2@example.com", PasswordHash: "x", Status: AccountActive})
		env.link("google", "sub-theirs", "u2")
		if err := env.engine.UnlinkExternalIdentity(env.ctx(), extLocalUserID, "google", "sub-theirs"); err != nil {
			t.Fatalf("Unlink: %v", err)
		}
		if uid, ok := env.up.linkedTo(env.tenant, "google", "sub-theirs"); !ok || uid != "u2" {
			t.Fatal("a link of another user was removed")
		}
	})

	t.Run("a link to a provider that is no longer configured can still be removed", func(t *testing.T) {
		env := newExtEnv(t)
		env.link("retired", "sub-old", extLocalUserID)
		if err := env.engine.UnlinkExternalIdentity(env.ctx(), extLocalUserID, "retired", "sub-old"); err != nil {
			t.Fatalf("Unlink: %v", err)
		}
	})

	t.Run("unknown user and provider failures", func(t *testing.T) {
		env := newExtEnv(t)
		requireCode(t, env.engine.UnlinkExternalIdentity(env.ctx(), "nobody", "google", "x"), CodeAuthAccountNotFound)
		env.up.listErr = errors.New("db down")
		requireCode(t, env.engine.UnlinkExternalIdentity(env.ctx(), extLocalUserID, "google", "x"), CodeSystemUnavailable)
	})
}

// NEW-API.
func TestListExternalIdentities(t *testing.T) {
	env := newExtEnv(t)
	got, err := env.engine.ListExternalIdentities(env.ctx(), extLocalUserID)
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty list = %v, %v", got, err)
	}
	env.mustLink(extLocalUserID, extTokenSpec{sub: "sub-g", email: "g@example.com", verified: true})
	env.mustLink(extLocalUserID, extTokenSpec{provider: "apple", sub: "sub-a"})

	got, err = env.engine.ListExternalIdentities(env.ctx(), extLocalUserID)
	if err != nil || len(got) != 2 {
		t.Fatalf("list = %v, %v", got, err)
	}
	if got[0].Provider != "apple" || got[1].Provider != "google" || got[1].Email != "g@example.com" {
		t.Fatalf("list = %+v", got)
	}

	requireCode(t, func() error { _, err := env.engine.ListExternalIdentities(env.ctx(), "nobody"); return err }(), CodeAuthAccountNotFound)
	env.up.listErr = errors.New("db down")
	requireCode(t, func() error { _, err := env.engine.ListExternalIdentities(env.ctx(), extLocalUserID); return err }(), CodeSystemUnavailable)
}
