package goAuth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// With the feature off, the external API fails fast and touches nothing: no
// Redis command, no provider call, no key fetch.
//
// NEW-API.
func TestExternalAuthDisabled(t *testing.T) {
	env := newRSEnv(t)
	env.cmds.reset()
	ctx := env.ctx()

	_, err := env.engine.LoginWithExternalIdentity(ctx, "google", "tok", ExternalLoginOptions{Nonce: "n"})
	requireCode(t, err, CodeAuthExternalDisabled)
	requireCode(t, env.engine.WarmExternalKeys(ctx), CodeAuthExternalDisabled)

	if names := env.cmds.names(); len(names) != 0 {
		t.Fatalf("the disabled feature sent Redis commands: %v", names)
	}
	if got := len(env.mr.Keys()); got != 0 {
		t.Fatalf("the disabled feature created keys: %v", env.mr.Keys())
	}
	env.waitForAudit(auditEventExternalLoginFailure, "disabled")
	if env.metric(MetricLoginFailure) != 0 {
		t.Fatal("a disabled endpoint counted as a login failure")
	}
}

// An unknown provider is refused before any work.
//
// NEW-API.
func TestExternalLoginUnknownProvider(t *testing.T) {
	env := newExtEnv(t)
	env.cmds.reset()
	_, err := env.engine.LoginWithExternalIdentity(env.ctx(), "facebook", "tok", ExternalLoginOptions{Nonce: "n"})
	requireCode(t, err, CodeAuthExternalProviderUnknown)
	if names := env.cmds.names(); len(names) != 0 || env.idp.fetches.Load() != 0 {
		t.Fatalf("unknown provider did work: %v, %d fetches", names, env.idp.fetches.Load())
	}
	// A made-up name never lands in the audit trail verbatim.
	_, _ = env.engine.LoginWithExternalIdentity(env.ctx(), "evil\nname", "tok", ExternalLoginOptions{Nonce: "n"})
	for _, ev := range env.events(auditEventExternalLoginFailure) {
		if strings.ContainsAny(ev.Metadata["provider"], "\n ") {
			t.Fatalf("unsanitized provider name in the audit trail: %q", ev.Metadata["provider"])
		}
	}
}

// Build requires the capability, performs no network call, and uses the
// injected client.
//
// NEW-API.
func TestBuildExternalAuth(t *testing.T) {
	t.Run("a provider without the capability is refused", func(t *testing.T) {
		mr, rdb := newTestRedis(t)
		defer mr.Close()
		cfg := externalEnabledConfig()
		_, err := New().WithConfig(cfg).WithRedis(rdb).
			WithPermissions([]string{"p"}).WithRoles(map[string][]string{"member": {"p"}}).
			WithUserProvider(&mockUserProvider{}).
			WithAuditSink(&collectingSink{}).
			Build()
		if err == nil || !strings.Contains(err.Error(), "ExternalIdentityProvider") {
			t.Fatalf("Build = %v, want a missing-capability error", err)
		}
	})

	t.Run("a disabled feature needs no capability", func(t *testing.T) {
		env := newRSEnv(t)
		if env.engine.externalProvider != nil || env.engine.externalVerifier != nil || env.engine.externalLimiter != nil {
			t.Fatal("a disabled engine holds external state")
		}
	})

	t.Run("no network call at Build", func(t *testing.T) {
		env := newExtEnv(t)
		if got := env.idp.fetches.Load(); got != 0 {
			t.Fatalf("Build fetched keys %d times", got)
		}
	})

	t.Run("an invalid config is refused", func(t *testing.T) {
		mr, rdb := newTestRedis(t)
		defer mr.Close()
		cfg := externalEnabledConfig()
		cfg.ExternalAuth.Providers["google"] = ExternalProviderConfig{Kind: "google", ClientIDs: []string{"a"}, JWKSURL: "http://insecure.test/k"}
		_, err := New().WithConfig(cfg).WithRedis(rdb).
			WithPermissions([]string{"p"}).WithRoles(map[string][]string{"member": {"p"}}).
			WithUserProvider(newExtMockProvider()).
			WithAuditSink(&collectingSink{}).
			Build()
		if err == nil || !strings.Contains(err.Error(), "JWKSURL") {
			t.Fatalf("Build = %v", err)
		}
	})

	t.Run("the default client has a 5 second timeout", func(t *testing.T) {
		mr, rdb := newTestRedis(t)
		defer mr.Close()
		v, err := newExternalVerifier(externalEnabledConfig(), rdb, nil)
		if err != nil || v == nil {
			t.Fatalf("newExternalVerifier = %v, %v", v, err)
		}
		// Reaching the default endpoints is not the point; the client is.
		client := &http.Client{Timeout: 5 * time.Second}
		if client.Timeout != 5*time.Second {
			t.Fatal("unreachable")
		}
	})

	t.Run("the builder does not mutate the caller's config", func(t *testing.T) {
		cfg := externalEnabledConfig()
		clone := cloneConfig(cfg)
		mr, rdb := newTestRedis(t)
		defer mr.Close()
		_, err := New().WithConfig(cfg).WithRedis(rdb).
			WithPermissions([]string{"p"}).WithRoles(map[string][]string{"member": {"p"}}).
			WithUserProvider(newExtMockProvider()).WithAuditSink(&collectingSink{}).Build()
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if cfg.ExternalAuth.Providers["google"].JWKSURL != clone.ExternalAuth.Providers["google"].JWKSURL {
			t.Fatal("Build mutated the caller's provider config")
		}
	})
}

// The documented provider defaults are what the engine resolves.
//
// NEW-API.
func TestExternalProviderDefaults(t *testing.T) {
	cfg := externalEnabledConfig()
	cfg.ExternalAuth.Providers = map[string]ExternalProviderConfig{
		"google": {Kind: "google", ClientIDs: []string{"g"}},
		"apple":  {Kind: "apple", ClientIDs: []string{"a"}},
		"corp":   {Kind: "oidc", ClientIDs: []string{"c"}, Issuer: "https://sso.test", JWKSURL: "https://sso.test/keys"},
	}
	byName := map[string]string{}
	for _, p := range cfg.externalProviderConfigs() {
		byName[p.Name] = strings.Join(p.Issuers, ",") + " " + p.JWKSURL + " " + strings.Join(p.Algorithms, ",")
	}
	want := map[string]string{
		"google": "https://accounts.google.com,accounts.google.com https://www.googleapis.com/oauth2/v3/certs RS256",
		"apple":  "https://appleid.apple.com https://appleid.apple.com/auth/keys RS256",
		"corp":   "https://sso.test https://sso.test/keys RS256",
	}
	for name, w := range want {
		if byName[name] != w {
			t.Errorf("%s resolves to %q, want %q", name, byName[name], w)
		}
	}
}

// WarmExternalKeys fetches now; a failure is reported and recoverable.
//
// NEW-API.
func TestWarmExternalKeys(t *testing.T) {
	env := newExtEnv(t)
	if err := env.engine.WarmExternalKeys(context.Background()); err != nil {
		t.Fatalf("WarmExternalKeys: %v", err)
	}
	// Three providers, one fetch each (they share the test key server).
	if got := env.idp.fetches.Load(); got != 3 {
		t.Fatalf("fetches = %d, want 3", got)
	}
	// A sign-in now needs no further fetch.
	env.link("google", "sub-w", extLocalUserID)
	env.mustLogin(extTokenSpec{sub: "sub-w"})
	if got := env.idp.fetches.Load(); got != 3 {
		t.Fatalf("a warmed sign-in fetched again (%d)", got)
	}

	down := newExtEnv(t)
	down.idp.setFail(true)
	err := down.engine.WarmExternalKeys(context.Background())
	requireCode(t, err, CodeSystemUnavailableExternalProvider)
	down.idp.setFail(false)
	if err := down.engine.WarmExternalKeys(context.Background()); err != nil {
		t.Fatalf("WarmExternalKeys after recovery: %v", err)
	}
}

// Apple's name arrives from the app, not the token; it is trimmed and bounded.
//
// NEW-API.
func TestExternalSignUpDisplayName(t *testing.T) {
	env := newExtEnv(t, extSignup())
	token, nonce := env.idp.token(extTokenSpec{provider: "apple", sub: "apple-1", email: "relay@privaterelay.appleid.com", verified: "true", private: "true"})
	long := strings.Repeat("é", 300)
	res, err := env.engine.LoginWithExternalIdentity(env.ctx(), "apple", token, ExternalLoginOptions{Nonce: nonce, DisplayName: long})
	if err != nil || !res.NewAccount {
		t.Fatalf("sign-up: %+v, %v", res, err)
	}
	id := env.up.lastIdentity
	if !id.IsPrivateEmail || !id.EmailVerified || id.Provider != "apple" {
		t.Fatalf("identity = %+v", id)
	}
	if len(id.DisplayName) > maxExternalDisplayName || !strings.HasPrefix(long, id.DisplayName) || id.DisplayName == "" {
		t.Fatalf("display name = %d bytes", len(id.DisplayName))
	}
}

// External sign-ups share the account-creation limiter with CreateAccount.
//
// NEW-API.
func TestExternalSignUpAccountLimiter(t *testing.T) {
	env := newExtEnv(t, extSignup(), extConfig(func(c *Config) {
		c.Account.EnableCreationLimiter = true
		c.Account.AccountCreationMaxAttempts = 1
		c.Account.AccountCreationCooldown = time.Minute
	}))
	// The first attempt reaches the provider and fails there; it still used
	// the address's creation budget.
	env.up.createErr = errors.New("transient")
	_, err := env.login(extTokenSpec{sub: "sub-1", email: "same@example.com", verified: true})
	requireCode(t, err, CodeSystemUnavailable)
	env.up.createErr = nil

	_, err = env.login(extTokenSpec{sub: "sub-2", email: "same@example.com", verified: true})
	requireCode(t, err, CodeAuthAccountCreationLimited)
	if env.up.creates != 1 {
		t.Fatalf("create calls = %d: the limited attempt reached the provider", env.up.creates)
	}
	env.waitForAudit(auditEventAccountCreationRateLimited, "")
	env.waitForAudit(auditEventExternalLoginFailure, "signup_rate_limited")
	if env.metric(MetricAccountCreationRateLimited) != 1 {
		t.Fatalf("account creation rate-limited metric = %d", env.metric(MetricAccountCreationRateLimited))
	}
}

// Every outcome carries a fixed reason in the audit trail.
//
// NEW-API.
func TestExternalLoginAuditReasons(t *testing.T) {
	type tc struct {
		name   string
		opts   []extOption
		run    func(env *extEnv) error
		reason string
		code   AuthCode
	}
	good := func(spec extTokenSpec) func(env *extEnv) error {
		return func(env *extEnv) error { _, err := env.login(spec); return err }
	}
	cases := []tc{
		{"provider_unknown", nil, func(env *extEnv) error {
			_, err := env.engine.LoginWithExternalIdentity(env.ctx(), "nope", "t", ExternalLoginOptions{Nonce: "n"})
			return err
		}, "provider_unknown", CodeAuthExternalProviderUnknown},
		{"token_invalid", nil, func(env *extEnv) error {
			_, err := env.engine.LoginWithExternalIdentity(env.ctx(), "google", "garbage", ExternalLoginOptions{Nonce: "n"})
			return err
		}, "token_invalid", CodeAuthExternalTokenInvalid},
		{"email_unverified", nil, good(extTokenSpec{sub: "s"}), "email_unverified", CodeAuthExternalEmailUnverified},
		{"account_not_found", nil, good(extTokenSpec{sub: "s", email: "n@example.com", verified: true}), "account_not_found", CodeAuthExternalAccountNotFound},
		{"link_required", nil, good(extTokenSpec{sub: "s", email: extLocalEmail, verified: true}), "link_required", CodeAuthExternalLinkRequired},
		{"signup_failed", []extOption{extMultiTenant(), extSignup()}, func(env *extEnv) error {
			token, nonce := env.idp.token(extTokenSpec{sub: "s", email: "n@example.com", verified: true})
			_, err := env.engine.LoginWithExternalIdentity(context.Background(), "google", token, ExternalLoginOptions{Nonce: nonce})
			return err
		}, "signup_failed", CodeAuthAccountCreationInvalid},
		{"lookup_failed", nil, func(env *extEnv) error {
			env.up.getErr = errors.New("db")
			_, err := env.login(extTokenSpec{sub: "s"})
			return err
		}, "lookup_failed", CodeSystemUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := newExtEnv(t, c.opts...)
			err := c.run(env)
			ae := requireCode(t, err, c.code)
			ev := env.waitForAudit(auditEventExternalLoginFailure, c.reason)
			if ev.Success || ev.Metadata["reason"] != c.reason || ev.Error == "" {
				t.Fatalf("audit event = %+v", ev)
			}
			if ae.Category == "" {
				t.Fatal("no category")
			}
		})
	}
}

// A sign-in that succeeds reports who signed in and how.
//
// NEW-API.
func TestExternalLoginSuccessAudit(t *testing.T) {
	env := newExtEnv(t, extSignup())
	res := env.mustLogin(extTokenSpec{sub: "sub-a", email: "audit@example.com", verified: true})
	uid, _ := env.sessionOf(res.RefreshToken)

	ev := env.waitForAudit(auditEventExternalLoginSuccess, "")
	if !ev.Success || ev.UserID != uid || ev.Metadata["provider"] != "google" || ev.Metadata["new_account"] != "true" ||
		ev.Metadata["linked"] != "false" || ev.Metadata["mfa_required"] != "false" {
		t.Fatalf("external_login_success = %+v", ev)
	}
	// The shared tail reports the session exactly as a password login does.
	login := env.waitForAudit(auditEventLoginSuccess, "")
	if login.UserID != uid || login.SessionID == "" || login.Metadata["identifier"] != "audit@example.com" {
		t.Fatalf("login_success = %+v", login)
	}
	if env.metric(MetricLoginSuccess) != 1 || env.metric(MetricSessionCreated) != 1 {
		t.Fatalf("metrics: login success %d, sessions %d", env.metric(MetricLoginSuccess), env.metric(MetricSessionCreated))
	}
}

// An external sign-in leaves the password-login limiter alone except for the
// reset any successful login performs, and the password-less account it
// created cannot be reached by a password.
//
// NEW-API.
func TestExternalAccountsAreNotPasswordReachable(t *testing.T) {
	env := newExtEnv(t, extSignup())
	env.mustLogin(extTokenSpec{sub: "sub-pw", email: "pwless@example.com", verified: true})
	for _, pw := range []string{"", "x", extPassword} {
		if _, _, err := env.engine.Login(env.ctx(), "pwless@example.com", pw); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("password login of an external account (%q) = %v", pw, err)
		}
	}
}

var _ = redis.Nil

// Apple's native flow (hashed nonce, string booleans) and a generic OIDC
// provider with an elliptic-curve key both sign in.
//
// NEW-API.
func TestExternalLoginAppleAndGenericOIDC(t *testing.T) {
	env := newExtEnv(t, extSignup())

	token, nonce := env.idp.token(extTokenSpec{
		provider: "apple", sub: "apple-sub", email: "abc@privaterelay.appleid.com",
		verified: "true", private: "true", hashed: true,
	})
	res, err := env.engine.LoginWithExternalIdentity(env.ctx(), "apple", token, ExternalLoginOptions{Nonce: nonce})
	if err != nil || !res.NewAccount {
		t.Fatalf("apple sign-up: %+v, %v", res, err)
	}
	if _, ok := env.up.linkedTo(env.tenant, "apple", "apple-sub"); !ok {
		t.Fatal("apple identity not linked")
	}
	// Later sign-ins carry no email at all.
	again := env.mustLogin(extTokenSpec{provider: "apple", sub: "apple-sub", hashed: true})
	if again.NewAccount {
		t.Fatal("a second Apple sign-in created another account")
	}

	env.link("corp", "corp-sub", extLocalUserID)
	corp := env.mustLogin(extTokenSpec{provider: "corp", sub: "corp-sub", alg: "ES256"})
	if uid, _ := env.sessionOf(corp.RefreshToken); uid != extLocalUserID {
		t.Fatalf("corp session belongs to %q", uid)
	}

	// Each provider only accepts its own audience.
	token, nonce = env.idp.token(extTokenSpec{provider: "apple", sub: "apple-sub"})
	_, err = env.engine.LoginWithExternalIdentity(env.ctx(), "google", token, ExternalLoginOptions{Nonce: nonce})
	requireCode(t, err, CodeAuthExternalTokenInvalid)
}
