package goAuth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal"
)

// Tests in this file cover the two-step external sign-up: DeferSignup,
// CompleteExternalSignup and CancelExternalSignup. All of it is NEW-API.

const signupEmail = "fresh@example.com"

// deferLogin runs step one for a new identity.
func (env *extEnv) deferLogin(spec extTokenSpec, opts ExternalLoginOptions) (*LoginResult, error) {
	env.t.Helper()
	if spec.provider == "" {
		spec.provider = "google"
	}
	token, nonce := env.idp.token(spec)
	opts.Nonce, opts.DeferSignup = nonce, true
	return env.engine.LoginWithExternalIdentity(env.ctx(), spec.provider, token, opts)
}

func (env *extEnv) mustDefer(sub string, opts ExternalLoginOptions) *ExternalSignupTicket {
	env.t.Helper()
	return env.mustDeferEmail(sub, signupEmail, opts)
}

func (env *extEnv) mustDeferEmail(sub, email string, opts ExternalLoginOptions) *ExternalSignupTicket {
	env.t.Helper()
	res, err := env.deferLogin(extTokenSpec{sub: sub, email: email, verified: true}, opts)
	if err != nil {
		env.t.Fatalf("step one: %v", err)
	}
	if res.ExternalSignup == nil {
		env.t.Fatalf("step one returned no ticket: %+v", res)
	}
	return res.ExternalSignup
}

func (env *extEnv) axsKeys() []string {
	env.t.Helper()
	keys, err := env.rdb.Keys(context.Background(), "axs:*").Result()
	if err != nil {
		env.t.Fatalf("keys: %v", err)
	}
	return keys
}

// Step one for an unknown identity creates nothing and returns a ticket.
func TestDeferredSignupStepOneCreatesNothing(t *testing.T) {
	clk := newManualClock(time.Now().Truncate(time.Second))
	env := newExtEnv(t, extSignup(), extClock(clk), extConfig(func(c *Config) {
		c.Account.EnableCreationLimiter = true
		c.Account.AccountCreationMaxAttempts = 5
		c.Account.AccountCreationCooldown = time.Minute
	}))
	users := env.up.userCount()

	res, err := env.deferLogin(extTokenSpec{sub: "sub-d", email: signupEmail, verified: true, private: true},
		ExternalLoginOptions{DisplayName: "  Fresh Person "})
	if err != nil {
		t.Fatalf("step one: %v", err)
	}
	if res.AccessToken != "" || res.RefreshToken != "" || res.NewAccount || res.LinkedIdentity || res.MFARequired {
		t.Fatalf("a deferred sign-in issued something: %+v", res)
	}
	tk := res.ExternalSignup
	if tk == nil || len(tk.Handle) < 40 {
		t.Fatalf("ticket = %+v", tk)
	}
	if tk.Provider != "google" || tk.Subject != "sub-d" || tk.Email != signupEmail || !tk.EmailVerified ||
		tk.DisplayName != "Fresh Person" {
		t.Fatalf("ticket = %+v", tk)
	}
	if want := clk.Now().Add(10 * time.Minute); !tk.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want the injected clock plus the 10m default (%v)", tk.ExpiresAt, want)
	}

	if env.up.creates != 0 || env.up.userCount() != users || env.up.linkCount() != 0 {
		t.Fatalf("step one touched the provider: creates=%d users=%d links=%d", env.up.creates, env.up.userCount(), env.up.linkCount())
	}
	if keys, _ := env.rdb.Keys(context.Background(), env.cfg.Session.RedisPrefix+":*").Result(); len(keys) != 0 {
		t.Fatalf("step one stored a session: %v", keys)
	}
	if env.cmds.touches("rl:account") {
		t.Fatal("step one used the account-creation limiter")
	}

	keys := env.axsKeys()
	if len(keys) != 1 || strings.Contains(keys[0], tk.Handle) {
		t.Fatalf("ticket keys = %v: want one key named by the handle's hash, not the handle", keys)
	}
	if ttl := env.mr.TTL(keys[0]); ttl <= 9*time.Minute || ttl > 10*time.Minute {
		t.Fatalf("ticket TTL = %v", ttl)
	}
	ev := env.waitForAudit(auditEventExternalSignupDeferred, "")
	if ev.Metadata["provider"] != "google" || len(ev.Metadata) != 1 {
		t.Fatalf("external_signup_deferred = %+v", ev)
	}
	if env.sink.find(auditEventExternalLoginSuccess, "") != nil {
		t.Fatal("a deferred sign-in audited a login success")
	}
}

// Step two creates the account, links it, signs in with NewAccount, and leaves
// the same audit events, metrics and provider inputs as the one-call sign-up.
func TestDeferredSignupStepTwoMatchesTheOneCallSignup(t *testing.T) {
	one := newExtEnv(t, extSignup())
	token, nonce := one.idp.token(extTokenSpec{sub: "sub-x", email: signupEmail, verified: true})
	oneRes, err := one.engine.LoginWithExternalIdentity(one.ctx(), "google", token, ExternalLoginOptions{Nonce: nonce, DisplayName: "Fresh Person"})
	if err != nil {
		t.Fatalf("one-call sign-up: %v", err)
	}

	two := newExtEnv(t, extSignup())
	ticket := two.mustDefer("sub-x", ExternalLoginOptions{DisplayName: "Fresh Person"})
	twoRes, err := two.engine.CompleteExternalSignup(two.ctx(), ticket.Handle, ExternalSignupOptions{})
	if err != nil {
		t.Fatalf("CompleteExternalSignup: %v", err)
	}

	if !twoRes.NewAccount || twoRes.LinkedIdentity || twoRes.MFARequired || twoRes.AccessToken == "" || twoRes.RefreshToken == "" || twoRes.ExternalSignup != nil {
		t.Fatalf("result = %+v", twoRes)
	}
	if uid, ok := two.up.linkedTo(two.tenant, "google", "sub-x"); !ok || uid != twoRes.NewUserID(two) {
		t.Fatalf("link = %q, %v", uid, ok)
	}
	if two.up.creates != 1 || !reflect.DeepEqual(one.up.lastCreate, two.up.lastCreate) {
		t.Fatalf("CreateUserInput one-call %+v, two-step %+v", one.up.lastCreate, two.up.lastCreate)
	}
	a, b := one.up.lastIdentity, two.up.lastIdentity
	a.LinkedAt, b.LinkedAt = time.Time{}, time.Time{}
	if a != b {
		t.Fatalf("identity one-call %+v, two-step %+v", a, b)
	}
	if oneRes.NewUserID(one) == "" {
		t.Fatal("one-call control produced no account")
	}

	// Same audit events: the two-step flow adds only external_signup_deferred.
	want := eventTypes(one.eventsAll())
	got := eventTypes(two.eventsAll())
	delete(got, auditEventExternalSignupDeferred)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("audit event types: one-call %v, two-step %v", want, got)
	}
	ev := two.waitForAudit(auditEventExternalLoginSuccess, "")
	if ev.Metadata["new_account"] != "true" || ev.Metadata["provider"] != "google" {
		t.Fatalf("external_login_success = %+v", ev)
	}
	created := two.waitForAudit(auditEventAccountCreationSuccess, "")
	if created.Metadata["method"] != "external" || created.Metadata["identifier"] != signupEmail {
		t.Fatalf("account_creation_success = %+v", created)
	}
	for _, id := range []MetricID{MetricAccountCreationSuccess, MetricLoginSuccess, MetricSessionCreated} {
		if one.metric(id) != two.metric(id) {
			t.Fatalf("metric %v: one-call %d, two-step %d", id, one.metric(id), two.metric(id))
		}
	}
}

func (env *extEnv) eventsAll() []AuditEvent {
	env.t.Helper()
	env.engine.Close()
	env.sink.mu.Lock()
	defer env.sink.mu.Unlock()
	return append([]AuditEvent(nil), env.sink.events...)
}

func eventTypes(events []AuditEvent) map[string]int {
	out := map[string]int{}
	for _, ev := range events {
		out[ev.EventType]++
	}
	return out
}

// A handle works once.
func TestDeferredSignupHandleIsSingleUse(t *testing.T) {
	env := newExtEnv(t, extSignup())
	ticket := env.mustDefer("sub-once", ExternalLoginOptions{})
	if _, err := env.engine.CompleteExternalSignup(env.ctx(), ticket.Handle, ExternalSignupOptions{}); err != nil {
		t.Fatalf("first use: %v", err)
	}
	_, err := env.engine.CompleteExternalSignup(env.ctx(), ticket.Handle, ExternalSignupOptions{})
	requireCode(t, err, CodeAuthExternalSignupInvalid)
	if !errors.Is(err, ErrExternalSignupInvalid) {
		t.Fatalf("err = %v", err)
	}
	if env.up.creates != 1 {
		t.Fatalf("creates = %d", env.up.creates)
	}
	env.waitForAudit(auditEventExternalLoginFailure, "signup_ticket_invalid")

	for _, bad := range []string{"", "not-a-handle", strings.Repeat("A", 43)} {
		_, err := env.engine.CompleteExternalSignup(env.ctx(), bad, ExternalSignupOptions{})
		requireCode(t, err, CodeAuthExternalSignupInvalid)
	}
}

// An expired handle, by the injected clock, is refused and consumed.
func TestDeferredSignupExpiredHandle(t *testing.T) {
	clk := newManualClock(time.Now().Truncate(time.Second))
	env := newExtEnv(t, extSignup(), extClock(clk), extConfig(func(c *Config) { c.ExternalAuth.SignupTicketTTL = 2 * time.Minute }))
	ticket := env.mustDefer("sub-exp", ExternalLoginOptions{})
	if want := clk.Now().Add(2 * time.Minute); !ticket.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", ticket.ExpiresAt, want)
	}

	// Only the clock moves: the key is still in Redis, so the engine itself is
	// what refuses the ticket.
	clk.Advance(2*time.Minute + time.Second)
	_, err := env.engine.CompleteExternalSignup(env.ctx(), ticket.Handle, ExternalSignupOptions{})
	requireCode(t, err, CodeAuthExternalSignupInvalid)
	if env.up.creates != 0 {
		t.Fatal("an account was created from an expired ticket")
	}
	if len(env.axsKeys()) != 0 {
		t.Fatal("the expired ticket was not consumed")
	}
}

// A handle belongs to the tenant of step one and is not burned by another's.
func TestDeferredSignupHandleIsTenantBound(t *testing.T) {
	env := newExtEnv(t, extSignup(), extMultiTenant())
	ticket := env.mustDefer("sub-t", ExternalLoginOptions{})

	other := WithTenantID(context.Background(), "tenant-b")
	_, err := env.engine.CompleteExternalSignup(other, ticket.Handle, ExternalSignupOptions{})
	requireCode(t, err, CodeAuthExternalSignupInvalid)
	if err := env.engine.CancelExternalSignup(other, ticket.Handle); err != nil {
		t.Fatalf("cancel from another tenant: %v", err)
	}
	if env.up.creates != 0 {
		t.Fatal("a foreign tenant created an account")
	}

	// Neither the attempt nor the cancel touched the real ticket.
	res, err := env.engine.CompleteExternalSignup(env.ctx(), ticket.Handle, ExternalSignupOptions{})
	if err != nil || !res.NewAccount {
		t.Fatalf("the owning tenant's ticket was burned: %+v, %v", res, err)
	}
	if env.up.lastCreate.TenantID != env.tenant {
		t.Fatalf("account created in tenant %q", env.up.lastCreate.TenantID)
	}
}

// An account that got the email between the steps: link required, no auto-link.
func TestDeferredSignupAccountAppearedInBetween(t *testing.T) {
	env := newExtEnv(t, extSignup(), extAutoLink())
	ticket := env.mustDefer("sub-between", ExternalLoginOptions{})
	env.addLocal(UserRecord{UserID: "late1", Identifier: signupEmail, Status: AccountActive})

	_, err := env.engine.CompleteExternalSignup(env.ctx(), ticket.Handle, ExternalSignupOptions{})
	requireCode(t, err, CodeAuthExternalLinkRequired)
	if env.up.linkCount() != 0 || env.up.creates != 0 {
		t.Fatalf("links=%d creates=%d: the identity must not be linked or an account created", env.up.linkCount(), env.up.creates)
	}
	env.waitForAudit(auditEventExternalLoginFailure, "link_required")
}

// The identity got linked between the steps.
func TestDeferredSignupIdentityLinkedInBetween(t *testing.T) {
	env := newExtEnv(t, extSignup())
	ticket := env.mustDefer("sub-linked-after", ExternalLoginOptions{})
	env.link("google", "sub-linked-after", extLocalUserID)

	_, err := env.engine.CompleteExternalSignup(env.ctx(), ticket.Handle, ExternalSignupOptions{})
	requireCode(t, err, CodeAuthExternalIdentityInUse)
	if env.up.creates != 0 {
		t.Fatal("an account was created for an identity that is linked")
	}
}

func TestCancelExternalSignupLeavesNothingBehind(t *testing.T) {
	env := newExtEnv(t, extSignup())
	users, links := env.up.userCount(), env.up.linkCount()
	ticket := env.mustDefer("sub-cancel", ExternalLoginOptions{})

	if err := env.engine.CancelExternalSignup(env.ctx(), ticket.Handle); err != nil {
		t.Fatalf("CancelExternalSignup: %v", err)
	}
	if len(env.axsKeys()) != 0 || env.up.userCount() != users || env.up.linkCount() != links || env.up.creates != 0 {
		t.Fatalf("cancel left state behind: keys=%v users=%d links=%d", env.axsKeys(), env.up.userCount(), env.up.linkCount())
	}
	_, err := env.engine.CompleteExternalSignup(env.ctx(), ticket.Handle, ExternalSignupOptions{})
	requireCode(t, err, CodeAuthExternalSignupInvalid)

	// Idempotent, and an unknown or empty handle is not an error.
	for _, h := range []string{ticket.Handle, "unknown", ""} {
		if err := env.engine.CancelExternalSignup(env.ctx(), h); err != nil {
			t.Fatalf("CancelExternalSignup(%q): %v", h, err)
		}
	}
}

// The account-creation limiter applies at step two, not step one, with the
// one-call sign-up's buckets.
func TestDeferredSignupAccountCreationLimiterAppliesAtStepTwo(t *testing.T) {
	env := newExtEnv(t, extSignup(), extConfig(func(c *Config) {
		c.Account.EnableCreationLimiter = true
		c.Account.AccountCreationMaxAttempts = 1
		c.Account.AccountCreationCooldown = time.Hour
	}))
	first := env.mustDefer("sub-lim-1", ExternalLoginOptions{})
	second := env.mustDefer("sub-lim-2", ExternalLoginOptions{}) // step one is not limited
	env.up.createErr = errors.New("database down")

	if _, err := env.engine.CompleteExternalSignup(env.ctx(), first.Handle, ExternalSignupOptions{}); !errors.Is(err, ErrSystemUnavailable) {
		t.Fatalf("first step two = %v, want the provider failure", err)
	}
	env.up.createErr = nil
	_, err := env.engine.CompleteExternalSignup(env.ctx(), second.Handle, ExternalSignupOptions{})
	requireCode(t, err, CodeAuthAccountCreationLimited)
	if env.metric(MetricAccountCreationRateLimited) != 1 {
		t.Fatalf("rate-limited metric = %d", env.metric(MetricAccountCreationRateLimited))
	}
	env.waitForAudit(auditEventAccountCreationRateLimited, "")
}

// The session profile and RememberMe of step two are honored, and an unknown
// profile does not spend the handle.
func TestDeferredSignupSessionProfileAndRememberMe(t *testing.T) {
	t.Run("profile named at step two", func(t *testing.T) {
		env := newExtEnv(t, extSignup(), extProfiles())
		ticket := env.mustDefer("sub-p", ExternalLoginOptions{})
		res, err := env.engine.CompleteExternalSignup(WithSessionProfile(env.ctx(), "agent"), ticket.Handle, ExternalSignupOptions{})
		if err != nil {
			t.Fatalf("step two: %v", err)
		}
		if _, profile := env.sessionOf(res.RefreshToken); profile != "agent" {
			t.Fatalf("session profile = %q, want agent", profile)
		}
	})
	t.Run("RememberMe selects the remember-me profile", func(t *testing.T) {
		env := newExtEnv(t, extSignup(), extProfiles())
		ticket := env.mustDefer("sub-rm", ExternalLoginOptions{})
		res, err := env.engine.CompleteExternalSignup(env.ctx(), ticket.Handle, ExternalSignupOptions{RememberMe: true})
		if err != nil {
			t.Fatalf("step two: %v", err)
		}
		if _, profile := env.sessionOf(res.RefreshToken); profile != "mobile" {
			t.Fatalf("session profile = %q, want mobile", profile)
		}
	})
	t.Run("RememberMe without profiles lengthens the session", func(t *testing.T) {
		env := newExtEnv(t, extSignup(), extConfig(func(c *Config) {
			c.Session.MaxSessionDuration = 24 * time.Hour
			c.Session.AbsoluteSessionLifetime = time.Hour
		}))
		short := env.mustDeferEmail("sub-short", "sub-short@example.com", ExternalLoginOptions{})
		long := env.mustDeferEmail("sub-long", "sub-long@example.com", ExternalLoginOptions{})
		resShort, err := env.engine.CompleteExternalSignup(env.ctx(), short.Handle, ExternalSignupOptions{})
		if err != nil {
			t.Fatal(err)
		}
		resLong, err := env.engine.CompleteExternalSignup(env.ctx(), long.Handle, ExternalSignupOptions{RememberMe: true})
		if err != nil {
			t.Fatal(err)
		}
		lifetime := func(refresh string) int64 {
			sid, _, err := internal.DecodeRefreshToken(refresh)
			if err != nil {
				t.Fatalf("decode refresh token: %v", err)
			}
			sess, err := env.engine.sessionStore.Peek(context.Background(), env.tenant, sid)
			if err != nil {
				t.Fatalf("peek: %v", err)
			}
			return sess.ExpiresAt - sess.CreatedAt
		}
		if s, l := lifetime(resShort.RefreshToken), lifetime(resLong.RefreshToken); l <= s {
			t.Fatalf("RememberMe session lifetime %ds is not longer than %ds", l, s)
		}
	})
	t.Run("unknown profile does not spend the handle", func(t *testing.T) {
		env := newExtEnv(t, extSignup(), extProfiles())
		ticket := env.mustDefer("sub-u", ExternalLoginOptions{})
		_, err := env.engine.CompleteExternalSignup(WithSessionProfile(env.ctx(), "kiosk"), ticket.Handle, ExternalSignupOptions{})
		if !errors.Is(err, ErrUnknownSessionProfile) {
			t.Fatalf("err = %v, want ErrUnknownSessionProfile", err)
		}
		if _, err := env.engine.CompleteExternalSignup(env.ctx(), ticket.Handle, ExternalSignupOptions{}); err != nil {
			t.Fatalf("the handle was spent by the refused profile: %v", err)
		}
	})
}

// A new account has no second factor to ask for.
func TestDeferredSignupNewAccountSkipsMFA(t *testing.T) {
	env := newExtEnv(t, extSignup(), extMFA())
	ticket := env.mustDefer("sub-mfa-new", ExternalLoginOptions{})
	res, err := env.engine.CompleteExternalSignup(env.ctx(), ticket.Handle, ExternalSignupOptions{})
	if err != nil || res.MFARequired || res.AccessToken == "" {
		t.Fatalf("result = %+v, %v", res, err)
	}
}

// Exactly one of many concurrent step twos with one handle creates the account.
func TestDeferredSignupConcurrentStepTwo(t *testing.T) {
	env := newExtEnv(t, extSignup())
	ticket := env.mustDefer("sub-race-two", ExternalLoginOptions{})
	users := env.up.userCount()

	const n = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := env.engine.CompleteExternalSignup(env.ctx(), ticket.Handle, ExternalSignupOptions{})
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var ok, invalid int
	for err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrExternalSignupInvalid):
			invalid++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if ok != 1 || invalid != n-1 || env.up.userCount() != users+1 || env.up.creates != 1 {
		t.Fatalf("ok=%d invalid=%d users+%d creates=%d, want exactly one account", ok, invalid, env.up.userCount()-users, env.up.creates)
	}
}

// DeferSignup changes only the branch that would create an account.
func TestDeferSignupLeavesEveryOtherBranchUnchanged(t *testing.T) {
	t.Run("without AllowSignup: not found, no ticket", func(t *testing.T) {
		env := newExtEnv(t)
		_, err := env.deferLogin(extTokenSpec{sub: "sub-n", email: "nobody@example.com", verified: true}, ExternalLoginOptions{})
		requireCode(t, err, CodeAuthExternalAccountNotFound)
		if len(env.axsKeys()) != 0 {
			t.Fatal("a ticket exists without AllowSignup")
		}
	})
	t.Run("a linked identity logs in", func(t *testing.T) {
		env := newExtEnv(t, extSignup())
		env.link("google", "sub-linked", extLocalUserID)
		res, err := env.deferLogin(extTokenSpec{sub: "sub-linked"}, ExternalLoginOptions{})
		if err != nil || res.ExternalSignup != nil || res.AccessToken == "" {
			t.Fatalf("result = %+v, %v", res, err)
		}
	})
	t.Run("auto-link links", func(t *testing.T) {
		env := newExtEnv(t, extSignup(), extAutoLink())
		res, err := env.deferLogin(extTokenSpec{sub: "sub-auto", email: extLocalEmail, verified: true}, ExternalLoginOptions{})
		if err != nil || res.ExternalSignup != nil || !res.LinkedIdentity {
			t.Fatalf("result = %+v, %v", res, err)
		}
	})
	t.Run("a matching account without auto-link: link required", func(t *testing.T) {
		env := newExtEnv(t, extSignup())
		_, err := env.deferLogin(extTokenSpec{sub: "sub-lr", email: extLocalEmail, verified: true}, ExternalLoginOptions{})
		requireCode(t, err, CodeAuthExternalLinkRequired)
	})
	t.Run("an unverified email: refused", func(t *testing.T) {
		env := newExtEnv(t, extSignup())
		_, err := env.deferLogin(extTokenSpec{sub: "sub-uv", email: signupEmail, verified: false}, ExternalLoginOptions{})
		requireCode(t, err, CodeAuthExternalEmailUnverified)
	})
	t.Run("a pending account: link requires verification", func(t *testing.T) {
		env := newExtEnv(t, extSignup(), extAutoLink())
		env.addLocal(UserRecord{UserID: "pend2", Identifier: signupEmail, Status: AccountPendingVerification})
		_, err := env.deferLogin(extTokenSpec{sub: "sub-pend", email: signupEmail, verified: true}, ExternalLoginOptions{})
		requireCode(t, err, CodeAuthExternalLinkRequiresVerify)
	})
	t.Run("the token is spent: a replay is refused", func(t *testing.T) {
		env := newExtEnv(t, extSignup())
		token, nonce := env.idp.token(extTokenSpec{sub: "sub-replay", email: signupEmail, verified: true})
		opts := ExternalLoginOptions{Nonce: nonce, DeferSignup: true}
		if _, err := env.engine.LoginWithExternalIdentity(env.ctx(), "google", token, opts); err != nil {
			t.Fatalf("step one: %v", err)
		}
		if _, err := env.engine.LoginWithExternalIdentity(env.ctx(), "google", token, opts); !errors.Is(err, ErrExternalTokenReplayed) {
			t.Fatalf("replay = %v, want ErrExternalTokenReplayed", err)
		}
	})
}

// The display name of step two replaces the one of step one when given, and is
// capped like it.
func TestDeferredSignupDisplayName(t *testing.T) {
	env := newExtEnv(t, extSignup())
	keep := env.mustDeferEmail("sub-n1", "sub-n1@example.com", ExternalLoginOptions{DisplayName: "From Step One"})
	if _, err := env.engine.CompleteExternalSignup(env.ctx(), keep.Handle, ExternalSignupOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := env.up.lastIdentity.DisplayName; got != "From Step One" {
		t.Fatalf("display name = %q, want step one's", got)
	}

	over := env.mustDeferEmail("sub-n2", "sub-n2@example.com", ExternalLoginOptions{DisplayName: "From Step One"})
	if _, err := env.engine.CompleteExternalSignup(env.ctx(), over.Handle, ExternalSignupOptions{DisplayName: "  Better Name "}); err != nil {
		t.Fatal(err)
	}
	if got := env.up.lastIdentity.DisplayName; got != "Better Name" {
		t.Fatalf("display name = %q, want step two's", got)
	}

	capped := env.mustDeferEmail("sub-n3", "sub-n3@example.com", ExternalLoginOptions{})
	if _, err := env.engine.CompleteExternalSignup(env.ctx(), capped.Handle, ExternalSignupOptions{DisplayName: strings.Repeat("é", 400)}); err != nil {
		t.Fatal(err)
	}
	if got := env.up.lastIdentity.DisplayName; len(got) > maxExternalDisplayName || got == "" {
		t.Fatalf("display name length %d, want 1..%d", len(got), maxExternalDisplayName)
	}
}

// Neither the handle nor the token reaches an audit event, a log line, or the
// ticket's own printed forms.
func TestDeferredSignupSecretsStayOutOfAuditAndLogs(t *testing.T) {
	logs := &syncBuffer{}
	env := newExtEnv(t, extSignup(), extConfig(func(c *Config) {
		c.Logger = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}))
	token, nonce := env.idp.token(extTokenSpec{sub: "sub-secret", email: signupEmail, verified: true})
	res, err := env.engine.LoginWithExternalIdentity(env.ctx(), "google", token, ExternalLoginOptions{Nonce: nonce, DeferSignup: true})
	if err != nil {
		t.Fatalf("step one: %v", err)
	}
	handle := res.ExternalSignup.Handle
	if _, err := env.engine.CompleteExternalSignup(env.ctx(), handle, ExternalSignupOptions{}); err != nil {
		t.Fatalf("step two: %v", err)
	}
	_, _ = env.engine.CompleteExternalSignup(env.ctx(), handle, ExternalSignupOptions{}) // the refused reuse

	events, err := json.Marshal(env.eventsAll())
	if err != nil {
		t.Fatal(err)
	}
	for name, secret := range map[string]string{"handle": handle, "token": token, "nonce": nonce} {
		if strings.Contains(string(events), secret) {
			t.Errorf("the %s reached the audit trail", name)
		}
		if logs.Contains(secret) {
			t.Errorf("the %s reached a log line", name)
		}
	}
	for _, shown := range []string{
		res.ExternalSignup.String(),
		fmt.Sprintf("%v %+v %#v %s", res.ExternalSignup, *res.ExternalSignup, *res.ExternalSignup, res.ExternalSignup),
	} {
		if strings.Contains(shown, handle) {
			t.Errorf("the ticket printed its handle: %s", shown)
		}
	}
	var out strings.Builder
	slog.New(slog.NewTextHandler(&out, nil)).Info("ticket", "t", *res.ExternalSignup)
	if strings.Contains(out.String(), handle) {
		t.Errorf("the ticket logged its handle: %s", out.String())
	}
}

func TestExternalSignupMethodsWhenExternalAuthIsOff(t *testing.T) {
	env := newExtEnv(t, extConfig(func(c *Config) { c.ExternalAuth.Enabled = false }))
	_, err := env.engine.CompleteExternalSignup(env.ctx(), "h", ExternalSignupOptions{})
	requireCode(t, err, CodeAuthExternalDisabled)
	requireCode(t, env.engine.CancelExternalSignup(env.ctx(), "h"), CodeAuthExternalDisabled)
}

func TestSignupTicketTTLConfig(t *testing.T) {
	for _, tc := range []struct {
		ttl  time.Duration
		ok   bool
		name string
	}{
		{0, true, "default"},
		{time.Minute, true, "lower bound"},
		{time.Hour, true, "upper bound"},
		{30 * time.Second, false, "below the bound"},
		{2 * time.Hour, false, "above the bound"},
		{-time.Minute, false, "negative"},
	} {
		cfg := defaultConfig()
		cfg.ExternalAuth = ExternalAuthConfig{
			Enabled:         true,
			Providers:       map[string]ExternalProviderConfig{"google": {Kind: ExternalKindGoogle, ClientIDs: []string{"c"}}},
			SignupTicketTTL: tc.ttl,
		}
		err := cfg.validateExternalAuth()
		if (err == nil) != tc.ok {
			t.Errorf("%s (%v): validateExternalAuth = %v, want ok=%v", tc.name, tc.ttl, err, tc.ok)
		}
	}
}
