package goAuth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal/clock"
	"github.com/MrEthical07/goAuth/internal/limiters"
	"github.com/MrEthical07/goAuth/internal/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

func extLimit(max int) extOption {
	return extConfig(func(c *Config) {
		c.ExternalAuth.MaxAttempts = max
		c.ExternalAuth.Cooldown = time.Minute
	})
}

// junk is a syntactically valid but wrongly signed token: it reaches the
// verifier and fails there.
func (env *extEnv) junkToken() string {
	token, _ := env.idp.token(extTokenSpec{sub: "junk"})
	return token[:len(token)-6] + "AAAAAA"
}

// The pre-verification limit is per client IP, claimed before any
// verification work, and reset by a success.
//
// NEW-API.
func TestExternalLoginLimiterBySourceIP(t *testing.T) {
	env := newExtEnv(t, extLimit(3))
	env.link("google", "sub-l", extLocalUserID)
	ipA := WithClientIP(env.ctx(), "203.0.113.10")
	ipB := WithClientIP(env.ctx(), "203.0.113.11")
	junk := func(ctx context.Context) error {
		_, err := env.engine.LoginWithExternalIdentity(ctx, "google", env.junkToken(), ExternalLoginOptions{Nonce: "n"})
		return err
	}

	for i := 0; i < 3; i++ {
		requireCode(t, junk(ipA), CodeAuthExternalTokenInvalid)
	}
	fetches := env.idp.fetches.Load()
	env.cmds.reset()
	err := junk(ipA)
	requireCode(t, err, CodeAuthExternalLoginRateLimited)
	if !errors.Is(err, ErrExternalLoginRateLimited) {
		t.Fatalf("err = %v", err)
	}
	// The refused attempt did one limiter command and nothing else.
	if env.idp.fetches.Load() != fetches {
		t.Fatal("a rate-limited attempt still touched the key server")
	}
	for _, name := range env.cmds.names() {
		if name != "evalsha" && name != "eval" {
			t.Fatalf("a rate-limited attempt sent %v", env.cmds.names())
		}
	}
	if env.metric(MetricLoginRateLimited) != 1 {
		t.Fatalf("rate-limited metric = %d", env.metric(MetricLoginRateLimited))
	}
	env.waitForAudit(auditEventRateLimitTriggered, "")
	env.waitForAudit(auditEventExternalLoginFailure, "rate_limited")

	// Even a valid token is refused from the exhausted source, and fine from another.
	token, nonce := env.idp.token(extTokenSpec{sub: "sub-l"})
	if _, err := env.engine.LoginWithExternalIdentity(ipA, "google", token, ExternalLoginOptions{Nonce: nonce}); !errors.Is(err, ErrExternalLoginRateLimited) {
		t.Fatalf("valid token from an exhausted source = %v", err)
	}
	if _, err := env.engine.LoginWithExternalIdentity(ipB, "google", token, ExternalLoginOptions{Nonce: nonce}); err != nil {
		t.Fatalf("valid token from another source: %v", err)
	}
	// ... and the exhausted source does not leak into another tenant's budget.

	// Success resets the source: after one, three more failures are allowed.
	fresh := newExtEnv(t, extLimit(3))
	fresh.link("google", "sub-l", extLocalUserID)
	ip := WithClientIP(fresh.ctx(), "203.0.113.20")
	for i := 0; i < 2; i++ {
		_, _ = fresh.engine.LoginWithExternalIdentity(ip, "google", fresh.junkToken(), ExternalLoginOptions{Nonce: "n"})
	}
	token, nonce = fresh.idp.token(extTokenSpec{sub: "sub-l"})
	if _, err := fresh.engine.LoginWithExternalIdentity(ip, "google", token, ExternalLoginOptions{Nonce: nonce}); err != nil {
		t.Fatalf("success under the limit: %v", err)
	}
	for i := 0; i < 3; i++ {
		_, err := fresh.engine.LoginWithExternalIdentity(ip, "google", fresh.junkToken(), ExternalLoginOptions{Nonce: "n"})
		requireCode(t, err, CodeAuthExternalTokenInvalid)
	}
}

// Without a client IP there is no shared pre-verification bucket: one that
// every such request shared could be exhausted by anyone, locking out every
// user of the provider.
//
// NEW-API.
func TestExternalLoginWithoutClientIPHasNoSharedBucket(t *testing.T) {
	env := newExtEnv(t, extLimit(3))
	env.link("google", "sub-l", extLocalUserID)
	for i := 0; i < 20; i++ {
		_, err := env.engine.LoginWithExternalIdentity(env.ctx(), "google", env.junkToken(), ExternalLoginOptions{Nonce: "n"})
		requireCode(t, err, CodeAuthExternalTokenInvalid)
	}
	if env.hasKey("rl:extlogin:ip:") || env.hasKey("rl:extlogin:prov:") {
		t.Fatalf("a source bucket exists without an IP: %v", env.mr.Keys())
	}
	if _, err := env.login(extTokenSpec{sub: "sub-l"}); err != nil {
		t.Fatalf("a legitimate sign-in after a junk flood: %v", err)
	}
}

// The post-verification limit is per identity, counts resolution failures,
// and is reset by a success.
//
// NEW-API.
func TestExternalLoginLimiterBySubject(t *testing.T) {
	env := newExtEnv(t, extLimit(3))
	attempt := func(sub string) error {
		_, err := env.login(extTokenSpec{sub: sub, email: extLocalEmail, verified: true})
		return err
	}
	for i := 0; i < 3; i++ {
		requireCode(t, attempt("sub-probe"), CodeAuthExternalLinkRequired)
	}
	requireCode(t, attempt("sub-probe"), CodeAuthExternalLoginRateLimited)
	// Another identity is not affected.
	requireCode(t, attempt("sub-other"), CodeAuthExternalLinkRequired)

	// A success resets the identity's bucket.
	ok := newExtEnv(t, extLimit(3), extAutoLink())
	var err error
	for i := 0; i < 2; i++ {
		_, err = ok.login(extTokenSpec{sub: "sub-r", email: "nobody@example.com", verified: true})
		requireCode(t, err, CodeAuthExternalAccountNotFound)
	}
	if _, err := ok.login(extTokenSpec{sub: "sub-r", email: extLocalEmail, verified: true}); err != nil {
		t.Fatalf("success under the limit: %v", err)
	}
	if ok.hasKey("rl:extlogin:sub:") {
		t.Fatalf("the identity's bucket survived a success: %v", ok.mr.Keys())
	}
}

// A limiter outage never blocks a sign-in, and is reported like every other
// limiter's.
//
// NEW-API.
func TestExternalLoginLimiterFailsOpen(t *testing.T) {
	env := newExtEnv(t)
	env.link("google", "sub-o", extLocalUserID)
	dead := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: 50 * time.Millisecond})
	t.Cleanup(func() { _ = dead.Close() })
	env.engine.externalLimiter = limiters.NewExternalLimiter(dead, limiters.ExternalConfig{MaxAttempts: 1})

	ctx := WithClientIP(env.ctx(), "203.0.113.30")
	token, nonce := env.idp.token(extTokenSpec{sub: "sub-o"})
	if _, err := env.engine.LoginWithExternalIdentity(ctx, "google", token, ExternalLoginOptions{Nonce: nonce}); err != nil {
		t.Fatalf("sign-in with the limiter down: %v", err)
	}
	ev := env.waitForAudit(auditEventLimiterFailOpen, "")
	if ev.Metadata["scope"] != "external_login" || ev.Metadata["policy"] != "fail_open" {
		t.Fatalf("limiter_fail_open = %+v", ev)
	}
	if env.metric(MetricLimiterFailOpen) == 0 {
		t.Fatal("fail-open metric not counted")
	}
}

// A token is accepted once.
//
// NEW-API.
func TestExternalLoginReplay(t *testing.T) {
	env := newExtEnv(t)
	env.link("google", "sub-rp", extLocalUserID)
	token, nonce := env.idp.token(extTokenSpec{sub: "sub-rp"})

	if _, err := env.engine.LoginWithExternalIdentity(env.ctx(), "google", token, ExternalLoginOptions{Nonce: nonce}); err != nil {
		t.Fatalf("first use: %v", err)
	}
	_, err := env.engine.LoginWithExternalIdentity(env.ctx(), "google", token, ExternalLoginOptions{Nonce: nonce})
	requireCode(t, err, CodeAuthExternalTokenReplayed)
	env.waitForAudit(auditEventExternalLoginFailure, "token_replayed")

	var replayKeys []string
	for _, k := range env.mr.Keys() {
		if strings.HasPrefix(k, "axt:google:") {
			replayKeys = append(replayKeys, k)
		}
	}
	if len(replayKeys) != 1 {
		t.Fatalf("replay keys = %v", replayKeys)
	}
	// 10 minutes of validity plus the 60s leeway, and never more.
	ttl := env.mr.TTL(replayKeys[0])
	if ttl < 9*time.Minute || ttl > 11*time.Minute+time.Second {
		t.Fatalf("replay key ttl = %v", ttl)
	}
}

// The nonce is required and may be raw or hashed.
//
// NEW-API.
func TestExternalLoginNonce(t *testing.T) {
	env := newExtEnv(t)
	env.link("google", "sub-n", extLocalUserID)
	link := func(t *testing.T, spec extTokenSpec, serverNonce string) error {
		token, _ := env.idp.token(spec)
		_, err := env.engine.LoginWithExternalIdentity(env.ctx(), "google", token, ExternalLoginOptions{Nonce: serverNonce})
		return err
	}

	if err := link(t, extTokenSpec{sub: "sub-n", nonce: "server-nonce-1"}, "server-nonce-1"); err != nil {
		t.Fatalf("raw nonce: %v", err)
	}
	if err := link(t, extTokenSpec{sub: "sub-n", nonce: "server-nonce-2", hashed: true}, "server-nonce-2"); err != nil {
		t.Fatalf("hashed nonce: %v", err)
	}
	requireCode(t, link(t, extTokenSpec{sub: "sub-n", nonce: "server-nonce-3"}, "someone-elses"), CodeAuthExternalTokenInvalid)
	requireCode(t, link(t, extTokenSpec{sub: "sub-n", nonce: "server-nonce-4"}, ""), CodeAuthExternalTokenInvalid)
	requireCode(t, link(t, extTokenSpec{sub: "sub-n", nonce: "n5", mutate: func(c jwt.MapClaims) { delete(c, "nonce") }}, "n5"), CodeAuthExternalTokenInvalid)

	// A nonce failure must not use up the token.
	token, nonce := env.idp.token(extTokenSpec{sub: "sub-n"})
	if _, err := env.engine.LoginWithExternalIdentity(env.ctx(), "google", token, ExternalLoginOptions{Nonce: "wrong"}); err == nil {
		t.Fatal("wrong nonce accepted")
	}
	if _, err := env.engine.LoginWithExternalIdentity(env.ctx(), "google", token, ExternalLoginOptions{Nonce: nonce}); err != nil {
		t.Fatalf("the token was consumed by a wrong-nonce attempt: %v", err)
	}
}

// Token verification failures reach the caller as the public error and the
// audit trail as a fixed reason.
//
// NEW-API.
func TestExternalLoginTokenFailures(t *testing.T) {
	cases := []struct {
		name   string
		spec   extTokenSpec
		mutate func(*extEnv, string) string
		code   AuthCode
		reason string
	}{
		{"bad signature", extTokenSpec{sub: "s"}, func(env *extEnv, tok string) string { return tok[:len(tok)-6] + "AAAAAA" }, CodeAuthExternalTokenInvalid, "token_invalid"},
		{"expired", extTokenSpec{sub: "s", mutate: func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }}, nil, CodeAuthExternalTokenInvalid, "token_invalid"},
		{"wrong audience", extTokenSpec{sub: "s", mutate: func(c jwt.MapClaims) { c["aud"] = "other-client" }}, nil, CodeAuthExternalTokenInvalid, "token_invalid"},
		{"wrong issuer", extTokenSpec{sub: "s", mutate: func(c jwt.MapClaims) { c["iss"] = "https://evil.test" }}, nil, CodeAuthExternalTokenInvalid, "token_invalid"},
		{"google's alternate issuer is accepted elsewhere; this is not google", extTokenSpec{sub: "s", mutate: func(c jwt.MapClaims) { c["iss"] = "https://appleid.apple.com" }}, nil, CodeAuthExternalTokenInvalid, "token_invalid"},
		{"not a token", extTokenSpec{sub: "s"}, func(env *extEnv, tok string) string { return "garbage" }, CodeAuthExternalTokenInvalid, "token_invalid"},
		{"empty", extTokenSpec{sub: "s"}, func(env *extEnv, tok string) string { return "" }, CodeAuthExternalTokenInvalid, "token_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newExtEnv(t, extSignup())
			token, nonce := env.idp.token(tc.spec)
			if tc.mutate != nil {
				token = tc.mutate(env, token)
			}
			_, err := env.engine.LoginWithExternalIdentity(env.ctx(), "google", token, ExternalLoginOptions{Nonce: nonce})
			requireCode(t, err, tc.code)
			env.waitForAudit(auditEventExternalLoginFailure, tc.reason)
			if env.up.creates != 0 || env.up.gets != 0 {
				t.Fatalf("a rejected token reached the user provider (gets %d, creates %d)", env.up.gets, env.up.creates)
			}
			if env.metric(MetricLoginFailure) != 1 {
				t.Fatalf("login failure metric = %d", env.metric(MetricLoginFailure))
			}
		})
	}
}

// If the provider's keys cannot be fetched and none are cached, nothing is
// accepted.
//
// NEW-API.
func TestExternalLoginProviderUnavailable(t *testing.T) {
	env := newExtEnv(t, extSignup())
	env.idp.setFail(true)
	token, nonce := env.idp.token(extTokenSpec{sub: "sub-u", email: "u@example.com", verified: true})
	_, err := env.engine.LoginWithExternalIdentity(env.ctx(), "google", token, ExternalLoginOptions{Nonce: nonce})
	ae := requireCode(t, err, CodeSystemUnavailableExternalProvider)
	if ae.Category != CategorySystem {
		t.Fatalf("category = %s", ae.Category)
	}
	env.waitForAudit(auditEventExternalLoginFailure, "provider_unavailable")
	if env.up.creates != 0 {
		t.Fatal("an account was created from a token that could not be verified")
	}
	if env.hasKey("axt:") {
		t.Fatal("an unverified token left a replay record")
	}

	// Keys come back: the same token verifies (it was never consumed) once
	// the failure back-off has passed.
	clk := clock.NewFake(time.Now())
	t.Cleanup(clock.Set(clk.Now))
	env.idp.setFail(false)
	clk.Advance(20 * time.Second)
	res, err := env.engine.LoginWithExternalIdentity(env.ctx(), "google", token, ExternalLoginOptions{Nonce: nonce})
	if err != nil || !res.NewAccount {
		t.Fatalf("after recovery: %+v, %v", res, err)
	}
}

// Every outcome is audited under a fixed reason, and no secret reaches the
// audit trail or the logs.
//
// NEW-API.
func TestExternalLoginNeverLeaksTokenOrNonce(t *testing.T) {
	var logs bytes.Buffer
	var logMu sync.Mutex
	logger := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logs.Write(p)
	}), &slog.HandlerOptions{Level: slog.LevelDebug}))

	env := newExtEnv(t, extSignup(), extConfig(func(c *Config) { c.Logger = logger }))
	env.link("google", "sub-ok", extLocalUserID)

	var secrets []string
	var errTexts []string
	run := func(spec extTokenSpec, mutate func(string) string, provider string) {
		token, nonce := env.idp.token(spec)
		if mutate != nil {
			token = mutate(token)
		}
		secrets = append(secrets, token, nonce)
		parts := strings.Split(token, ".")
		secrets = append(secrets, parts...)
		_, err := env.engine.LoginWithExternalIdentity(env.ctx(), provider, token, ExternalLoginOptions{Nonce: nonce})
		if err != nil {
			errTexts = append(errTexts, err.Error())
		}
		_, err = env.engine.LoginWithExternalIdentity(env.ctx(), provider, token, ExternalLoginOptions{Nonce: nonce}) // replay
		if err != nil {
			errTexts = append(errTexts, err.Error())
		}
	}
	run(extTokenSpec{sub: "sub-ok"}, nil, "google")
	run(extTokenSpec{sub: "sub-new", email: "leak@example.com", verified: true}, nil, "google")
	run(extTokenSpec{sub: "sub-bad"}, func(s string) string { return s[:len(s)-6] + "AAAAAA" }, "google")
	run(extTokenSpec{sub: "sub-x", email: "x@example.com", verified: false}, nil, "google")
	run(extTokenSpec{sub: "sub-y"}, nil, "no-such-provider")
	env.idp.setFail(true)
	env.engine.externalVerifier = mustRebuildVerifier(t, env) // cold key cache: an outage
	run(extTokenSpec{sub: "sub-z", email: "z@example.com", verified: true}, nil, "google")

	events := env.sink
	time.Sleep(100 * time.Millisecond)
	events.mu.Lock()
	encoded, _ := json.Marshal(events.events)
	events.mu.Unlock()
	logMu.Lock()
	logged := logs.String()
	logMu.Unlock()
	haystack := string(encoded) + "\n" + logged + "\n" + strings.Join(errTexts, "\n")

	for _, s := range secrets {
		if len(s) < 8 {
			continue
		}
		if strings.Contains(haystack, s) {
			t.Fatalf("a token fragment or nonce %q... appears in the audit trail, logs or errors", s[:8])
		}
	}
	// Nor in Redis: only the hash of the signed part is stored.
	for _, k := range env.mr.Keys() {
		for _, s := range secrets {
			if len(s) >= 8 && strings.Contains(k, s) {
				t.Fatalf("redis key %q contains a secret", k)
			}
		}
	}
}

type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func mustRebuildVerifier(t *testing.T, env *extEnv) *oidc.Verifier {
	t.Helper()
	v, err := newExternalVerifier(env.cfg, env.rdb, env.idp.server.Client())
	if err != nil {
		t.Fatalf("newExternalVerifier: %v", err)
	}
	return v
}
