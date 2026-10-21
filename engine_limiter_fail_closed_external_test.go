package goAuth

import (
	"errors"
	"testing"
	"time"
)

// External sign-in has two limiter buckets before verification and after it,
// and sign-up reuses the account-creation limiter. Each honors
// Security.LimiterFailClosed.
//
// NEW-API (Security.LimiterFailClosed); the open rows are ALREADY-TRUE.
func TestLimiterFailClosedExternalSignIn(t *testing.T) {
	const ip = "203.0.113.50"

	type row struct {
		name   string
		filter string
		opts   []extOption
		spec   extTokenSpec
		ip     string
		scope  string
		reason string
	}
	rows := []row{
		{name: "source bucket (client IP)", filter: "rl:extlogin:ip:", ip: ip, scope: "external_login",
			spec: extTokenSpec{sub: "sub-ip"}, reason: externalReasonLimiterUnavailable},
		{name: "identity bucket", filter: "rl:extlogin:sub:", scope: "external_login",
			spec: extTokenSpec{sub: "sub-id"}, reason: externalReasonLimiterUnavailable},
		{name: "sign-up account creation", filter: "rl:account:", scope: "account_creation",
			opts: []extOption{extSignup(), extConfig(func(c *Config) {
				c.Account.EnableCreationLimiter = true
				c.Account.AccountCreationMaxAttempts = 5
				c.Account.AccountCreationCooldown = time.Minute
			})},
			spec: extTokenSpec{sub: "sub-new", email: "brand-new@example.com", verified: true}, reason: externalReasonLimiterUnavailable},
	}

	for _, r := range rows {
		for _, closed := range []bool{true, false} {
			name := r.name + "/open"
			if closed {
				name = r.name + "/closed"
			}
			t.Run(name, func(t *testing.T) {
				opts := append([]extOption{extConfig(func(c *Config) { c.Security.LimiterFailClosed = closed })}, r.opts...)
				env := newExtEnv(t, opts...)
				env.link("google", "sub-ip", extLocalUserID)
				env.link("google", "sub-id", extLocalUserID)
				br := &limiterBreaker{}
				br.filter.Store(r.filter)
				env.rdb.AddHook(br)
				br.set(breakAll)

				ctx := env.ctx()
				if r.ip != "" {
					ctx = WithClientIP(ctx, r.ip)
				}
				r.spec.provider = "google"
				token, nonce := env.idp.token(r.spec)
				_, err := env.engine.LoginWithExternalIdentity(ctx, "google", token, ExternalLoginOptions{Nonce: nonce})

				if closed {
					if !isSystemError(err) {
						t.Fatalf("limiter down with LimiterFailClosed: got %v, want a system error", err)
					}
					if errors.Is(err, ErrExternalLoginRateLimited) {
						t.Fatalf("an outage must not read as a rate limit: %v", err)
					}
					ev := env.waitForAudit(auditEventLimiterFailOpen, "")
					if ev.Metadata["scope"] != r.scope || ev.Metadata["fail_closed"] != "true" {
						t.Fatalf("limiter event = %v", ev.Metadata)
					}
					failure := env.waitForAudit(auditEventExternalLoginFailure, r.reason)
					if failure.Success {
						t.Fatalf("failure event reports success: %+v", failure)
					}
					return
				}
				if err != nil {
					t.Fatalf("fail-open default: sign-in must go through, got %v", err)
				}
				ev := env.waitForAudit(auditEventLimiterFailOpen, "")
				if _, ok := ev.Metadata["fail_closed"]; ok || ev.Metadata["policy"] != "fail_open" {
					t.Fatalf("limiter event = %v", ev.Metadata)
				}
			})
		}
	}
}
