package goAuth

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func loginIPConfig(max int) Config {
	cfg := accountTestConfig()
	cfg.Security.MaxLoginAttempts = 50 // the per-identifier budgets stay out of the way
	cfg.Security.LoginIPLimiter = LoginIPLimiterConfig{Enabled: true, MaxAttempts: max, Cooldown: time.Minute}
	return cfg
}

// NEW-API (Security.LoginIPLimiter). R2-06: the documented per-IP half of the
// credential-stuffing control did not exist; one address could try a guess
// against every account.
func TestLoginIPLimiterBoundsOneAddressAcrossAccounts(t *testing.T) {
	cfg := loginIPConfig(5)
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := WithClientIP(context.Background(), "203.0.113.7")

	for i := 1; i <= 5; i++ {
		identifier := fmt.Sprintf("user-%d", i)
		if i == 2 {
			identifier = "alice"
		}
		if _, _, err := engine.Login(ctx, identifier, "wrong-password-1"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v, want ErrInvalidCredentials", i, err)
		}
	}
	for _, identifier := range []string{"bob", "user-99", "alice"} {
		if _, _, err := engine.Login(ctx, identifier, "correct-password-123"); !errors.Is(err, ErrLoginRateLimited) {
			t.Fatalf("%s after the budget: %v, want ErrLoginRateLimited", identifier, err)
		}
	}

	// Another address, and a request that carries no address, are not limited.
	other := WithClientIP(context.Background(), "203.0.113.8")
	if _, _, err := engine.Login(other, "bob", "correct-password-123"); err != nil {
		t.Fatalf("another address: %v", err)
	}
	if _, _, err := engine.Login(context.Background(), "bob", "correct-password-123"); err != nil {
		t.Fatalf("no address: %v", err)
	}
}

func TestLoginIPLimiterIsOffByDefault(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Security.MaxLoginAttempts = 500
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := WithClientIP(context.Background(), "203.0.113.7")

	for i := 0; i < 60; i++ {
		if _, _, err := engine.Login(ctx, fmt.Sprintf("user-%d", i), "wrong-password-1"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
}

// A good login gives its slot back; it does not reset an address that is still
// guessing, so it cannot be used to refill the budget.
func TestLoginIPLimiterCountsFailuresNotLogins(t *testing.T) {
	cfg := loginIPConfig(5)
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := WithClientIP(context.Background(), "203.0.113.7")

	for i := 0; i < 4; i++ {
		_, _, _ = engine.Login(ctx, fmt.Sprintf("user-%d", i), "wrong-password-1")
	}
	for i := 0; i < 3; i++ {
		if _, _, err := engine.Login(ctx, "bob", "correct-password-123"); err != nil {
			t.Fatalf("good login %d: %v", i, err)
		}
	}
	if _, _, err := engine.Login(ctx, "user-4", "wrong-password-1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("the fifth failure: %v, want ErrInvalidCredentials", err)
	}
	if _, _, err := engine.Login(ctx, "user-5", "wrong-password-1"); !errors.Is(err, ErrLoginRateLimited) {
		t.Fatalf("the sixth failure: %v, want ErrLoginRateLimited (good logins must not refill the budget)", err)
	}
}

func TestLoginIPLimiterHonorsTheSlidingWindowMode(t *testing.T) {
	cfg := loginIPConfig(3)
	cfg.Security.LimiterWindowMode = "sliding"
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := WithClientIP(context.Background(), "203.0.113.7")

	for i := 0; i < 3; i++ {
		_, _, _ = engine.Login(ctx, fmt.Sprintf("user-%d", i), "wrong-password-1")
	}
	if _, _, err := engine.Login(ctx, "user-9", "wrong-password-1"); !errors.Is(err, ErrLoginRateLimited) {
		t.Fatalf("got %v, want ErrLoginRateLimited", err)
	}
}

// The throttle follows LimiterFailClosed like every other limiter.
func TestLoginIPLimiterFollowsLimiterFailClosed(t *testing.T) {
	for _, closed := range []bool{true, false} {
		env := newRSEnv(t, limiterFailClosedConfig(closed), rsConfig(func(c *Config) {
			c.Security.LoginIPLimiter = LoginIPLimiterConfig{Enabled: true, MaxAttempts: 5, Cooldown: time.Minute}
		}))
		br := &limiterBreaker{}
		br.filter.Store("login:ip")
		env.rdb.AddHook(br)
		br.set(breakAll)

		ctx := WithClientIP(env.ctx(), "203.0.113.7")
		_, _, err := env.engine.Login(ctx, rsIdentifier, rsPassword)
		if closed {
			if !isSystemError(err) {
				t.Fatalf("closed: %v, want a system error", err)
			}
		} else if err != nil {
			t.Fatalf("open: %v, want the login to go through", err)
		}
		waitForLimiterEvent(t, env, "login_ip")
	}
}

func withIPLimiter() *Config {
	cfg := loginIPConfig(5)
	return &cfg
}

func TestLoginIPLimiterConfigIsValidatedAndLinted(t *testing.T) {
	cfg := loginIPConfig(0)
	if err := cfg.Validate(); err == nil {
		t.Fatal("an enabled limiter without MaxAttempts must be rejected")
	}
	cfg = loginIPConfig(5)
	cfg.Security.LoginIPLimiter.Cooldown = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("an enabled limiter without Cooldown must be rejected")
	}

	off := accountTestConfig()
	if !hasLintCode((&off).Lint(), "login_ip_limiter_disabled") {
		t.Fatal("expected the login_ip_limiter_disabled note while the limiter is off")
	}
	if hasLintCode(withIPLimiter().Lint(), "login_ip_limiter_disabled") {
		t.Fatal("the note must disappear once the limiter is on")
	}
}
