package limiters

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal/window"
)

// NEW-API.
func TestExternalLimiterReserveAndReset(t *testing.T) {
	for _, mode := range []window.Mode{window.Fixed, window.Sliding} {
		name := "fixed"
		if mode == window.Sliding {
			name = "sliding"
		}
		t.Run(name, func(t *testing.T) {
			_, rdb := newRoleSwitchTestRedis(t)
			l := NewExternalLimiter(rdb, ExternalConfig{MaxAttempts: 3, Cooldown: time.Minute, WindowMode: mode})
			ctx := context.Background()
			key := l.SourceKey("t1", "203.0.113.7")

			for i := 0; i < 3; i++ {
				if err := l.Reserve(ctx, key); err != nil {
					t.Fatalf("attempt %d should be allowed: %v", i+1, err)
				}
			}
			if err := l.Reserve(ctx, key); !errors.Is(err, ErrExternalRateLimited) {
				t.Fatalf("4th attempt = %v, want ErrExternalRateLimited", err)
			}
			// Another IP, another tenant and another provider have their own budget.
			for _, other := range []string{
				l.SourceKey("t1", "203.0.113.8"),
				l.SourceKey("t2", "203.0.113.7"),
				l.SubjectKey("t1", "google", "203.0.113.7"),
			} {
				if err := l.Reserve(ctx, other); err != nil {
					t.Fatalf("%s should be unaffected: %v", other, err)
				}
			}
			if err := l.Reset(ctx, key); err != nil {
				t.Fatalf("reset: %v", err)
			}
			if err := l.Reserve(ctx, key); err != nil {
				t.Fatalf("attempt after reset should be allowed: %v", err)
			}
		})
	}
}

// NEW-API.
func TestExternalLimiterKeys(t *testing.T) {
	_, rdb := newRoleSwitchTestRedis(t)
	l := NewExternalLimiter(rdb, ExternalConfig{})

	if got := l.SourceKey("t", "1.2.3.4"); got != "rl:extlogin:ip:t:1.2.3.4" {
		t.Fatalf("ip key = %q", got)
	}
	// No IP, no shared bucket: one that every unknown-IP request shared
	// could be exhausted by anyone, locking out every user of the provider.
	if got := l.SourceKey("t", ""); got != "" {
		t.Fatalf("key without an IP = %q, want none", got)
	}
	if got := l.SubjectKey("t", "apple", "sub"); got != "rl:extlogin:sub:t:apple:sub" {
		t.Fatalf("subject key = %q", got)
	}
	for _, k := range []string{l.SourceKey("t", "ip"), l.SubjectKey("t", "p", "s")} {
		if !strings.HasPrefix(k, "rl:extlogin:") {
			t.Fatalf("key %q is outside the rl:extlogin: namespace", k)
		}
	}
}

// NEW-API.
func TestExternalLimiterDefaults(t *testing.T) {
	_, rdb := newRoleSwitchTestRedis(t)
	l := NewExternalLimiter(rdb, ExternalConfig{})
	if l.maxAttempts != 10 || l.cooldown != 15*time.Minute {
		t.Fatalf("defaults = %d / %v, want 10 / 15m", l.maxAttempts, l.cooldown)
	}
}

// NEW-API.
func TestExternalLimiterBackendFailureIsUnavailable(t *testing.T) {
	mr, rdb := newRoleSwitchTestRedis(t)
	l := NewExternalLimiter(rdb, ExternalConfig{MaxAttempts: 3, Cooldown: time.Minute})
	mr.Close()

	if err := l.Reserve(context.Background(), "k"); !errors.Is(err, ErrExternalUnavailable) {
		t.Fatalf("Reserve with a dead backend = %v, want ErrExternalUnavailable", err)
	}
	if err := l.Reset(context.Background(), "k"); !errors.Is(err, ErrExternalUnavailable) {
		t.Fatalf("Reset with a dead backend = %v, want ErrExternalUnavailable", err)
	}
}
