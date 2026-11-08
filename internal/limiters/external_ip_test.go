package limiters

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal/window"
)

// The pre-verification bucket groups client addresses the way the password
// login's IP budget does, so rotating addresses does not buy a fresh budget.
func TestExternalSourceKeyCanonicalizesTheClientAddress(t *testing.T) {
	_, rdb := newRoleSwitchTestRedis(t)
	l := NewExternalLimiter(rdb, ExternalConfig{})

	same := [][]string{
		// Addresses of one IPv6 /64 share a bucket.
		{"2001:db8:1:2::1", "2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2:aaaa:bbbb:cccc:dddd"},
		// IPv4 and its IPv4-mapped IPv6 spellings.
		{"203.0.113.7", "::ffff:203.0.113.7", "::ffff:cb00:7107"},
		// A port or a zone does not make a new address.
		{"203.0.113.7", "203.0.113.7:443"},
		{"2001:db8:1:2::1", "[2001:db8:1:2::1]:443", "2001:db8:1:2::1%eth0"},
		{"fe80::1%eth0", "fe80::1%eth1", "fe80::1"},
	}
	for _, group := range same {
		want := l.SourceKey("t1", group[0])
		for _, ip := range group[1:] {
			if got := l.SourceKey("t1", ip); got != want {
				t.Errorf("%q and %q should share a bucket:\n %s\n %s", group[0], ip, want, got)
			}
		}
	}

	distinct := []string{
		"2001:db8:1:2::1",
		"2001:db8:1:3::1", // the next /64
		"2001:db8:2:2::1",
		"203.0.113.7",
		"203.0.113.8",
	}
	seen := map[string]string{}
	for _, ip := range distinct {
		k := l.SourceKey("t1", ip)
		if prev, dup := seen[k]; dup {
			t.Errorf("%q and %q must not share a bucket", prev, ip)
		}
		seen[k] = ip
	}
	// The tenant still separates buckets, and a string that is not an address
	// keeps counting against itself.
	if l.SourceKey("t1", "203.0.113.7") == l.SourceKey("t2", "203.0.113.7") {
		t.Error("tenants share a bucket")
	}
	if l.SourceKey("t1", "not-an-ip") == l.SourceKey("t1", "also-not-an-ip") {
		t.Error("two different non-address strings share a bucket")
	}
	if got := l.SourceKey("t1", ""); got != "" {
		t.Errorf("unknown address: key %q, want none", got)
	}
}

// The consequence: attempts from different addresses of one /64 draw on one
// budget.
func TestExternalSourceBudgetIsSharedAcrossAnIPv6Slash64(t *testing.T) {
	for _, mode := range []window.Mode{window.Fixed, window.Sliding} {
		t.Run(modeName(mode), func(t *testing.T) {
			_, rdb := newRoleSwitchTestRedis(t)
			l := NewExternalLimiter(rdb, ExternalConfig{MaxAttempts: 3, Cooldown: time.Minute, WindowMode: mode})
			ctx := context.Background()

			rotating := []string{"2001:db8:9:9::1", "2001:db8:9:9::2", "2001:db8:9:9:1:2:3:4"}
			for i := 0; i < 3; i++ {
				if err := l.Reserve(ctx, l.SourceKey("t1", rotating[i%len(rotating)])); err != nil {
					t.Fatalf("attempt %d should be allowed: %v", i+1, err)
				}
			}
			if err := l.Reserve(ctx, l.SourceKey("t1", "2001:db8:9:9:ffff::5")); !errors.Is(err, ErrExternalRateLimited) {
				t.Fatalf("a fresh address in the same /64 got its own budget: %v", err)
			}
			if err := l.Reserve(ctx, l.SourceKey("t1", "2001:db8:9:a::1")); err != nil {
				t.Fatalf("a different /64 is unaffected: %v", err)
			}
		})
	}
}

func modeName(m window.Mode) string {
	if m == window.Sliding {
		return "sliding"
	}
	return "fixed"
}
