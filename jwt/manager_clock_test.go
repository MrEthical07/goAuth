package jwt

import (
	"errors"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
)

func newClockManager(t *testing.T, now func() time.Time) *Manager {
	t.Helper()
	pub, priv := newEdKeys(t)
	m, err := NewManager(Config{
		AccessTTL:     time.Minute,
		SigningMethod: MethodEd25519,
		PrivateKey:    priv,
		PublicKey:     pub,
		Issuer:        "goauth",
		Audience:      "api",
		RequireIAT:    true,
		Now:           now,
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return m
}

// Token issue and validation both read the injected clock, on the fast and the
// legacy creation path alike.
func TestManagerUsesInjectedClock(t *testing.T) {
	for _, path := range []string{"fast", "legacy"} {
		t.Run(path, func(t *testing.T) {
			now := time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC)
			m := newClockManager(t, func() time.Time { return now })
			if path == "legacy" {
				m.fast = nil
			}
			token := mintAccess(t, m, -1, false)

			claims, err := m.ParseAccess(token)
			if err != nil {
				t.Fatalf("ParseAccess at issue time: %v", err)
			}
			if got := claims.IssuedAt.Unix(); got != now.Unix() {
				t.Fatalf("iat = %d, want the injected %d", got, now.Unix())
			}
			if got := claims.ExpiresAt.Unix(); got != now.Add(time.Minute).Unix() {
				t.Fatalf("exp = %d, want %d", got, now.Add(time.Minute).Unix())
			}

			now = now.Add(59 * time.Second)
			if _, err := m.ParseAccess(token); err != nil {
				t.Fatalf("ParseAccess just before exp: %v", err)
			}
			now = now.Add(2 * time.Second)
			if _, err := m.ParseAccess(token); !errors.Is(err, gjwt.ErrTokenExpired) {
				t.Fatalf("ParseAccess after exp = %v, want expired", err)
			}
		})
	}
}

// The iat future bound is measured against the injected clock too.
func TestManagerIATFutureBoundUsesInjectedClock(t *testing.T) {
	issuer := time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC)
	now := issuer
	m := newClockManager(t, func() time.Time { return now })
	token := mintAccess(t, m, -1, false)

	// A validator whose clock is an hour behind the issuer sees a token from
	// the future.
	now = issuer.Add(-time.Hour)
	if _, err := m.ParseAccess(token); err == nil {
		t.Fatal("token issued an hour ahead of the validator's clock must be refused")
	}
}

func TestManagerDefaultClockIsWallClock(t *testing.T) {
	m := newClockManager(t, nil)
	claims, err := m.ParseAccess(mintAccess(t, m, -1, false))
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	if d := time.Since(claims.IssuedAt.Time); d < -2*time.Second || d > time.Minute {
		t.Fatalf("iat is %v away from the wall clock", d)
	}
}
