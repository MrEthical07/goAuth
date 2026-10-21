package jwt

import (
	"reflect"
	"testing"
	"time"
)

func accessLifetime(t *testing.T, m *Manager, token string) (time.Duration, *AccessClaims) {
	t.Helper()
	claims, err := m.ParseAccess(token)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	return claims.ExpiresAt.Sub(claims.IssuedAt.Time), claims
}

func mintAccess(t *testing.T, m *Manager, ttl time.Duration, isRoot bool) string {
	t.Helper()
	mask := []byte{1, 2, 3}
	var (
		token string
		err   error
	)
	if ttl < 0 {
		token, err = m.CreateAccess("u1", "t1", "s1", mask, 4, 5, 6, true, true, true, true, isRoot)
	} else {
		token, err = m.CreateAccessWithTTL(ttl, "u1", "t1", "s1", mask, 4, 5, 6, true, true, true, true, isRoot)
	}
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return token
}

func TestCreateAccessWithTTL(t *testing.T) {
	for _, path := range []string{"fast", "legacy"} {
		t.Run(path, func(t *testing.T) {
			m, _ := newAllowExpiredManager(t) // AccessTTL = 1m
			if path == "legacy" {
				m.fast = nil
			}

			cases := []struct {
				name   string
				ttl    time.Duration // -1 = CreateAccess
				isRoot bool
				want   time.Duration
			}{
				{"CreateAccess keeps the configured TTL", -1, false, time.Minute},
				{"explicit longer TTL", 10 * time.Minute, false, 10 * time.Minute},
				{"explicit shorter TTL", 20 * time.Second, false, 20 * time.Second},
				{"zero inherits the configured TTL", 0, false, time.Minute},
				{"root tokens stay capped at two minutes", 10 * time.Minute, true, 2 * time.Minute},
				{"root cap does not lengthen a short TTL", 30 * time.Second, true, 30 * time.Second},
				{"CreateAccess root", -1, true, time.Minute},
			}
			for _, tc := range cases {
				got, _ := accessLifetime(t, m, mintAccess(t, m, tc.ttl, tc.isRoot))
				if got != tc.want {
					t.Errorf("%s: lifetime = %v, want %v", tc.name, got, tc.want)
				}
			}
		})
	}
}

// Apart from exp, a token minted with its own TTL carries exactly the claims
// CreateAccess produces.
func TestCreateAccessWithTTLClaimsMatchCreateAccess(t *testing.T) {
	m, _ := newAllowExpiredManager(t)
	_, plain := accessLifetime(t, m, mintAccess(t, m, -1, false))
	_, custom := accessLifetime(t, m, mintAccess(t, m, 7*time.Minute, false))

	plain.ExpiresAt, custom.ExpiresAt = nil, nil
	plain.IssuedAt, custom.IssuedAt = nil, nil
	if !reflect.DeepEqual(plain, custom) {
		t.Fatalf("claims differ beyond exp/iat:\n plain:  %+v\n custom: %+v", plain, custom)
	}
}
