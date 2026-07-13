package jwt

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
)

func newAllowExpiredManager(t *testing.T) (*Manager, ed25519.PrivateKey) {
	t.Helper()

	pub, priv := newEdKeys(t)
	m, err := NewManager(Config{
		AccessTTL:     time.Minute,
		SigningMethod: MethodEd25519,
		PrivateKey:    priv,
		PublicKey:     pub,
		Issuer:        "goauth",
		Audience:      "api",
		Leeway:        30 * time.Second,
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return m, priv
}

func expiredClaims(issuer, audience, sid string) AccessClaims {
	return AccessClaims{
		UID: "u1",
		SID: sid,
		RegisteredClaims: gjwt.RegisteredClaims{
			Issuer:    issuer,
			Audience:  gjwt.ClaimStrings{audience},
			ExpiresAt: gjwt.NewNumericDate(time.Now().Add(-2 * time.Minute)),
			IssuedAt:  gjwt.NewNumericDate(time.Now().Add(-3 * time.Minute)),
		},
	}
}

func TestParseAccessAllowExpiredAcceptsExpiredToken(t *testing.T) {
	m, priv := newAllowExpiredManager(t)

	tok := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, expiredClaims("goauth", "api", "s1"))
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	if _, err := m.ParseAccess(signed); !errors.Is(err, gjwt.ErrTokenExpired) {
		t.Fatalf("expected strict parse to fail with ErrTokenExpired, got %v", err)
	}

	claims, err := m.ParseAccessAllowExpired(signed)
	if err != nil {
		t.Fatalf("expected expired-but-authentic token to parse, got %v", err)
	}
	if claims.SID != "s1" || claims.UID != "u1" {
		t.Fatalf("unexpected claims: sid=%q uid=%q", claims.SID, claims.UID)
	}
}

func TestParseAccessAllowExpiredPassesThroughValidToken(t *testing.T) {
	m, _ := newAllowExpiredManager(t)

	access, err := m.CreateAccess("u1", "t1", "s1", nil, 0, 0, 0, false, false, false, false, false)
	if err != nil {
		t.Fatalf("create access: %v", err)
	}

	claims, err := m.ParseAccessAllowExpired(access)
	if err != nil {
		t.Fatalf("expected valid token to parse: %v", err)
	}
	if claims.SID != "s1" {
		t.Fatalf("unexpected sid: %q", claims.SID)
	}
}

func TestParseAccessAllowExpiredRejectsForgedSignature(t *testing.T) {
	m, _ := newAllowExpiredManager(t)
	_, otherPriv := newEdKeys(t)

	tok := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, expiredClaims("goauth", "api", "s1"))
	forged, err := tok.SignedString(otherPriv)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	if _, err := m.ParseAccessAllowExpired(forged); err == nil {
		t.Fatal("expected forged expired token to be rejected")
	}
}

func TestParseAccessAllowExpiredRejectsWrongIssuerAndAudience(t *testing.T) {
	m, priv := newAllowExpiredManager(t)

	badIssuer := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, expiredClaims("other", "api", "s1"))
	badIssuerSigned, _ := badIssuer.SignedString(priv)
	if _, err := m.ParseAccessAllowExpired(badIssuerSigned); err == nil {
		t.Fatal("expected wrong-issuer expired token to be rejected")
	}

	badAudience := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, expiredClaims("goauth", "other-api", "s1"))
	badAudienceSigned, _ := badAudience.SignedString(priv)
	if _, err := m.ParseAccessAllowExpired(badAudienceSigned); err == nil {
		t.Fatal("expected wrong-audience expired token to be rejected")
	}
}

func TestParseAccessAllowExpiredRejectsFutureNotBefore(t *testing.T) {
	m, priv := newAllowExpiredManager(t)

	claims := expiredClaims("goauth", "api", "s1")
	claims.NotBefore = gjwt.NewNumericDate(time.Now().Add(time.Hour))
	tok := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, claims)
	signed, _ := tok.SignedString(priv)

	if _, err := m.ParseAccessAllowExpired(signed); err == nil {
		t.Fatal("expected future-nbf expired token to be rejected")
	}
}

func TestParseAccessAllowExpiredRejectsGarbage(t *testing.T) {
	m, _ := newAllowExpiredManager(t)
	if _, err := m.ParseAccessAllowExpired("not-a-token"); err == nil {
		t.Fatal("expected garbage token to be rejected")
	}
}

func TestParseAccessAllowExpiredEnforcesKid(t *testing.T) {
	pub, priv := newEdKeys(t)
	m, err := NewManager(Config{
		AccessTTL:     time.Minute,
		SigningMethod: MethodEd25519,
		VerifyKeys:    map[string][]byte{"k1": pub},
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	// Missing kid must be rejected even on the lenient path.
	noKid := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, expiredClaims("", "", "s1"))
	noKidSigned, _ := noKid.SignedString(priv)
	if _, err := m.ParseAccessAllowExpired(noKidSigned); err == nil {
		t.Fatal("expected missing-kid expired token to be rejected")
	}

	withKid := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, expiredClaims("", "", "s1"))
	withKid.Header["kid"] = "k1"
	withKidSigned, _ := withKid.SignedString(priv)
	claims, err := m.ParseAccessAllowExpired(withKidSigned)
	if err != nil {
		t.Fatalf("expected kid-bearing expired token to parse: %v", err)
	}
	if claims.SID != "s1" {
		t.Fatalf("unexpected sid: %q", claims.SID)
	}
}
