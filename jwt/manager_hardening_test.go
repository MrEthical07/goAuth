package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
)

func newEdKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return pub, priv
}

func TestParseAccessRejectsWrongAlgorithm(t *testing.T) {
	pub, _ := newEdKeys(t)
	m, err := NewManager(Config{AccessTTL: time.Minute, SigningMethod: MethodEd25519, PublicKey: pub})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	claims := AccessClaims{SID: "s1", RegisteredClaims: gjwt.RegisteredClaims{ExpiresAt: gjwt.NewNumericDate(time.Now().Add(time.Minute))}}
	tok := gjwt.NewWithClaims(gjwt.SigningMethodHS256, claims)
	token, err := tok.SignedString([]byte("secret-secret-secret-secret"))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	if _, err := m.ParseAccess(token); err == nil {
		t.Fatal("expected wrong algorithm to be rejected")
	}
}

func TestParseAccessIssuerAudienceAndLeeway(t *testing.T) {
	_, priv := newEdKeys(t)
	m, err := NewManager(Config{
		AccessTTL:     time.Minute,
		SigningMethod: MethodEd25519,
		PrivateKey:    priv,
		PublicKey:     priv.Public().(ed25519.PublicKey),
		Issuer:        "goauth",
		Audience:      "api",
		Leeway:        30 * time.Second,
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	access, err := m.CreateAccess("u", 1, "s1", nil, 0, 0, 0, false, false, false, false, false)
	if err != nil {
		t.Fatalf("create access: %v", err)
	}
	if _, err := m.ParseAccess(access); err != nil {
		t.Fatalf("expected valid token to parse: %v", err)
	}

	wrongIssuer := AccessClaims{SID: "s1", RegisteredClaims: gjwt.RegisteredClaims{
		Issuer:    "other",
		Audience:  gjwt.ClaimStrings{"api"},
		ExpiresAt: gjwt.NewNumericDate(time.Now().Add(time.Minute)),
		IssuedAt:  gjwt.NewNumericDate(time.Now()),
	}}
	badIssuerTok := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, wrongIssuer)
	badIssuer, _ := badIssuerTok.SignedString(priv)
	if _, err := m.ParseAccess(badIssuer); err == nil {
		t.Fatal("expected wrong issuer to fail")
	}

	wrongAudience := AccessClaims{SID: "s1", RegisteredClaims: gjwt.RegisteredClaims{
		Issuer:    "goauth",
		Audience:  gjwt.ClaimStrings{"other-api"},
		ExpiresAt: gjwt.NewNumericDate(time.Now().Add(time.Minute)),
		IssuedAt:  gjwt.NewNumericDate(time.Now()),
	}}
	badAudienceTok := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, wrongAudience)
	badAudience, _ := badAudienceTok.SignedString(priv)
	if _, err := m.ParseAccess(badAudience); err == nil {
		t.Fatal("expected wrong audience to fail")
	}

	expWithinLeeway := AccessClaims{SID: "s1", RegisteredClaims: gjwt.RegisteredClaims{
		Issuer:    "goauth",
		Audience:  gjwt.ClaimStrings{"api"},
		ExpiresAt: gjwt.NewNumericDate(time.Now().Add(-15 * time.Second)),
		IssuedAt:  gjwt.NewNumericDate(time.Now().Add(-time.Minute)),
	}}
	withinTok := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, expWithinLeeway)
	within, _ := withinTok.SignedString(priv)
	if _, err := m.ParseAccess(within); err != nil {
		t.Fatalf("expected token within leeway to pass: %v", err)
	}

	expired := AccessClaims{SID: "s1", RegisteredClaims: gjwt.RegisteredClaims{
		Issuer:    "goauth",
		Audience:  gjwt.ClaimStrings{"api"},
		ExpiresAt: gjwt.NewNumericDate(time.Now().Add(-2 * time.Minute)),
		IssuedAt:  gjwt.NewNumericDate(time.Now().Add(-3 * time.Minute)),
	}}
	expiredTok := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, expired)
	expiredSigned, _ := expiredTok.SignedString(priv)
	if _, err := m.ParseAccess(expiredSigned); err == nil {
		t.Fatal("expected expired token to fail")
	}
}

func TestParseAccessUnknownKidFails(t *testing.T) {
	pub1, priv1 := newEdKeys(t)
	pub2, _ := newEdKeys(t)
	m, err := NewManager(Config{
		AccessTTL:     time.Minute,
		SigningMethod: MethodEd25519,
		PrivateKey:    priv1,
		PublicKey:     pub1,
		KeyID:         "k1",
		VerifyKeys: map[string][]byte{
			"k1": pub1,
		},
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	claims := AccessClaims{SID: "s1", RegisteredClaims: gjwt.RegisteredClaims{ExpiresAt: gjwt.NewNumericDate(time.Now().Add(time.Minute))}}
	tok := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = "k2"
	token, err := tok.SignedString(priv1)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	if _, err := m.ParseAccess(token); err == nil {
		t.Fatal("expected unknown kid failure")
	}

	tok2 := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, claims)
	tok2.Header["kid"] = "k1"
	good, _ := tok2.SignedString(priv1)
	if _, err := m.ParseAccess(good); err != nil {
		t.Fatalf("expected known kid token to pass: %v", err)
	}

	m2, _ := NewManager(Config{AccessTTL: time.Minute, SigningMethod: MethodEd25519, PublicKey: pub2, VerifyKeys: map[string][]byte{"k2": pub2}})
	if _, err := m2.ParseAccess(good); err == nil {
		t.Fatal("expected parse failure with mismatched key set")
	}
}
