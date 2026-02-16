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

	// aud array containing expected value should pass.
	multiAudience := AccessClaims{SID: "s1", RegisteredClaims: gjwt.RegisteredClaims{
		Issuer:    "goauth",
		Audience:  gjwt.ClaimStrings{"api", "mobile"},
		ExpiresAt: gjwt.NewNumericDate(time.Now().Add(time.Minute)),
	}}
	multiAudienceTok := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, multiAudience)
	multiAudienceSigned, _ := multiAudienceTok.SignedString(priv)
	if _, err := m.ParseAccess(multiAudienceSigned); err != nil {
		t.Fatalf("expected audience list token to pass: %v", err)
	}

	// aud scalar string should also pass.
	mapClaimsTok := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, gjwt.MapClaims{
		"uid": "u",
		"sid": "s1",
		"iss": "goauth",
		"aud": "api",
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	mapClaimsSigned, _ := mapClaimsTok.SignedString(priv)
	if _, err := m.ParseAccess(mapClaimsSigned); err != nil {
		t.Fatalf("expected scalar audience token to pass: %v", err)
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

func TestParseAccessKeyIDMismatchWithoutVerifyMapFails(t *testing.T) {
	pub, priv := newEdKeys(t)
	m, err := NewManager(Config{
		AccessTTL:     time.Minute,
		SigningMethod: MethodEd25519,
		PrivateKey:    priv,
		PublicKey:     pub,
		KeyID:         "k1",
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	claims := AccessClaims{SID: "s1", RegisteredClaims: gjwt.RegisteredClaims{ExpiresAt: gjwt.NewNumericDate(time.Now().Add(time.Minute))}}
	bad := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, claims)
	bad.Header["kid"] = "k2"
	badToken, err := bad.SignedString(priv)
	if err != nil {
		t.Fatalf("sign bad token: %v", err)
	}
	if _, err := m.ParseAccess(badToken); err == nil {
		t.Fatal("expected mismatched kid to fail")
	}

	good := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, claims)
	good.Header["kid"] = "k1"
	goodToken, err := good.SignedString(priv)
	if err != nil {
		t.Fatalf("sign good token: %v", err)
	}
	if _, err := m.ParseAccess(goodToken); err != nil {
		t.Fatalf("expected matching kid to pass: %v", err)
	}
}

func TestParseAccessIATPolicy(t *testing.T) {
	pub, priv := newEdKeys(t)

	// Default policy: iat is optional.
	defaultMgr, err := NewManager(Config{
		AccessTTL:     time.Minute,
		SigningMethod: MethodEd25519,
		PrivateKey:    priv,
		PublicKey:     pub,
	})
	if err != nil {
		t.Fatalf("new default manager: %v", err)
	}

	claimsNoIAT := AccessClaims{
		SID: "s1",
		RegisteredClaims: gjwt.RegisteredClaims{
			ExpiresAt: gjwt.NewNumericDate(time.Now().Add(time.Minute)),
		},
	}
	noIATTok := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, claimsNoIAT)
	noIATSigned, _ := noIATTok.SignedString(priv)
	if _, err := defaultMgr.ParseAccess(noIATSigned); err != nil {
		t.Fatalf("expected missing iat to pass by default: %v", err)
	}

	// Tolerant "not crazy future" check.
	futureMgr, err := NewManager(Config{
		AccessTTL:     time.Minute,
		SigningMethod: MethodEd25519,
		PrivateKey:    priv,
		PublicKey:     pub,
		MaxFutureIAT:  10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("new future manager: %v", err)
	}

	crazyFuture := AccessClaims{
		SID: "s1",
		RegisteredClaims: gjwt.RegisteredClaims{
			IssuedAt:  gjwt.NewNumericDate(time.Now().Add(20 * time.Minute)),
			ExpiresAt: gjwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		},
	}
	crazyTok := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, crazyFuture)
	crazySigned, _ := crazyTok.SignedString(priv)
	if _, err := futureMgr.ParseAccess(crazySigned); err == nil {
		t.Fatal("expected iat too far in the future to fail")
	}
}
