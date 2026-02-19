//go:build integration
// +build integration

package test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/jwt"
	gjwt "github.com/golang-jwt/jwt/v5"
)

func TestJWTIntegrationHardeningChecks(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	manager, err := jwt.NewManager(jwt.Config{
		AccessTTL:     time.Minute,
		SigningMethod: jwt.MethodEd25519,
		PrivateKey:    priv,
		PublicKey:     pub,
		Issuer:        "goauth",
		Audience:      "api",
		Leeway:        30 * time.Second,
		KeyID:         "k1",
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	access, err := manager.CreateAccess("u1", 0, "s1", nil, 0, 0, 0, false, false, false, false, false)
	if err != nil {
		t.Fatalf("CreateAccess failed: %v", err)
	}

	if _, err := manager.ParseAccess(access); err != nil {
		t.Fatalf("ParseAccess valid token failed: %v", err)
	}

	badClaims := jwt.AccessClaims{
		UID: "u1",
		SID: "s1",
		RegisteredClaims: gjwt.RegisteredClaims{
			Issuer:    "goauth",
			Audience:  gjwt.ClaimStrings{"api"},
			ExpiresAt: gjwt.NewNumericDate(time.Now().Add(time.Minute)),
			IssuedAt:  gjwt.NewNumericDate(time.Now()),
		},
	}

	badToken := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, badClaims)
	badToken.Header["kid"] = "unknown"
	signedBad, err := badToken.SignedString(priv)
	if err != nil {
		t.Fatalf("SignedString failed: %v", err)
	}

	if _, err := manager.ParseAccess(signedBad); err == nil {
		t.Fatal("expected unknown kid token to fail")
	}
}
