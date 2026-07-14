package jwt

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestGenerateEd25519KeyWorksWithManager(t *testing.T) {
	pub, priv, err := GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key failed: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize || len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("unexpected key sizes: pub=%d priv=%d", len(pub), len(priv))
	}

	kid, err := Ed25519KeyFingerprint(pub)
	if err != nil {
		t.Fatalf("fingerprint failed: %v", err)
	}

	m, err := NewManager(Config{
		AccessTTL:     time.Minute,
		SigningMethod: MethodEd25519,
		PrivateKey:    priv,
		PublicKey:     pub,
		KeyID:         kid,
		VerifyKeys:    map[string][]byte{kid: pub},
	})
	if err != nil {
		t.Fatalf("NewManager with generated keys failed: %v", err)
	}

	token, err := m.CreateAccess("u1", "", "s1", nil, 0, 0, 0, false, false, false, false, false)
	if err != nil {
		t.Fatalf("CreateAccess failed: %v", err)
	}
	claims, err := m.ParseAccess(token)
	if err != nil {
		t.Fatalf("ParseAccess failed: %v", err)
	}
	if claims.UID != "u1" || claims.SID != "s1" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestEd25519KeyFingerprintDeterministicAcrossEncodings(t *testing.T) {
	pub, _ := newEdKeys(t)

	rawFP, err := Ed25519KeyFingerprint(pub)
	if err != nil {
		t.Fatalf("raw fingerprint failed: %v", err)
	}
	if len(rawFP) != 16 {
		t.Fatalf("expected 16 hex chars, got %q", rawFP)
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	pemFP, err := Ed25519KeyFingerprint(pemBytes)
	if err != nil {
		t.Fatalf("pem fingerprint failed: %v", err)
	}
	if pemFP != rawFP {
		t.Fatalf("fingerprint differs across encodings: raw=%s pem=%s", rawFP, pemFP)
	}

	again, err := Ed25519KeyFingerprint(pub)
	if err != nil || again != rawFP {
		t.Fatalf("fingerprint not deterministic: %s vs %s (err=%v)", again, rawFP, err)
	}

	otherPub, _ := newEdKeys(t)
	otherFP, err := Ed25519KeyFingerprint(otherPub)
	if err != nil {
		t.Fatalf("other fingerprint failed: %v", err)
	}
	if otherFP == rawFP {
		t.Fatal("distinct keys produced the same fingerprint")
	}
}

func TestEd25519KeyFingerprintRejectsInvalidKey(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte("short"), []byte("not a key at all, definitely not 32B")} {
		if _, err := Ed25519KeyFingerprint(bad); err == nil {
			t.Fatalf("expected fingerprint rejection for %q", bad)
		}
	}
}
