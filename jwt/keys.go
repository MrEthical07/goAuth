package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// GenerateEd25519Key generates a new Ed25519 keypair and returns the raw
// key bytes, directly usable as [Config] PrivateKey/PublicKey (and as
// VerifyKeys values). Intended for key provisioning and rotation; see
// docs/ops.md for the rotation ceremony.
//
//	Docs: docs/jwt.md, docs/ops.md
func GenerateEd25519Key() (publicKey, privateKey []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// Ed25519KeyFingerprint returns a short, stable fingerprint of an Ed25519
// public key (raw or PEM): the first 8 bytes of SHA-256 over the raw key,
// hex-encoded. Suitable as a kid value for [Config] KeyID/VerifyKeys.
//
//	Docs: docs/jwt.md, docs/ops.md
func Ed25519KeyFingerprint(publicKey []byte) (string, error) {
	pub, err := parseEdPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8]), nil
}
