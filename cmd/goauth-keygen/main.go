// Command goauth-keygen generates Ed25519 signing keypairs and key
// fingerprints (kid values) for goAuth JWT key provisioning and rotation.
//
// Usage:
//
//	goauth-keygen                     generate a keypair (base64 raw keys)
//	goauth-keygen -pem                generate a keypair (PKCS#8/PKIX PEM)
//	goauth-keygen -fingerprint FILE   print the kid of an existing public key
//	                                  (PEM, raw, or base64 file)
//
// See docs/ops.md for the full key-rotation ceremony.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/MrEthical07/goAuth/jwt"
)

func main() {
	var (
		pemOut      = flag.Bool("pem", false, "output keys as PKCS#8/PKIX PEM instead of base64 raw bytes")
		fingerprint = flag.String("fingerprint", "", "print the kid fingerprint of an existing Ed25519 public key file (PEM, raw, or base64) and exit")
	)
	flag.Parse()

	if *fingerprint != "" {
		if err := printFingerprint(*fingerprint); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}

	pub, priv, err := jwt.GenerateEd25519Key()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: generate key:", err)
		os.Exit(1)
	}
	kid, err := jwt.Ed25519KeyFingerprint(pub)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: fingerprint:", err)
		os.Exit(1)
	}

	if *pemOut {
		privDER, err := x509.MarshalPKCS8PrivateKey(ed25519.PrivateKey(priv))
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: encode private key:", err)
			os.Exit(1)
		}
		pubDER, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(pub))
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: encode public key:", err)
			os.Exit(1)
		}
		fmt.Printf("suggested kid: %s\n\n", kid)
		_ = pem.Encode(os.Stdout, &pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
		fmt.Println()
		_ = pem.Encode(os.Stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
		return
	}

	fmt.Printf("suggested kid:        %s\n", kid)
	fmt.Printf("private key (base64): %s\n", base64.StdEncoding.EncodeToString(priv))
	fmt.Printf("public key (base64):  %s\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Println()
	fmt.Println("Decode with base64.StdEncoding and pass the raw bytes as")
	fmt.Println("JWTConfig.PrivateKey / PublicKey / VerifyKeys values.")
}

func printFingerprint(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Accept PEM, raw 32-byte, or base64-encoded public keys.
	candidates := [][]byte{data}
	if trimmed := strings.TrimSpace(string(data)); !bytes.Contains(data, []byte("-----")) {
		if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
			candidates = append(candidates, decoded)
		}
	}
	for _, key := range candidates {
		if kid, err := jwt.Ed25519KeyFingerprint(key); err == nil {
			fmt.Println(kid)
			return nil
		}
	}
	return fmt.Errorf("%s: not a valid Ed25519 public key (PEM, raw, or base64)", path)
}
