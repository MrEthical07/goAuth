package goAuth

import (
	"strings"
	"testing"

	authjwt "github.com/MrEthical07/goAuth/jwt"
)

func ed25519RotationConfig(t *testing.T) Config {
	t.Helper()

	pub, priv, err := authjwt.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	cfg := accountTestConfig()
	cfg.JWT.SigningMethod = "ed25519"
	cfg.JWT.PrivateKey = priv
	cfg.JWT.PublicKey = pub
	cfg.JWT.KeyID = "k1"
	cfg.JWT.VerifyKeys = map[string][]byte{"k1": pub}
	return cfg
}

func TestConfigValidateVerifyKeysRequiresKeyID(t *testing.T) {
	cfg := ed25519RotationConfig(t)
	cfg.JWT.KeyID = ""

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "requires KeyID") {
		t.Fatalf("expected VerifyKeys-without-KeyID rejection, got %v", err)
	}
}

func TestConfigValidateVerifyKeysRejectsEmptyKid(t *testing.T) {
	cfg := ed25519RotationConfig(t)
	cfg.JWT.VerifyKeys[" "] = cfg.JWT.PublicKey

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "empty kid") {
		t.Fatalf("expected empty kid rejection, got %v", err)
	}
}

func TestConfigValidateVerifyKeysRejectsEmptyKeyMaterial(t *testing.T) {
	cfg := ed25519RotationConfig(t)
	cfg.JWT.VerifyKeys["k2"] = nil

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "empty key material") {
		t.Fatalf("expected empty key material rejection, got %v", err)
	}
}

func TestConfigValidateKeyIDMustBeInVerifyKeys(t *testing.T) {
	cfg := ed25519RotationConfig(t)
	cfg.JWT.KeyID = "k2"

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "present in VerifyKeys") {
		t.Fatalf("expected KeyID-not-in-VerifyKeys rejection, got %v", err)
	}
}

func TestConfigValidateVerifyKeysValidSetPassesAndBuilds(t *testing.T) {
	cfg := ed25519RotationConfig(t)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid rotation config to validate, got %v", err)
	}

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	if engine == nil {
		t.Fatal("expected engine to build")
	}
}

func TestConfigValidateProductionRejectsWeakHS256VerifyKey(t *testing.T) {
	cfg := accountTestConfig()
	cfg.Security.ProductionMode = true
	secret := []byte("01234567890123456789012345678901")
	cfg.JWT.PrivateKey = secret
	cfg.JWT.KeyID = "k1"
	cfg.JWT.VerifyKeys = map[string][]byte{
		"k1": secret,
		"k0": []byte("weak"),
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "verify key length") {
		t.Fatalf("expected weak hs256 verify key rejection, got %v", err)
	}
}

func TestConfigLintKeyIDMissing(t *testing.T) {
	cfg := ed25519RotationConfig(t)
	cfg.JWT.KeyID = ""
	cfg.JWT.VerifyKeys = nil

	codes := cfg.Lint().Codes()
	found := false
	for _, code := range codes {
		if code == "keyid_missing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected keyid_missing lint for ed25519 without KeyID, got %v", codes)
	}

	cfg.JWT.KeyID = "k1"
	cfg.JWT.VerifyKeys = map[string][]byte{"k1": cfg.JWT.PublicKey}
	for _, code := range cfg.Lint().Codes() {
		if code == "keyid_missing" {
			t.Fatal("keyid_missing lint should not fire when KeyID is set")
		}
	}
}

func TestBuildVerifyKeysImmutabilityAgainstExternalMutation(t *testing.T) {
	cfg := ed25519RotationConfig(t)
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	before := engine.config.JWT.VerifyKeys["k1"][0]
	cfg.JWT.VerifyKeys["k1"][0] ^= 0xFF
	cfg.JWT.VerifyKeys["injected"] = []byte("evil")

	if engine.config.JWT.VerifyKeys["k1"][0] != before {
		t.Fatal("engine verify key mutated from external config after build")
	}
	if _, ok := engine.config.JWT.VerifyKeys["injected"]; ok {
		t.Fatal("engine verify key set gained an entry from external config after build")
	}
}
