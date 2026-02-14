package password

import (
	"strings"
	"testing"
)

func secureConfig() Config {
	return Config{
		Memory:      65536,
		Time:        3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func TestHashAndVerify(t *testing.T) {
	hasher, err := NewArgon2(secureConfig())
	if err != nil {
		t.Fatalf("NewArgon2 error: %v", err)
	}

	hash, err := hasher.Hash("P@ssw0rd-Ascii")
	if err != nil {
		t.Fatalf("Hash error: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("unexpected PHC prefix: %s", hash)
	}

	ok, err := hasher.Verify("P@ssw0rd-Ascii", hash)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !ok {
		t.Fatal("expected password verification to succeed")
	}
}

func TestVerifyWrongPassword(t *testing.T) {
	hasher, err := NewArgon2(secureConfig())
	if err != nil {
		t.Fatalf("NewArgon2 error: %v", err)
	}

	hash, err := hasher.Hash("correct-password")
	if err != nil {
		t.Fatalf("Hash error: %v", err)
	}

	ok, err := hasher.Verify("wrong-password", hash)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if ok {
		t.Fatal("expected wrong password verification to fail")
	}
}

func TestNeedsUpgrade(t *testing.T) {
	oldHasher, err := NewArgon2(Config{
		Memory:      32768,
		Time:        2,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	})
	if err != nil {
		t.Fatalf("NewArgon2(old) error: %v", err)
	}

	hash, err := oldHasher.Hash("test-password")
	if err != nil {
		t.Fatalf("Hash error: %v", err)
	}

	newHasher, err := NewArgon2(secureConfig())
	if err != nil {
		t.Fatalf("NewArgon2(new) error: %v", err)
	}

	needsUpgrade, err := newHasher.NeedsUpgrade(hash)
	if err != nil {
		t.Fatalf("NeedsUpgrade error: %v", err)
	}
	if !needsUpgrade {
		t.Fatal("expected NeedsUpgrade to return true for weaker hash parameters")
	}
}

func TestNeedsUpgradeSameConfig(t *testing.T) {
	hasher, err := NewArgon2(secureConfig())
	if err != nil {
		t.Fatalf("NewArgon2 error: %v", err)
	}

	hash, err := hasher.Hash("same-config-password")
	if err != nil {
		t.Fatalf("Hash error: %v", err)
	}

	needsUpgrade, err := hasher.NeedsUpgrade(hash)
	if err != nil {
		t.Fatalf("NeedsUpgrade error: %v", err)
	}
	if needsUpgrade {
		t.Fatal("expected NeedsUpgrade to return false for current parameters")
	}
}

func TestVerifyMalformedHash(t *testing.T) {
	hasher, err := NewArgon2(secureConfig())
	if err != nil {
		t.Fatalf("NewArgon2 error: %v", err)
	}

	if _, err := hasher.Verify("password", "not-a-phc-hash"); err == nil {
		t.Fatal("expected malformed hash verification to fail")
	}
}

func TestVerifyWrongVersion(t *testing.T) {
	hasher, err := NewArgon2(secureConfig())
	if err != nil {
		t.Fatalf("NewArgon2 error: %v", err)
	}

	hash, err := hasher.Hash("version-test")
	if err != nil {
		t.Fatalf("Hash error: %v", err)
	}

	wrongVersion := strings.Replace(hash, "$v=19$", "$v=18$", 1)
	if _, err := hasher.Verify("version-test", wrongVersion); err == nil {
		t.Fatal("expected unsupported version verification to fail")
	}
}

func TestHashEmptyPassword(t *testing.T) {
	hasher, err := NewArgon2(secureConfig())
	if err != nil {
		t.Fatalf("NewArgon2 error: %v", err)
	}

	if _, err := hasher.Hash(""); err == nil {
		t.Fatal("expected empty password hash to fail")
	}
}

func TestHashTooShortPassword(t *testing.T) {
	hasher, err := NewArgon2(secureConfig())
	if err != nil {
		t.Fatalf("NewArgon2 error: %v", err)
	}

	if _, err := hasher.Hash("short"); err == nil {
		t.Fatal("expected short password hash to fail")
	}
}
