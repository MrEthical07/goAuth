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

func TestHashTooLongPasswordRejected(t *testing.T) {
	cfg := secureConfig()
	cfg.MaxPasswordBytes = 64
	hasher, err := NewArgon2(cfg)
	if err != nil {
		t.Fatalf("NewArgon2 error: %v", err)
	}

	longPwd := strings.Repeat("a", 65)
	if _, err := hasher.Hash(longPwd); err == nil {
		t.Fatal("expected long password to be rejected by Hash()")
	}
}

func TestHashAtMaxLengthAccepted(t *testing.T) {
	cfg := secureConfig()
	cfg.MaxPasswordBytes = 64
	hasher, err := NewArgon2(cfg)
	if err != nil {
		t.Fatalf("NewArgon2 error: %v", err)
	}

	exactPwd := strings.Repeat("b", 64)
	hash, err := hasher.Hash(exactPwd)
	if err != nil {
		t.Fatalf("expected exactly-max password to be accepted: %v", err)
	}

	ok, err := hasher.Verify(exactPwd, hash)
	if err != nil || !ok {
		t.Fatalf("Verify failed for max-length password: ok=%v err=%v", ok, err)
	}
}

func TestVerifyTooLongPasswordRejected(t *testing.T) {
	cfg := secureConfig()
	cfg.MaxPasswordBytes = 64
	hasher, err := NewArgon2(cfg)
	if err != nil {
		t.Fatalf("NewArgon2 error: %v", err)
	}

	// Hash a valid password first.
	normalPwd := "valid-password-123"
	hash, err := hasher.Hash(normalPwd)
	if err != nil {
		t.Fatalf("Hash error: %v", err)
	}

	// Verify with an overly long password should fail fast.
	longPwd := strings.Repeat("c", 65)
	_, err = hasher.Verify(longPwd, hash)
	if err == nil {
		t.Fatal("expected long password to be rejected by Verify()")
	}
}

func TestDefaultMaxPasswordBytesApplied(t *testing.T) {
	cfg := secureConfig()
	// MaxPasswordBytes left as zero — should use DefaultMaxPasswordBytes (1024).
	hasher, err := NewArgon2(cfg)
	if err != nil {
		t.Fatalf("NewArgon2 error: %v", err)
	}

	longPwd := strings.Repeat("d", DefaultMaxPasswordBytes+1)
	if _, err := hasher.Hash(longPwd); err == nil {
		t.Fatalf("expected password > %d bytes to be rejected", DefaultMaxPasswordBytes)
	}

	exactPwd := strings.Repeat("e", DefaultMaxPasswordBytes)
	if _, err := hasher.Hash(exactPwd); err != nil {
		t.Fatalf("expected password of exactly %d bytes to be accepted: %v", DefaultMaxPasswordBytes, err)
	}
}
