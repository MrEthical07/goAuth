package goAuth

import (
	"context"
	"errors"
	"testing"

	authjwt "github.com/MrEthical07/goAuth/jwt"
	"github.com/redis/go-redis/v9"
)

func newRotationEngine(t *testing.T, rdb *redis.Client, cfg Config, up UserProvider) *Engine {
	t.Helper()

	engine, err := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"perm.read"}).
		WithRoles(map[string][]string{"member": {}}).
		WithUserProvider(up).
		Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	return engine
}

// TestKeyRotationCeremony walks the documented Ed25519 rotation ceremony
// end-to-end: introduce k2 alongside k1, flip signing to k2, retire k1 —
// verifying token acceptance at every step across engine generations that
// share one Redis.
func TestKeyRotationCeremony(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()
	ctx := context.Background()

	pub1, priv1, err := authjwt.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("generate k1: %v", err)
	}
	pub2, priv2, err := authjwt.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("generate k2: %v", err)
	}
	up := newHardeningUserProvider(t)

	baseCfg := func() Config {
		cfg := accountTestConfig()
		cfg.JWT.SigningMethod = "ed25519"
		return cfg
	}

	// Step 0: current fleet — signs k1, verifies {k1}.
	cfgA := baseCfg()
	cfgA.JWT.PrivateKey = priv1
	cfgA.JWT.PublicKey = pub1
	cfgA.JWT.KeyID = "k1"
	cfgA.JWT.VerifyKeys = map[string][]byte{"k1": pub1}
	engineA := newRotationEngine(t, rdb, cfgA, up)

	accessK1, _, err := engineA.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login on engine A failed: %v", err)
	}

	// Step 1+2: rotated fleet — signs k2, still verifies {k1, k2}.
	cfgB := baseCfg()
	cfgB.JWT.PrivateKey = priv2
	cfgB.JWT.PublicKey = pub2
	cfgB.JWT.KeyID = "k2"
	cfgB.JWT.VerifyKeys = map[string][]byte{"k1": pub1, "k2": pub2}
	engineB := newRotationEngine(t, rdb, cfgB, up)

	if _, err := engineB.Validate(ctx, accessK1, ModeInherit); err != nil {
		t.Fatalf("rotated engine rejected k1 token during overlap window: %v", err)
	}
	if _, err := engineB.Validate(ctx, accessK1, ModeStrict); err != nil {
		t.Fatalf("rotated engine rejected k1 token in strict mode (shared session): %v", err)
	}

	accessK2, _, err := engineB.Login(ctx, "bob", "correct-password-123")
	if err != nil {
		t.Fatalf("login on engine B failed: %v", err)
	}
	if _, err := engineB.Validate(ctx, accessK2, ModeInherit); err != nil {
		t.Fatalf("rotated engine rejected its own k2 token: %v", err)
	}
	if _, err := engineA.Validate(ctx, accessK2, ModeInherit); err == nil {
		t.Fatal("pre-rotation engine unexpectedly accepted a k2 token (k2 not in its verify set)")
	}

	// Step 3: retired fleet — signs k2, verifies {k2} only.
	cfgC := baseCfg()
	cfgC.JWT.PrivateKey = priv2
	cfgC.JWT.PublicKey = pub2
	cfgC.JWT.KeyID = "k2"
	cfgC.JWT.VerifyKeys = map[string][]byte{"k2": pub2}
	engineC := newRotationEngine(t, rdb, cfgC, up)

	if _, err := engineC.Validate(ctx, accessK1, ModeInherit); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected retired-key token to fail with ErrUnauthorized, got %v", err)
	}
	if _, err := engineC.Validate(ctx, accessK2, ModeInherit); err != nil {
		t.Fatalf("post-retirement engine rejected current k2 token: %v", err)
	}
}

func TestKeyRotationRejectsKidlessTokensOnceVerifyKeysConfigured(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()
	ctx := context.Background()

	pub, priv, err := authjwt.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	up := newHardeningUserProvider(t)

	// Legacy engine: same key material but no KeyID/VerifyKeys → kid-less tokens.
	cfgLegacy := accountTestConfig()
	cfgLegacy.JWT.SigningMethod = "ed25519"
	cfgLegacy.JWT.PrivateKey = priv
	cfgLegacy.JWT.PublicKey = pub
	legacy := newRotationEngine(t, rdb, cfgLegacy, up)

	kidless, _, err := legacy.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login on legacy engine failed: %v", err)
	}

	cfgStrict := accountTestConfig()
	cfgStrict.JWT.SigningMethod = "ed25519"
	cfgStrict.JWT.PrivateKey = priv
	cfgStrict.JWT.PublicKey = pub
	cfgStrict.JWT.KeyID = "k1"
	cfgStrict.JWT.VerifyKeys = map[string][]byte{"k1": pub}
	strict := newRotationEngine(t, rdb, cfgStrict, up)

	if _, err := strict.Validate(ctx, kidless, ModeInherit); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected kid-less token to fail once VerifyKeys is configured, got %v", err)
	}
}
