package goAuth

import (
	"testing"

	internalflows "github.com/MrEthical07/goAuth/internal/flows"
)

// A real account is verified at the cost of its own hash, so the dummy and the
// real path agree whenever the stored hash was made under the current
// configuration.
func TestDummyHashDiffersPerEngineAndIsNotThePublicConstant(t *testing.T) {
	cfg := accountTestConfig()
	e1, _, done1 := newCreateAccountEngine(t, cfg, newHardeningUserProvider(t))
	defer done1()
	e2, _, done2 := newCreateAccountEngine(t, cfg, newHardeningUserProvider(t))
	defer done2()
	if e1.dummyHash == "" || e1.dummyHash == e2.dummyHash {
		t.Fatalf("each engine must hash its own throwaway password: %q vs %q", e1.dummyHash, e2.dummyHash)
	}
	if ok, err := e1.passwordHash.Verify(internalflows.DummyTimingPassword, e1.dummyHash); err != nil || ok {
		t.Fatalf("the dummy hash must not verify the well-known dummy password: ok=%v err=%v", ok, err)
	}
}
