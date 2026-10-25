package goAuth

import (
	"testing"
	"time"
)

// The cap is part of the public contract: hosts that allow longer logins have
// to shorten them, so the number is pinned.
func TestMaxIdentifierBytesIsPartOfTheContract(t *testing.T) {
	if MaxIdentifierBytes != 320 {
		t.Fatalf("MaxIdentifierBytes = %d, want 320", MaxIdentifierBytes)
	}
}

// The engine hands both enumeration-safe request flows a 20-40 ms floor.
func TestEnumerationFloorIsWiredForBothRequestFlows(t *testing.T) {
	engine, _, done := newCreateAccountEngine(t, accountTestConfig(), newHardeningUserProvider(t))
	defer done()

	for name, draw := range map[string]func() time.Duration{
		"password reset":     engine.passwordResetFlowDeps().EnumerationFloor,
		"email verification": engine.emailVerificationFlowDeps().EnumerationFloor,
	} {
		if draw == nil {
			t.Fatalf("%s: no floor wired", name)
		}
		for i := 0; i < 50; i++ {
			if d := draw(); d < 20*time.Millisecond || d > 40*time.Millisecond {
				t.Fatalf("%s: floor %v outside 20-40ms", name, d)
			}
		}
	}
}
