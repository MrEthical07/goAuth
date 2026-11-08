package goAuth

import (
	"strings"
	"testing"
)

// A valid ID must never be refused: every ID each generator produces passes
// its strategy's rule, and the parser hands the same ID back.
func TestEveryGeneratedChallengeParses(t *testing.T) {
	for i := 0; i < 200; i++ {
		for _, strategy := range []VerificationStrategyType{VerificationToken, VerificationUUID, VerificationOTP} {
			id, challenge, _, err := generateEmailVerificationChallenge(strategy, 6, "tenant-a")
			if err != nil {
				t.Fatal(err)
			}
			if !validVerificationIDText(strategy, id) {
				t.Fatalf("verification strategy %v: generated ID %q refused", strategy, id)
			}
			tenant, parsedID, _, err := parseEmailVerificationChallenge(strategy, challenge, 6)
			if err != nil || tenant != "tenant-a" || parsedID != id {
				t.Fatalf("verification strategy %v: challenge %q: %q %q %v", strategy, challenge, tenant, parsedID, err)
			}
			parts := strings.SplitN(challenge, ":", 3)
			if _, err := parseEmailVerificationChallengeCode(strategy, id, parts[2], 6); err != nil {
				t.Fatalf("verification strategy %v: code of %q: %v", strategy, id, err)
			}
		}
		for _, strategy := range []ResetStrategyType{ResetToken, ResetUUID, ResetOTP} {
			var e *Engine
			id, challenge, _, err := e.generatePasswordResetChallenge(strategy, 6)
			if err != nil {
				t.Fatal(err)
			}
			if !validResetChallengeText(strategy, challenge, 6) {
				t.Fatalf("reset strategy %v: generated challenge %q refused", strategy, challenge)
			}
			parsedID, _, err := parsePasswordResetChallenge(strategy, challenge, 6)
			if err != nil || parsedID != id {
				t.Fatalf("reset strategy %v: challenge %q: %q %v", strategy, challenge, parsedID, err)
			}
		}
	}
}
