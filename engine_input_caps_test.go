package goAuth

import "testing"

// The cap is part of the public contract: hosts that allow longer logins have
// to shorten them, so the number is pinned.
func TestMaxIdentifierBytesIsPartOfTheContract(t *testing.T) {
	if MaxIdentifierBytes != 320 {
		t.Fatalf("MaxIdentifierBytes = %d, want 320", MaxIdentifierBytes)
	}
}
