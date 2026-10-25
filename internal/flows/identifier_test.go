package flows

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestAuditIdentifierBoundsCallerInput(t *testing.T) {
	short := strings.Repeat("a", MaxIdentifierBytes)
	if got := auditIdentifier(short); got != short {
		t.Fatal("an identifier at the cap must be kept whole")
	}
	if got := auditIdentifier(strings.Repeat("a", MaxIdentifierBytes+500)); len(got) != MaxIdentifierBytes {
		t.Fatalf("got %d bytes, want %d", len(got), MaxIdentifierBytes)
	}

	// A multi-byte character cut by the limit is dropped, not left as an
	// invalid sequence in the audit trail.
	cut := strings.Repeat("a", MaxIdentifierBytes-1) + "é" + "tail"
	got := auditIdentifier(cut)
	if !utf8.ValidString(got) || len(got) > MaxIdentifierBytes {
		t.Fatalf("got %q (%d bytes, valid=%v)", got, len(got), utf8.ValidString(got))
	}
}

func TestIdentifierTooLongIsInclusiveAtTheCap(t *testing.T) {
	if identifierTooLong(strings.Repeat("a", MaxIdentifierBytes)) {
		t.Fatal("an identifier of exactly MaxIdentifierBytes is allowed")
	}
	if !identifierTooLong(strings.Repeat("a", MaxIdentifierBytes+1)) {
		t.Fatal("an identifier one byte over the cap is refused")
	}
}
