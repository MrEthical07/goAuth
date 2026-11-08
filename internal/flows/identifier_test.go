package flows

import (
	"strings"
	"testing"
	"unicode/utf8"
	"unsafe"
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

// A queued audit event must not keep the caller's whole request alive: the cut
// value owns its bytes, where a slice of the input would pin the input's
// backing array for as long as the sink lags.
func TestAuditIdentifierTruncationDoesNotShareTheInput(t *testing.T) {
	huge := strings.Repeat("c", 1<<20)
	got := auditIdentifier(huge)
	if len(got) != MaxIdentifierBytes {
		t.Fatalf("got %d bytes, want %d", len(got), MaxIdentifierBytes)
	}
	start := uintptr(unsafe.Pointer(unsafe.StringData(huge)))
	end := start + uintptr(len(huge))
	p := uintptr(unsafe.Pointer(unsafe.StringData(got)))
	if p >= start && p < end {
		t.Fatal("the truncated identifier points into the caller's string and keeps it alive")
	}

	// The same holds when the cut lands inside a multi-byte character.
	cut := strings.Repeat("a", MaxIdentifierBytes-1) + strings.Repeat("é", 1<<19)
	got = auditIdentifier(cut)
	start = uintptr(unsafe.Pointer(unsafe.StringData(cut)))
	end = start + uintptr(len(cut))
	p = uintptr(unsafe.Pointer(unsafe.StringData(got)))
	if len(got) > MaxIdentifierBytes || (p >= start && p < end) {
		t.Fatalf("got %d bytes, shares input: %v", len(got), p >= start && p < end)
	}
}

// An identifier within the cap is returned as it came: the normal path pays
// no copy.
func TestAuditIdentifierWithinTheCapIsNotCopied(t *testing.T) {
	for _, n := range []int{1, 64, MaxIdentifierBytes} {
		id := strings.Repeat("x", n)
		if unsafe.StringData(auditIdentifier(id)) != unsafe.StringData(id) {
			t.Fatalf("a %d-byte identifier was copied", n)
		}
	}
	if allocs := testing.AllocsPerRun(100, func() { _ = auditIdentifier("user@example.test") }); allocs != 0 {
		t.Fatalf("the normal path allocates %v times", allocs)
	}
}
