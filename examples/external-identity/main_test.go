package main

import (
	"bytes"
	"strings"
	"testing"
)

// The walkthrough must keep running as the library evolves: it is what the
// documentation points at.
func TestWalkthroughRuns(t *testing.T) {
	var out bytes.Buffer
	if err := run(&out); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	got := out.String()
	for _, want := range []string{
		"first sign-in with Google: new account=true, session issued=true",
		"returning sign-in: new account=false, session issued=true",
		"replaying a used token: refused with ErrExternalTokenReplayed",
		"Google email matches a password account: refused with ErrExternalAccountLinkRequired",
		"linked google identity to alice (email verified=true)",
		"alice signs in with Google: session issued=true",
		"carol (no password) VerifyPassword: refused with ErrPasswordNotSet",
		"carol unlinking her only identity: refused with ErrLastLoginMethod",
		"alice (has a password) unlinked Google",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output is missing %q:\n%s", want, got)
		}
	}
}
