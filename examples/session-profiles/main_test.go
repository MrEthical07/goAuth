package main

import (
	"bytes"
	"regexp"
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
		"logged in as web and as mobile",
		"sessions after login:",
		"mobile ceiling +365d, idle window ends 2160h0m0s after login",
		"web    ceiling +15d, fixed (no idle window)",
		"sessions after refresh:",
		"login with an unknown profile: refused with ErrUnknownSessionProfile",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output is missing %q:\n%s", want, got)
		}
	}

	// After the refresh the mobile idle window has moved a little further
	// from the login time, while its ceiling is unchanged.
	after := got[strings.Index(got, "sessions after refresh:"):]
	if !regexp.MustCompile(`mobile ceiling \+365d, idle window ends 2160h0m[1-9]s after login`).MatchString(after) {
		t.Errorf("the idle window did not move after the refresh:\n%s", after)
	}
}
