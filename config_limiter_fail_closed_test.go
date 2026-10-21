package goAuth

import "testing"

// SecurityConfig stays comparable with ==: the new field is a bool.
var _ = SecurityConfig{} == SecurityConfig{}

func TestLimiterFailClosedDefaultsOffAndLintsInfoWhenOn(t *testing.T) {
	cfg := defaultConfig()
	if cfg.Security.LimiterFailClosed {
		t.Fatal("LimiterFailClosed must default to false")
	}
	for _, w := range cfg.Lint() {
		if w.Code == "limiter_fail_closed_outage_blocks_signin" {
			t.Fatalf("lint reported the fail-closed note with the flag off: %+v", w)
		}
	}

	cfg.Security.LimiterFailClosed = true
	var found *LintWarning
	for _, w := range cfg.Lint() {
		if w.Code == "limiter_fail_closed_outage_blocks_signin" {
			w := w
			found = &w
		}
	}
	if found == nil {
		t.Fatal("expected the limiter_fail_closed_outage_blocks_signin lint note")
	}
	if found.Severity != LintInfo {
		t.Fatalf("severity = %v, want INFO", found.Severity)
	}
}
