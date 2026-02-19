package test

import (
	"testing"

	goAuth "github.com/MrEthical07/goAuth"
)

func TestDefaultConfigPresetValidates(t *testing.T) {
	cfg := goAuth.DefaultConfig()

	if cfg.ValidationMode != goAuth.ModeHybrid {
		t.Fatalf("expected ModeHybrid, got %v", cfg.ValidationMode)
	}
	if !cfg.Security.EnforceRefreshRotation || !cfg.Security.EnforceRefreshReuseDetection {
		t.Fatal("expected refresh rotation/reuse detection to stay enabled")
	}
	if len(cfg.JWT.PrivateKey) == 0 || len(cfg.JWT.PublicKey) == 0 {
		t.Fatal("expected preset to include generated ed25519 keys")
	}
	if cfg.Account.Enabled {
		t.Fatal("expected account creation disabled in preset baseline")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected preset to validate, got %v", err)
	}
}

func TestHighSecurityConfigPresetValidates(t *testing.T) {
	cfg := goAuth.HighSecurityConfig()

	if cfg.ValidationMode != goAuth.ModeStrict {
		t.Fatalf("expected ModeStrict, got %v", cfg.ValidationMode)
	}
	if !cfg.Security.ProductionMode {
		t.Fatal("expected production mode enabled")
	}
	if !cfg.JWT.RequireIAT {
		t.Fatal("expected RequireIAT=true")
	}
	if !cfg.DeviceBinding.Enabled || !cfg.DeviceBinding.EnforceUserAgentBinding {
		t.Fatal("expected device binding enforcement enabled")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected high security preset to validate, got %v", err)
	}
}

func TestHighThroughputConfigPresetValidates(t *testing.T) {
	cfg := goAuth.HighThroughputConfig()

	if cfg.ValidationMode != goAuth.ModeHybrid {
		t.Fatalf("expected ModeHybrid, got %v", cfg.ValidationMode)
	}
	if !cfg.Security.ProductionMode {
		t.Fatal("expected production mode enabled")
	}
	if cfg.JWT.AccessTTL <= 0 || cfg.JWT.RefreshTTL <= 0 {
		t.Fatal("expected positive token ttls")
	}
	if cfg.Security.EnableIPThrottle {
		t.Fatal("expected ip throttle disabled for throughput preset")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected high throughput preset to validate, got %v", err)
	}
}
