package goAuth

import (
	"strings"
	"testing"
	"time"
)

func TestConfigValidateWebAuthnRequiredFields(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"missing rpid", func(c *Config) { c.WebAuthn.RPID = "" }, "RPID"},
		{"missing display name", func(c *Config) { c.WebAuthn.RPDisplayName = "" }, "RPDisplayName"},
		{"missing origins", func(c *Config) { c.WebAuthn.RPOrigins = nil }, "RPOrigins"},
		{"empty origin", func(c *Config) { c.WebAuthn.RPOrigins = []string{" "} }, "empty origins"},
		{"bad attestation", func(c *Config) { c.WebAuthn.AttestationPreference = "full" }, "AttestationPreference"},
		{"bad user verification", func(c *Config) { c.WebAuthn.UserVerification = "always" }, "UserVerification"},
		{"negative ttl", func(c *Config) { c.WebAuthn.CeremonyTTL = -time.Second }, "CeremonyTTL"},
		{"tiny ttl", func(c *Config) { c.WebAuthn.CeremonyTTL = time.Second }, "CeremonyTTL"},
		{"huge ttl", func(c *Config) { c.WebAuthn.CeremonyTTL = time.Hour }, "CeremonyTTL"},
	}

	for _, tc := range cases {
		cfg := webauthnTestConfig()
		tc.mutate(&cfg)
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s: expected error containing %q, got %v", tc.name, tc.wantErr, err)
		}
	}
}

func TestConfigValidateWebAuthnRequireForLoginNeedsEnabled(t *testing.T) {
	cfg := accountTestConfig()
	cfg.WebAuthn.RequireForLogin = true

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "RequireForLogin requires WebAuthn Enabled") {
		t.Fatalf("expected RequireForLogin gating error, got %v", err)
	}
}

func TestConfigValidateWebAuthnValidConfigPasses(t *testing.T) {
	cfg := webauthnTestConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid webauthn config to pass, got %v", err)
	}

	// Disabled configs skip webauthn field validation entirely.
	cfg = accountTestConfig()
	cfg.WebAuthn.RPID = ""
	cfg.WebAuthn.AttestationPreference = "junk"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected disabled webauthn config to pass, got %v", err)
	}
}

func TestBuildWebAuthnRPOriginsImmutability(t *testing.T) {
	cfg := webauthnTestConfig()
	up := newWebAuthnMockProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	cfg.WebAuthn.RPOrigins[0] = "https://evil.example.net"
	if engine.config.WebAuthn.RPOrigins[0] != "https://example.com" {
		t.Fatal("engine RPOrigins mutated from external config after build")
	}
}
