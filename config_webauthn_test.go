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
		{"ip address rpid", func(c *Config) { c.WebAuthn.RPID = "192.168.1.1" }, "not an IP address"},
		{"ipv6 rpid", func(c *Config) { c.WebAuthn.RPID = "::1" }, "not an IP address"},
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

func TestConfigValidateWebAuthnRPIDLocalhostPasses(t *testing.T) {
	cfg := webauthnTestConfig()
	cfg.WebAuthn.RPID = "localhost"
	cfg.WebAuthn.RPOrigins = []string{"http://localhost:8080"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected localhost RPID to pass, got %v", err)
	}
}

// An IP RPID must fail fast at Build() with goAuth's own readable message,
// not a library error the first time a ceremony starts.
func TestBuildRejectsIPAddressRPID(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	cfg := webauthnTestConfig()
	cfg.WebAuthn.RPID = "203.0.113.5"

	_, err := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"perm.read"}).
		WithRoles(map[string][]string{"member": {}}).
		WithUserProvider(newWebAuthnMockProvider(t)).
		Build()
	if err == nil || !strings.Contains(err.Error(), "not an IP address") {
		t.Fatalf("expected Build to fail fast on an IP RPID, got %v", err)
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
