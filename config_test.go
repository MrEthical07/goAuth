package goAuth

import (
	"testing"
	"time"
)

func TestConfigValidateEnums(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Config)
		wantValid bool
	}{
		{
			name: "jwt leeway valid",
			mutate: func(c *Config) {
				c.JWT.Leeway = 45 * time.Second
			},
			wantValid: true,
		},
		{
			name: "jwt leeway invalid",
			mutate: func(c *Config) {
				c.JWT.Leeway = 3 * time.Minute
			},
			wantValid: false,
		},
		{
			name: "jwt audience blank invalid",
			mutate: func(c *Config) {
				c.JWT.Audience = "   "
			},
			wantValid: false,
		},
		{
			name: "jwt max future iat invalid negative",
			mutate: func(c *Config) {
				c.JWT.MaxFutureIAT = -time.Second
			},
			wantValid: false,
		},
		{
			name: "jwt signing valid",
			mutate: func(c *Config) {
				c.JWT.SigningMethod = "hs256"
			},
			wantValid: true,
		},
		{
			name: "jwt signing invalid",
			mutate: func(c *Config) {
				c.JWT.SigningMethod = "rs256"
			},
			wantValid: false,
		},
		{
			name: "session encoding valid",
			mutate: func(c *Config) {
				c.Session.SessionEncoding = "msgpack"
			},
			wantValid: true,
		},
		{
			name: "session encoding invalid",
			mutate: func(c *Config) {
				c.Session.SessionEncoding = "json"
			},
			wantValid: false,
		},
		{
			name: "password reset strategy valid",
			mutate: func(c *Config) {
				c.PasswordReset.Enabled = true
				c.PasswordReset.Strategy = ResetUUID
			},
			wantValid: true,
		},
		{
			name: "password reset strategy invalid",
			mutate: func(c *Config) {
				c.PasswordReset.Enabled = true
				c.PasswordReset.Strategy = ResetStrategyType(99)
			},
			wantValid: false,
		},
		{
			name: "email verification strategy valid",
			mutate: func(c *Config) {
				c.EmailVerification.Enabled = true
				c.EmailVerification.Strategy = VerificationUUID
			},
			wantValid: true,
		},
		{
			name: "email verification strategy invalid",
			mutate: func(c *Config) {
				c.EmailVerification.Enabled = true
				c.EmailVerification.Strategy = VerificationStrategyType(99)
			},
			wantValid: false,
		},
		{
			name: "totp algorithm valid",
			mutate: func(c *Config) {
				c.TOTP.Enabled = true
				c.TOTP.Issuer = "goAuth"
				c.TOTP.Algorithm = "SHA512"
			},
			wantValid: true,
		},
		{
			name: "totp algorithm invalid",
			mutate: func(c *Config) {
				c.TOTP.Enabled = true
				c.TOTP.Issuer = "goAuth"
				c.TOTP.Algorithm = "MD5"
			},
			wantValid: false,
		},
		{
			name: "validation mode valid",
			mutate: func(c *Config) {
				c.ValidationMode = ModeStrict
			},
			wantValid: true,
		},
		{
			name: "validation mode invalid",
			mutate: func(c *Config) {
				c.ValidationMode = ValidationMode(77)
			},
			wantValid: false,
		},
		{
			name: "permission bits valid",
			mutate: func(c *Config) {
				c.Permission.MaxBits = 512
			},
			wantValid: true,
		},
		{
			name: "permission bits invalid",
			mutate: func(c *Config) {
				c.Permission.MaxBits = 1024
			},
			wantValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := accountTestConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if tc.wantValid && err != nil {
				t.Fatalf("expected valid config, got %v", err)
			}
			if !tc.wantValid && err == nil {
				t.Fatal("expected invalid config, got nil")
			}
		})
	}
}
