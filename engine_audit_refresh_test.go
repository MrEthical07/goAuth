package goAuth

import (
	"context"
	"errors"
	"testing"
)

// Regression tests for the refresh findings of the v0.8.0 security audit
// (run 2): R2-17. Each is labelled FAILED-BEFORE with the finding ID.

// FAILED-BEFORE (R2-17): in enforce mode Refresh ignored device binding, so a
// stolen refresh token worked from any address.
func TestRefreshEnforcesDeviceBinding(t *testing.T) {
	login := func(t *testing.T, mutate func(*Config)) (*Engine, string) {
		t.Helper()
		cfg := accountTestConfig()
		cfg.DeviceBinding.Enabled = true
		mutate(&cfg)
		up := newHardeningUserProvider(t)
		engine, _, done := newCreateAccountEngine(t, cfg, up)
		t.Cleanup(done)
		_, refresh, err := engine.Login(boundDevice(), "alice", "correct-password-123")
		if err != nil {
			t.Fatal(err)
		}
		return engine, refresh
	}

	t.Run("enforced IP", func(t *testing.T) {
		engine, refresh := login(t, func(c *Config) {
			c.DeviceBinding.EnforceIPBinding = true
			c.DeviceBinding.DetectIPChange = true
		})
		if _, _, err := engine.Refresh(otherAddress(), refresh); !errors.Is(err, ErrDeviceBindingRejected) {
			t.Fatalf("from another address: %v, want ErrDeviceBindingRejected", err)
		}
		// Nothing was rotated or deleted: the owner's token still works.
		if _, _, err := engine.Refresh(boundDevice(), refresh); err != nil {
			t.Fatalf("from the bound device: %v", err)
		}
	})
	t.Run("enforced user agent", func(t *testing.T) {
		engine, refresh := login(t, func(c *Config) {
			c.DeviceBinding.EnforceUserAgentBinding = true
			c.DeviceBinding.DetectUserAgentChange = true
		})
		if _, _, err := engine.Refresh(otherAgent(), refresh); !errors.Is(err, ErrDeviceBindingRejected) {
			t.Fatalf("from another agent: %v, want ErrDeviceBindingRejected", err)
		}
		if _, _, err := engine.Refresh(boundDevice(), refresh); err != nil {
			t.Fatalf("from the bound device: %v", err)
		}
	})
	t.Run("detect only is unchanged", func(t *testing.T) {
		engine, refresh := login(t, func(c *Config) {
			c.DeviceBinding.DetectIPChange = true
			c.DeviceBinding.DetectUserAgentChange = true
		})
		if _, _, err := engine.Refresh(otherAddress(), refresh); err != nil {
			t.Fatalf("detect mode must not refuse a refresh: %v", err)
		}
	})
	t.Run("off is unchanged", func(t *testing.T) {
		engine, refresh := login(t, func(c *Config) { c.DeviceBinding.Enabled = false })
		if _, _, err := engine.Refresh(otherAddress(), refresh); err != nil {
			t.Fatalf("binding off must not refuse a refresh: %v", err)
		}
	})
	t.Run("a spent token is still reuse", func(t *testing.T) {
		engine, refresh := login(t, func(c *Config) {
			c.DeviceBinding.EnforceIPBinding = true
			c.DeviceBinding.DetectIPChange = true
		})
		if _, _, err := engine.Refresh(boundDevice(), refresh); err != nil {
			t.Fatal(err)
		}
		if _, _, err := engine.Refresh(otherAddress(), refresh); !errors.Is(err, ErrRefreshReuse) {
			t.Fatalf("a spent token: %v, want ErrRefreshReuse", err)
		}
	})
}

func boundDevice() context.Context {
	return WithUserAgent(WithClientIP(context.Background(), "203.0.113.10"), "ua-v1")
}

func otherAddress() context.Context {
	return WithUserAgent(WithClientIP(context.Background(), "198.51.100.7"), "ua-v1")
}

func otherAgent() context.Context {
	return WithUserAgent(WithClientIP(context.Background(), "203.0.113.10"), "ua-v2")
}
