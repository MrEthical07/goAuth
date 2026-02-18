package goAuth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDeviceBindingDetectOnlyLogsButAllows(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeStrict
	cfg.DeviceBinding.Enabled = true
	cfg.DeviceBinding.DetectIPChange = true
	cfg.DeviceBinding.DetectUserAgentChange = true
	cfg.Metrics.Enabled = true
	cfg.Audit.Enabled = true
	cfg.Audit.BufferSize = 32
	cfg.Audit.DropIfFull = true

	up := newHardeningUserProvider(t)
	sink := newCaptureSink(16)
	engine, done := buildAuditTestEngine(t, cfg, sink, up)
	defer done()

	loginCtx := WithUserAgent(WithClientIP(context.Background(), "203.0.113.1"), "ua-v1")
	access, _, err := engine.Login(loginCtx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	validateCtx := WithUserAgent(WithClientIP(context.Background(), "203.0.113.2"), "ua-v2")
	if _, err := engine.Validate(validateCtx, access, ModeInherit); err != nil {
		t.Fatalf("expected validate success in detect-only mode, got %v", err)
	}

	if got := engine.metrics.Value(MetricDeviceIPMismatch); got != 1 {
		t.Fatalf("expected MetricDeviceIPMismatch=1, got %d", got)
	}
	if got := engine.metrics.Value(MetricDeviceUAMismatch); got != 1 {
		t.Fatalf("expected MetricDeviceUAMismatch=1, got %d", got)
	}
	if got := engine.metrics.Value(MetricDeviceRejected); got != 0 {
		t.Fatalf("expected MetricDeviceRejected=0, got %d", got)
	}

	found := false
	deadline := time.After(2 * time.Second)
	for !found {
		select {
		case ev := <-sink.events:
			if ev.EventType == auditEventDeviceAnomalyDetected {
				found = true
			}
		case <-deadline:
			t.Fatal("expected device anomaly audit event")
		}
	}
}

func TestDeviceBindingEnforcementRejects(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeStrict
	cfg.DeviceBinding.Enabled = true
	cfg.DeviceBinding.EnforceIPBinding = true
	cfg.DeviceBinding.DetectIPChange = true
	cfg.Metrics.Enabled = true

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	loginCtx := WithUserAgent(WithClientIP(context.Background(), "203.0.113.10"), "ua-v1")
	access, _, err := engine.Login(loginCtx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	validateCtx := WithUserAgent(WithClientIP(context.Background(), "203.0.113.11"), "ua-v1")
	if _, err := engine.Validate(validateCtx, access, ModeInherit); !errors.Is(err, ErrDeviceBindingRejected) {
		t.Fatalf("expected ErrDeviceBindingRejected, got %v", err)
	}

	if got := engine.metrics.Value(MetricDeviceIPMismatch); got != 1 {
		t.Fatalf("expected MetricDeviceIPMismatch=1, got %d", got)
	}
	if got := engine.metrics.Value(MetricDeviceRejected); got != 1 {
		t.Fatalf("expected MetricDeviceRejected=1, got %d", got)
	}
}

func TestDeviceBindingReplayStillHandled(t *testing.T) {
	cfg := accountTestConfig()
	cfg.DeviceBinding.Enabled = true
	cfg.DeviceBinding.EnforceIPBinding = true
	cfg.DeviceBinding.EnforceUserAgentBinding = true
	cfg.DeviceBinding.DetectIPChange = true
	cfg.DeviceBinding.DetectUserAgentChange = true

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	ctx := WithUserAgent(WithClientIP(context.Background(), "203.0.113.20"), "ua-v1")
	_, refresh, err := engine.Login(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	if _, _, err := engine.Refresh(ctx, refresh); err != nil {
		t.Fatalf("first refresh failed: %v", err)
	}
	if _, _, err := engine.Refresh(ctx, refresh); !errors.Is(err, ErrRefreshReuse) {
		t.Fatalf("expected ErrRefreshReuse, got %v", err)
	}
}

func TestDeviceBindingDisabledHasNoEffect(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeStrict
	cfg.DeviceBinding.Enabled = false
	cfg.Metrics.Enabled = true

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	loginCtx := WithUserAgent(WithClientIP(context.Background(), "198.51.100.1"), "ua-v1")
	access, _, err := engine.Login(loginCtx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	validateCtx := WithUserAgent(WithClientIP(context.Background(), "198.51.100.2"), "ua-v2")
	if _, err := engine.Validate(validateCtx, access, ModeInherit); err != nil {
		t.Fatalf("expected validate success with binding disabled, got %v", err)
	}

	if got := engine.metrics.Value(MetricDeviceIPMismatch); got != 0 {
		t.Fatalf("expected MetricDeviceIPMismatch=0, got %d", got)
	}
	if got := engine.metrics.Value(MetricDeviceUAMismatch); got != 0 {
		t.Fatalf("expected MetricDeviceUAMismatch=0, got %d", got)
	}
	if got := engine.metrics.Value(MetricDeviceRejected); got != 0 {
		t.Fatalf("expected MetricDeviceRejected=0, got %d", got)
	}
}

func TestDeviceBindingDisabledValidateNoProviderCallsRegression(t *testing.T) {
	engine, up, done := newStatusEngine(t, AccountActive, ModeStrict)
	defer done()

	engine.config.DeviceBinding.Enabled = false

	loginCtx := WithUserAgent(WithClientIP(context.Background(), "192.0.2.1"), "ua-a")
	access, _, err := engine.Login(loginCtx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	up.getByIdentifierCalls = 0
	up.getByIDCalls = 0
	up.createCalls = 0
	up.updatePasswordCalls = 0
	up.updateStatusCalls = 0

	validateCtx := WithUserAgent(WithClientIP(context.Background(), "192.0.2.2"), "ua-b")
	if _, err := engine.Validate(validateCtx, access, ModeInherit); err != nil {
		t.Fatalf("validate failed: %v", err)
	}

	if up.getByIdentifierCalls != 0 || up.getByIDCalls != 0 || up.createCalls != 0 || up.updatePasswordCalls != 0 || up.updateStatusCalls != 0 {
		t.Fatalf("expected validate to avoid provider calls, got counts: %+v", up)
	}
}

func TestDeviceBindingMissingContextEnforceRejects(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeStrict
	cfg.DeviceBinding.Enabled = true
	cfg.DeviceBinding.EnforceIPBinding = true
	cfg.DeviceBinding.DetectIPChange = true

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	loginCtx := WithUserAgent(WithClientIP(context.Background(), "203.0.113.50"), "ua-v1")
	access, _, err := engine.Login(loginCtx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	validateCtx := WithUserAgent(context.Background(), "ua-v1")
	if _, err := engine.Validate(validateCtx, access, ModeInherit); !errors.Is(err, ErrDeviceBindingRejected) {
		t.Fatalf("expected ErrDeviceBindingRejected when IP context missing, got %v", err)
	}
}

func TestDeviceBindingMissingContextDetectOnlyCountsAnomaly(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeStrict
	cfg.DeviceBinding.Enabled = true
	cfg.DeviceBinding.DetectIPChange = true
	cfg.Metrics.Enabled = true

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	loginCtx := WithClientIP(context.Background(), "203.0.113.51")
	access, _, err := engine.Login(loginCtx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	if _, err := engine.Validate(context.Background(), access, ModeInherit); err != nil {
		t.Fatalf("expected validate success in detect-only with missing IP, got %v", err)
	}
	if got := engine.metrics.Value(MetricDeviceIPMismatch); got != 1 {
		t.Fatalf("expected MetricDeviceIPMismatch=1, got %d", got)
	}
}

func TestDeviceBindingDetectOnlyAnomalyThrottled(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeStrict
	cfg.DeviceBinding.Enabled = true
	cfg.DeviceBinding.DetectIPChange = true
	cfg.Metrics.Enabled = true
	cfg.Audit.Enabled = true
	cfg.Audit.BufferSize = 32
	cfg.Audit.DropIfFull = true

	up := newHardeningUserProvider(t)
	sink := newCaptureSink(32)
	engine, done := buildAuditTestEngine(t, cfg, sink, up)
	defer done()

	loginCtx := WithClientIP(context.Background(), "203.0.113.60")
	access, _, err := engine.Login(loginCtx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	validateCtx := WithClientIP(context.Background(), "203.0.113.61")
	for i := 0; i < 5; i++ {
		if _, err := engine.Validate(validateCtx, access, ModeInherit); err != nil {
			t.Fatalf("validate %d failed: %v", i, err)
		}
	}

	if got := engine.metrics.Value(MetricDeviceIPMismatch); got != 1 {
		t.Fatalf("expected throttled MetricDeviceIPMismatch=1, got %d", got)
	}

	anomalyEvents := 0
drain:
	for {
		select {
		case ev := <-sink.events:
			if ev.EventType == auditEventDeviceAnomalyDetected {
				anomalyEvents++
			}
		default:
			break drain
		}
	}
	if anomalyEvents != 1 {
		t.Fatalf("expected exactly one throttled anomaly audit event, got %d", anomalyEvents)
	}
}
