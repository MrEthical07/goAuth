package goAuth

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMetricsDisabledNoIncrement(t *testing.T) {
	m := NewMetrics(MetricsConfig{Enabled: false})
	m.Inc(MetricLoginSuccess)

	if got := m.Value(MetricLoginSuccess); got != 0 {
		t.Fatalf("expected 0, got %d", got)
	}
}

func TestMetricsEnabledIncrement(t *testing.T) {
	m := NewMetrics(MetricsConfig{Enabled: true})
	m.Inc(MetricLoginSuccess)
	m.Inc(MetricLoginSuccess)
	m.Inc(MetricLoginSuccess)

	if got := m.Value(MetricLoginSuccess); got != 3 {
		t.Fatalf("expected 3, got %d", got)
	}
}

func TestMetricsConcurrentIncrementSafe(t *testing.T) {
	m := NewMetrics(MetricsConfig{Enabled: true})

	const goroutines = 32
	const perG = 4000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perG; j++ {
				m.Inc(MetricRefreshSuccess)
			}
		}()
	}
	wg.Wait()

	want := uint64(goroutines * perG)
	if got := m.Value(MetricRefreshSuccess); got != want {
		t.Fatalf("expected %d, got %d", want, got)
	}
}

func TestMetricsHistogramBucketCorrectness(t *testing.T) {
	m := NewMetrics(MetricsConfig{
		Enabled:                 true,
		EnableLatencyHistograms: true,
	})

	observations := []time.Duration{
		5 * time.Millisecond,
		10 * time.Millisecond,
		25 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
		250 * time.Millisecond,
		500 * time.Millisecond,
		700 * time.Millisecond,
	}

	for _, d := range observations {
		m.Observe(MetricValidateLatency, d)
	}

	snap := m.Snapshot()
	buckets := snap.Histograms[MetricValidateLatency]
	if len(buckets) != 8 {
		t.Fatalf("expected 8 buckets, got %d", len(buckets))
	}

	for i, v := range buckets {
		if v != 1 {
			t.Fatalf("bucket %d expected 1, got %d", i, v)
		}
	}
}

func TestMetricsSnapshotConsistency(t *testing.T) {
	m := NewMetrics(MetricsConfig{
		Enabled:                 true,
		EnableLatencyHistograms: true,
	})
	m.Inc(MetricLoginSuccess)
	m.Inc(MetricLoginFailure)
	m.Inc(MetricLoginFailure)
	m.Observe(MetricValidateLatency, 2*time.Millisecond)

	snap := m.Snapshot()

	if snap.Counters[MetricLoginSuccess] != 1 {
		t.Fatalf("expected MetricLoginSuccess=1 got %d", snap.Counters[MetricLoginSuccess])
	}
	if snap.Counters[MetricLoginFailure] != 2 {
		t.Fatalf("expected MetricLoginFailure=2 got %d", snap.Counters[MetricLoginFailure])
	}
	if len(snap.Histograms[MetricValidateLatency]) != 8 {
		t.Fatalf("expected histogram length 8")
	}
	if snap.Histograms[MetricValidateLatency][0] != 1 {
		t.Fatalf("expected first histogram bucket=1 got %d", snap.Histograms[MetricValidateLatency][0])
	}
}

func TestValidateWithMetricsStillAvoidsProviderCalls(t *testing.T) {
	engine, up, done := newStatusEngine(t, AccountActive, ModeStrict)
	defer done()

	engine.metrics = NewMetrics(MetricsConfig{
		Enabled:                 true,
		EnableLatencyHistograms: true,
	})

	access, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	up.getByIdentifierCalls = 0
	up.getByIDCalls = 0
	up.createCalls = 0
	up.updatePasswordCalls = 0
	up.updateStatusCalls = 0

	_, err = engine.Validate(context.Background(), access, ModeInherit)
	if err != nil {
		t.Fatalf("validate failed: %v", err)
	}

	if up.getByIdentifierCalls != 0 || up.getByIDCalls != 0 || up.createCalls != 0 || up.updatePasswordCalls != 0 || up.updateStatusCalls != 0 {
		t.Fatalf("expected validate to avoid provider calls, got counts: %+v", up)
	}
}
