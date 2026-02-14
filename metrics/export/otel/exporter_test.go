package otel

import (
	"context"
	"sync"
	"testing"

	goAuth "github.com/MrEthical07/goAuth"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type fakeSource struct {
	mu       sync.RWMutex
	snapshot goAuth.MetricsSnapshot
	dropped  uint64
}

func (f *fakeSource) MetricsSnapshot() goAuth.MetricsSnapshot {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := goAuth.MetricsSnapshot{
		Counters:   make(map[goAuth.MetricID]uint64, len(f.snapshot.Counters)),
		Histograms: make(map[goAuth.MetricID][]uint64, len(f.snapshot.Histograms)),
	}
	for k, v := range f.snapshot.Counters {
		out.Counters[k] = v
	}
	for k, buckets := range f.snapshot.Histograms {
		next := make([]uint64, len(buckets))
		copy(next, buckets)
		out.Histograms[k] = next
	}
	return out
}

func (f *fakeSource) AuditDropped() uint64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.dropped
}

func TestExporterRegistersAndCollects(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	meter := provider.Meter("goauth-test")

	src := &fakeSource{
		snapshot: goAuth.MetricsSnapshot{
			Counters: map[goAuth.MetricID]uint64{
				goAuth.MetricLoginSuccess: 3,
			},
			Histograms: map[goAuth.MetricID][]uint64{
				goAuth.MetricValidateLatency: {1, 1, 1, 1, 1, 1, 1, 1},
			},
		},
		dropped: 1,
	}

	exp, err := NewOTelExporterFromSource(meter, src)
	if err != nil {
		t.Fatalf("NewOTelExporterFromSource failed: %v", err)
	}
	defer func() {
		if err := exp.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	}()

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if len(rm.ScopeMetrics) == 0 {
		t.Fatal("expected collected metrics, got none")
	}
}

func TestExporterRejectsNilSource(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	meter := provider.Meter("goauth-test")

	if _, err := NewOTelExporterFromSource(meter, nil); err == nil {
		t.Fatal("expected error for nil source")
	}
}

func TestExporterConcurrentCollectNoPanic(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	meter := provider.Meter("goauth-test")

	src := &fakeSource{
		snapshot: goAuth.MetricsSnapshot{
			Counters: map[goAuth.MetricID]uint64{
				goAuth.MetricLoginSuccess: 1,
			},
			Histograms: map[goAuth.MetricID][]uint64{
				goAuth.MetricValidateLatency: {1, 0, 0, 0, 0, 0, 0, 0},
			},
		},
	}

	exp, err := NewOTelExporterFromSource(meter, src)
	if err != nil {
		t.Fatalf("NewOTelExporterFromSource failed: %v", err)
	}
	defer func() {
		if err := exp.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(v uint64) {
			defer wg.Done()
			src.mu.Lock()
			src.snapshot.Counters[goAuth.MetricLoginSuccess] = v
			src.mu.Unlock()

			var rm metricdata.ResourceMetrics
			_ = reader.Collect(context.Background(), &rm)
		}(uint64(i + 1))
	}
	wg.Wait()
}
