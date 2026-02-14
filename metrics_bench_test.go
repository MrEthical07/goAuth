package goAuth

import (
	"sync/atomic"
	"testing"
	"time"
)

func BenchmarkMetricsInc(b *testing.B) {
	m := NewMetrics(MetricsConfig{Enabled: true})
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.Inc(MetricLoginSuccess)
	}
}

func BenchmarkMetricsIncDisabled(b *testing.B) {
	m := NewMetrics(MetricsConfig{Enabled: false})
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.Inc(MetricLoginSuccess)
	}
}

func BenchmarkMetricsIncParallel(b *testing.B) {
	m := NewMetrics(MetricsConfig{Enabled: true})
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.Inc(MetricLoginSuccess)
		}
	})
}

func BenchmarkMetricsIncDisabledParallel(b *testing.B) {
	m := NewMetrics(MetricsConfig{Enabled: false})
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.Inc(MetricLoginSuccess)
		}
	})
}

func BenchmarkMetricsObserveLatencyParallel(b *testing.B) {
	m := NewMetrics(MetricsConfig{
		Enabled:                 true,
		EnableLatencyHistograms: true,
	})
	d := 12 * time.Millisecond
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.Observe(MetricValidateLatency, d)
		}
	})
}

type packedBenchmarkMetrics struct {
	counters [metricIDCount]uint64
}

func (m *packedBenchmarkMetrics) Inc(id MetricID) {
	atomic.AddUint64(&m.counters[id], 1)
}

var mixedHotMetricIDs = [...]MetricID{
	MetricLoginSuccess,
	MetricLoginFailure,
	MetricSessionCreated,
	MetricRefreshSuccess,
	MetricRefreshFailure,
	MetricPasswordResetConfirmSuccess,
	MetricEmailVerificationSuccess,
	MetricLogoutAll,
}

func BenchmarkMetricsIncMixedParallelPaddedRoundRobin(b *testing.B) {
	m := NewMetrics(MetricsConfig{Enabled: true})
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		idx := 0
		for pb.Next() {
			m.Inc(mixedHotMetricIDs[idx])
			idx++
			if idx == len(mixedHotMetricIDs) {
				idx = 0
			}
		}
	})
}

func BenchmarkMetricsIncMixedParallelPackedRoundRobin(b *testing.B) {
	m := &packedBenchmarkMetrics{}
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		idx := 0
		for pb.Next() {
			m.Inc(mixedHotMetricIDs[idx])
			idx++
			if idx == len(mixedHotMetricIDs) {
				idx = 0
			}
		}
	})
}

func BenchmarkMetricsIncMixedParallelPaddedPseudoRandom(b *testing.B) {
	m := NewMetrics(MetricsConfig{Enabled: true})
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		var s uint64 = 0x9e3779b97f4a7c15
		for pb.Next() {
			// xorshift64*
			s ^= s >> 12
			s ^= s << 25
			s ^= s >> 27
			i := (s * 2685821657736338717) % uint64(len(mixedHotMetricIDs))
			m.Inc(mixedHotMetricIDs[i])
		}
	})
}

func BenchmarkMetricsIncMixedParallelPackedPseudoRandom(b *testing.B) {
	m := &packedBenchmarkMetrics{}
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		var s uint64 = 0x9e3779b97f4a7c15
		for pb.Next() {
			// xorshift64*
			s ^= s >> 12
			s ^= s << 25
			s ^= s >> 27
			i := (s * 2685821657736338717) % uint64(len(mixedHotMetricIDs))
			m.Inc(mixedHotMetricIDs[i])
		}
	})
}
