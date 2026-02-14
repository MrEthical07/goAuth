package goAuth

import (
	"sync/atomic"
	"time"
)

type MetricID uint16

const (
	MetricLoginSuccess MetricID = iota
	MetricLoginFailure
	MetricLoginRateLimited
	MetricRefreshSuccess
	MetricRefreshFailure
	MetricRefreshReuseDetected
	MetricReplayDetected
	MetricRefreshRateLimited
	MetricDeviceIPMismatch
	MetricDeviceUAMismatch
	MetricDeviceRejected
	MetricTOTPRequired
	MetricTOTPFailure
	MetricTOTPSuccess
	MetricMFALoginRequired
	MetricMFALoginSuccess
	MetricMFALoginFailure
	MetricMFAReplayAttempt
	MetricBackupCodeUsed
	MetricBackupCodeFailed
	MetricBackupCodeRegenerated
	MetricRateLimitHit
	MetricSessionCreated
	MetricSessionInvalidated
	MetricLogout
	MetricLogoutAll
	MetricAccountCreationSuccess
	MetricAccountCreationDuplicate
	MetricAccountCreationRateLimited
	MetricPasswordChangeSuccess
	MetricPasswordChangeInvalidOld
	MetricPasswordChangeReuseRejected
	MetricPasswordResetRequest
	MetricPasswordResetConfirmSuccess
	MetricPasswordResetConfirmFailure
	MetricPasswordResetAttemptsExceeded
	MetricEmailVerificationRequest
	MetricEmailVerificationSuccess
	MetricEmailVerificationFailure
	MetricEmailVerificationAttemptsExceeded
	MetricAccountDisabled
	MetricAccountLocked
	MetricAccountDeleted
	MetricValidateLatency
	metricIDCount
)

const (
	histBucketCount = 8
	cacheLineSize   = 64
)

type metricHistogram struct {
	buckets [histBucketCount]uint64
}

type paddedCounter struct {
	value uint64
	_     [cacheLineSize - 8]byte
}

type Metrics struct {
	enabled       bool
	enableLatency bool
	counters      [metricIDCount]paddedCounter
	histograms    [metricIDCount]metricHistogram
}

type MetricsSnapshot struct {
	Counters   map[MetricID]uint64
	Histograms map[MetricID][]uint64
}

func NewMetrics(cfg MetricsConfig) *Metrics {
	return &Metrics{
		enabled:       cfg.Enabled,
		enableLatency: cfg.Enabled && cfg.EnableLatencyHistograms,
	}
}

func (m *Metrics) Enabled() bool {
	return m != nil && m.enabled
}

func (m *Metrics) LatencyEnabled() bool {
	return m != nil && m.enableLatency
}

func (m *Metrics) Inc(id MetricID) {
	if m == nil || !m.enabled || id >= metricIDCount {
		return
	}
	atomic.AddUint64(&m.counters[id].value, 1)
}

func (m *Metrics) Observe(id MetricID, d time.Duration) {
	if m == nil || !m.enabled || !m.enableLatency || id >= metricIDCount {
		return
	}
	if id != MetricValidateLatency {
		return
	}

	b := bucketIndex(d)
	atomic.AddUint64(&m.histograms[id].buckets[b], 1)
}

func (m *Metrics) Value(id MetricID) uint64 {
	if m == nil || id >= metricIDCount {
		return 0
	}
	return atomic.LoadUint64(&m.counters[id].value)
}

func (m *Metrics) Snapshot() MetricsSnapshot {
	if m == nil || !m.enabled {
		return MetricsSnapshot{
			Counters:   map[MetricID]uint64{},
			Histograms: map[MetricID][]uint64{},
		}
	}

	s := MetricsSnapshot{
		Counters:   make(map[MetricID]uint64, int(metricIDCount)),
		Histograms: make(map[MetricID][]uint64, 1),
	}

	for id := MetricID(0); id < metricIDCount; id++ {
		s.Counters[id] = atomic.LoadUint64(&m.counters[id].value)
	}

	if m.enableLatency {
		buckets := make([]uint64, histBucketCount)
		for i := 0; i < histBucketCount; i++ {
			buckets[i] = atomic.LoadUint64(&m.histograms[MetricValidateLatency].buckets[i])
		}
		s.Histograms[MetricValidateLatency] = buckets
	}

	return s
}

func bucketIndex(d time.Duration) int {
	ms := d.Milliseconds()

	switch {
	case ms <= 5:
		return 0
	case ms <= 10:
		return 1
	case ms <= 25:
		return 2
	case ms <= 50:
		return 3
	case ms <= 100:
		return 4
	case ms <= 250:
		return 5
	case ms <= 500:
		return 6
	default:
		return 7
	}
}
