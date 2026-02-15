package goAuth

import (
	"sync/atomic"
	"time"
)

// MetricID defines a public type used by goAuth APIs.
//
// MetricID instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type MetricID uint16

const (
	// MetricLoginSuccess is an exported constant or variable used by the authentication engine.
	MetricLoginSuccess MetricID = iota
	// MetricLoginFailure is an exported constant or variable used by the authentication engine.
	MetricLoginFailure
	// MetricLoginRateLimited is an exported constant or variable used by the authentication engine.
	MetricLoginRateLimited
	// MetricRefreshSuccess is an exported constant or variable used by the authentication engine.
	MetricRefreshSuccess
	// MetricRefreshFailure is an exported constant or variable used by the authentication engine.
	MetricRefreshFailure
	// MetricRefreshReuseDetected is an exported constant or variable used by the authentication engine.
	MetricRefreshReuseDetected
	// MetricReplayDetected is an exported constant or variable used by the authentication engine.
	MetricReplayDetected
	// MetricRefreshRateLimited is an exported constant or variable used by the authentication engine.
	MetricRefreshRateLimited
	// MetricDeviceIPMismatch is an exported constant or variable used by the authentication engine.
	MetricDeviceIPMismatch
	// MetricDeviceUAMismatch is an exported constant or variable used by the authentication engine.
	MetricDeviceUAMismatch
	// MetricDeviceRejected is an exported constant or variable used by the authentication engine.
	MetricDeviceRejected
	// MetricTOTPRequired is an exported constant or variable used by the authentication engine.
	MetricTOTPRequired
	// MetricTOTPFailure is an exported constant or variable used by the authentication engine.
	MetricTOTPFailure
	// MetricTOTPSuccess is an exported constant or variable used by the authentication engine.
	MetricTOTPSuccess
	// MetricMFALoginRequired is an exported constant or variable used by the authentication engine.
	MetricMFALoginRequired
	// MetricMFALoginSuccess is an exported constant or variable used by the authentication engine.
	MetricMFALoginSuccess
	// MetricMFALoginFailure is an exported constant or variable used by the authentication engine.
	MetricMFALoginFailure
	// MetricMFAReplayAttempt is an exported constant or variable used by the authentication engine.
	MetricMFAReplayAttempt
	// MetricBackupCodeUsed is an exported constant or variable used by the authentication engine.
	MetricBackupCodeUsed
	// MetricBackupCodeFailed is an exported constant or variable used by the authentication engine.
	MetricBackupCodeFailed
	// MetricBackupCodeRegenerated is an exported constant or variable used by the authentication engine.
	MetricBackupCodeRegenerated
	// MetricRateLimitHit is an exported constant or variable used by the authentication engine.
	MetricRateLimitHit
	// MetricSessionCreated is an exported constant or variable used by the authentication engine.
	MetricSessionCreated
	// MetricSessionInvalidated is an exported constant or variable used by the authentication engine.
	MetricSessionInvalidated
	// MetricLogout is an exported constant or variable used by the authentication engine.
	MetricLogout
	// MetricLogoutAll is an exported constant or variable used by the authentication engine.
	MetricLogoutAll
	// MetricAccountCreationSuccess is an exported constant or variable used by the authentication engine.
	MetricAccountCreationSuccess
	// MetricAccountCreationDuplicate is an exported constant or variable used by the authentication engine.
	MetricAccountCreationDuplicate
	// MetricAccountCreationRateLimited is an exported constant or variable used by the authentication engine.
	MetricAccountCreationRateLimited
	// MetricPasswordChangeSuccess is an exported constant or variable used by the authentication engine.
	MetricPasswordChangeSuccess
	// MetricPasswordChangeInvalidOld is an exported constant or variable used by the authentication engine.
	MetricPasswordChangeInvalidOld
	// MetricPasswordChangeReuseRejected is an exported constant or variable used by the authentication engine.
	MetricPasswordChangeReuseRejected
	// MetricPasswordResetRequest is an exported constant or variable used by the authentication engine.
	MetricPasswordResetRequest
	// MetricPasswordResetConfirmSuccess is an exported constant or variable used by the authentication engine.
	MetricPasswordResetConfirmSuccess
	// MetricPasswordResetConfirmFailure is an exported constant or variable used by the authentication engine.
	MetricPasswordResetConfirmFailure
	// MetricPasswordResetAttemptsExceeded is an exported constant or variable used by the authentication engine.
	MetricPasswordResetAttemptsExceeded
	// MetricEmailVerificationRequest is an exported constant or variable used by the authentication engine.
	MetricEmailVerificationRequest
	// MetricEmailVerificationSuccess is an exported constant or variable used by the authentication engine.
	MetricEmailVerificationSuccess
	// MetricEmailVerificationFailure is an exported constant or variable used by the authentication engine.
	MetricEmailVerificationFailure
	// MetricEmailVerificationAttemptsExceeded is an exported constant or variable used by the authentication engine.
	MetricEmailVerificationAttemptsExceeded
	// MetricAccountDisabled is an exported constant or variable used by the authentication engine.
	MetricAccountDisabled
	// MetricAccountLocked is an exported constant or variable used by the authentication engine.
	MetricAccountLocked
	// MetricAccountDeleted is an exported constant or variable used by the authentication engine.
	MetricAccountDeleted
	// MetricValidateLatency is an exported constant or variable used by the authentication engine.
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

// Metrics defines a public type used by goAuth APIs.
//
// Metrics instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type Metrics struct {
	enabled       bool
	enableLatency bool
	counters      [metricIDCount]paddedCounter
	histograms    [metricIDCount]metricHistogram
}

// MetricsSnapshot defines a public type used by goAuth APIs.
//
// MetricsSnapshot instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type MetricsSnapshot struct {
	Counters   map[MetricID]uint64
	Histograms map[MetricID][]uint64
}

// NewMetrics describes the newmetrics operation and its observable behavior.
//
// NewMetrics may return an error when input validation, dependency calls, or security checks fail.
// NewMetrics does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func NewMetrics(cfg MetricsConfig) *Metrics {
	return &Metrics{
		enabled:       cfg.Enabled,
		enableLatency: cfg.Enabled && cfg.EnableLatencyHistograms,
	}
}

// Enabled describes the enabled operation and its observable behavior.
//
// Enabled may return an error when input validation, dependency calls, or security checks fail.
// Enabled does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (m *Metrics) Enabled() bool {
	return m != nil && m.enabled
}

// LatencyEnabled describes the latencyenabled operation and its observable behavior.
//
// LatencyEnabled may return an error when input validation, dependency calls, or security checks fail.
// LatencyEnabled does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (m *Metrics) LatencyEnabled() bool {
	return m != nil && m.enableLatency
}

// Inc describes the inc operation and its observable behavior.
//
// Inc may return an error when input validation, dependency calls, or security checks fail.
// Inc does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (m *Metrics) Inc(id MetricID) {
	if m == nil || !m.enabled || id >= metricIDCount {
		return
	}
	atomic.AddUint64(&m.counters[id].value, 1)
}

// Observe describes the observe operation and its observable behavior.
//
// Observe may return an error when input validation, dependency calls, or security checks fail.
// Observe does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
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

// Value describes the value operation and its observable behavior.
//
// Value may return an error when input validation, dependency calls, or security checks fail.
// Value does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (m *Metrics) Value(id MetricID) uint64 {
	if m == nil || id >= metricIDCount {
		return 0
	}
	return atomic.LoadUint64(&m.counters[id].value)
}

// Snapshot describes the snapshot operation and its observable behavior.
//
// Snapshot may return an error when input validation, dependency calls, or security checks fail.
// Snapshot does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
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
