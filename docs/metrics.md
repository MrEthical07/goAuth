# Module: Metrics

## Purpose

Lock-free, cache-line-padded counters and latency histograms for every security-relevant operation. Designed for zero-allocation reads on validation hot paths.

## Primitives

### MetricID

44 `MetricID` constants covering every observable security event:

| Range | Category | Examples |
|-------|----------|----------|
| 0-2 | Login | `MetricLoginSuccess`, `MetricLoginFailure`, `MetricLoginRateLimited` |
| 3-7 | Refresh | `MetricRefreshSuccess`, `MetricRefreshReuseDetected`, `MetricReplayDetected` |
| 8-10 | Device | `MetricDeviceIPMismatch`, `MetricDeviceUAMismatch`, `MetricDeviceRejected` |
| 11-17 | MFA | `MetricTOTPRequired/Success/Failure`, `MetricMFALogin*`, `MetricMFAReplayAttempt` |
| 18-20 | Backup Codes | `MetricBackupCodeUsed/Failed/Regenerated` |
| 21 | Rate Limit | `MetricRateLimitHit` |
| 22-25 | Session | `MetricSessionCreated/Invalidated`, `MetricLogout/LogoutAll` |
| 26-28 | Account | `MetricAccountCreationSuccess/Duplicate/RateLimited` |
| 29-31 | Password | `MetricPasswordChangeSuccess/InvalidOld/ReuseRejected` |
| 32-35 | Password Reset | `MetricPasswordResetRequest/ConfirmSuccess/ConfirmFailure/AttemptsExceeded` |
| 36-39 | Email Verification | `MetricEmailVerification*` |
| 40-42 | Account Status | `MetricAccountDisabled/Locked/Deleted` |
| 43 | Latency | `MetricValidateLatency` |

### Core API

```go
func New(cfg Config) *Metrics
func (m *Metrics) Inc(id MetricID)
func (m *Metrics) Observe(id MetricID, d time.Duration)
func (m *Metrics) Value(id MetricID) uint64
func (m *Metrics) Snapshot() Snapshot
```

| Config Field | Type | Description |
|-------------|------|-------------|
| `Enabled` | `bool` | Master toggle |
| `EnableLatency` | `bool` | Enable histogram recording |

### Histogram

8 fixed buckets: ≤5 ms, ≤10 ms, ≤25 ms, ≤50 ms, ≤100 ms, ≤250 ms, ≤500 ms, +Inf.  
Only `MetricValidateLatency` supports `Observe()`.

### Snapshot

```go
type Snapshot struct {
    Counters   map[MetricID]uint64
    Histograms map[MetricID][]uint64
}
```

## Exporters

| Package | Constructor | Output |
|---------|-------------|--------|
| `metrics/export/prometheus` | `NewPrometheusExporter(engine)` | `http.Handler` serving `text/plain` Prometheus format |
| `metrics/export/otel` | `NewOTelExporter(meter, engine)` | OTel `Int64ObservableCounter` + `Int64ObservableGauge` per bucket |

Both exporters implement the same `metricsSource` interface:

```go
type metricsSource interface {
    MetricsSnapshot() goAuth.MetricsSnapshot
    AuditDropped() uint64
}
```

### Prometheus Names

All counters are prefixed `goauth_*_total`. Histogram: `goauth_validate_latency_seconds`. Extra: `goauth_audit_dropped_total`.

## Performance Notes

- Counters use `atomic.AddUint64` on cache-line-padded slots — no mutexes.
- `Snapshot()` is the only allocation path (builds maps).
- Exporters read snapshots on scrape — no locking on write path.
