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

## Architecture

The metrics system uses a fixed-size array of cache-line-padded atomic counters indexed by `MetricID`. Each counter occupies its own cache line to prevent false sharing. Exporters (Prometheus, OTel) call `Snapshot()` on scrape to build a point-in-time view.

```
Engine method → metrics.Inc(MetricID)
                  └─ atomic.AddUint64(&counters[id].value, 1)

Prometheus scrape → Snapshot()
                     └─ iterate counters[] → build map[MetricID]uint64
```

When `Enabled == false`, `New()` returns nil and all `Inc()`/`Observe()` calls on nil are no-ops.

## Security Considerations

- Metrics endpoints should be protected from public access (e.g., bind to internal interface or require auth).
- Counter values may reveal operational patterns (login volume, failure rates). Treat the metrics endpoint as sensitive.
- The `goauth_audit_dropped_total` metric signals potential audit data loss and should trigger alerts.

## Error Reference

The metrics system does not produce errors. All operations are infallible:

| Condition | Behavior |
|-----------|----------|
| `Enabled = false` | Nil receiver — all calls are no-ops |
| Invalid `MetricID` | Out-of-range IDs are silently ignored |
| `EnableLatency = false` | `Observe()` calls are silently ignored |

## Flow Ownership

| Flow | Entry Point | Internal Module |
|------|-------------|------------------|
| Counter Increment | `Metrics.Inc(id)` | `internal/metrics/metrics.go` |
| Latency Observation | `Metrics.Observe(id, d)` | `internal/metrics/metrics.go` |
| Snapshot | `Metrics.Snapshot()` | `internal/metrics/metrics.go` |
| Prometheus Export | `prometheus.NewPrometheusExporter` | `metrics/export/prometheus/` |
| OTel Export | `otel.NewOTelExporter` | `metrics/export/otel/` |

Metrics are incremented by every flow in `internal/flows/` at the end of each operation.

## Testing Evidence

| Category | File | Notes |
|----------|------|-------|
| Core Metrics | `metrics_test.go` | Inc, Observe, Snapshot, nil safety |
| Benchmarks | `metrics_bench_test.go` | Concurrent Inc, Snapshot allocation |
| Prometheus Exporter | `metrics/export/prometheus/exporter_test.go` | Output format, counter names |
| OTel Exporter | `metrics/export/otel/exporter_test.go` | Callback registration, gauge values |
| Config Lint | `config_lint_test.go` | Metrics-disabled warnings |

## Migration Notes

- **Enabling metrics**: Setting `Metrics.Enabled = true` activates counter tracking. There is no performance penalty when disabled (nil receiver).
- **Adding exporters**: Prometheus and OTel exporters are additive — enabling one does not affect the other.
- **Histogram buckets**: The 8 fixed latency buckets (≤5ms to +Inf) are not configurable. Custom bucketing requires a custom exporter.

## See Also

- [Flows](flows.md)
- [Configuration](config.md)
- [Audit](audit.md)
- [Performance](performance.md)
- [Engine](engine.md)
