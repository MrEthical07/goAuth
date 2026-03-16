# Module: Audit

## Purpose

Structured, async event dispatch for every security-relevant operation. Audit calls are non-blocking in drop-if-full mode and may block when `DropIfFull = false`.

## Primitives

### Event

```go
type Event struct {
    Timestamp time.Time         `json:"timestamp"`
    EventType string            `json:"event_type"`
    UserID    string            `json:"user_id,omitempty"`
    TenantID  string            `json:"tenant_id,omitempty"`
    SessionID string            `json:"session_id,omitempty"`
    IP        string            `json:"ip,omitempty"`
    Success   bool              `json:"success"`
    Error     string            `json:"error,omitempty"`
    Metadata  map[string]string `json:"metadata,omitempty"`
}
```

### Sink Interface

```go
type Sink interface {
    Emit(ctx context.Context, event Event)
}
```

### Sink Implementations

| Sink | Constructor | Behaviour |
|------|-------------|-----------|
| `NoOpSink` | Zero value | Drops all events |
| `ChannelSink` | `NewChannelSink(buffer int)` | Writes into `chan Event`; expose `Events() <-chan Event` |
| `JSONWriterSink` | `NewJSONWriterSink(w io.Writer)` | One JSON line per event; mutex-protected; nil-safe; exposes `ErrorCount()` |
| `SlogAuditSink` | `NewSlogAuditSink(logger *slog.Logger)` | Emits structured events through `slog` handlers |

### Dispatcher

```go
func NewDispatcher(cfg Config, sink Sink) *Dispatcher
func (d *Dispatcher) Emit(ctx context.Context, event Event)
func (d *Dispatcher) Close()
func (d *Dispatcher) Dropped() uint64
func (d *Dispatcher) SinkErrors() uint64
```

| Config Field | Type | Description |
|-------------|------|-------------|
| `Enabled` | `bool` | Master toggle |
| `BufferSize` | `int` | Channel capacity |
| `DropIfFull` | `bool` | Non-blocking send if true |

## Strategies

- **Drop-if-full** (`DropIfFull = true`): Non-blocking. Increments atomic `dropped` counter on overflow. Preferred for latency-sensitive deployments.
- **Block-if-full** (`DropIfFull = false`): Blocks until space or context cancellation. Guarantees delivery but may add tail latency.

## Lifecycle

1. `NewDispatcher` returns `nil` when `Enabled == false`; caller skips audit calls.
2. Spawns one drain goroutine on construction.
3. `Close()` signals stop, drains remaining events, waits via `sync.WaitGroup`. Idempotent (`sync.Once`).

## Security Notes

- Audit disabled triggers `WARN`-level config lint warning (`audit_disabled`).
- `Build()` fails when `Audit.Enabled = true` but no sink is configured.
- `Dropped()` is exported to metrics as `goauth_audit_dropped_total`.
- `SinkErrors()` is exported to metrics as `goauth_audit_sink_errors_total` when the sink reports write errors.

## Performance Notes

- `Emit()` calls are non-blocking only under drop-if-full mode.
- Single goroutine drain avoids contention on the sink.

## Architecture

The audit subsystem uses a single-goroutine drain pattern. `Emit()` writes to a buffered channel; the drain goroutine reads events and forwards them to the configured `Sink`. This decouples security event recording from the hot path.

```text
Engine method
  -> dispatcher.Emit(event)
       -> chan Event (buffered)
            -> drain goroutine -> Sink.Emit(event)
```

The dispatcher is created at `Build()` time and stopped by `Engine.Close()`. When `Enabled == false`, the dispatcher is nil and all audit calls are no-ops.

## Error Reference

| Error / Condition | Description |
|-------------------|-------------|
| Dropped events | Channel full under `DropIfFull=true`; counter incremented via `atomic.AddUint64` |
| Blocked caller | Channel full under `DropIfFull=false`; caller blocks until space or context cancellation |
| Sink write failure | Sink-specific encoding / write error; observable via `SinkErrors()` / `goauth_audit_sink_errors_total` |
| Nil dispatcher | `Enabled=false`; no error, all calls are silently skipped |

The audit system does not return errors to callers. Issues are observable via `Dropped()` / `SinkErrors()` and the `goauth_audit_dropped_total` / `goauth_audit_sink_errors_total` metrics.

## Flow Ownership

| Flow | Entry Point | Internal Module |
|------|-------------|-----------------|
| Event Dispatch | `Dispatcher.Emit` | `internal/audit/dispatcher.go` |
| Drain Loop | `Dispatcher` goroutine | `internal/audit/dispatcher.go` |
| Graceful Shutdown | `Dispatcher.Close` | `internal/audit/dispatcher.go` |
| Channel Sink | `NewChannelSink` | `internal/audit/audit.go` |
| JSON Writer Sink | `NewJSONWriterSink` | `internal/audit/audit.go` |
| Slog Sink | `NewSlogAuditSink` | `internal/audit/audit.go` |

Audit events are emitted by every flow in `internal/flows/` (login, refresh, logout, password change/reset, email verification, MFA, account status, device binding, backup codes).

## Testing Evidence

| Category | File | Notes |
|----------|------|-------|
| Audit Dispatch | `audit_test.go` | Emit, drain, close, drop-if-full, sink error counting, slog sink |
| Config Lint | `config_lint_test.go` | Audit-disabled warning |
| Metrics Export | `metrics/export/prometheus/exporter_test.go` | `goauth_audit_dropped_total`, `goauth_audit_sink_errors_total` |
| Flow Coverage | `engine_backup_codes_test.go` | Backup-code audit failures and success |

## Migration Notes

- **Enabling audit**: Setting `Audit.Enabled = true` starts the drain goroutine. A sink must be configured via `WithAuditSink()` or `Build()` fails.
- **Buffer sizing**: `BufferSize` controls channel capacity. Under-sizing causes drops (if `DropIfFull`) or backpressure (if not). Monitor `Dropped()` after deployment.
- **Custom sinks**: Implement the `Sink` interface for custom integrations (for example Kafka or a database sink). The sink must be safe for concurrent use by the drain goroutine.
- **Log backends**: `NewSlogAuditSink(...)` is the easiest way to forward audit events into backends already wired through `slog`.

## See Also

- [Flows](flows.md)
- [Configuration](config.md)
- [Metrics](metrics.md)
- [Security Model](security.md)
- [Engine](engine.md)
