# Module: Audit

## Purpose

Structured, async event dispatch for every security-relevant operation. All audit calls are non-blocking to avoid latency impact on hot paths.

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
| `JSONWriterSink` | `NewJSONWriterSink(w io.Writer)` | One JSON line per event; mutex-protected; nil-safe |

### Dispatcher

```go
func NewDispatcher(cfg Config, sink Sink) *Dispatcher
func (d *Dispatcher) Emit(ctx context.Context, event Event)
func (d *Dispatcher) Close()
func (d *Dispatcher) Dropped() uint64
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

1. `NewDispatcher` returns `nil` when `Enabled == false` — caller skips audit calls.
2. Spawns one drain goroutine on construction.
3. `Close()` signals stop, drains remaining events, waits via `sync.WaitGroup`. Idempotent (`sync.Once`).

## Security Notes

- Audit disabled triggers `WARN`-level config lint warning (`audit_disabled`).
- `Dropped()` is exported to the Prometheus exporter as `goauth_audit_dropped_total`.

## Performance Notes

- All `Emit()` calls are non-blocking under drop-if-full mode.
- Single goroutine drain avoids contention on the sink.
