# Concurrency Model

## Thread-safety guarantees

- Engine APIs are designed for multi-goroutine use after construction.
- Mutable counters/metrics are implemented with atomic operations.
- Redis-backed operations rely on datastore atomicity for cross-process coordination.

## Mutable vs immutable state

- Builder is mutable until `Build()` and should not be shared for concurrent mutation.
- Post-build Engine configuration and permission topology are treated as immutable.
- Session state and limiter counters are externalized into Redis and can change concurrently.

## Atomic usage

- Metrics counters and selected status paths use atomics to avoid lock contention in hot paths.

## Race validation

Run:

- `go test -race ./...`

No race detector findings are acceptable for production readiness.

## Known limitations

- Cross-instance ordering of audit/metrics events is eventually consistent and transport-dependent.
- Caller-owned dependencies (custom providers/sinks) must provide their own synchronization guarantees.
