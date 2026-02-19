// Package metrics provides lock-free counters and latency histograms for goAuth
// observability.
//
// # Design
//
// Counters are stored in cache-line-padded uint64 slots and incremented
// atomically via [sync/atomic.AddUint64]. Histograms use 8 fixed buckets
// (≤5ms … +Inf). Both are allocation-free on the write path.
//
// # Architecture boundaries
//
// This package owns metric storage and snapshot creation. Metric export
// (Prometheus, OTel) lives in metrics/export/ and reads Snapshot values.
//
// # What this package must NOT do
//
//   - Perform I/O or network calls.
//   - Import goAuth or any sibling package.
//   - Expose global metric registries.
package metrics
