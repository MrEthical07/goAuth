# Benchmark Summary

Benchmarks were executed with:

- `go test -run '^$' -bench . -benchmem ./...`

## goAuth package highlights

- `BenchmarkMetricsInc`: 6.214 ns/op, 0 B/op, 0 allocs/op.
- `BenchmarkMetricsIncParallel`: 27.81 ns/op, 0 B/op, 0 allocs/op.
- `BenchmarkMetricsObserveLatencyParallel`: 25.35 ns/op, 0 B/op, 0 allocs/op.
- Mixed parallel increments ranged from 22.18 ns/op to 55.54 ns/op depending on padding and key selection strategy.

## Prometheus exporter

- `BenchmarkRender`: 5609 ns/op, 8224 B/op, 10 allocs/op.

## Interpretation

- Core in-process metrics paths are allocation-free and optimized for concurrent increments.
- Export rendering is intentionally more expensive because it materializes scrape output payloads.
- Results should be re-baselined per deployment CPU and Go version before setting SLO budgets.

## Suggested Perf Budgets

Use these as initial targets (adjust to your hardware and Redis topology):

- `ValidateJWTOnly`: p95 under 1ms, 0 allocs/op ideal in hot path.
- `ValidateStrict`: p95 under 5ms with Redis healthy.
- `Refresh`: p95 under 8ms including Redis round trip and rotation logic.
- `Login`: bounded primarily by password hash policy; tune Argon2 cost against latency budget.
