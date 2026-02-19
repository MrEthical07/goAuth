# Performance Guide

This document consolidates performance information for goAuth: benchmark methodology, budgets, Redis command costs, and tuning guidance.

For capacity planning, see [capacity.md](capacity.md). For operational settings, see [ops.md](ops.md).

---

## 1. Benchmark Methodology

### Running Benchmarks

**Miniredis (in-process, no network)**

```bash
go test -run '^$' -bench . -benchmem ./...
```

This uses miniredis, which inflates Lua script timings (see interpretation below) but provides deterministic, CI-friendly results.

**Real Redis (network-bound, production-representative)**

```bash
REDIS_ADDR=127.0.0.1:6379 go test -run '^$' -bench . -benchmem -tags=integration ./test/...
```

Set `REDIS_ADDR` to your Redis instance. This exercises real network latency and Redis server overhead.

### Key Benchmarks

| Benchmark | File | What it measures |
|-----------|------|-----------------|
| `BenchmarkValidateJWTOnly` | `auth_bench_test.go` | JWT parse + claims extraction (0 Redis) |
| `BenchmarkValidateStrict` | `auth_bench_test.go` | JWT parse + Redis session GET |
| `BenchmarkRefresh` | `auth_bench_test.go` | Refresh rotation (Lua CAS + JWT issue) |
| `BenchmarkMetricsInc` | `metrics_bench_test.go` | Single counter increment (serial) |
| `BenchmarkMetricsIncParallel` | `metrics_bench_test.go` | Counter increment (parallel, cache-line padded) |
| `BenchmarkMetricsObserveLatencyParallel` | `metrics_bench_test.go` | Histogram observation (parallel) |
| `BenchmarkRender` | `metrics/export/prometheus` | Prometheus text marshalling |

### Reproducing Benchmarks

```bash
# Correctness benchmarks (miniredis)
go test -run '^$' -bench 'Benchmark(Validate|Refresh)' -benchmem -count=5 .

# Real Redis benchmarks
REDIS_ADDR=localhost:6379 go test -run '^$' -bench 'Benchmark(Validate|Refresh)' \
  -benchmem -count=5 -tags=integration ./test/...

# Metrics benchmarks
go test -run '^$' -bench 'BenchmarkMetrics' -benchmem -count=5 .

# Full suite
go test -run '^$' -bench . -benchmem ./...
```

---

## 2. Interpreting Results

### Why Miniredis Inflates Lua Timings

Miniredis executes Lua scripts in a Go-based interpreter rather than Redis's embedded Lua VM. This means:

- `RotateRefreshHash` (Lua CAS) appears slower than it is in production.
- `session.Store.Delete` (Lua DEL+SREM+DECR) similarly inflated.

**Rule of thumb:** Divide miniredis Lua benchmark results by 2–3× for real Redis estimates.

### What Is Network-Bound

Operations that hit Redis are dominated by network RTT in production:

| Operation | CPU-bound portion | Network-bound portion |
|-----------|------------------|-----------------------|
| ValidateJWTOnly | 100% | 0% |
| ValidateStrict | JWT parse (~30%) | Redis GET (~70%) |
| Refresh | JWT issue (~20%) | Lua CAS (~80%) |
| Login | Argon2 hash (~90%) | Session save (~10%) |

### Sample Results (Reference Hardware)

| Benchmark | ns/op | B/op | allocs/op |
|-----------|-------|------|-----------|
| `BenchmarkMetricsInc` | ~6 | 0 | 0 |
| `BenchmarkMetricsIncParallel` | ~28 | 0 | 0 |
| `BenchmarkMetricsObserveLatencyParallel` | ~25 | 0 | 0 |
| `BenchmarkRender` (Prometheus) | ~5600 | ~8200 | 10 |

*Results vary by CPU, Go version, and Redis topology. Re-baseline on your hardware.*

---

## 3. Performance Budgets

| Flow | p95 Target | Allocs Target | Notes |
|------|-----------|---------------|-------|
| ValidateJWTOnly | < 1 ms | 0 beyond claims | Hot path; CPU-only |
| ValidateStrict | < 5 ms | 1 (session decode) | Includes 1 Redis GET |
| Refresh | < 8 ms | 2 (JWT + refresh encode) | Includes Lua CAS |
| Login | < 300 ms | Dominated by Argon2 | Tune `Password.Memory` |

### CI Regression Gate

```bash
bash security/run_perf_sanity.sh
```

This runs tracked benchmarks with `-count=5`, compares against baseline via `benchstat`, and fails on > +30% regression. See [perf-budgets.md](perf-budgets.md) for details.

---

## 4. Redis Command Budget Table

| Operation | Redis Commands | Script Type |
|-----------|---------------|-------------|
| **Login** (session save) | SET + SADD + INCR (pipeline) | Pipeline |
| **Login** (rate check) | GET + INCR + EXPIRE | Atomic keys |
| **ValidateJWTOnly** | 0 | — |
| **ValidateStrict** | 1 GET (+ 1 EXPIRE if sliding) | Simple |
| **Refresh** (rotate) | 1 EVALSHA (Lua CAS) | Lua script |
| **Refresh** (rate check) | 1 INCR | Atomic key |
| **Logout** (single) | 1 EVALSHA (DEL+SREM+DECR) | Lua script |
| **LogoutAll** | SMEMBERS + N×EXISTS + N×DEL + SREM + DECR | Pipeline + Tx |
| **PasswordReset** (request) | 1 SET | Simple |
| **PasswordReset** (confirm) | WATCH + GET + MULTI (optimistic) | Transaction |
| **EmailVerification** (confirm) | 1 EVALSHA (Lua CAS) | Lua script |
| **MFA challenge** (save) | 1 SET | Simple |
| **MFA challenge** (consume) | WATCH + GET + MULTI | Transaction |
| **Rate limit** (any) | 1 INCR + conditional EXPIRE | Atomic key |
| **Introspection** (count) | 1 SCARD | Simple |
| **Introspection** (list) | SMEMBERS + N×GET | Pipeline |
| **Introspection** (estimate) | 1 DBSIZE | Simple |
| **Health** | 1 PING | Simple |

---

## 5. Sizing Redis for 1M Sessions

See [capacity.md](capacity.md) for detailed byte-level analysis.

**Quick reference:**

| Scale | Memory Estimate | Redis Config |
|-------|----------------|-------------|
| 100K sessions | 30–50 MB | 256 MB `maxmemory` |
| 500K sessions | 150–250 MB | 512 MB `maxmemory` |
| 1M sessions | 300 MB–1.2 GB | 2 GB `maxmemory` |

Add 30–50% headroom for rate-limit keys, replay tracking, session indexes, and fragmentation.

**Key settings:**
- `maxmemory-policy`: **noeviction** (goAuth manages TTLs; eviction causes silent auth failures)
- Persistence: AOF or RDB based on your RPO/RTO
- Connection pool: 25–50 max connections

---

## 6. TTL Recommendations (Performance/Security Tradeoffs)

| Setting | Perf Optimized | Security Optimized | Default |
|---------|---------------|--------------------|---------|
| `JWT.AccessTTL` | 15 min | 2–3 min | 5 min |
| `JWT.RefreshTTL` | 30 days | 24 hours | 7 days |
| `Session.AbsoluteSessionLifetime` | 30 days | 24 hours | 7 days |
| `Session.SlidingExpiration` | enabled (fewer re-logins) | disabled (bounded lifetime) | enabled |

**Trade-off:** Longer TTLs reduce write churn and re-authentication frequency but increase the exposure window for compromised tokens. Sliding expiration adds 1 EXPIRE per strict-mode read.

---

## 7. When to Use JWT-Only vs Strict

| Criterion | JWT-Only | Strict |
|-----------|----------|--------|
| Latency budget | < 1 ms | < 5 ms |
| Instant revocation needed | No | Yes |
| Redis dependency acceptable | No | Yes |
| Use case | Dashboards, search, read-heavy APIs | Account changes, payments, admin panels |

**Recommendation:** Use `ModeHybrid` globally, then override per-route:

```go
// Fast reads
mux.Handle("/api/search", middleware.RequireJWTOnly(engine)(searchHandler))
// Sensitive writes
mux.Handle("/api/transfer", middleware.RequireStrict(engine)(transferHandler))
```

---

## 8. Bottleneck Analysis

| Bottleneck | Impact | Mitigation |
|------------|--------|-----------|
| Argon2 hashing | Login latency (~100 ms default) | Tune `Password.Memory`/`Time`; use `HighThroughputConfig()` |
| Redis network RTT | Strict validate + refresh | Use local Redis; connection pooling |
| Lua script first-call | +1 command on cold EVALSHA | Scripts warm on first use; negligible after |
| `ListActiveSessions` | O(n) in user sessions | Use `ActiveSessionEstimate` for dashboards |
| Prometheus render | ~5.6 µs per scrape | Acceptable for scrape intervals ≥ 10s |
| `DeleteAllForUser` | Non-atomic O(n) | Call twice for stronger guarantee |

---

## See Also

- [benchmarks.md](benchmarks.md) — Raw benchmark numbers
- [perf-budgets.md](perf-budgets.md) — CI regression gate details
- [capacity.md](capacity.md) — Redis memory sizing
- [ops.md](ops.md) — Deployment and monitoring
- [flows.md](flows.md) — Redis op budgets per flow
- [config.md](config.md) — Tuning configuration knobs
