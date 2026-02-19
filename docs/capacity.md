# Capacity Planning (Redis Sessions)

This document provides practical sizing guidance for Redis when using goAuth session storage at high scale (100K-1M active sessions).

## Session Record Shape

A single session entry stores:

- `UserID` (string)
- `TenantID` (string)
- `Role` (string)
- `PermissionVersion` / `RoleVersion` / `AccountVersion`
- `Status`
- Permission bitmask bytes (`64/128/256/512` bits)
- `RefreshHash` (32 bytes)
- `IPHash` (32 bytes)
- `UserAgentHash` (32 bytes)
- `CreatedAt` / `ExpiresAt`

Keys involved per session:

- Session blob key: `as:{tenant}:{sid}`
- User index set entry: `au:{tenant}:{uid}` contains `sid`
- Tenant counter key: `ast:{tenant}:count` (shared counter)

## Estimated Size Per Session

Approximate payload (session value only) in typical deployments:

- Binary session blob: ~80-180 bytes (depends on string lengths + mask size)
- Redis key + metadata overhead: often 80-200+ bytes per key (allocator/encoding dependent)
- User set membership overhead: additional set encoding + element overhead

Practical planning range:

- **~300 to 700 bytes per active session** in Redis memory footprint.

For **1,000,000 active sessions**:

- Lower bound: ~300 MB
- Conservative real-world planning: **500 MB to 1.2 GB**
- Add headroom for replay/anomaly keys, rate-limit keys, and fragmentation.

## TTL and Churn Guidance

- Keep access token TTL short (minutes) and refresh/session TTL bounded (days).
- Sliding expiration increases write churn (`EXPIRE` updates) and can affect Redis CPU.
- Refresh rotation churn scales with refresh frequency; size `maxmemory` for peak + fragmentation headroom.

## Recommended Redis Settings (Baseline)

- Enable persistence mode consistent with your recovery RPO/RTO (`AOF` or `RDB`).
- Set `maxmemory` with explicit policy aligned to auth semantics (usually avoid evicting active sessions unpredictably).
- Monitor:
  - memory used / RSS
  - ops/sec
  - keyspace hits/misses
  - latency percentiles
  - eviction count (should be near zero for session keys)

## Validation Workflow

Use:

- `go test -run '^$' -bench 'Benchmark(Login|Refresh|Validate)' -benchmem ./...`
- `go run ./cmd/goauth-loadtest -sessions 1000000 -concurrency 512 -ops 1000000`

Re-baseline on your actual instance class and Redis topology before final capacity decisions.
