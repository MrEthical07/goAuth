# Module: Device Binding

## Purpose

Detect and optionally reject requests whose IP or User-Agent has changed since session creation, implementing session-to-device affinity.

## Primitives

### DeviceBindingConfig

| Field | Type | Description |
|-------|------|-------------|
| `Enabled` | `bool` | Master toggle |
| `EnforceIPBinding` | `bool` | Hard-reject on IP hash mismatch |
| `DetectIPChange` | `bool` | Emit anomaly audit (soft) on IP change |
| `EnforceUserAgentBinding` | `bool` | Hard-reject on UA hash mismatch |
| `DetectUserAgentChange` | `bool` | Emit anomaly audit (soft) on UA change |

### Core Function

```go
func RunValidateDeviceBinding(ctx context.Context, sess DeviceBindingSession, deps DeviceBindingDeps) error
```

### DeviceBindingSession

```go
type DeviceBindingSession struct {
    SessionID     string
    UserID        string
    TenantID      string
    IPHash        [32]byte
    UserAgentHash [32]byte
}
```

### Hash Function

```go
func HashBindingValue(v string) [32]byte  // sha256.Sum256
```

## Strategies

### Detect Mode (soft)

- Compares current IP/UA hash against stored session hash.
- On mismatch: emits `EventDeviceAnomalyDetected` audit event with metadata (`ip_mismatch=1` or `ua_mismatch=1`).
- Deduplicated via `ShouldEmitDeviceAnomaly` — Redis fixed-window (1 per session+kind per window, default 1 min).
- Does **not** reject the request.

### Enforce Mode (hard)

- On mismatch: returns `ErrDeviceBindingRejected`, emits `EventDeviceBindingRejected` audit, increments `MetricDeviceRejected`.
- Missing stored hash + enforce = mismatch (strict by default).

### Comparison

All hash comparisons use `subtle.ConstantTimeCompare` to prevent timing side-channels.

## Metrics

| ID | Name |
|----|------|
| `MetricDeviceIPMismatch` | IP hash mismatch detected |
| `MetricDeviceUAMismatch` | UA hash mismatch detected |
| `MetricDeviceRejected` | Hard rejection |

## Security Notes

- Enabling device binding with `ModeJWTOnly` triggers a HIGH-severity config lint warning (`jwtonly_device_binding`) because JWT-only mode skips session store lookups where binding data lives.
- SHA-256 hashes are stored in the session binary encoding — no plaintext IPs are persisted.
- `ShouldEmitDeviceAnomaly` uses Redis `INCR` + `EXPIRE` to avoid audit floods.

## Edge Cases

- Missing both stored hashes → no mismatch (session predates device binding).
- `Enabled = false` → function is never called.

## Architecture

Device binding is integrated into the validate and refresh flows. It is not a standalone module — the check runs as a sub-step within `RunValidate` (strict mode) and `RunRefresh`.

```
RunValidate / RunRefresh
  └─ RunValidateDeviceBinding(ctx, sess, deps)
       ├─ HashBindingValue(clientIP) → compare stored IPHash
       ├─ HashBindingValue(userAgent) → compare stored UserAgentHash
       ├─ Detect mode: emit audit (deduplicated via ShouldEmitDeviceAnomaly)
       └─ Enforce mode: return ErrDeviceBindingRejected
```

Context values (`WithClientIP`, `WithUserAgent`) must be set in an outer middleware for binding checks to function.

## Error Reference

| Error | Condition |
|-------|----------|
| `ErrDeviceBindingRejected` | IP or UA hash mismatch in enforce mode |
| `ErrDeviceIPMismatch` | IP hash mismatch detected (detect mode — audit only, not an error) |
| `ErrDeviceUAMismatch` | UA hash mismatch detected (detect mode — audit only, not an error) |

## Flow Ownership

| Flow | Entry Point | Internal Module |
|------|-------------|------------------|
| Device Binding Check | `RunValidateDeviceBinding` | `internal/flows/device_binding.go` |
| Anomaly Dedup | `ShouldEmitDeviceAnomaly` | `internal/device.go` (Redis INCR + EXPIRE) |
| Hash Computation | `HashBindingValue` | `internal/device.go` |

Device binding is invoked by:
- `internal/flows/validate.go` → `RunValidate` (strict mode only)
- `internal/flows/refresh.go` → `RunRefresh`

## Testing Evidence

| Category | File | Notes |
|----------|------|-------|
| Device Binding | `engine_device_binding_test.go` | IP/UA detect, enforce, missing hashes |
| Config Lint | `config_lint_test.go` | `jwtonly_device_binding` warning |
| Security Invariants | `security_invariants_test.go` | Binding enforcement properties |
| Session Hardening | `engine_session_hardening_test.go` | Binding in strict validate |

## Migration Notes

- **Enabling device binding**: Set `DeviceBinding.Enabled = true`. Existing sessions without stored hashes will not trigger mismatches (zero-hash is treated as "unknown").
- **Detect vs Enforce**: Start with detect mode (`DetectIPChange = true`) to observe anomalies via audit before enabling enforcement (`EnforceIPBinding = true`).
- **JWT-Only incompatibility**: Device binding requires session data from Redis. Enabling binding with `ModeJWTOnly` triggers a config lint warning because JWT-Only mode skips session lookups.

## See Also

- [Flows](flows.md)
- [Configuration](config.md)
- [Session](session.md)
- [Security Model](security.md)
- [Engine](engine.md)
