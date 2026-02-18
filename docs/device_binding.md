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
