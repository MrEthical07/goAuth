# Security Findings Register

This file tracks scanner findings and their disposition.

Status values:

- `fixed`: resolved in code or toolchain policy
- `false positive`: scanner signal is not a real vulnerability for this code
- `accepted risk`: intentional behavior with bounded impact and explicit guardrails

## Findings

| Finding | Source | Status | Mitigation |
| --- | --- | --- | --- |
| `G104` (unchecked `binary.Write` in mask codec) | gosec | fixed | `permission/mask_codec.go` now handles and propagates write errors for all mask widths. |
| `G404|cmd/goauth-loadtest/main.go|114` | gosec | accepted risk | `cmd/goauth-loadtest/main.go` uses `math/rand` only for load-distribution simulation, not for security tokens; allowlisted in `security/baselines/gosec.allowlist`. |
| `G404|cmd/goauth-loadtest/main.go|152` | gosec | accepted risk | Same mitigation and scope as above; non-production benchmarking path only. |
| `G505|internal/security/totp.go|6` | gosec | accepted risk | RFC 6238 interoperability requires SHA1 support; stronger SHA256/SHA512 options are supported via config. Finding is allowlisted in `security/baselines/gosec.allowlist`. |
| `G101` (constant-name credential pattern) | gosec | false positive | Excluded via `security/gosec.excludes`; tracked here and re-evaluated on scanner updates. |
| `G115` (integer conversion noise) | gosec | false positive | Excluded via `security/gosec.excludes`; bounded conversions are validated by code-level length/range checks and tests. |
| `G117` (secret-pattern field names) | gosec | false positive | Excluded via `security/gosec.excludes`; findings are naming-pattern matches on public API fields, not leaked secrets. |
| `GO-2025-4006` | govulncheck (stdlib) | fixed | CI fails closed on unknown stdlib CVEs and requires patched Go toolchain via `security/cmd/scanner-baseline` and `.github/workflows/go-race.yml`. |
| `GO-2026-4340` | govulncheck (stdlib) | fixed | CI fails closed on unknown stdlib CVEs and requires patched Go toolchain via `security/cmd/scanner-baseline` and `.github/workflows/go-race.yml`. |
| `GO-2026-4337` | govulncheck (stdlib) | fixed | Same mitigation as above (toolchain patch gate). |
| `GO-2025-4175` | govulncheck (stdlib) | fixed | Same mitigation as above (toolchain patch gate). |
| `GO-2025-4155` | govulncheck (stdlib) | fixed | Same mitigation as above (toolchain patch gate). |
| `GO-2025-4013` | govulncheck (stdlib) | fixed | Same mitigation as above (toolchain patch gate). |
| `GO-2025-4011` | govulncheck (stdlib) | fixed | Same mitigation as above (toolchain patch gate). |
| `GO-2025-4010` | govulncheck (stdlib) | fixed | Same mitigation as above (toolchain patch gate). |
| `GO-2025-4009` | govulncheck (stdlib) | fixed | Same mitigation as above (toolchain patch gate). |
| `GO-2025-4008` | govulncheck (stdlib) | fixed | Same mitigation as above (toolchain patch gate). |
| `GO-2025-4007` | govulncheck (stdlib) | fixed | Same mitigation as above (toolchain patch gate). |
| `GO-2025-4012` | govulncheck (stdlib) | fixed | Same mitigation as above (toolchain patch gate). |
| `GO-2025-4014` | govulncheck (stdlib) | fixed | Same mitigation as above (toolchain patch gate). |
| `GO-2025-4015` | govulncheck (stdlib) | fixed | Same mitigation as above (toolchain patch gate). |
| `GO-2026-4341` | govulncheck (stdlib) | fixed | Same mitigation as above (toolchain patch gate). |
| `GO-2026-4342` | govulncheck (stdlib) | fixed | Same mitigation as above (toolchain patch gate). |
