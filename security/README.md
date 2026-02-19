# Security Scanner Workflow

This directory contains reproducible scanner tooling so CI can stay strict
without being noisy.

## What Runs

- `gosec` with explicit rule exclusions from `security/gosec.excludes`.
- `govulncheck` in JSON mode.
- Baseline enforcement via `security/cmd/scanner-baseline`.

CI command:

```bash
bash security/run_scanners.sh
```

## Baseline Files

- `security/baselines/gosec.allowlist`
- `security/baselines/govulncheck.allowlist`

The baseline checker behavior is:

- fail on any finding not present in baseline
- fail on any unknown stdlib CVE from `govulncheck`
- print stale baseline entries that can be removed

## Why These gosec Exclusions Exist

`security/gosec.excludes` currently excludes:

- `G101`: false positives on constant names like `invalid_credentials`
- `G115`: high-noise integer conversion warnings in bounded code paths
- `G117`: secret-pattern matches on exported API fields (`AccessToken`, etc.)

All excluded findings are tracked in `SECURITY_FINDINGS.md`.

## Updating Baselines

1. Run `bash security/run_scanners.sh`.
2. If the checker reports new findings, review and classify them in
   `SECURITY_FINDINGS.md` as `fixed`, `false positive`, or `accepted risk`.
3. For accepted findings, add the corresponding fingerprint to the right
   baseline file.
4. Rerun `bash security/run_scanners.sh` until it passes.

## Toolchain Requirement

If `govulncheck` reports stdlib vulnerabilities, upgrade to a patched Go
toolchain and rerun. The baseline checker intentionally fails closed for new
stdlib CVEs.
