# Release Readiness Assessment

Date: 2026-04-06  
Branch: fix/dualratelimit  
Release Target: v0.3.0  
Status: Ready for release

---

## Summary

v0.3.0 is a breaking release that finalizes the new limiter architecture, canonical AuthError boundary normalization, and expanded guardrail coverage.

All release-critical tests pass on this branch, and migration guidance is now documented.

---

## Breaking Scope (v0.3.0)

1. Canonical public error model is now enforced at engine boundaries:
   - Exported Engine methods now return normalized AuthError-compatible failures.
   - Unknown internal errors collapse to ErrSystemInternal.
   - Availability/dependency failures collapse to ErrSystemUnavailable or domain-specific unavailable sentinels.
2. Refresh-throttle path removed:
   - Security.EnableRefreshThrottle, Security.MaxRefreshAttempts, Security.RefreshCooldownDuration removed.
   - ErrRefreshRateLimited and MetricRefreshRateLimited removed.
3. Config field migration required:
   - Security.EnableIPThrottle -> Security.EnableLoginFailureLimiter
   - PasswordReset and EmailVerification toggles split into request and confirm-failure limiter toggles.
   - Account creation limiter toggles consolidated under Account.EnableCreationLimiter.
4. Limiter keyspace moved to tenant-scoped rl:* prefixes.
5. Runtime limiter wrappers now apply fail-open behavior for limiter backend failures with audit+metrics signals.

---

## Verification Gates

### Full test suite

Command:

```bash
go test ./...
```

Result: PASS

Key package outcomes:

- ok github.com/MrEthical07/goAuth
- ok github.com/MrEthical07/goAuth/internal
- ok github.com/MrEthical07/goAuth/jwt
- ok github.com/MrEthical07/goAuth/metrics/export/otel
- ok github.com/MrEthical07/goAuth/metrics/export/prometheus
- ok github.com/MrEthical07/goAuth/password
- ok github.com/MrEthical07/goAuth/permission
- ok github.com/MrEthical07/goAuth/session
- ok github.com/MrEthical07/goAuth/test

### Boundary guardrails

The static and runtime boundary guardrails are present and passing in targeted runs:

```bash
go test ./... -run "TestEngineErrorBoundaryStatic|TestEngineErrorBoundaryRuntime"
```

Result: PASS

---

## Documentation Status

Release docs were updated for v0.3.0:

- CHANGELOG updated with v0.3.0 breaking release notes.
- docs/migrations updated with v0.3.0 migration mapping and rollout guidance.
- docs/error-model added and linked from core documentation.
- Existing docs for config, rate limiting, engine behavior, flows, security, and API reference were aligned with the new semantics.

---

## Release Checklist

- [x] Breaking changes documented in changelog
- [x] Migration guide updated for renamed/removed config fields
- [x] Public error-boundary contract documented and test-enforced
- [x] Full repository test suite passes
- [x] Release branch is ready for commit and tag v0.3.0
