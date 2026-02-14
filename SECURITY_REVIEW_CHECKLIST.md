# goAuth v1 Security Review Checklist

Use this checklist for release gating and security regressions.

## 1. Build-Time Configuration Gates

- [ ] `Config.Validate()` passes only with intended deployment settings.
- [ ] ProductionMode enabled in production deployments.
- [ ] HS256 key length >= 32 bytes (if HS256 used).
- [ ] Access TTL and refresh TTL within production bounds.
- [ ] Argon2 parameters meet production minimums.
- [ ] Strict/JWT-only/hybrid mode is intentionally selected.
- [ ] Contradictory config combinations are rejected at startup.

## 2. Hot-Path Guarantees

- [ ] `Validate()` has no provider/database calls.
- [ ] JWT-only path has no Redis reads.
- [ ] Strict path fails closed on Redis unavailability.
- [ ] Permission checks remain bitmask-based and constant-time where applicable.

## 3. Refresh and Session Security

- [ ] Refresh tokens are opaque (not JWT refresh tokens).
- [ ] Refresh rotation occurs on every successful refresh.
- [ ] Refresh hash mismatch deletes session immediately.
- [ ] Session keys and user index keys are tenant-scoped.
- [ ] Absolute session lifetime cap is enforced.

## 4. MFA and Recovery Controls

- [ ] TOTP replay protection is enabled where required.
- [ ] MFA login challenge is one-time and expires absolutely.
- [ ] Backup codes are hashed at rest and never logged.
- [ ] Backup code hash is user-bound salted.
- [ ] Backup code consume path is atomic in provider implementation.
- [ ] Backup code rate limiting is enabled and tenant-scoped.

## 5. Password and Account Lifecycle

- [ ] Password hashing uses Argon2id PHC.
- [ ] Password verification uses constant-time comparison.
- [ ] Status transitions increment `AccountVersion`.
- [ ] Account status changes invalidate all sessions.
- [ ] Password reset and email verification challenges are one-time consumable.

## 6. Audit and Observability

- [ ] Audit enabled and sink configured for environment risk profile.
- [ ] `DropIfFull` behavior is intentional and monitored.
- [ ] `AuditDropped()` monitored/alerted.
- [ ] Audit records use stable error codes (no raw sensitive error leakage).
- [ ] Metrics exporters are adapter-only and do not touch hot path.

## 7. Boundary and Operational Assumptions

- [ ] Application supplies trusted tenant/IP/UA context values.
- [ ] Redis and DB are protected by network and access controls.
- [ ] Key management/rotation is defined operationally.
- [ ] Time synchronization (NTP) is healthy for token/TOTP validity.

## 8. Regression Test Gates

- [ ] `go test ./...` passes.
- [ ] `go test -race ./...` passes.
- [ ] Critical security tests exist for:
  - [ ] refresh reuse detection
  - [ ] strict fail-closed behavior
  - [ ] account status/version drift
  - [ ] MFA challenge replay
  - [ ] backup code one-time consume
  - [ ] config hardening validation

## 9. Provider Contract Audit (Required)

- [ ] `ConsumeBackupCode` is atomic and one-time.
- [ ] `UpdateAccountStatus` advances `AccountVersion`.
- [ ] TOTP secret storage is protected at rest.
- [ ] Tenant isolation policy is explicit and tested.
- [ ] Errors returned to engine do not include sensitive secret material.
