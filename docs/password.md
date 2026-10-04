# Module: Password

## Purpose

The `password` package implements password hashing and verification with Argon2id defaults, following OWASP recommendations.

## Primitives

| Primitive | Signature | Description |
|-----------|-----------|-------------|
| `NewArgon2` | `func NewArgon2(cfg Config) (*Argon2, error)` | Create a validated hasher |
| `Hash` | `(password string) (string, error)` | Hash a password → PHC-format string |
| `Verify` | `(password, encodedHash string) (bool, error)` | Constant-time comparison |
| `NeedsUpgrade` | `(encodedHash string) (bool, error)` | Check if parameters are outdated |

### Config

```go
type Config struct {
    Memory      uint32  // min 8192 KB (8 MB), recommended ≥65536 (64 MB)
    Time        uint32  // min 1 iteration
    Parallelism uint8   // min 1 thread
    SaltLength  uint32  // min 16 bytes
    KeyLength   uint32  // min 16 bytes
}
```

### Output Format

PHC-encoded string: `$argon2id$v=19$m=65536,t=3,p=4$<salt_b64>$<hash_b64>`

## Strategies

| Strategy | Config | Use Case |
|----------|--------|----------|
| Default | Memory=64MB, Time=3, Parallelism=4 | Balanced security/performance |
| High Security | Memory=128MB, Time=4, Parallelism=4 | Maximum brute-force resistance |
| High Throughput | Memory=32MB, Time=2, Parallelism=2 | High-volume login services |

Controlled by `Config.Password.*` fields.

## Examples

```go
hasher, err := password.NewArgon2(password.Config{
    Memory:      64 * 1024,
    Time:        3,
    Parallelism: 4,
    SaltLength:  16,
    KeyLength:   32,
})

hash, err := hasher.Hash("correct horse battery staple")
ok, err := hasher.Verify("correct horse battery staple", hash)

if needs, _ := hasher.NeedsUpgrade(oldHash); needs {
    newHash, _ := hasher.Hash(password)
    // store newHash
}
```

## Security Notes

- Minimum password length enforced: 10 bytes.
- All comparisons use `crypto/subtle.ConstantTimeCompare`.
- Salt is generated from `crypto/rand` — never reused.
- `NeedsUpgrade` enables transparent hash migration on login.
- `Engine.ChangePassword`'s old-password check and `Engine.VerifyPassword`
  share a dedicated rate limiter (own Redis key namespace,
  `Security.MaxLoginAttempts` / `Security.LoginCooldownDuration`). Each
  attempt is *reserved atomically* (a single Redis `INCR`) before Argon2
  runs, rather than checked and recorded as two separate steps, so a burst
  of concurrent requests cannot run more verifications than the configured
  limit — a rate-limited caller, including one racing inside a burst, costs
  no verification CPU. It never triggers account auto-lockout — a caller
  holding only a stolen access token must not be able to lock the real
  owner out of login.

## Performance Notes

- 64 MB / 3 iterations takes ~100ms on modern hardware.
- Memory cost dominates — tune `Memory` for your latency budget.
- Hash operations are CPU/memory-bound; consider throttling concurrent hashes.

## Edge Cases & Gotchas

- Passwords shorter than 10 bytes are rejected.
- Config validation runs at `NewArgon2` time — invalid params fail early.
- `NeedsUpgrade` returns true when stored hash uses different parameters than current config.
- Enable `Config.Password.UpgradeOnLogin` to automatically re-hash on successful login.
- Hash writes (`ChangePassword`, password-reset confirm and rehash-on-login) call `UserProvider.UpdatePasswordHash`, or, when `MultiTenant.Enabled` and the provider implements the optional `TenantAwarePasswordUpdater`, `UpdatePasswordHashInTenant(ctx, tenantID, userID, newHash)` with the tenant goAuth resolved. See [multi_tenancy.md](multi_tenancy.md#tenant-aware-password-writes).

## Architecture

The password package is a self-contained hashing module with no Redis dependency. It is instantiated at `Build()` time and injected into the engine for use by login, password change, and password reset flows.

```
Builder.Build()
  └─ password.NewArgon2(cfg)
       ├─ Validate config (Memory, Time, Parallelism, Salt/Key lengths)
       └─ Return *Argon2 (stateless, safe for concurrent use)

Login flow:
  └─ Argon2.Verify(password, storedHash)
       ├─ Parse PHC string → extract params + salt + hash
       ├─ Re-derive hash with same params
       └─ subtle.ConstantTimeCompare
```

## Error Reference

| Error | Condition |
|-------|----------|
| `ErrPasswordPolicy` | Password too short (< 10 bytes) or too long |
| `ErrPasswordReuse` | New password matches current hash |
| `Config.Validate` / `password.NewArgon2` error (non-sentinel) | Invalid Argon2 configuration (memory, time, parallelism) |
| `ErrInvalidCredentials` | Password verification failed (returned by engine, not password package) |
| `ErrPasswordVerifyRateLimited` | Repeated `ChangePassword`/`VerifyPassword` failures for the user exceeded `Security.MaxLoginAttempts` within `Security.LoginCooldownDuration`; never triggers account auto-lockout |

## Flow Ownership

| Flow | Entry Point | Internal Module |
|------|-------------|------------------|
| Password Hashing | `Argon2.Hash` | `password/argon2.go` |
| Password Verification | `Argon2.Verify` | `password/argon2.go` (called by `internal/flows/login.go`) |
| Password Upgrade Check | `Argon2.NeedsUpgrade` | `password/argon2.go` (called during login) |
| Password Change | `Engine.ChangePassword` | `internal/flows/password.go` |
| Password Verify (step-up) | `Engine.VerifyPassword` | `engine.go` (shares `ChangePassword`'s rate limiter) |
| Password Reset Confirm | `Engine.ConfirmPasswordReset` | `internal/flows/password_reset.go` |

## Testing Evidence

| Category | File | Notes |
|----------|------|-------|
| Argon2 Hash/Verify | `password/argon2_test.go` | Hash, verify, config validation, NeedsUpgrade |
| Password Change | `engine_change_password_test.go` | Old password verify, reuse, policy |
| Password Verify + Rate Limiting | `engine_verify_password_test.go` | Step-up verify, rate limiting shared with `ChangePassword`, no auto-lockout, tenant isolation, concurrent-burst bound (`TestVerifyPasswordConcurrentBurstBoundedByMaxAttempts`) |
| Password Reset | `engine_password_reset_test.go` | Reset with new password hashing |
| Config Validation | `config_test.go` | Password config bounds |
| Security Invariants | `security_invariants_test.go` | Constant-time comparison |
| Benchmarks | `auth_bench_test.go` | Hash and verify latency |

## Migration Notes

- **Parameter upgrades**: Changing Argon2 parameters (Memory, Time, Parallelism) only affects new hashes. Existing hashes remain valid. Enable `UpgradeOnLogin` to transparently re-hash on next successful login.
- **PHC format**: The `$argon2id$v=19$...` format is self-describing. Old hashes with different parameters can always be verified — `NeedsUpgrade` detects the mismatch.
- **Minimum password length**: The 10-byte minimum is enforced at the engine level. Lowering it is not supported.

## See Also

- [Flows](flows.md)
- [Configuration](config.md)
- [Engine](engine.md)
- [Security Model](security.md)
- [Password Reset](password_reset.md)
