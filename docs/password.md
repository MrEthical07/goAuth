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

## Performance Notes

- 64 MB / 3 iterations takes ~100ms on modern hardware.
- Memory cost dominates — tune `Memory` for your latency budget.
- Hash operations are CPU/memory-bound; consider throttling concurrent hashes.

## Edge Cases & Gotchas

- Passwords shorter than 10 bytes are rejected.
- Config validation runs at `NewArgon2` time — invalid params fail early.
- `NeedsUpgrade` returns true when stored hash uses different parameters than current config.
- Enable `Config.Password.UpgradeOnLogin` to automatically re-hash on successful login.
