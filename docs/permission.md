# Module: Permission

## Purpose

The `permission` package provides fixed-size bitmask types, a permission registry, and role composition helpers used by goAuth authorization checks. Permissions are represented as bit positions in compile-time-frozen masks, enabling O(1) permission checks with zero allocations.

## Primitives

### Mask Types

| Type | Size | Fields |
|------|------|--------|
| `Mask64` | 64 bits (8 bytes) | Single `uint64` |
| `Mask128` | 128 bits (16 bytes) | `A, B uint64` |
| `Mask256` | 256 bits (32 bytes) | `A, B, C, D uint64` |
| `Mask512` | 512 bits (64 bytes) | `A, B, C, D, E, F, G, H uint64` |

All implement `PermissionMask` interface: `Has(bit int) bool`, `Set(bit int)`, `Raw() any`.

### Registry

| Primitive | Signature | Description |
|-----------|-----------|-------------|
| `NewRegistry` | `func NewRegistry(maxBits int, rootReserved bool) (*Registry, error)` | Create a permission registry |
| `Register` | `(name string) (int, error)` | Register a named permission, returns bit index |
| `Bit` | `(name string) (int, bool)` | Look up bit index by name |
| `Name` | `(bit int) (string, bool)` | Look up name by bit index |
| `Freeze` | `()` | Lock the registry (no more registrations) |
| `Count` | `() int` | Number of registered permissions |
| `RootBit` | `() (int, bool)` | Returns root bit index if `rootReserved=true` |

### RoleManager

| Primitive | Signature | Description |
|-----------|-----------|-------------|
| `NewRoleManager` | `func NewRoleManager(registry *Registry) *RoleManager` | Create a role manager |
| `RegisterRole` | `(roleName string, permNames []string, maxBits int, rootReserved bool) error` | Register a role with permissions |
| `GetMask` | `(roleName string) (interface{}, bool)` | Get the compiled mask for a role |
| `Freeze` | `()` | Lock the role manager |

### Codec

| Primitive | Signature | Description |
|-----------|-----------|-------------|
| `EncodeMask` | `func EncodeMask(mask interface{}) ([]byte, error)` | Serialize mask to bytes |
| `DecodeMask` | `func DecodeMask(data []byte) (interface{}, error)` | Deserialize bytes to mask |

## Strategies

| MaxBits | Use Case |
|---------|----------|
| 64 | Small apps with ≤63 permissions (1 reserved for root) |
| 128 | Medium apps with ≤127 permissions |
| 256 | Large apps with ≤255 permissions |
| 512 | Enterprise apps with ≤511 permissions |

Configure via `Config.Permission.MaxBits`.

## Examples

### Register permissions and roles

```go
engine, err := goAuth.New().
    WithPermissions([]string{"user.read", "user.write", "admin.panel"}).
    WithRoles(map[string][]string{
        "viewer": {"user.read"},
        "editor": {"user.read", "user.write"},
        "admin":  {"user.read", "user.write", "admin.panel"},
    }).
    // ... other config ...
    Build()
```

### Check permissions

```go
result, err := engine.Validate(ctx, token, goAuth.ModeStrict)
if engine.HasPermission(result.Mask, "admin.panel") {
    // authorized
}
```

### Direct codec usage

```go
mask := permission.Mask64(0xFF)
encoded, _ := permission.EncodeMask(&mask)
decoded, _ := permission.DecodeMask(encoded)
```

## Security Notes

- Registry is frozen at `Build()` time — no runtime mutation.
- Root bit (bit 0 when `rootReserved=true`) grants all permissions.
- Masks are embedded in JWT claims — changing permissions requires re-login.

## Performance Notes

- `Has(bit)` is a single bitwise AND — zero allocations.
- Masks are fixed-size: no heap allocation for permission checks.
- Binary codec avoids reflection.

## Edge Cases & Gotchas

- `maxBits` must be 64, 128, 256, or 512 — other values are rejected.
- Exceeding `maxBits` permission registrations causes `Build()` to fail.
- Permission names are case-sensitive.
- Role masks are computed once at build time and never change.
