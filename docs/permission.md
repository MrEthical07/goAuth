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

## Architecture

The permission system is a compile-time registry with no runtime mutation. At `Build()` time, permissions are registered as bit positions, roles are compiled into bitmasks, and both are frozen. The resulting masks are embedded into JWT claims and session data.

```
Builder.Build()
  ├─ Registry.Register(name) → assigns bit index
  ├─ Registry.Freeze() → locks registration
  ├─ RoleManager.RegisterRole(role, perms) → compiles mask
  ├─ RoleManager.Freeze() → locks role definitions
  └─ Masks embedded in JWT claims + session binary encoding
```

Permission checks at runtime are a single bitwise AND on fixed-size masks — no map lookups, no allocations.

## Error Reference

| Error | Condition |
|-------|----------|
| `ErrRegistryFrozen` | Attempt to register permissions after `Freeze()` |
| `ErrPermissionNotFound` | Permission name not in registry |
| `ErrMaxBitsExceeded` | Registered permissions exceed `maxBits` capacity |
| `ErrInvalidMaxBits` | `maxBits` not one of 64, 128, 256, 512 |
| `ErrRoleNotFound` | Role name not registered in role manager |

## Flow Ownership

| Flow | Entry Point | Internal Module |
|------|-------------|------------------|
| Permission Registration | `Builder.WithPermissions` | `permission.Registry.Register` |
| Role Compilation | `Builder.WithRoles` | `permission.RoleManager.RegisterRole` |
| Permission Check | `Engine.HasPermission` | `permission.Mask*.Has(bit)` |
| Mask Encoding | Session save / JWT issuance | `permission.EncodeMask` / `permission.DecodeMask` |

## Testing Evidence

| Category | File | Notes |
|----------|------|-------|
| Codec Fuzz | `permission/fuzz_codec_test.go` | Encode/decode round-trip with random masks |
| Security Invariants | `security_invariants_test.go` | Cross-module permission checks |
| Config Validation | `config_test.go` | MaxBits validation, role mapping |
| Integration | `test/public_api_test.go` | HasPermission in full engine context |

## Migration Notes

- **Adding permissions**: New permissions can be appended to the `WithPermissions` list. Existing bit assignments are stable as long as the order is preserved.
- **Changing `maxBits`**: Increasing `maxBits` (e.g., 64 → 128) changes the mask type. All active sessions and tokens become incompatible — force re-login.
- **Removing permissions**: Removing a permission from the list shifts bit assignments for subsequent permissions. This invalidates all existing masks. Prefer deprecating (not removing) permissions.

## See Also

- [Flows](flows.md)
- [Configuration](config.md)
- [Engine](engine.md)
- [Security Model](security.md)
- [JWT](jwt.md)
- [Middleware](middleware.md)
