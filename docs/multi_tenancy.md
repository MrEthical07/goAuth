# Module: Multi-Tenancy

## Purpose

goAuth partitions everything it stores by tenant: session keys, user and role
version counters, rate-limiter and lockout keys, password-reset and
email-verification records, and MFA/WebAuthn challenge records. Multi-tenancy
completes that partitioning at the one place it did not previously reach —
**user lookup**, the step that decides who you are.

The tenant is a goAuth concept, not a domain concept. It is an opaque string
the caller attaches to the request context; the engine never interprets it.

## The switch

`Config.MultiTenant.Enabled` is the single switch governing tenant
enforcement.

| `Enabled` | User lookup | Record binding | Provider requirement |
|-----------|-------------|----------------|----------------------|
| `false` (default) | Tenant-blind, across the whole user table | Resolved user's tenant | `UserProvider` only |
| `true` | Scoped to the request's tenant | Request's tenant | `UserProvider` + `TenantAwareUserProvider` |

With `Enabled` false, behavior is exactly what it was before tenant-scoped
lookup existed. Single-tenant deployments need no changes.

## Provider capability

When `Enabled` is true, the user provider must also implement
`TenantAwareUserProvider`:

```go
type TenantAwareUserProvider interface {
    GetUserByIdentifierInTenant(ctx context.Context, tenantID, identifier string) (UserRecord, error)
    GetUserByIDInTenant(ctx context.Context, tenantID, userID string) (UserRecord, error)
}
```

It is detected by type assertion at `Builder.Build()`, the same mechanism as
`WebAuthnCredentialProvider`. Enabling multi-tenancy without it fails the
build:

```
MultiTenant is enabled but the user provider does not implement TenantAwareUserProvider
```

This is deliberate. A silent fallback to the tenant-blind lookup in a
multi-tenant deployment would mean credentials from one tenant authenticating
under another, so it must be impossible to configure.

### Implementation contract

Implementations **must** constrain the query to `tenantID` and return a
not-found error when the record exists only in another tenant. Returning a
foreign-tenant record is an isolation failure.

- Do **not** treat an empty `tenantID` as "any tenant". The engine only calls
  these with the tenant resolved from the request context.
- Scope the query in the database, not in Go. A `WHERE tenant_id = $1` clause
  is the point of the interface.

```go
func (p *Provider) GetUserByIdentifierInTenant(
    ctx context.Context, tenantID, identifier string,
) (goAuth.UserRecord, error) {
    row := p.db.QueryRowContext(ctx,
        `SELECT id, identifier, tenant_id, password_hash, status, role
           FROM users WHERE tenant_id = $1 AND identifier = $2`,
        tenantID, identifier)
    // ...
}
```

The engine still applies an equality guard on the resolved record as
defence-in-depth, but that backstop is not a substitute for scoping the query.

## Attaching the tenant

Tenant scoping comes exclusively from the request context:

```go
ctx := goAuth.WithTenantID(r.Context(), tenantID)
access, refresh, err := engine.Login(ctx, identifier, password)
```

The engine is transport-agnostic and never reads HTTP headers. Extract the
tenant in your HTTP layer — from a header, a subdomain, a path segment, or a
session — validate it, and attach it with `WithTenantID`. See the note on
`MultiTenant.TenantHeader` under [Deprecated fields](#deprecated-fields).

## Enforced paths

With `Enabled` true, these resolve the user through the tenant-scoped lookup
and reject a tenant mismatch:

| Path | Behavior on mismatch |
|------|----------------------|
| Login | Generic invalid-credentials error, no token |
| MFA confirm | Challenge destroyed, generic MFA-invalid error |
| Password-reset request | Enumeration-safe response, no record written |
| Email-verification request | Enumeration-safe response, no record written |
| Change password, account status, backup codes, TOTP, WebAuthn ceremonies | User-not-found |
| `VerifyBackupCode`, `VerifyBackupCodeInTenant` (checked against the request tenant or the explicit `tenantID`; a miss also counts toward the backup-code limiter) | User-not-found |
| `ListWebAuthnCredentials`, `RemoveWebAuthnCredential` | User-not-found |
| `SwitchRole` (the session is read from the request tenant; a token minted in another tenant is session-not-found, never reaches the provider, and still consumes a switch-attempt slot under the request tenant. The account is resolved with the *session's* tenant and a foreign-tenant record is session-not-found) | Session-not-found |
| Refresh role re-check (only with `RoleSwitch.Enabled`: `CanAssumeRole` is called with the session's own tenant, never a caller-supplied one) | No provider call for a foreign-tenant token |

Refresh needs no explicit guard: the session is loaded from a key built with
the context tenant, so a token minted in one tenant misses in another and
fails closed.

### Tenant-aware password writes

`UserProvider.UpdatePasswordHash(userID, newHash)` addresses a user by ID
alone, so it can write a hash the lookup never resolved for this tenant. A
provider that implements the optional `TenantAwarePasswordUpdater` closes
that:

```go
type TenantAwarePasswordUpdater interface {
    UpdatePasswordHashInTenant(ctx context.Context, tenantID, userID, newHash string) error
}
```

When `MultiTenant.Enabled` is true **and** the provider implements it, the
engine calls it instead of `UpdatePasswordHash` in all three places a hash is
written, always with the tenant goAuth resolved itself:

| Writer | Tenant passed |
|--------|---------------|
| `ChangePassword` | the resolved user's tenant |
| Password-reset confirm | the tenant the reset record is bound to |
| Rehash-on-login | the login's resolved tenant |

Otherwise (multi-tenancy off, or the provider does not implement it) behavior
is exactly as before and error mapping is unchanged. The implementation must
constrain the write to `tenantID` and return an error when the user belongs to
another tenant.

### Reading the tenant back

`goAuth.TenantIDFromContext(ctx)` returns the tenant attached with
`WithTenantID` as `(tenant, true)`, or `("", false)` when none is attached. It
never synthesizes the internal default `"0"` (an explicitly attached `"0"` is
returned as `"0", true`), so a caller can tell "no tenant set" from "tenant
0". Attach the tenant once, in your HTTP layer; code downstream (including
your provider implementations) can read it back from the same context.

## Enumeration resistance

A cross-tenant identifier must be indistinguishable from one that does not
exist. The engine preserves this:

- **Login** returns the same generic invalid-credentials error as a wrong
  password and performs the same dummy password verification, so the timing
  posture is unchanged.
- **Password reset and email verification** take the existing
  enumeration-safe branch: same synthetic challenge, same `nil` error, same
  delay. No record is written.

The rejection is recorded in the **audit trail** with
`reason: "tenant_mismatch"` against the context tenant, so it stays visible
to defenders while remaining invisible to the caller.

> **Do not surface raw audit events to tenant users.** The audit stream
> deliberately distinguishes a cross-tenant attempt from an unknown
> identifier. Exposing it to end users would reintroduce the enumeration
> oracle the response shape is designed to remove.

## Record binding

When `Enabled` is true, password-reset and email-verification records are
always stored under the **request's** tenant. Binding them to the resolved
user's tenant instead is what allowed a request made in one tenant to write a
redeemable reset record into another tenant's keyspace.

When `Enabled` is false, records bind to the user's tenant exactly as before.
With no tenant boundary for goAuth to enforce, that placement is not a
security property, and preserving it keeps existing single-tenant deployments
byte-identical.

## Deprecated fields

These are retained for backwards compatibility and do nothing. Each emits a
lint warning when set; none affects behavior.

| Field | Status |
|-------|--------|
| `MultiTenant.EnforceIsolation` | **Deprecated, no-op.** Never gated anything. Tenant enforcement is governed entirely by `MultiTenant.Enabled`. Warns `tenant_enforce_isolation_noop`. |
| `MultiTenant.TenantHeader` | **Deprecated, no-op.** The engine and shipped middleware never read it. Extract the header in your HTTP layer and use `WithTenantID`. Warns `tenant_header_noop`. |
| `Account.AllowDuplicateIdentifierAcrossTenants` | **Provider-owned contract.** goAuth never queries across tenants, so it cannot enforce global identifier uniqueness — only your provider's schema can (a unique index on `identifier` versus on `(tenant_id, identifier)`). Warns `account_duplicate_identifier_provider_owned`. |

## Adopting multi-tenancy

1. Implement `TenantAwareUserProvider` on your existing provider, scoping
   both queries by `tenant_id`.
2. Ensure every `UserRecord` you return carries the correct `TenantID`.
3. Attach the tenant to every request context with `WithTenantID`.
4. Set `MultiTenant.Enabled = true`. The build now fails fast if step 1 was
   missed.
5. Optional: also implement `TenantAwarePasswordUpdater` so password-hash
   writes are tenant-scoped too (see above).
6. If you enable [role switching](role_switching.md), `RoleSwitchProvider`'s
   `CanAssumeRole` receives the session's tenant; scope it by that tenant.

Turning the switch on changes where reset and verification records are
stored, from the user's tenant to the request's. In-flight reset and
verification links issued before the switch may not resolve afterwards;
either drain them first or accept that users re-request. Everything else is
unchanged.

## Related

- [config.md](config.md) — full config reference
- [security-model.md](security-model.md) — threat model
- [audit.md](audit.md) — audit event shape and `TenantID`
- [session.md](session.md) — tenant-scoped session keys
- [role_switching.md](role_switching.md) — tenant-scoped role switching
