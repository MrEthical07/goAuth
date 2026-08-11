# Security Model

## Threat model

goAuth assumes attackers may obtain stolen access tokens, replay refresh tokens, brute-force credentials, or send malformed authorization requests.

## Mitigated attacks

- JWT signature forgery via configured asymmetric/symmetric verification.
- Refresh replay through mandatory rotation and stored refresh-secret hash comparison.
- Credential stuffing pressure via login/TOTP/reset/verification rate limiters.
- Permission escalation by fixed registry-bit mapping and frozen role compilation.

## Not mitigated directly

- Client endpoint compromise (e.g., malware with valid session context).
- Upstream transport insecurity when TLS is not enforced externally.
- Business-logic authorization mistakes outside goAuth checks.

## Tenant isolation

Applies when `MultiTenant.Enabled` is true. With it false, goAuth is not the
tenant-isolation authority and enforces no tenant boundary.

- Every user lookup is scoped to the tenant on the request context, so
  credentials and user ids from one tenant do not resolve under another.
  `TenantAwareUserProvider` is required at build time; the tenant-blind
  fallback cannot be configured in a multi-tenant deployment.
- Sessions, version counters, rate-limiter and lockout keys, and reset,
  verification, MFA, and WebAuthn challenge records are all keyed by tenant.
  Password-reset and email-verification records bind to the **request's**
  tenant, so a request in one tenant cannot write a redeemable record into
  another.
- Cross-tenant attempts fail closed and are indistinguishable from unknown
  identifiers in response shape, error value, and timing. They are recorded in
  the audit trail as `reason: "tenant_mismatch"`; that stream must not be
  exposed to tenant users, as it distinguishes cases the response does not.

Tenant values themselves are opaque and trusted: goAuth never derives a tenant
from transport. Extracting and authorizing the tenant before attaching it with
`WithTenantID` is the caller's responsibility. See
[multi_tenancy.md](multi_tenancy.md).

## Token lifecycle

- Access tokens are short-lived JWTs.
- Refresh tokens are opaque `base64url(SID||SECRET)` values.
- Refresh flow rotates SECRET and invalidates session on reuse/mismatch.

## Rate limiting and account protection

- Login, TOTP, reset, and verification flows support request/failure limits.
- Account status controls can disable, lock, and invalidate sessions.
- Strict route checks fail closed when required backend verification is unavailable.
