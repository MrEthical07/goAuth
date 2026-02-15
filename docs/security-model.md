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

## Token lifecycle

- Access tokens are short-lived JWTs.
- Refresh tokens are opaque `base64url(SID||SECRET)` values.
- Refresh flow rotates SECRET and invalidates session on reuse/mismatch.

## Rate limiting and account protection

- Login, TOTP, reset, and verification flows support request/failure limits.
- Account status controls can disable, lock, and invalidate sessions.
- Strict route checks fail closed when required backend verification is unavailable.
