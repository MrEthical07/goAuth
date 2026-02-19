# API Reference

This index lists every exported symbol in the goAuth module, organised by package.
Test and benchmark functions are excluded.
For detailed behaviour, see the GoDoc comments in source or the linked module docs.

> **Tip:** In Go, run `go doc github.com/MrEthical07/goAuth/<pkg>` to browse any package locally.

---

## Package `goAuth` (root)

The root package contains the authentication engine, builder, configuration, types, context helpers, audit primitives, and in-process metrics.

**Module docs:** [engine.md](engine.md) · [config.md](config.md) · [audit.md](audit.md) · [metrics.md](metrics.md)

### Engine

| Symbol | Kind | Description |
|--------|------|-------------|
| `Engine` | type | Central authentication engine; thread-safe after construction. |
| `Close` | method | Shuts down the audit dispatcher and releases resources. |

### Builder

| Symbol | Kind | Description |
|--------|------|-------------|
| `Builder` | type | Fluent builder for constructing an `Engine` with validated configuration. |
| `New` | func | Creates a new `Builder` with `DefaultConfig()` and mandatory dependencies. |
| `WithConfig` | method | Overrides the default configuration. |
| `WithRedis` | method | Attaches a Redis client for session storage. |
| `WithPermissions` | method | Attaches a `permission.Registry` for bitmask RBAC. |
| `WithRoles` | method | Attaches a `permission.RoleManager` for named-role → bitmask lookup. |
| `WithUserProvider` | method | Attaches a `UserProvider` for user lookup and mutation. |
| `WithAuditSink` | method | Attaches an `AuditSink` for event dispatching. |
| `WithMetricsEnabled` | method | Enables in-process counter metrics. |
| `WithLatencyHistograms` | method | Enables latency histogram recording. |
| `Build` | method | Validates config and returns a ready `*Engine`. |

### Authentication

| Symbol | Kind | Description |
|--------|------|-------------|
| `Login` | method | Authenticates by identifier+password; returns access + refresh tokens. |
| `LoginWithTOTP` | method | Authenticates with password + TOTP code in a single call. |
| `LoginWithBackupCode` | method | Authenticates with password + backup code in a single call. |
| `LoginWithResult` | method | Authenticates and returns a `LoginResult` indicating MFA challenge status. |
| `ConfirmLoginMFA` | method | Completes a pending MFA challenge with a TOTP code. |
| `ConfirmLoginMFAWithType` | method | Completes a pending MFA challenge with a specified code type (TOTP or backup). |

### Token Lifecycle

| Symbol | Kind | Description |
|--------|------|-------------|
| `Refresh` | method | Rotates a refresh token, returning a new access + refresh pair. |
| `ValidateAccess` | method | Validates an access token (JWT-only, no Redis). |
| `Validate` | method | Validates an access token with session verification (may hit Redis). |
| `HasPermission` | method | Checks whether a token carries a specific permission bit. |

### Logout & Session Invalidation

| Symbol | Kind | Description |
|--------|------|-------------|
| `Logout` | method | Destroys a single session by refresh token. |
| `LogoutByAccessToken` | method | Destroys a session using the access token's session ID. |
| `LogoutAll` | method | Destroys all sessions for a user. |
| `LogoutInTenant` | method | Destroys a single session scoped to a tenant. |
| `LogoutAllInTenant` | method | Destroys all sessions for a user within a tenant. |
| `InvalidateUserSessions` | method | Destroys all sessions for a user (called internally on password/status changes). |

### Account Management

| Symbol | Kind | Description |
|--------|------|-------------|
| `CreateAccount` | method | Creates a user account with optional auto-login and role assignment. |
| `ChangePassword` | method | Changes a user's password after verifying the old password. |
| `DisableAccount` | method | Disables an account, preventing new logins. |
| `EnableAccount` | method | Re-enables a previously disabled account. |
| `LockAccount` | method | Locks an account (e.g. after brute-force detection). |
| `DeleteAccount` | method | Soft-deletes an account, invalidating all sessions. |

### TOTP (Time-based One-Time Password)

| Symbol | Kind | Description |
|--------|------|-------------|
| `GenerateTOTPSetup` | method | Generates a TOTP secret and provisioning URI for QR display. |
| `ProvisionTOTP` | method | Provisions TOTP for a user (stores unverified record). |
| `ConfirmTOTPSetup` | method | Confirms TOTP setup by verifying a code, then enables MFA. |
| `VerifyTOTP` | method | Verifies a TOTP code against a user's stored secret. |
| `DisableTOTP` | method | Disables TOTP for a user and invalidates sessions. |

### Backup Codes

| Symbol | Kind | Description |
|--------|------|-------------|
| `GenerateBackupCodes` | method | Generates a set of single-use backup codes (stores only hashes). |
| `RegenerateBackupCodes` | method | Replaces the existing backup code set with a fresh one. |
| `VerifyBackupCode` | method | Verifies and consumes a backup code. |
| `VerifyBackupCodeInTenant` | method | Verifies a backup code scoped to a specific tenant. |

### Password Reset

| Symbol | Kind | Description |
|--------|------|-------------|
| `RequestPasswordReset` | method | Initiates a password reset; returns a token/OTP/UUID depending on strategy. |
| `ConfirmPasswordReset` | method | Completes a password reset using the issued credential. |
| `ConfirmPasswordResetWithTOTP` | method | Completes a reset with additional TOTP verification. |
| `ConfirmPasswordResetWithBackupCode` | method | Completes a reset with a backup code as second factor. |
| `ConfirmPasswordResetWithMFA` | method | Completes a reset with a generic MFA code type. |

### Email Verification

| Symbol | Kind | Description |
|--------|------|-------------|
| `RequestEmailVerification` | method | Sends a verification credential (token/OTP/UUID) for the user's email. |
| `ConfirmEmailVerification` | method | Confirms email verification using the issued credential. |

### Introspection & Health

| Symbol | Kind | Description |
|--------|------|-------------|
| `GetActiveSessionCount` | method | Returns the number of active sessions for a user. |
| `ListActiveSessions` | method | Returns metadata for all active sessions of a user. |
| `GetSessionInfo` | method | Returns metadata for a single session by ID. |
| `ActiveSessionEstimate` | method | Returns a probabilistic estimate of total active sessions (HyperLogLog). |
| `Health` | method | Pings Redis and returns a `HealthStatus`. |
| `GetLoginAttempts` | method | Returns the current failed-login count for a user+IP key. |
| `MetricsSnapshot` | method | Returns a point-in-time copy of all in-process metrics. |
| `AuditDropped` | method | Returns the number of audit events dropped due to buffer overflow. |
| `SecurityReport` | method | Returns a `SecurityReport` reflecting the engine's security posture. |

### Configuration

| Symbol | Kind | Description |
|--------|------|-------------|
| `Config` | type | Top-level configuration struct for the engine. |
| `DefaultConfig` | func | Returns a production-safe default configuration. |
| `HighSecurityConfig` | func | Returns a hardened configuration preset. |
| `HighThroughputConfig` | func | Returns a performance-optimised preset with relaxed security. |
| `Validate` | method | Validates a `Config`, returning an error if any field is invalid. |
| `Lint` | method | Returns non-fatal warnings about suboptimal settings. |
| `JWTConfig` | type | JWT signing/verification settings. |
| `SessionConfig` | type | Session TTL and storage settings. |
| `PasswordConfig` | type | Argon2id parameter settings. |
| `SecurityConfig` | type | Rate-limit thresholds and lockout durations. |
| `SessionHardeningConfig` | type | Concurrent session limits and replay detection. |
| `DeviceBindingConfig` | type | IP/UA fingerprint binding mode (off / detect / enforce). |
| `TOTPConfig` | type | TOTP algorithm, digits, period, drift window. |
| `PasswordResetConfig` | type | Reset strategy, TTL, MFA requirement, OTP settings. |
| `EmailVerificationConfig` | type | Verification strategy, TTL, login-gate behaviour. |
| `AccountConfig` | type | Account creation rate-limits and default role. |
| `AuditConfig` | type | Audit buffer size, drop-on-full policy. |
| `MetricsConfig` | type | Counter/histogram enable flags. |
| `PermissionConfig` | type | Bitmask width selection (64/128/256/512). |
| `MultiTenantConfig` | type | Tenant isolation and session caps. |
| `ValidationMode` | type | Enum: `JWTOnly`, `Hybrid`, `Strict`. |
| `RouteMode` | type | Per-route validation override. |
| `ResetStrategyType` | type | Enum: `token`, `otp`, `uuid`. |
| `VerificationStrategyType` | type | Enum: `token`, `otp`, `uuid`. |
| `ResultConfig` | type | Controls what `CreateAccountResult` includes. |
| `DatabaseConfig` | type | Placeholder for future SQL backing store. |
| `CacheConfig` | type | Placeholder for future local cache layer. |

### Types

| Symbol | Kind | Description |
|--------|------|-------------|
| `AccountStatus` | type | Enum (active / disabled / locked / deleted). |
| `PermissionMask` | type | Interface for bitmask permission checking. |
| `User` | type | Minimal user identity (ID, roles, permissions). |
| `AuthResult` | type | Validated-token result: user ID, session ID, claims, permissions. |
| `UserStore` | type | Interface for user CRUD operations. |
| `RoleStore` | type | Interface for role → permission lookups. |
| `KeyBuilder` | type | Interface for generating Redis key prefixes. |
| `UserProvider` | type | Unified user-store adapter used by the engine. |
| `UserRecord` | type | Full user record including password hash and status. |
| `TOTPProvision` | type | Provisioning result: secret + URI. |
| `TOTPSetup` | type | Alias for `TOTPProvision`. |
| `TOTPRecord` | type | Stored TOTP state: secret, verified flag, counters. |
| `LoginResult` | type | Login outcome: tokens or MFA challenge ID. |
| `BackupCodeRecord` | type | Stored backup code: hash, used flag, timestamps. |
| `CreateUserInput` | type | Input struct for `CreateAccount`. |
| `CreateAccountRequest` | type | Public request struct for account creation. |
| `CreateAccountResult` | type | Result struct: user ID + optional tokens. |
| `SecurityReport` | type | Engine security posture report. |
| `PasswordConfigReport` | type | Argon2 parameter snapshot within `SecurityReport`. |
| `HealthStatus` | type | Redis health status returned by `Health()`. |
| `SessionInfo` | type | Session metadata returned by introspection. |

### Audit

| Symbol | Kind | Description |
|--------|------|-------------|
| `AuditEvent` | type | Structured audit event (action, user, IP, tenant, metadata). |
| `AuditSink` | type | Interface for receiving audit events. |
| `NoOpSink` | type | Sink that discards all events. |
| `ChannelSink` | type | Sink backed by a Go channel for testing/buffering. |
| `JSONWriterSink` | type | Sink that writes JSON-line events to an `io.Writer`. |
| `NewChannelSink` | func | Creates a `ChannelSink` with the given buffer size. |
| `NewJSONWriterSink` | func | Creates a `JSONWriterSink` writing to the given writer. |

### Metrics

| Symbol | Kind | Description |
|--------|------|-------------|
| `MetricID` | type | Enum identifying a specific counter or histogram. |
| `Metrics` | type | Thread-safe in-process metric store (counters + histograms). |
| `MetricsSnapshot` | type | Point-in-time copy of all metric values. |
| `NewMetrics` | func | Creates a `Metrics` instance with the given enable flags. |

### Context Helpers

| Symbol | Kind | Description |
|--------|------|-------------|
| `WithClientIP` | func | Attaches a client IP address to a `context.Context`. |
| `WithTenantID` | func | Attaches a tenant ID to a `context.Context`. |
| `WithUserAgent` | func | Attaches a User-Agent string to a `context.Context`. |

---

## Package `jwt`

JWT token creation and parsing.

**Module doc:** [jwt.md](jwt.md)

| Symbol | Kind | Description |
|--------|------|-------------|
| `SigningMethod` | type | Enum: `HS256`, `RS256`, `EdDSA`. |
| `Config` | type | Signing key, method, issuer, audience. |
| `Manager` | type | Stateless JWT issuer/verifier; safe for concurrent use. |
| `NewManager` | func | Creates a `Manager` from a `Config`. |
| `CreateAccess` | method | Signs a new access token with the given claims. |
| `ParseAccess` | method | Parses and validates an access token string. |
| `AccessClaims` | type | JWT claims struct embedded in access tokens. |

---

## Package `session`

Redis-backed session storage with binary encoding.

**Module doc:** [session.md](session.md)

| Symbol | Kind | Description |
|--------|------|-------------|
| `Store` | type | Redis-backed session store; all methods are concurrency-safe. |
| `NewStore` | func | Creates a `Store` connected to the given Redis client. |
| `Session` | type | In-memory session record (user, tenant, device hash, version, timestamps). |
| `Save` | method | Persists a session to Redis with the configured TTL. |
| `Get` | method | Fetches a session by ID, verifying the refresh hash atomically. |
| `GetReadOnly` | method | Fetches a session without refresh-hash verification. |
| `GetManyReadOnly` | method | Batch-fetches multiple sessions by ID. |
| `Delete` | method | Removes a single session from Redis. |
| `DeleteAllForUser` | method | Removes all sessions for a user (and optional tenant). |
| `RotateRefreshHash` | method | Atomically replaces the refresh hash on an existing session. |
| `ActiveSessionCount` | method | Returns the number of active sessions for a user. |
| `ActiveSessionIDs` | method | Returns all session IDs for a user. |
| `EstimateActiveSessions` | method | HyperLogLog-based estimate of total active sessions. |
| `SetTenantSessionCount` | method | Increments/decrements the per-tenant session gauge. |
| `TenantSessionCount` | method | Returns the current tenant session count. |
| `ShouldEmitDeviceAnomaly` | method | Rate-limits device-anomaly audit events. |
| `TrackReplayAnomaly` | method | Records a refresh-token replay for anomaly detection. |
| `Ping` | method | Checks Redis connectivity. |
| `Encode` | func | Serialises a `Session` to binary format. |
| `Decode` | func | Deserialises binary data into a `Session`. |
| `ErrRedisUnavailable` | var | Sentinel error for Redis connection failures. |
| `ErrRefreshHashMismatch` | var | Sentinel error for refresh token replay detection. |

---

## Package `permission`

Bitmask-based RBAC: registries, role managers, and fixed-width mask types.

**Module doc:** [permission.md](permission.md)

### Registry

| Symbol | Kind | Description |
|--------|------|-------------|
| `Registry` | type | Maps permission names to bit positions; freeze-once semantics. |
| `NewRegistry` | func | Creates an empty registry with the given bitmask width. |
| `Register` | method | Assigns the next available bit to a named permission. |
| `Bit` | method | Returns the bit position for a named permission. |
| `Name` | method | Returns the name for a bit position. |
| `RootBit` | method | Returns the superuser bit position. |
| `Count` | method | Returns the number of registered permissions. |
| `Freeze` | method | Locks the registry against further registration. |

### RoleManager

| Symbol | Kind | Description |
|--------|------|-------------|
| `RoleManager` | type | Maps named roles to aggregated permission bitmasks. |
| `NewRoleManager` | func | Creates a `RoleManager` backed by the given `Registry`. |
| `RegisterRole` | method | Defines a role with a list of permission names. |
| `GetMask` | method | Returns the bitmask for a named role. |
| `Count` | method | Returns the number of registered roles. |
| `Freeze` | method | Locks the role manager against further registration. |

### Mask Types

| Symbol | Kind | Description |
|--------|------|-------------|
| `Mask64` | type | 64-bit permission bitmask. |
| `Mask128` | type | 128-bit permission bitmask. |
| `Mask256` | type | 256-bit permission bitmask. |
| `Mask512` | type | 512-bit permission bitmask. |
| `Has` | method | Tests whether a specific bit is set. |
| `Set` | method | Sets a specific bit. |
| `Clear` | method | Clears a specific bit. |
| `Raw` | method | Returns the underlying integer(s) (Mask64 only; others use Has/Set/Clear). |

### Codec

| Symbol | Kind | Description |
|--------|------|-------------|
| `EncodeMask` | func | Serialises any mask to a width-prefixed byte slice. |
| `DecodeMask` | func | Deserialises a byte slice into the appropriate mask type. |

---

## Package `password`

Argon2id password hashing.

**Module doc:** [password.md](password.md)

| Symbol | Kind | Description |
|--------|------|-------------|
| `Config` | type | Argon2id parameters: time, memory, threads, key/salt lengths. |
| `Argon2` | type | Stateless hasher/verifier; safe for concurrent use. |
| `NewArgon2` | func | Creates an `Argon2` instance with the given config. |
| `Hash` | method | Hashes a plaintext password, returning a PHC-format string. |
| `Verify` | method | Verifies a plaintext password against a stored hash. |
| `NeedsUpgrade` | method | Reports whether a hash was produced with older parameters. |

---

## Package `middleware`

HTTP middleware for token validation.

**Module doc:** [middleware.md](middleware.md)

| Symbol | Kind | Description |
|--------|------|-------------|
| `Guard` | func | Returns middleware that validates via the engine's configured validation mode. |
| `RequireJWTOnly` | func | Returns middleware that validates using JWT-only (0 Redis calls). |
| `RequireStrict` | func | Returns middleware that validates with full session verification (1 Redis GET). |
| `AuthResultFromContext` | func | Extracts the `AuthResult` set by any guard middleware. |

---

## Package `metrics/export/prometheus`

Prometheus text-format exporter.

**Module doc:** [metrics.md](metrics.md)

| Symbol | Kind | Description |
|--------|------|-------------|
| `PrometheusExporter` | type | Renders engine metrics in Prometheus exposition format. |
| `NewPrometheusExporter` | func | Creates an exporter from an `*Engine`. |
| `NewPrometheusExporterFromSource` | func | Creates an exporter from any `MetricsSnapshot` + `AuditDropped` source. |
| `Render` | method | Returns the Prometheus text body as a byte slice. |
| `Handler` | method | Returns an `http.Handler` for `/metrics`. |

---

## Package `metrics/export/otel`

OpenTelemetry metric bridge.

**Module doc:** [metrics.md](metrics.md)

| Symbol | Kind | Description |
|--------|------|-------------|
| `OTelExporter` | type | Pushes engine metrics into an OTel `metric.Meter`. |
| `NewOTelExporter` | func | Creates an exporter from an `*Engine` and a `metric.Meter`. |
| `NewOTelExporterFromSource` | func | Creates an exporter from any snapshot source and meter. |
| `Close` | method | Stops the background collection goroutine. |

---

## Package `metrics/export/internaldefs`

Shared counter/histogram definitions used by exporters.

| Symbol | Kind | Description |
|--------|------|-------------|
| `CounterDef` | type | Metadata for a single counter (name, help text, metric ID). |
| `HistogramDef` | type | Metadata for a single histogram (name, help text, metric ID). |
| `CounterDefs` | var | Ordered slice of all counter definitions. |
| `HistogramDefs` | var | Ordered slice of all histogram definitions. |
| `HistogramBounds` | var | Default histogram bucket boundaries. |
| `HistogramBoundSuffix` | var | Prometheus-style boundary suffixes. |
| `CumulativeBuckets` | func | Converts differential histogram buckets to cumulative form. |
| `NormalizeBuckets` | func | Pads a bucket slice to match the expected length. |

---

## Internal Packages

These packages are not importable by external Go code but are documented here for contributor reference.

### Package `internal`

| Symbol | Kind | Description |
|--------|------|-------------|
| `SessionID` | type | 128-bit cryptographic session identifier. |
| `NewSessionID` | func | Generates a new random `SessionID`. |
| `ParseSessionID` | func | Parses a hex-encoded session ID string. |
| `String` | method | Returns the hex representation of a `SessionID`. |
| `Bytes` | method | Returns the raw 16-byte slice. |
| `NewRefreshSecret` | func | Generates a 32-byte cryptographic refresh secret. |
| `EncodeRefreshToken` | func | Base64url-encodes a refresh secret for transport. |
| `DecodeRefreshToken` | func | Decodes a base64url refresh token. |
| `HashRefreshSecret` | func | SHA-256 hashes a refresh secret for storage. |
| `NewResetSecret` | func | Generates a 32-byte password-reset secret. |
| `EncodeResetToken` | func | Base64url-encodes a reset secret. |
| `DecodeResetToken` | func | Decodes a base64url reset token. |
| `HashResetSecret` | func | SHA-256 hashes a reset secret. |
| `HashResetBytes` | func | SHA-256 hashes raw reset bytes. |
| `NewOTP` | func | Generates a numeric OTP of the configured length. |
| `HashBindingValue` | func | SHA-256 hashes a device-binding value (IP or UA). |

### Package `internal/rate`

| Symbol | Kind | Description |
|--------|------|-------------|
| `Config` | type | Rate-limiter configuration (max attempts, window, lockout). |
| `Limiter` | type | Redis-backed sliding-window rate limiter. |
| `New` | func | Creates a `Limiter` from a `Config` and Redis client. |
| `CheckLogin` | method | Returns whether a login attempt is allowed for the given key. |
| `IncrementLogin` | method | Records a failed login attempt. |
| `ResetLogin` | method | Clears the failure counter after a successful login. |
| `CheckRefresh` | method | Returns whether a refresh attempt is allowed. |
| `IncrementRefresh` | method | Records a failed refresh attempt. |
| `GetLoginAttempts` | method | Returns the current failure count for an identifier. |

---

*Auto-generated descriptions have been replaced with source-derived summaries.
For full signatures and behaviour details, see the GoDoc comments in source.*
