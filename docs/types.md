# `types.go`

## 1) File Responsibility
This file belongs to package `goAuth` and implements part of the goAuth authentication stack. It exists to encapsulate the concerns represented by `types.go` and keep hot-path auth logic modular.

## 2) Exported API in This File
- `AccountStatus`: public API element defined in this file; see source doc comments for exact behavior, error conditions, and guarantees.
- `PermissionMask`: public API element defined in this file; see source doc comments for exact behavior, error conditions, and guarantees.
- `User`: public API element defined in this file; see source doc comments for exact behavior, error conditions, and guarantees.
- `AuthResult`: public API element defined in this file; see source doc comments for exact behavior, error conditions, and guarantees.
- `UserStore`: public API element defined in this file; see source doc comments for exact behavior, error conditions, and guarantees.
- `RoleStore`: public API element defined in this file; see source doc comments for exact behavior, error conditions, and guarantees.
- `KeyBuilder`: public API element defined in this file; see source doc comments for exact behavior, error conditions, and guarantees.
- `UserProvider`: public API element defined in this file; see source doc comments for exact behavior, error conditions, and guarantees.
- `UserRecord`: public API element defined in this file; see source doc comments for exact behavior, error conditions, and guarantees.
- `TOTPProvision`: public API element defined in this file; see source doc comments for exact behavior, error conditions, and guarantees.
- `TOTPSetup`: public API element defined in this file; see source doc comments for exact behavior, error conditions, and guarantees.
- `TOTPRecord`: public API element defined in this file; see source doc comments for exact behavior, error conditions, and guarantees.
- `LoginResult`: public API element defined in this file; see source doc comments for exact behavior, error conditions, and guarantees.
- `BackupCodeRecord`: public API element defined in this file; see source doc comments for exact behavior, error conditions, and guarantees.
- `CreateUserInput`: public API element defined in this file; see source doc comments for exact behavior, error conditions, and guarantees.
- `CreateAccountRequest`: public API element defined in this file; see source doc comments for exact behavior, error conditions, and guarantees.
- `CreateAccountResult`: public API element defined in this file; see source doc comments for exact behavior, error conditions, and guarantees.

## 3) Internal Interactions
- Depends on imports such as: standard package-local declarations.
- Is consumed by higher-level Engine flows through package-level integration.
- Typical flow: caller entrypoint → validation/normalization → security checks → storage/crypto operation → result mapping.

## 4) Concurrency Behavior
- Read-only helpers are goroutine-safe.
- Mutating operations are expected to run against receiver-managed synchronization or external datastore atomicity.
- Initialization-time configuration should be treated as immutable after Engine/Builder construction.

## 5) Performance Characteristics
- Designed to avoid database round-trips in request hot paths where possible.
- Uses fixed-width masks and bounded token/session structures to control allocations.
- Any Redis/network access is explicit in method behavior and should be budgeted by callers.

## 6) Security Implications
- Enforces fail-closed behavior for validation failures and malformed inputs.
- Security-sensitive comparisons and token handling rely on cryptographic primitives defined in source.
- Does not protect callers that bypass required verification sequencing.
