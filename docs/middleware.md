# Module: Middleware

## Purpose

The `middleware` package exposes HTTP middleware adapters for JWT-only, hybrid, and strict authorization enforcement modes built on top of `Engine.Validate()`.

## Primitives

| Primitive | Signature | Description |
|-----------|-----------|-------------|
| `Guard` | `func Guard(engine *Engine, routeMode RouteMode) func(http.Handler) http.Handler` | Generic middleware with configurable validation mode |
| `RequireJWTOnly` | `func RequireJWTOnly(engine *Engine) func(http.Handler) http.Handler` | Shorthand for `Guard(engine, ModeJWTOnly)` |
| `RequireStrict` | `func RequireStrict(engine *Engine) func(http.Handler) http.Handler` | Shorthand for `Guard(engine, ModeStrict)` |
| `AuthResultFromContext` | `func AuthResultFromContext(ctx context.Context) (*AuthResult, bool)` | Extract validated result from request context |

### Behavior

1. Extracts `Bearer <token>` from the `Authorization` header.
2. Calls `engine.Validate(ctx, token, routeMode)`.
3. On success: stores `*AuthResult` in context, calls next handler.
4. On failure: responds with `401 Unauthorized` (JSON body: `{"error": "..."}`).

## Strategies

| Mode | Middleware | Redis Required | Description |
|------|-----------|----------------|-------------|
| JWT-Only | `RequireJWTOnly` | No | Token-only validation, fastest |
| Hybrid | `Guard(engine, ModeHybrid)` | Optional | JWT + optional session check |
| Strict | `RequireStrict` | Yes | JWT + mandatory Redis session check |
| Per-route | `Guard(engine, mode)` | Varies | Different modes for different routes |

## Examples

### Basic setup

```go
mux := http.NewServeMux()

// Public routes (no auth)
mux.Handle("/health", healthHandler)

// JWT-only routes (fast, no Redis)
protected := middleware.RequireJWTOnly(engine)
mux.Handle("/api/profile", protected(profileHandler))

// Strict routes (session-backed)
strict := middleware.RequireStrict(engine)
mux.Handle("/api/admin", strict(adminHandler))
```

### Accessing auth result

```go
func myHandler(w http.ResponseWriter, r *http.Request) {
    result, ok := middleware.AuthResultFromContext(r.Context())
    if !ok {
        http.Error(w, "unauthorized", 401)
        return
    }
    fmt.Fprintf(w, "Hello, %s", result.UserID)
}
```

### Per-route mode

```go
// Strict for write operations, JWT-only for reads
mux.Handle("/api/data", middleware.RequireJWTOnly(engine)(readHandler))
mux.Handle("/api/data/write", middleware.Guard(engine, goAuth.ModeStrict)(writeHandler))
```

## Security Notes

- Always use `RequireStrict` for sensitive operations (account changes, payments).
- `RequireJWTOnly` cannot detect revoked sessions — use only for read-heavy, non-critical routes.
- The middleware does not enforce permissions — use `engine.HasPermission()` in your handler.

## Performance Notes

- JWT-only: ~microsecond overhead per request.
- Strict: adds one Redis GET per request (~0.5ms typical).
- No allocations in the hot path beyond the AuthResult struct.

## Edge Cases & Gotchas

- Missing or malformed `Authorization` header returns 401 immediately.
- `ModeInherit` (-1) uses the engine's global `ValidationMode`.
- Context must carry client IP and tenant ID for rate limiting / multi-tenancy — set via `goAuth.WithClientIP()` and `goAuth.WithTenantID()` in an outer middleware.

## Architecture

The middleware package is a thin HTTP adapter layer. It does not contain business logic — all authorization decisions are delegated to `Engine.Validate()`.

```
HTTP Request
  └─ Guard(engine, routeMode)
       ├─ Extract Bearer token from Authorization header
       ├─ engine.Validate(ctx, token, routeMode)
       ├─ On success: store *AuthResult in context, call next handler
       └─ On failure: respond 401 JSON
```

The middleware is stateless and safe for concurrent use across all HTTP handlers.

## Error Reference

| HTTP Status | Condition |
|-------------|----------|
| `401 Unauthorized` | Missing/malformed `Authorization` header |
| `401 Unauthorized` | Token expired, invalid signature, or revoked session |
| `401 Unauthorized` | Account disabled/locked/deleted (strict mode) |
| `401 Unauthorized` | Device binding rejection (strict mode) |

All 401 responses include a JSON body: `{"error": "<message>"}`. The error message is taken from the underlying `Engine.Validate()` error.

## Flow Ownership

| Flow | Entry Point | Internal Module |
|------|-------------|------------------|
| JWT-Only Validation | `RequireJWTOnly(engine)` | Delegates to `Engine.Validate` → `internal/flows/validate.go` |
| Strict Validation | `RequireStrict(engine)` | Delegates to `Engine.Validate` → `internal/flows/validate.go` |
| Hybrid Validation | `Guard(engine, ModeHybrid)` | Delegates to `Engine.Validate` → `internal/flows/validate.go` |
| Auth Result Extraction | `AuthResultFromContext(ctx)` | Context value lookup (no flow) |

## Testing Evidence

| Category | File | Notes |
|----------|------|-------|
| Validation Modes | `validation_mode_test.go` | JWT-Only, Hybrid, Strict through middleware |
| Security Invariants | `security_invariants_test.go` | Middleware auth enforcement |
| Integration | `test/public_api_test.go` | HTTP handler integration |
| Session Hardening | `engine_session_hardening_test.go` | Strict mode session checks |
| Benchmarks | `auth_bench_test.go` | Validate hot path latency |

## Migration Notes

- **Per-route modes**: Use `Guard(engine, mode)` instead of the global shorthands when different routes need different validation modes.
- **Context values**: Middleware expects `goAuth.WithClientIP()` and `goAuth.WithTenantID()` to be set in an outer middleware. If missing, rate limiting and multi-tenancy features are disabled for that request.
- **Error format**: The JSON error body format (`{"error": "..."}`) is fixed and not customizable. For custom error responses, wrap the middleware and intercept 401 responses.

## See Also

- [Flows](flows.md)
- [Configuration](config.md)
- [Engine](engine.md)
- [JWT](jwt.md)
- [Session](session.md)
- [Security Model](security.md)
- [Permission](permission.md)
