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
