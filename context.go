package goAuth

import "context"

type clientIPContextKey struct{}
type tenantIDContextKey struct{}
type userAgentContextKey struct{}

// WithClientIP attaches the caller’s IP address to ctx. The Engine uses it
// for per-IP rate limiting, audit logging, and device binding checks.
//
//	Docs: docs/rate_limiting.md, docs/device_binding.md
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPContextKey{}, ip)
}

// WithTenantID attaches a tenant identifier to ctx for multi-tenant
// session isolation. When multi-tenancy is disabled, the default tenant
// "0" is used.
//
//	Docs: docs/session.md, docs/engine.md
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantIDContextKey{}, tenantID)
}

// WithUserAgent attaches the HTTP User-Agent string to ctx. Used by the
// device binding subsystem to detect session hijacking.
//
//	Docs: docs/device_binding.md
func WithUserAgent(ctx context.Context, userAgent string) context.Context {
	return context.WithValue(ctx, userAgentContextKey{}, userAgent)
}

func clientIPFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}

	ip, _ := ctx.Value(clientIPContextKey{}).(string)
	return ip
}

func userAgentFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}

	userAgent, _ := ctx.Value(userAgentContextKey{}).(string)
	return userAgent
}

func tenantIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return "0"
	}

	tenantID, _ := ctx.Value(tenantIDContextKey{}).(string)
	if tenantID == "" {
		return "0"
	}

	return tenantID
}

func tenantIDFromContextExplicit(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}

	tenantID, _ := ctx.Value(tenantIDContextKey{}).(string)
	if tenantID == "" {
		return "", false
	}

	return tenantID, true
}
