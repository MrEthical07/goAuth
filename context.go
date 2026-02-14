package goAuth

import "context"

type clientIPContextKey struct{}
type tenantIDContextKey struct{}
type userAgentContextKey struct{}

func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPContextKey{}, ip)
}

func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantIDContextKey{}, tenantID)
}

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
