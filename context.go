package goAuth

import "context"

type clientIPContextKey struct{}
type tenantIDContextKey struct{}
type userAgentContextKey struct{}

// WithClientIP describes the withclientip operation and its observable behavior.
//
// WithClientIP may return an error when input validation, dependency calls, or security checks fail.
// WithClientIP does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPContextKey{}, ip)
}

// WithTenantID describes the withtenantid operation and its observable behavior.
//
// WithTenantID may return an error when input validation, dependency calls, or security checks fail.
// WithTenantID does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantIDContextKey{}, tenantID)
}

// WithUserAgent describes the withuseragent operation and its observable behavior.
//
// WithUserAgent may return an error when input validation, dependency calls, or security checks fail.
// WithUserAgent does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
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
