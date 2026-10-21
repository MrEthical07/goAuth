package goAuth

import "context"

type clientIPContextKey struct{}
type tenantIDContextKey struct{}
type userAgentContextKey struct{}
type sessionProfileContextKey struct{}

// WithClientIP attaches the caller’s IP address to ctx. The Engine uses it
// for audit metadata and device binding checks.
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

// TenantIDFromContext returns the tenant attached to ctx with [WithTenantID].
// The boolean is false, and the tenant empty, when none was attached or the
// attached value is empty. It never synthesizes the internal default tenant
// "0": that value is returned only when it was attached explicitly, so a
// caller can tell "no tenant set" apart from "tenant 0".
//
// Host code that needs the request's tenant (for example a provider
// implementation reached through the engine) can read it here instead of
// threading it through a second channel.
//
//	Docs: docs/multi_tenancy.md
func TenantIDFromContext(ctx context.Context) (string, bool) {
	return tenantIDFromContextExplicit(ctx)
}

// WithUserAgent attaches the HTTP User-Agent string to ctx. Used by the
// device binding subsystem to detect session hijacking.
//
//	Docs: docs/device_binding.md
func WithUserAgent(ctx context.Context, userAgent string) context.Context {
	return context.WithValue(ctx, userAgentContextKey{}, userAgent)
}

// WithSessionProfile selects the session profile (see Config.SessionProfiles.Profiles)
// for the sessions created under ctx. It applies to every path that creates a
// session: Login, LoginWithResult, LoginWithOptions, LoginWithTOTP,
// LoginWithBackupCode, ConfirmLoginMFA and CreateAccount with auto-login. With
// none attached the DefaultProfile applies, and with no profiles configured
// sessions are created exactly as before.
//
// Choose the profile from trusted server-side signals only (which client
// application or route is calling), never from request input such as a header
// or body field a client controls. A name that is not a configured profile
// fails with [ErrUnknownSessionProfile] before any password is verified. It
// cannot be combined with LoginOptions.RememberMe ([ErrSessionProfileConflict]),
// and an MFA confirm must not name a different profile than the login did.
//
//	Docs: docs/session.md
func WithSessionProfile(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, sessionProfileContextKey{}, name)
}

// SessionProfileFromContext returns the profile attached to ctx with
// [WithSessionProfile]. The boolean is false, and the name empty, when none
// was attached or the attached name is empty.
//
//	Docs: docs/session.md
func SessionProfileFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	name, _ := ctx.Value(sessionProfileContextKey{}).(string)
	if name == "" {
		return "", false
	}
	return name, true
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
