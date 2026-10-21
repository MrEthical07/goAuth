package flows

import (
	"context"
	"time"
)

// SessionProfileStatus is the outcome of resolving which session profile a
// new session gets.
type SessionProfileStatus int

const (
	// SessionProfileOK: a profile was chosen (or none is configured and the
	// name is empty).
	SessionProfileOK SessionProfileStatus = iota
	// SessionProfileUnknown: the requested profile does not exist.
	SessionProfileUnknown
	// SessionProfileConflict: the request names a profile in two
	// incompatible ways (remember-me together with an explicit profile, or
	// remember-me with no remember-me profile configured, or an MFA confirm
	// naming a different profile than its challenge).
	SessionProfileConflict
)

// SessionProfileResolver chooses the profile for a new session from the
// request context and the remember-me flag. It returns an empty name when no
// profiles are configured. The root package provides it only while profiles
// are configured; with a nil resolver every flow behaves exactly as before
// profiles existed.
type SessionProfileResolver func(ctx context.Context, rememberMe bool) (string, SessionProfileStatus)

// SessionProfileConfirmer decides the profile of a session issued after an
// MFA step: the profile stored with the challenge wins, and a different
// profile named by the confirming request is a conflict.
type SessionProfileConfirmer func(ctx context.Context, stored string, rememberMe bool) (string, SessionProfileStatus)

// SessionProfileLifetime returns the ExpiresAt and initial key TTL a session
// created at now under the named profile receives.
type SessionProfileLifetime func(profile string, now time.Time) (expiresAt int64, ttl time.Duration, err error)

type resolvedSessionProfileKey struct{}

// withResolvedSessionProfile records the profile chosen for the session being
// created on ctx, so the later steps of a login (challenge creation, token
// issuance, assurance) use the same one. An empty name leaves ctx untouched.
func withResolvedSessionProfile(ctx context.Context, name string) context.Context {
	if name == "" {
		return ctx
	}
	return context.WithValue(ctx, resolvedSessionProfileKey{}, name)
}

// ResolvedSessionProfile returns the profile a flow resolved for the session
// it is creating, or "" when none was (profiles unconfigured).
func ResolvedSessionProfile(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	name, _ := ctx.Value(resolvedSessionProfileKey{}).(string)
	return name
}

// sessionProfileFor returns the profile for the session about to be created:
// the one an earlier step of the same flow already resolved, otherwise a fresh
// resolution. Every session-creating path therefore applies a profile even if
// it did not resolve one up front. It returns "" and SessionProfileOK when
// profiles are not configured.
func sessionProfileFor(ctx context.Context, rememberMe bool, resolve SessionProfileResolver) (string, SessionProfileStatus) {
	if resolve == nil {
		return "", SessionProfileOK
	}
	if name := ResolvedSessionProfile(ctx); name != "" {
		return name, SessionProfileOK
	}
	return resolve(ctx, rememberMe)
}

// sessionPlan is the lifetime a new session is created with.
type sessionPlan struct {
	profile   string
	expiresAt int64
	ttl       time.Duration
}

// legacyPlan is the lifetime every session received before profiles: the
// engine's lifetime for the remember-me choice, from now.
func legacyPlan(now time.Time, lifetime time.Duration) sessionPlan {
	return sessionPlan{expiresAt: now.Add(lifetime).Unix(), ttl: lifetime}
}

// profilePlan is the lifetime of a session created under profile, computed by
// the session store from the profile's current policy.
func profilePlan(profile string, now time.Time, lifetime SessionProfileLifetime) (sessionPlan, error) {
	expiresAt, ttl, err := lifetime(profile, now)
	if err != nil {
		return sessionPlan{}, err
	}
	return sessionPlan{profile: profile, expiresAt: expiresAt, ttl: ttl}, nil
}

// profileMeta adds the session profile to audit metadata when the session has
// one, leaving the metadata of a legacy session exactly as it was.
func profileMeta(meta map[string]string, profile string) map[string]string {
	if profile == "" {
		return meta
	}
	if meta == nil {
		meta = make(map[string]string, 1)
	}
	meta["profile"] = profile
	return meta
}
