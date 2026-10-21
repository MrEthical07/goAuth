package goAuth

import (
	"context"
	"errors"
	"time"

	internalflows "github.com/MrEthical07/goAuth/internal/flows"
	"github.com/MrEthical07/goAuth/session"
)

const auditEventSessionInvalid = "session_invalid"

// session_invalid metadata.reason values.
const (
	sessionInvalidReasonExpired        = "expired"
	sessionInvalidReasonProfileUnknown = "profile_unknown"
)

// sessionProfilesEnabled reports whether session profiles are configured.
// Every profile code path is gated on it, so an engine without profiles runs
// exactly the code it ran before profiles existed.
func (e *Engine) sessionProfilesEnabled() bool {
	return e != nil && len(e.config.Session.Profiles) > 0
}

// sessionProfilePolicies converts the configured profiles into the session
// store's form. It returns nil when there are none.
func sessionProfilePolicies(profiles map[string]SessionProfile) map[string]session.ProfilePolicy {
	if len(profiles) == 0 {
		return nil
	}
	out := make(map[string]session.ProfilePolicy, len(profiles))
	for name, p := range profiles {
		out[name] = session.ProfilePolicy{
			IdleTimeout:      p.IdleTimeout,
			AbsoluteLifetime: p.AbsoluteLifetime,
			RenewOnUse:       p.RenewOnUse,
		}
	}
	return out
}

// resolveSessionProfile chooses the profile of a session about to be created.
//
// An explicit profile on the context wins, but cannot be combined with
// RememberMe. RememberMe alone selects Session.RememberMeProfile, and is
// refused when none is configured. With neither, the DefaultProfile applies.
// The choice is made from trusted server-side input only: the context value is
// set by the caller's own code, never read from a request.
func (e *Engine) resolveSessionProfile(ctx context.Context, rememberMe bool) (string, internalflows.SessionProfileStatus) {
	cfg := e.config.Session
	name, explicit := SessionProfileFromContext(ctx)

	// With no profiles configured there is nothing to choose: a session is
	// created exactly as before, unless the caller named a profile, which
	// cannot exist.
	if !e.sessionProfilesEnabled() {
		if explicit {
			return "", internalflows.SessionProfileUnknown
		}
		return "", internalflows.SessionProfileOK
	}

	if explicit {
		if _, ok := cfg.Profiles[name]; !ok {
			return "", internalflows.SessionProfileUnknown
		}
		if rememberMe {
			return "", internalflows.SessionProfileConflict
		}
		return name, internalflows.SessionProfileOK
	}
	if rememberMe {
		if cfg.RememberMeProfile == "" {
			return "", internalflows.SessionProfileConflict
		}
		return cfg.RememberMeProfile, internalflows.SessionProfileOK
	}
	return cfg.DefaultProfile, internalflows.SessionProfileOK
}

// confirmSessionProfile decides the profile of a session issued after an MFA
// step. The profile stored with the challenge wins; a confirm that names a
// different one conflicts. A challenge from before profiles were configured
// (no stored profile) is resolved like a fresh login.
func (e *Engine) confirmSessionProfile(ctx context.Context, stored string, rememberMe bool) (string, internalflows.SessionProfileStatus) {
	if stored == "" {
		return e.resolveSessionProfile(ctx, rememberMe)
	}
	if !e.sessionProfilesEnabled() {
		return "", internalflows.SessionProfileUnknown
	}
	if _, ok := e.config.Session.Profiles[stored]; !ok {
		return "", internalflows.SessionProfileUnknown
	}
	if named, explicit := SessionProfileFromContext(ctx); explicit && named != stored {
		return "", internalflows.SessionProfileConflict
	}
	return stored, internalflows.SessionProfileOK
}

// sessionProfileLifetime returns the ExpiresAt and key TTL for a new session
// under the named profile, as computed by the session store.
func (e *Engine) sessionProfileLifetime(profile string, now time.Time) (int64, time.Duration, error) {
	if e.sessionStore == nil {
		return 0, 0, ErrEngineNotReady
	}
	return e.sessionStore.NewSessionLifetime(profile, now)
}

// sessionProfileAccessTTL is the access-token lifetime of a profile; zero
// means the global JWT.AccessTTL applies.
func (e *Engine) sessionProfileAccessTTL(profile string) time.Duration {
	if profile == "" {
		return 0
	}
	return e.config.Session.Profiles[profile].AccessTTL
}

// sessionProfileAssuranceTTL is how long a login's MFA assurance record may
// live under the profile: as long as the session can (its ceiling), or one
// idle window when the profile has none. A missing assurance only means a
// later step-up asks for the factor again.
func (e *Engine) sessionProfileAssuranceTTL(profile string) time.Duration {
	p := e.config.Session.Profiles[profile]
	if p.AbsoluteLifetime > 0 {
		return p.AbsoluteLifetime
	}
	return p.IdleTimeout
}

// configureLoginProfileDeps wires profile resolution into the login flow.
// Without configured profiles the resolvers are inert: they choose no profile
// (and refuse only a caller-named one, which cannot exist), so a login runs
// and stores exactly what it did before profiles.
func (e *Engine) configureLoginProfileDeps(deps *internalflows.LoginDeps) {
	deps.Errors.UnknownSessionProfile = ErrUnknownSessionProfile
	deps.Errors.SessionProfileConflict = ErrSessionProfileConflict
	if e == nil {
		return
	}
	deps.ResolveSessionProfile = e.resolveSessionProfile
	deps.ConfirmSessionProfile = e.confirmSessionProfile
	deps.SessionProfileLifetime = e.sessionProfileLifetime
}

// configureAccountProfileDeps wires profile resolution into account creation
// with auto-login and the account session issuer.
func (e *Engine) configureAccountProfileDeps(flow *internalflows.AccountDeps, sess *internalflows.AccountSessionDeps) {
	flow.Errors.UnknownSessionProfile = ErrUnknownSessionProfile
	flow.Errors.SessionProfileConflict = ErrSessionProfileConflict
	sess.ErrUnknownSessionProfile = ErrUnknownSessionProfile
	sess.ErrSessionProfileConflict = ErrSessionProfileConflict
	if e == nil {
		return
	}
	flow.ResolveSessionProfile = e.resolveSessionProfile
	sess.ResolveSessionProfile = e.resolveSessionProfile
	sess.SessionProfileLifetime = e.sessionProfileLifetime
}

// peekSessionProfile reads the profile of a session, for audit metadata. It
// is used only while profiles are configured, and a read failure simply
// leaves the profile out of the event.
func (e *Engine) peekSessionProfile(ctx context.Context, tenantID, sessionID string) string {
	if !e.sessionProfilesEnabled() || e.sessionStore == nil {
		return ""
	}
	sess, err := e.sessionStore.Peek(ctx, tenantID, sessionID)
	if err != nil || sess == nil {
		return ""
	}
	return sess.Profile
}

// profileAudit returns a metadata builder carrying the profile, or nil when
// there is none, so the event of a legacy session is unchanged.
func profileAudit(profile string) func() map[string]string {
	if profile == "" {
		return nil
	}
	return func() map[string]string { return map[string]string{"profile": profile} }
}

// withProfile extends metadata with the profile when there is one.
func withProfile(meta map[string]string, profile string) map[string]string {
	if profile != "" {
		meta["profile"] = profile
	}
	return meta
}

// auditProfileSessionEnd records that a strict read ended a profile session
// because its profile was removed or its ceiling passed. It is silent for
// every other failure, and for engines without profiles.
func (e *Engine) auditProfileSessionEnd(ctx context.Context, tenantID string, err error) {
	if !e.sessionProfilesEnabled() {
		return
	}
	var reason string
	switch {
	case errors.Is(err, session.ErrProfileUnknown):
		reason = sessionInvalidReasonProfileUnknown
	case errors.Is(err, session.ErrSessionExpired):
		reason = sessionInvalidReasonExpired
	default:
		return
	}
	e.emitAudit(ctx, auditEventSessionInvalid, false, "", tenantID, "", ErrSessionNotFound, func() map[string]string {
		meta := map[string]string{"reason": reason}
		if name := session.EndedProfileName(err); name != "" {
			meta["profile"] = name
		}
		return meta
	})
}

// refreshInvalidMeta builds the audit metadata of a failed refresh: the
// reason, plus the session's profile when it is known.
func refreshInvalidMeta(reason string, sess *session.Session) func() map[string]string {
	return func() map[string]string {
		meta := map[string]string{"reason": reason}
		if sess != nil {
			meta = withProfile(meta, sess.Profile)
		}
		return meta
	}
}

// refreshNotFoundMeta builds the audit metadata of a refresh that found no
// usable session. A session ended because its profile is no longer configured
// is reported as profile_unknown, naming the profile; everything else keeps
// the reason it always had.
func (e *Engine) refreshNotFoundMeta(err error) func() map[string]string {
	if errors.Is(err, session.ErrProfileUnknown) {
		name := session.EndedProfileName(err)
		return func() map[string]string {
			return withProfile(map[string]string{"reason": sessionInvalidReasonProfileUnknown}, name)
		}
	}
	return func() map[string]string {
		return map[string]string{"reason": "session_not_found"}
	}
}

// logoutProfilePeeker returns the hook that reads a session's profile just
// before logout destroys it, or nil when profiles are not configured, in
// which case logout reads nothing extra.
func (e *Engine) logoutProfilePeeker() func(context.Context, string, string) string {
	if !e.sessionProfilesEnabled() {
		return nil
	}
	return e.peekSessionProfile
}
