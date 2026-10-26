package goAuth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/MrEthical07/goAuth/internal/clock"
	internalflows "github.com/MrEthical07/goAuth/internal/flows"
	"github.com/MrEthical07/goAuth/internal/limiters"
	"github.com/MrEthical07/goAuth/internal/oidc"
	"github.com/MrEthical07/goAuth/password"
	"github.com/redis/go-redis/v9"
)

const (
	auditEventExternalLoginSuccess  = "external_login_success"
	auditEventExternalLoginFailure  = "external_login_failure"
	auditEventExternalLinked        = "external_identity_linked"
	auditEventExternalUnlinked      = "external_identity_unlinked"
	auditEventExternalLinkFailure   = "external_identity_link_failure"
	auditEventExternalUnlinkFailure = "external_identity_unlink_failure"
)

// external_login_failure and external_identity_link_failure metadata.reason
// values. The login tail audits its own failures (account status of a linked
// account, session hardening, device binding, MFA) as login_failure and
// mfa_failure, exactly as a password login does.
const (
	externalReasonDisabled                 = "disabled"
	externalReasonProviderUnknown          = "provider_unknown"
	externalReasonTokenInvalid             = "token_invalid"
	externalReasonTokenReplayed            = "token_replayed"
	externalReasonProviderUnavailable      = "provider_unavailable"
	externalReasonStoreUnavailable         = "store_unavailable"
	externalReasonRateLimited              = "rate_limited"
	externalReasonLimiterUnavailable       = "limiter_unavailable"
	externalReasonEmailUnverified          = "email_unverified"
	externalReasonLinkRequired             = "link_required"
	externalReasonLinkRequiresVerification = "link_requires_verification"
	externalReasonAccountNotFound          = "account_not_found"
	externalReasonAccountStatus            = "account_status"
	externalReasonSessionProfile           = "session_profile"
	externalReasonSignupRateLimited        = "signup_rate_limited"
	externalReasonSignupFailed             = "signup_failed"
	externalReasonAccountExists            = "account_exists"
	externalReasonIdentityInUse            = "identity_in_use"
	externalReasonLookupFailed             = "lookup_failed"
	externalReasonUnavailable              = "unavailable"
	externalReasonLastLoginMethod          = "last_login_method"
	externalReasonUserNotFound             = "user_not_found"
)

// maxExternalDisplayName bounds the name handed to the user provider.
const maxExternalDisplayName = 256

// verifyHash verifies password against an encoded hash. Every password check
// in the engine goes through it, which gives tests one place to count Argon2
// verifications; in production it is exactly passwordHash.Verify.
func (e *Engine) verifyHash(password, encodedHash string) (bool, error) {
	if e.verifyHashFn != nil {
		return e.verifyHashFn(password, encodedHash)
	}
	return e.passwordHash.Verify(password, encodedHash)
}

// dummyTimingHash is the hash verified in place of a real one when there is
// none: a hash of a throwaway password made by the engine's own hasher at
// Build, so an unknown identifier or an account without a password costs the
// same Argon2 work as a wrong password on an account hashed under the current
// configuration. An engine that was not built with Build falls back to the
// fixed-cost constant.
func (e *Engine) dummyTimingHash() string {
	if e.dummyHash != "" {
		return e.dummyHash
	}
	return internalflows.DummyTimingHash
}

// newDummyTimingHash hashes a random password once with the configured hasher.
func newDummyTimingHash(hasher *password.Argon2) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hasher.Hash(hex.EncodeToString(raw[:]))
}

// rejectPasswordless is the guard ChangePassword and VerifyPassword run after
// resolving the account. An account created through external sign-in has no
// password: there is nothing to verify, so the call fails with
// [ErrPasswordNotSet]. A dummy verification runs first so the response takes
// as long as one that did verify, and the attempt has already been counted by
// the password-verify limiter.
func (e *Engine) rejectPasswordless(ctx context.Context, event string, user UserRecord) error {
	if user.PasswordHash != "" {
		return nil
	}
	_, _ = e.verifyHash(internalflows.DummyTimingPassword, e.dummyTimingHash())
	e.emitAudit(ctx, event, false, user.UserID, user.TenantID, "", ErrPasswordNotSet, func() map[string]string {
		return map[string]string{
			"reason": "password_not_set",
		}
	})
	return ErrPasswordNotSet
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

// redisReplayGuard records used ID tokens with SET NX.
type redisReplayGuard struct {
	rdb redis.UniversalClient
}

func (g redisReplayGuard) SetNX(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return g.rdb.SetNX(ctx, key, 1, ttl).Result()
}

// newExternalVerifier builds the token verifier for the configured providers.
// It performs no network call.
func newExternalVerifier(cfg Config, rdb redis.UniversalClient, client *http.Client) (*oidc.Verifier, error) {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return oidc.NewVerifier(cfg.externalProviderConfigs(), oidc.Options{
		Client:        client,
		Replay:        redisReplayGuard{rdb: rdb},
		Leeway:        cfg.ExternalAuth.ClockLeeway,
		KeyRefreshMin: cfg.ExternalAuth.KeyRefreshMin,
		KeyMaxStale:   cfg.ExternalAuth.KeyMaxStale,
	})
}

// externalProviderConfigs resolves the configured providers, filling the
// documented defaults of each kind, in name order.
func (c *Config) externalProviderConfigs() []oidc.ProviderConfig {
	names := make([]string, 0, len(c.ExternalAuth.Providers))
	for name := range c.ExternalAuth.Providers {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]oidc.ProviderConfig, 0, len(names))
	for _, name := range names {
		p := c.ExternalAuth.Providers[name]
		cfg := oidc.ProviderConfig{
			Name:          name,
			Kind:          p.Kind,
			ClientIDs:     cloneStrings(p.ClientIDs),
			JWKSURL:       p.JWKSURL,
			Algorithms:    cloneStrings(p.Algorithms),
			HostedDomains: cloneStrings(p.AllowedHostedDomains),
		}
		switch p.Kind {
		case ExternalKindGoogle:
			if p.Issuer == "" || p.Issuer == googleExternalIssuer {
				// Google signs tokens with either spelling.
				cfg.Issuers = []string{googleExternalIssuer, googleExternalIssuerAlt}
			} else {
				cfg.Issuers = []string{p.Issuer}
			}
			if cfg.JWKSURL == "" {
				cfg.JWKSURL = googleExternalJWKSURL
			}
		case ExternalKindApple:
			cfg.Issuers = []string{appleExternalIssuer}
			if p.Issuer != "" {
				cfg.Issuers = []string{p.Issuer}
			}
			if cfg.JWKSURL == "" {
				cfg.JWKSURL = appleExternalJWKSURL
			}
		default:
			cfg.Issuers = []string{p.Issuer}
		}
		if len(cfg.Algorithms) == 0 {
			cfg.Algorithms = []string{"RS256"}
		}
		out = append(out, cfg)
	}
	return out
}

// WarmExternalKeys fetches every configured provider's signing keys now,
// instead of on the first sign-in. It is optional: call it at startup to fail
// fast on an unreachable provider or a wrong URL. It returns
// [ErrExternalAuthDisabled] when external sign-in is off and
// [ErrExternalProviderUnavailable] when any provider's keys cannot be
// fetched. A failure leaves the engine usable; the next sign-in tries again.
//
//	Docs: docs/external_identity.md
func (e *Engine) WarmExternalKeys(ctx context.Context) error {
	if !e.config.ExternalAuth.Enabled || e.externalVerifier == nil {
		return mapToAuthError(ErrExternalAuthDisabled)
	}
	if err := e.externalVerifier.Warm(ctx); err != nil {
		return mapToAuthError(errors.Join(oidc.ErrUnavailable, err))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// externalAuditProvider returns a provider name that is safe to put in an
// audit event: a configured-looking name, or a fixed marker for anything a
// caller could have made up.
func externalAuditProvider(name string) string {
	if validSessionProfileName(name) {
		return name
	}
	return "invalid"
}

// externalTenantBackstop reports whether a record returned by the external
// identity provider must carry the request's tenant. Like the other lookups
// it applies only while multi-tenancy is on, when a record of another tenant
// is a provider bug, not a legitimate answer.
func (e *Engine) externalTenantBackstop() bool {
	return e.config.MultiTenant.Enabled
}

// externalUserInTenant applies the record-tenant backstop to a user returned
// by GetUserByExternalIdentity: a record of another tenant is treated as not
// found.
func (e *Engine) externalUserInTenant(user UserRecord, tenantID string) bool {
	if !e.externalTenantBackstop() || tenantID == "" || user.TenantID == tenantID {
		return true
	}
	e.warn("goAuth: GetUserByExternalIdentity returned a user from another tenant; check the ExternalIdentityProvider implementation")
	return false
}

// externalUnavailable wraps a failure of the user provider so it reaches the
// caller as a service-unavailable error, with the cause kept for errors.Is.
func externalUnavailable(err error) error {
	return WrapAuthError(ErrSystemUnavailable, err)
}

func cleanExternalDisplayName(name string) string {
	name = strings.TrimSpace(name)
	if len(name) <= maxExternalDisplayName {
		return name
	}
	name = name[:maxExternalDisplayName]
	for !utf8.ValidString(name) {
		name = name[:len(name)-1]
	}
	return strings.TrimSpace(name)
}

// externalSource and externalSubject are the two limiter buckets of one
// sign-in attempt.
type externalAttempt struct {
	e        *Engine
	tenantID string
	sources  string
	subject  string
}

// reserveExternal claims one attempt in key. An explicit denial reports false.
// A limiter backend error is decided by limiterOutage: it fails open unless
// Security.LimiterFailClosed, in which case the error is returned.
func (e *Engine) reserveExternal(ctx context.Context, tenantID, key string) (bool, error) {
	if key == "" || e.externalLimiter == nil {
		return true, nil
	}
	e.metricInc(MetricLimiterCheck)
	err := e.externalLimiter.Reserve(ctx, key)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, limiters.ErrExternalRateLimited) {
		return false, nil
	}
	if outage := e.limiterOutage(ctx, "external_login", tenantID, err); outage != nil {
		return false, outage
	}
	return true, nil
}

func (e *Engine) resetExternal(ctx context.Context, tenantID string, keys ...string) {
	if e.externalLimiter == nil {
		return
	}
	for _, key := range keys {
		if key == "" {
			continue
		}
		if err := e.externalLimiter.Reset(ctx, key); err != nil {
			e.limiterCleanupFailed(ctx, "external_login", tenantID, err)
		}
	}
}

// externalVerifyFailure maps a verifier error to the public sentinel and the
// audit reason. Nothing from the token reaches either.
func externalVerifyFailure(err error) (string, error) {
	switch {
	case errors.Is(err, oidc.ErrReplayed):
		return externalReasonTokenReplayed, ErrExternalTokenReplayed
	case errors.Is(err, oidc.ErrUnavailable):
		return externalReasonProviderUnavailable, ErrExternalProviderUnavailable
	case errors.Is(err, oidc.ErrStore):
		return externalReasonStoreUnavailable, ErrSystemUnavailable
	case errors.Is(err, oidc.ErrUnknownProvider):
		return externalReasonProviderUnknown, ErrExternalProviderUnknown
	default:
		return externalReasonTokenInvalid, ErrExternalTokenInvalid
	}
}

// externalPreflight runs the checks every external operation starts with:
// the feature is on and the provider is configured.
func (e *Engine) externalEnabled() bool {
	return e.config.ExternalAuth.Enabled && e.externalVerifier != nil && e.externalProvider != nil
}

// verifyExternalToken runs the two-stage limiter around token verification
// and returns the verified claims. On failure the second return value is the
// audit reason. The caller resets the buckets it is handed after it succeeds.
func (e *Engine) verifyExternalToken(ctx context.Context, tenantID, provider, idToken, nonce string) (*oidc.Claims, externalAttempt, string, error) {
	att := externalAttempt{e: e, tenantID: tenantID}

	if e.externalLimiter != nil {
		att.sources = e.externalLimiter.SourceKey(tenantID, clientIPFromContext(ctx))
	}
	if allowed, err := e.reserveExternal(ctx, tenantID, att.sources); err != nil {
		return nil, att, externalReasonLimiterUnavailable, err
	} else if !allowed {
		e.limitedExternal(ctx, tenantID, provider)
		return nil, att, externalReasonRateLimited, ErrExternalLoginRateLimited
	}

	claims, err := e.externalVerifier.Verify(ctx, provider, idToken, nonce)
	if err != nil {
		reason, public := externalVerifyFailure(err)
		if reason == externalReasonProviderUnavailable || reason == externalReasonStoreUnavailable {
			e.warn("goAuth: external identity token could not be verified; the provider's keys or the replay store are unavailable")
		}
		return nil, att, reason, public
	}

	if e.externalLimiter != nil {
		att.subject = e.externalLimiter.SubjectKey(tenantID, provider, claims.Subject)
	}
	if allowed, err := e.reserveExternal(ctx, tenantID, att.subject); err != nil {
		return nil, att, externalReasonLimiterUnavailable, err
	} else if !allowed {
		e.limitedExternal(ctx, tenantID, provider)
		return nil, att, externalReasonRateLimited, ErrExternalLoginRateLimited
	}
	return claims, att, "", nil
}

func (e *Engine) limitedExternal(ctx context.Context, tenantID, provider string) {
	e.metricInc(MetricLoginRateLimited)
	e.emitRateLimit(ctx, "external_login", tenantID, func() map[string]string {
		return map[string]string{"provider": externalAuditProvider(provider)}
	})
}

// ---------------------------------------------------------------------------
// LoginWithExternalIdentity
// ---------------------------------------------------------------------------

// LoginWithExternalIdentity signs a user in with an OpenID Connect ID token
// the application already obtained from the named provider (Google Identity
// Services, the Google or Apple native SDKs, Sign in with Apple JS). It
// verifies the token, resolves or links or creates the account, and then
// continues exactly like a password login: account status, session hardening,
// the MFA decision, session issuance, audit and metrics. The result has the
// same shape as [Engine.LoginWithResult]'s, plus NewAccount and
// LinkedIdentity; when MFA is required, [Engine.ConfirmLoginMFA] completes the
// sign-in unchanged.
//
// goAuth does not run the OAuth2 code exchange, PKCE, redirects or discovery,
// and stores no provider refresh token.
//
// opts.Nonce must be the raw nonce the server issued for this sign-in. The
// token is accepted only once. The session profile is chosen before any work,
// as for every login, from [WithSessionProfile] and opts.RememberMe. Pass the
// client IP with [WithClientIP]: the pre-verification rate limit is per IP and
// is skipped without one.
//
// How the account is found:
//
//   - the identity is already linked: that account;
//
//   - otherwise the token's email, if the provider verified it, is looked up as
//     a local identifier. A match is linked when
//     Config.ExternalAuth.AutoLinkVerifiedEmail is on and the account is
//     Active; refused with [ErrExternalLinkRequiresVerification] when it is
//     still pending verification, [ErrExternalAccountLinkRequired] when
//     auto-linking is off, or the account's own status error;
//
//   - with no match, an account is created when Config.ExternalAuth.AllowSignup
//     is on, otherwise [ErrExternalAccountNotFound];
//
//   - no verified email is [ErrExternalEmailUnverified]; an unverified one is
//     never used.
//
//     Flow:        External Login
//     Docs:        docs/external_identity.md
//     Performance: one RSA/ECDSA verification, a SET NX and two limiter
//     counters on top of a password login's Redis commands; keys are
//     cached.
//     Security:    audience, issuer, expiry, nonce and single-use enforced; rate
//     limited per IP and per identity; never trusts an unverified
//     email.
func (e *Engine) LoginWithExternalIdentity(ctx context.Context, provider, idToken string, opts ExternalLoginOptions) (*LoginResult, error) {
	result, err := e.loginWithExternalIdentity(ctx, provider, idToken, opts)
	if err != nil {
		return nil, mapToAuthError(err)
	}
	return result, nil
}

// externalLoginFail records a failed external sign-in and returns err.
func (e *Engine) externalLoginFail(ctx context.Context, tenantID, provider, userID, reason string, err error) error {
	if reason != externalReasonDisabled {
		e.metricInc(MetricLoginFailure)
	}
	e.emitAudit(ctx, auditEventExternalLoginFailure, false, userID, tenantID, "", err, func() map[string]string {
		return map[string]string{
			"provider": externalAuditProvider(provider),
			"reason":   reason,
		}
	})
	return err
}

func (e *Engine) loginWithExternalIdentity(ctx context.Context, provider, idToken string, opts ExternalLoginOptions) (*LoginResult, error) {
	tenantID := tenantIDFromContext(ctx)

	if !e.externalEnabled() {
		return nil, e.externalLoginFail(ctx, tenantID, provider, "", externalReasonDisabled, ErrExternalAuthDisabled)
	}
	if !e.externalVerifier.Has(provider) {
		return nil, e.externalLoginFail(ctx, tenantID, provider, "", externalReasonProviderUnknown, ErrExternalProviderUnknown)
	}

	// The profile is chosen before any limiter, verification or provider call.
	profile, status := e.resolveSessionProfile(ctx, opts.RememberMe)
	switch status {
	case internalflows.SessionProfileUnknown:
		return nil, e.externalLoginFail(ctx, tenantID, provider, "", externalReasonSessionProfile, ErrUnknownSessionProfile)
	case internalflows.SessionProfileConflict:
		return nil, e.externalLoginFail(ctx, tenantID, provider, "", externalReasonSessionProfile, ErrSessionProfileConflict)
	}
	ctx = internalflows.WithResolvedSessionProfile(ctx, profile)

	claims, att, reason, err := e.verifyExternalToken(ctx, tenantID, provider, idToken, opts.Nonce)
	if err != nil {
		return nil, e.externalLoginFail(ctx, tenantID, provider, "", reason, err)
	}

	res, reason, err := e.resolveExternalAccount(ctx, tenantID, claims, cleanExternalDisplayName(opts.DisplayName))
	if err != nil {
		return nil, e.externalLoginFail(ctx, tenantID, provider, res.user.UserID, reason, err)
	}

	// The revocation epoch is read before the account is read again, so a
	// password change or status change that lands in between is caught when
	// the session is stored.
	epoch, err := e.readRevocationEpoch(ctx, tenantID, res.user.UserID)
	if err != nil {
		return nil, e.externalLoginFail(ctx, tenantID, provider, res.user.UserID, externalReasonUnavailable, ErrSystemUnavailable)
	}
	fresh, err := e.lookupUserByID(ctx, res.user.UserID)
	switch {
	case errors.Is(err, ErrUserNotFound):
		return nil, e.externalLoginFail(ctx, tenantID, provider, res.user.UserID, externalReasonUserNotFound, ErrExternalAccountNotFound)
	case err != nil:
		return nil, e.externalLoginFail(ctx, tenantID, provider, res.user.UserID, externalReasonLookupFailed, ErrSystemUnavailable)
	}
	res.user = fresh

	e.ensureFlowDeps()
	identifier := res.user.Identifier
	if identifier == "" {
		identifier = res.user.UserID
	}
	flowResult, err := e.flows.CompleteLogin(ctx, identifier, toFlowLoginUser(res.user), internalflows.LoginOptions{RememberMe: opts.RememberMe, Epoch: epoch})
	if err != nil {
		// The shared tail has already audited and counted the failure.
		return nil, err
	}

	e.resetExternal(ctx, tenantID, att.sources, att.subject)
	e.emitAudit(ctx, auditEventExternalLoginSuccess, true, res.user.UserID, tenantID, "", nil, func() map[string]string {
		meta := map[string]string{
			"provider":     provider,
			"new_account":  boolString(res.newAccount),
			"linked":       boolString(res.linked),
			"mfa_required": boolString(flowResult.MFARequired),
		}
		if profile != "" {
			meta["profile"] = profile
		}
		return meta
	})

	out := fromFlowLoginResult(flowResult)
	out.NewAccount = res.newAccount
	out.LinkedIdentity = res.linked
	return out, nil
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// externalResolution is the account an external identity resolved to.
type externalResolution struct {
	user       UserRecord
	newAccount bool
	linked     bool
}

// resolveExternalAccount finds, links or creates the account for a verified
// identity. A concurrent first sign-in of the same person makes the provider
// report a duplicate; the resolution is then run once more, which finds what
// the winner created.
func (e *Engine) resolveExternalAccount(ctx context.Context, tenantID string, claims *oidc.Claims, displayName string) (externalResolution, string, error) {
	for attempt := 0; ; attempt++ {
		res, reason, err, retry := e.resolveExternalAccountOnce(ctx, tenantID, claims, displayName, attempt > 0)
		if retry && attempt == 0 {
			continue
		}
		return res, reason, err
	}
}

func (e *Engine) externalIdentityFor(claims *oidc.Claims, displayName string) ExternalIdentity {
	return ExternalIdentity{
		Provider:       claims.Provider,
		Subject:        claims.Subject,
		Email:          claims.Email,
		EmailVerified:  claims.EmailVerified,
		IsPrivateEmail: claims.IsPrivateEmail,
		DisplayName:    displayName,
		LinkedAt:       clock.Now(),
	}
}

// resolveExternalAccountOnce is one pass of the resolution. retry is true when
// the provider reported a concurrent creation that a second pass would see.
func (e *Engine) resolveExternalAccountOnce(ctx context.Context, tenantID string, claims *oidc.Claims, displayName string, retried bool) (res externalResolution, reason string, err error, retry bool) {
	identity := e.externalIdentityFor(claims, displayName)

	// 1. The identity is already linked.
	user, lookupErr := e.externalProvider.GetUserByExternalIdentity(ctx, tenantID, claims.Provider, claims.Subject)
	switch {
	case lookupErr == nil && e.externalUserInTenant(user, tenantID):
		if statusErr := accountStatusToError(user.Status); statusErr != nil {
			return externalResolution{user: user}, externalReasonAccountStatus, statusErr, false
		}
		return externalResolution{user: user}, "", nil, false
	case lookupErr == nil:
		// Another tenant's record: as if there were none.
	case errors.Is(lookupErr, ErrUserNotFound):
	default:
		return externalResolution{}, externalReasonLookupFailed, externalUnavailable(lookupErr), false
	}

	// 2. A verified email is required to link or create anything.
	if claims.Email == "" || !claims.EmailVerified {
		return externalResolution{}, externalReasonEmailUnverified, ErrExternalEmailUnverified, false
	}

	local, localErr := e.lookupUserByIdentifier(ctx, claims.Email)
	if localErr == nil && e.tenantScopedLookup() && tenantID != "" && local.TenantID != tenantID {
		e.warn("goAuth: tenant-scoped lookup returned a user from another tenant; check the TenantAwareUserProvider implementation")
		localErr = ErrUserNotFound
	}

	switch {
	case localErr == nil:
		return e.linkMatchedAccount(ctx, tenantID, local, identity, retried)
	case !errors.Is(localErr, ErrUserNotFound):
		// Only "no such user" lets the sign-in go on to create one. An outage
		// or any other failure must not look like an absent account.
		return externalResolution{}, externalReasonLookupFailed, externalUnavailable(localErr), false
	}

	// 3. No such account: create one, or refuse.
	if !e.config.ExternalAuth.AllowSignup {
		return externalResolution{}, externalReasonAccountNotFound, ErrExternalAccountNotFound, false
	}
	return e.createExternalAccount(ctx, tenantID, claims, identity, retried)
}

// linkMatchedAccount handles a local account whose identifier is the token's
// verified email.
func (e *Engine) linkMatchedAccount(ctx context.Context, tenantID string, local UserRecord, identity ExternalIdentity, retried bool) (externalResolution, string, error, bool) {
	switch local.Status {
	case AccountPendingVerification:
		// Linking an account whose own email was never proved would let
		// whoever pre-registered the address take over the sign-in.
		return externalResolution{user: local}, externalReasonLinkRequiresVerification, ErrExternalLinkRequiresVerification, false
	case AccountActive:
	default:
		if statusErr := accountStatusToError(local.Status); statusErr != nil {
			return externalResolution{user: local}, externalReasonAccountStatus, statusErr, false
		}
	}
	if !e.config.ExternalAuth.AutoLinkVerifiedEmail {
		return externalResolution{user: local}, externalReasonLinkRequired, ErrExternalAccountLinkRequired, false
	}

	if err := e.externalProvider.LinkExternalIdentity(ctx, tenantID, local.UserID, identity); err != nil {
		if errors.Is(err, ErrExternalIdentityInUse) {
			// Linked to another account since we looked: see what is there now.
			if !retried {
				return externalResolution{}, "", err, true
			}
			return externalResolution{user: local}, externalReasonIdentityInUse, ErrExternalIdentityInUse, false
		}
		return externalResolution{user: local}, externalReasonLookupFailed, externalUnavailable(err), false
	}
	e.emitAudit(ctx, auditEventExternalLinked, true, local.UserID, tenantID, "", nil, func() map[string]string {
		return map[string]string{
			"provider": identity.Provider,
			"via":      "verified_email",
		}
	})
	return externalResolution{user: local, linked: true}, "", nil, false
}

// createExternalAccount creates a password-less account for a verified
// identity, under the account-creation limiter.
func (e *Engine) createExternalAccount(ctx context.Context, tenantID string, claims *oidc.Claims, identity ExternalIdentity, retried bool) (externalResolution, string, error, bool) {
	if e.config.MultiTenant.Enabled {
		if _, ok := tenantIDFromContextExplicit(ctx); !ok {
			return externalResolution{}, externalReasonSignupFailed, ErrAccountCreationInvalid, false
		}
	}
	if err := e.enforceExternalSignupLimit(ctx, tenantID, claims.Email); err != nil {
		reason := externalReasonSignupRateLimited
		if errors.Is(err, ErrSystemUnavailable) {
			reason = externalReasonLimiterUnavailable
		}
		return externalResolution{}, reason, err, false
	}

	created, err := e.externalProvider.CreateUserWithExternalIdentity(ctx, CreateUserInput{
		Identifier:        claims.Email,
		PasswordHash:      "",
		Role:              e.config.Account.DefaultRole,
		TenantID:          tenantID,
		Status:            AccountActive,
		PermissionVersion: 1,
		RoleVersion:       1,
		AccountVersion:    1,
	}, identity)
	if err != nil {
		switch {
		case errors.Is(err, ErrProviderDuplicateIdentifier), errors.Is(err, ErrExternalIdentityInUse):
			if !retried {
				return externalResolution{}, "", err, true
			}
			if errors.Is(err, ErrExternalIdentityInUse) {
				return externalResolution{}, externalReasonIdentityInUse, ErrExternalIdentityInUse, false
			}
			e.metricInc(MetricAccountCreationDuplicate)
			return externalResolution{}, externalReasonAccountExists, ErrAccountExists, false
		}
		return externalResolution{}, externalReasonSignupFailed, externalUnavailable(err), false
	}
	if created.UserID == "" {
		return externalResolution{}, externalReasonSignupFailed, ErrAccountCreationUnavailable, false
	}
	if created.Role == "" {
		created.Role = e.config.Account.DefaultRole
	}
	if created.TenantID == "" {
		created.TenantID = tenantID
	}
	if created.Identifier == "" {
		created.Identifier = claims.Email
	}
	if created.PermissionVersion == 0 {
		created.PermissionVersion = 1
	}
	if created.RoleVersion == 0 {
		created.RoleVersion = 1
	}
	if created.AccountVersion == 0 {
		created.AccountVersion = 1
	}

	e.metricInc(MetricAccountCreationSuccess)
	e.emitAudit(ctx, auditEventAccountCreationSuccess, true, created.UserID, created.TenantID, "", nil, func() map[string]string {
		return map[string]string{
			"identifier": claims.Email,
			"role":       created.Role,
			"method":     "external",
			"provider":   identity.Provider,
		}
	})
	return externalResolution{user: created, newAccount: true}, "", nil, false
}

// enforceExternalSignupLimit applies the account-creation limiter to an
// external sign-up exactly as CreateAccount applies it: same switch, same
// buckets, same fail-open, same audit and metrics.
func (e *Engine) enforceExternalSignupLimit(ctx context.Context, tenantID, identifier string) error {
	if !e.config.Account.EnableCreationLimiter || e.accountLimiter == nil {
		return nil
	}
	e.metricInc(MetricLimiterCheck)
	err := e.accountLimiter.Enforce(ctx, tenantID, identifier)
	if err == nil {
		return nil
	}
	if !errors.Is(err, limiters.ErrAccountRateLimited) {
		return e.limiterOutage(ctx, "account_creation", tenantID, err)
	}
	e.metricInc(MetricAccountCreationRateLimited)
	e.emitAudit(ctx, auditEventAccountCreationRateLimited, false, "", tenantID, "", ErrAccountCreationRateLimited, func() map[string]string {
		return map[string]string{"identifier": identifier}
	})
	e.emitRateLimit(ctx, "account_creation", tenantID, func() map[string]string {
		return map[string]string{"identifier": identifier}
	})
	return ErrAccountCreationRateLimited
}

// ---------------------------------------------------------------------------
// Link, unlink, list
// ---------------------------------------------------------------------------

func (e *Engine) externalLinkFail(ctx context.Context, tenantID, provider, userID, reason string, err error) error {
	e.emitAudit(ctx, auditEventExternalLinkFailure, false, userID, tenantID, "", err, func() map[string]string {
		return map[string]string{
			"provider": externalAuditProvider(provider),
			"reason":   reason,
		}
	})
	return err
}

// lookupExternalManagedUser resolves the authenticated user of a link, unlink
// or list call through the tenant-scoped lookup, so an ID from another tenant
// is not found. Only [ErrUserNotFound] (from the provider, or from the
// tenant-mismatch backstop) means the user is gone; any other provider error is
// an outage and is reported as one, never as a missing account.
func (e *Engine) lookupExternalManagedUser(ctx context.Context, userID string) (UserRecord, error) {
	if userID == "" {
		return UserRecord{}, ErrUserNotFound
	}
	user, err := e.lookupUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return UserRecord{}, ErrUserNotFound
		}
		return UserRecord{}, externalUnavailable(err)
	}
	return user, nil
}

// externalLookupReason is the audit reason for a failed lookupExternalManagedUser.
func externalLookupReason(err error) string {
	if errors.Is(err, ErrSystemUnavailable) {
		return externalReasonLookupFailed
	}
	return externalReasonUserNotFound
}

// LinkExternalIdentity links the external identity proved by idToken to the
// authenticated user userID, who must have signed in some other way first. The
// token is verified exactly as for sign-in (including the nonce, the rate
// limit and single use). Unlike sign-in it does not need a verified email,
// because the user is already authenticated; EmailVerified is stored as the
// provider reported it.
//
// Linking an identity already linked to this user succeeds without change.
// One linked to a different user fails with [ErrExternalIdentityInUse]. An
// account that is still pending email verification cannot be linked
// ([ErrExternalLinkRequiresVerification]): until its address is verified it
// may belong to whoever registered it.
//
// goAuth does not ask the user to prove themselves again: have the application
// require a step-up (for example [Engine.VerifyPassword], or a recent MFA)
// before calling this. userID must come from the session, never from the
// request.
//
//	Flow:        Link External Identity
//	Docs:        docs/external_identity.md
func (e *Engine) LinkExternalIdentity(ctx context.Context, userID, provider, idToken string, nonce string) (*ExternalIdentity, error) {
	identity, err := e.linkExternalIdentity(ctx, userID, provider, idToken, nonce)
	if err != nil {
		return nil, mapToAuthError(err)
	}
	return identity, nil
}

func (e *Engine) linkExternalIdentity(ctx context.Context, userID, provider, idToken, nonce string) (*ExternalIdentity, error) {
	tenantID := tenantIDFromContext(ctx)
	if !e.externalEnabled() {
		return nil, e.externalLinkFail(ctx, tenantID, provider, userID, externalReasonDisabled, ErrExternalAuthDisabled)
	}
	if !e.externalVerifier.Has(provider) {
		return nil, e.externalLinkFail(ctx, tenantID, provider, userID, externalReasonProviderUnknown, ErrExternalProviderUnknown)
	}

	claims, att, reason, err := e.verifyExternalToken(ctx, tenantID, provider, idToken, nonce)
	if err != nil {
		return nil, e.externalLinkFail(ctx, tenantID, provider, userID, reason, err)
	}

	user, err := e.lookupExternalManagedUser(ctx, userID)
	if err != nil {
		return nil, e.externalLinkFail(ctx, tenantID, provider, userID, externalLookupReason(err), err)
	}
	if statusErr := accountStatusToError(user.Status); statusErr != nil {
		return nil, e.externalLinkFail(ctx, tenantID, provider, userID, externalReasonAccountStatus, statusErr)
	}
	if user.Status == AccountPendingVerification {
		// Same gate as linking by email: an account whose own address was never
		// proved may belong to whoever registered it, who could otherwise keep
		// a way in after the real owner verifies the address.
		return nil, e.externalLinkFail(ctx, tenantID, provider, userID, externalReasonLinkRequiresVerification, ErrExternalLinkRequiresVerification)
	}

	identity := e.externalIdentityFor(claims, "")
	existing, err := e.externalProvider.GetUserByExternalIdentity(ctx, tenantID, provider, claims.Subject)
	switch {
	case err == nil && e.externalUserInTenant(existing, tenantID):
		if existing.UserID != user.UserID {
			return nil, e.externalLinkFail(ctx, tenantID, provider, userID, externalReasonIdentityInUse, ErrExternalIdentityInUse)
		}
		// Already linked to this user: nothing to do.
		e.resetExternal(ctx, tenantID, att.sources, att.subject)
		return &identity, nil
	case err == nil, errors.Is(err, ErrUserNotFound):
	default:
		return nil, e.externalLinkFail(ctx, tenantID, provider, userID, externalReasonLookupFailed, externalUnavailable(err))
	}

	if err := e.externalProvider.LinkExternalIdentity(ctx, tenantID, user.UserID, identity); err != nil {
		if errors.Is(err, ErrExternalIdentityInUse) {
			return nil, e.externalLinkFail(ctx, tenantID, provider, userID, externalReasonIdentityInUse, ErrExternalIdentityInUse)
		}
		return nil, e.externalLinkFail(ctx, tenantID, provider, userID, externalReasonLookupFailed, externalUnavailable(err))
	}
	e.resetExternal(ctx, tenantID, att.sources, att.subject)
	e.emitAudit(ctx, auditEventExternalLinked, true, user.UserID, tenantID, "", nil, func() map[string]string {
		return map[string]string{
			"provider": provider,
			"via":      "link",
		}
	})
	return &identity, nil
}

// UnlinkExternalIdentity removes the link between userID and the identity
// (provider, subject). It refuses with [ErrLastLoginMethod] when the account
// has no password and this is its only linked identity, which would leave it
// with no way to sign in. Unlinking an identity that is not linked succeeds.
//
// Have the application require a step-up before calling this, and take userID
// from the session. Two concurrent unlinks of an account's last two identities
// can each see the other still linked; a user provider that must prevent that
// should enforce it in its own transaction.
//
//	Flow:        Unlink External Identity
//	Docs:        docs/external_identity.md
func (e *Engine) UnlinkExternalIdentity(ctx context.Context, userID, provider, subject string) error {
	return mapToAuthErrorOrNil(e.unlinkExternalIdentity(ctx, userID, provider, subject))
}

func (e *Engine) unlinkExternalIdentity(ctx context.Context, userID, provider, subject string) error {
	tenantID := tenantIDFromContext(ctx)
	if !e.externalEnabled() {
		return e.externalUnlinkFail(ctx, tenantID, provider, userID, externalReasonDisabled, ErrExternalAuthDisabled)
	}
	user, err := e.lookupExternalManagedUser(ctx, userID)
	if err != nil {
		reason := externalReasonUserNotFound
		if errors.Is(err, ErrSystemUnavailable) {
			reason = externalReasonUnavailable
		}
		return e.externalUnlinkFail(ctx, tenantID, provider, userID, reason, err)
	}
	if statusErr := accountStatusToError(user.Status); statusErr != nil {
		return e.externalUnlinkFail(ctx, tenantID, provider, userID, externalReasonAccountStatus, statusErr)
	}

	identities, err := e.externalProvider.ListExternalIdentities(ctx, tenantID, user.UserID)
	if err != nil {
		return e.externalUnlinkFail(ctx, tenantID, provider, userID, externalReasonUnavailable, externalUnavailable(err))
	}
	linked := false
	for _, id := range identities {
		if id.Provider == provider && id.Subject == subject {
			linked = true
		}
	}
	if !linked {
		return nil
	}
	if user.PasswordHash == "" && len(identities) <= 1 {
		return e.externalUnlinkFail(ctx, tenantID, provider, userID, externalReasonLastLoginMethod, ErrLastLoginMethod)
	}

	if err := e.externalProvider.UnlinkExternalIdentity(ctx, tenantID, user.UserID, provider, subject); err != nil {
		return e.externalUnlinkFail(ctx, tenantID, provider, userID, externalReasonUnavailable, externalUnavailable(err))
	}
	e.emitAudit(ctx, auditEventExternalUnlinked, true, user.UserID, tenantID, "", nil, func() map[string]string {
		return map[string]string{"provider": externalAuditProvider(provider)}
	})
	return nil
}

func (e *Engine) externalUnlinkFail(ctx context.Context, tenantID, provider, userID, reason string, err error) error {
	e.emitAudit(ctx, auditEventExternalUnlinkFailure, false, userID, tenantID, "", err, func() map[string]string {
		return map[string]string{
			"provider": externalAuditProvider(provider),
			"reason":   reason,
		}
	})
	return err
}

// ListExternalIdentities returns the external identities linked to userID,
// for a settings screen. userID must come from the session.
//
//	Flow:        List External Identities
//	Docs:        docs/external_identity.md
func (e *Engine) ListExternalIdentities(ctx context.Context, userID string) ([]ExternalIdentity, error) {
	identities, err := e.listExternalIdentities(ctx, userID)
	if err != nil {
		return nil, mapToAuthError(err)
	}
	return identities, nil
}

func (e *Engine) listExternalIdentities(ctx context.Context, userID string) ([]ExternalIdentity, error) {
	if !e.externalEnabled() {
		return nil, ErrExternalAuthDisabled
	}
	user, err := e.lookupExternalManagedUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	identities, err := e.externalProvider.ListExternalIdentities(ctx, tenantIDFromContext(ctx), user.UserID)
	if err != nil {
		return nil, externalUnavailable(err)
	}
	out := make([]ExternalIdentity, len(identities))
	copy(out, identities)
	return out, nil
}
