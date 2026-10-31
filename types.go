package goAuth

import (
	"context"
	"io"
	"log/slog"
	"time"

	internalaudit "github.com/MrEthical07/goAuth/internal/audit"
	internalflows "github.com/MrEthical07/goAuth/internal/flows"
	internalmetrics "github.com/MrEthical07/goAuth/internal/metrics"
)

// MaxIdentifierBytes is the longest identifier, in bytes, that the
// unauthenticated entry points accept: login, account creation, password-reset
// requests and email-verification requests. A longer identifier is refused
// before any lookup or limiter sees it, as a failed login (ErrInvalidCredentials)
// or as an invalid request, and identifiers copied into audit events are
// truncated to this length. Hosts that allow longer logins must shorten them.
//
//	Docs: docs/security.md, docs/flows.md
const MaxIdentifierBytes = internalflows.MaxIdentifierBytes

// AccountStatus represents the lifecycle state of a user account.
//
//	Docs: docs/functionality-account-status.md
type AccountStatus uint8

const (
	// AccountActive is an exported constant or variable used by the authentication engine.
	AccountActive AccountStatus = iota
	// AccountPendingVerification is an exported constant or variable used by the authentication engine.
	AccountPendingVerification
	// AccountDisabled is an exported constant or variable used by the authentication engine.
	AccountDisabled
	// AccountLocked is an exported constant or variable used by the authentication engine.
	AccountLocked
	// AccountDeleted is an exported constant or variable used by the authentication engine.
	AccountDeleted

	// StatusPendingVerification is an exported constant or variable used by the authentication engine.
	StatusPendingVerification = AccountPendingVerification
)

// PermissionMask is the interface satisfied by all bitmask widths
// ([permission.Mask64], [permission.Mask128], [permission.Mask256],
// [permission.Mask512]).
//
//	Docs: docs/permission.md
type PermissionMask interface {
	Has(bit int) bool
	Set(bit int)
	Raw() any
}

// User is a minimal user representation used by the legacy [UserStore]
// interface. Prefer [UserRecord] for new integrations.
type User struct {
	ID             string
	TenantID       string
	PasswordHash   string
	PermissionMask PermissionMask
	Role           string
	PermVersion    uint32
	RoleVersion    uint32
}

// AuthResult is returned by [Engine.Validate] and [Engine.ValidateAccess].
// It contains the authenticated user’s ID, tenant, role, decoded permission
// mask, and optionally the permission name list.
//
//	Docs: docs/jwt.md, docs/permission.md
type AuthResult struct {
	UserID   string
	TenantID string

	Role string

	Mask interface{}

	Permissions []string
}

// UserStore is a legacy credential-lookup interface. Prefer [UserProvider]
// for full account lifecycle support.
type UserStore interface {
	GetByIdentifier(ctx context.Context, identifier string) (*User, error)
	UpdatePermissionMask(ctx context.Context, userID string, mask PermissionMask) error
}

// RoleStore is a legacy role-lookup interface.
type RoleStore interface {
	GetRoleMask(ctx context.Context, tenantID, role string) (PermissionMask, uint32, error)
}

// KeyBuilder defines the Redis key layout for sessions and version counters.
type KeyBuilder interface {
	SessionKey(tenantID, sessionID string) string
	UserVersionKey(tenantID, userID string) string
	RoleVersionKey(tenantID, role string) string
}

// UserProvider is the primary interface that callers must implement to
// integrate goAuth with their user database. It covers credential lookup,
// account creation, password updates, TOTP secret management, and backup
// code storage.
//
//	Docs: docs/engine.md, docs/usage.md
type UserProvider interface {
	GetUserByIdentifier(identifier string) (UserRecord, error)
	GetUserByID(userID string) (UserRecord, error)
	UpdatePasswordHash(userID string, newHash string) error
	CreateUser(ctx context.Context, input CreateUserInput) (UserRecord, error)
	UpdateAccountStatus(ctx context.Context, userID string, status AccountStatus) (UserRecord, error)
	GetTOTPSecret(ctx context.Context, userID string) (*TOTPRecord, error)
	EnableTOTP(ctx context.Context, userID string, secret []byte) error
	DisableTOTP(ctx context.Context, userID string) error
	MarkTOTPVerified(ctx context.Context, userID string) error
	UpdateTOTPLastUsedCounter(ctx context.Context, userID string, counter int64) error
	GetBackupCodes(ctx context.Context, userID string) ([]BackupCodeRecord, error)
	ReplaceBackupCodes(ctx context.Context, userID string, codes []BackupCodeRecord) error
	ConsumeBackupCode(ctx context.Context, userID string, codeHash [32]byte) (bool, error)
}

// TenantAwareUserProvider is an optional capability interface a
// [UserProvider] can additionally implement to scope user lookup to a
// single tenant. It is detected via type assertion at [Builder.Build];
// when [Config.MultiTenant] is enabled and the user provider does not
// implement it, Build fails. Existing UserProvider implementations are
// unaffected when multi-tenancy is disabled.
//
// The plain [UserProvider] lookups are tenant-blind: they resolve an
// identifier or user ID across the whole user table. In a multi-tenant
// deployment that is an isolation failure — credentials belonging to one
// tenant resolve under another tenant's request context. These variants
// take the tenant the request is scoped to, and implementations MUST
// constrain the query to it, returning a not-found error when the record
// exists only in a different tenant.
//
// Implementations must not treat an empty tenantID as "any tenant"; the
// engine only calls these methods with the tenant resolved from the
// request context.
//
//	Docs: docs/multi_tenancy.md
type TenantAwareUserProvider interface {
	// GetUserByIdentifierInTenant resolves an identifier within tenantID
	// only. It must return an error (not another tenant's record) when the
	// identifier exists solely in a different tenant.
	GetUserByIdentifierInTenant(ctx context.Context, tenantID, identifier string) (UserRecord, error)

	// GetUserByIDInTenant resolves a user ID within tenantID only. It must
	// return an error (not the record) when the user belongs to a
	// different tenant.
	GetUserByIDInTenant(ctx context.Context, tenantID, userID string) (UserRecord, error)
}

// TenantAwarePasswordUpdater is an optional capability interface a
// [UserProvider] can additionally implement to scope password-hash writes to
// a single tenant. It is detected via type assertion at [Builder.Build] and
// is consulted only when [Config.MultiTenant] is enabled; with it disabled,
// or when the provider does not implement it, every writer keeps calling
// [UserProvider.UpdatePasswordHash] exactly as before.
//
// [UserProvider.UpdatePasswordHash] addresses a user by ID alone, so in a
// multi-tenant deployment it can overwrite a hash that the lookup path never
// resolved for this tenant. When the capability is present the engine calls
// UpdatePasswordHashInTenant instead, in all three places it writes a hash:
// [Engine.ChangePassword], the password-reset confirm flow, and the
// rehash-on-login upgrade. The tenantID is always the one the engine
// resolved itself, never a caller-supplied value.
//
// Implementations MUST constrain the write to tenantID and return an error
// (not silently succeed) when the user belongs to a different tenant.
//
//	Docs: docs/multi_tenancy.md
type TenantAwarePasswordUpdater interface {
	UpdatePasswordHashInTenant(ctx context.Context, tenantID, userID, newHash string) error
}

// PasswordHashCASUpdater is an optional capability interface a [UserProvider]
// can additionally implement so the rehash-on-login upgrade
// ([PasswordConfig.UpgradeOnLogin]) cannot overwrite a password that changed
// after the login read the account. It is detected via type assertion at
// [Builder.Build].
//
// CompareAndSwapPasswordHash must store newHash only if the user's current
// hash is exactly expectedOldHash, in one atomic step (UPDATE ... WHERE
// password_hash = $expected), and report whether it did. A hash that no longer
// matches is (false, nil), not an error: a password change or reset that
// landed since the login read the account stays in force and the upgrade is
// skipped. tenantID is the tenant the engine resolved itself.
//
// Without it the engine re-reads the user immediately before the write and
// skips the upgrade unless the hash is still the verified one. That narrows the
// window to the gap between the re-read and the write; it cannot close it.
// The upgrade runs after the session has been issued (or the MFA challenge
// created), so a login that is refused afterwards upgrades nothing.
//
//	Docs: docs/password.md
type PasswordHashCASUpdater interface {
	CompareAndSwapPasswordHash(ctx context.Context, tenantID, userID, expectedOldHash, newHash string) (applied bool, err error)
}

// AccountStatusCASUpdater is an optional capability interface a [UserProvider]
// can additionally implement so email verification cannot undo a status change
// that landed after the verification was read. It is detected via type
// assertion at [Builder.Build].
//
// UpdateAccountStatusIf must store next only if the account's current status
// is exactly expected, in one atomic step (UPDATE ... WHERE status =
// $expected), and report whether it did. Like [UserProvider.UpdateAccountStatus]
// it must advance the account version when it applies. A status that no longer
// matches is (false, nil), not an error. tenantID is the tenant the engine
// resolved itself.
//
// The engine uses it for the pending-verification to active transition that
// confirming an email address performs; a disabled, locked or deleted account
// is then never made active again by a verification that was in flight when it
// was blocked. Without it the engine reads the account again immediately before
// the write and transitions only from pending-verification, which narrows the
// window to the gap between that read and the write but cannot close it.
//
//	Docs: docs/email_verification.md
type AccountStatusCASUpdater interface {
	UpdateAccountStatusIf(ctx context.Context, tenantID, userID string, expected, next AccountStatus) (applied bool, err error)
}

// RoleSwitchProvider is an optional capability interface a [UserProvider]
// can additionally implement to enable [Engine.SwitchRole]. It is detected
// via type assertion at [Builder.Build]; when [Config.RoleSwitch] is enabled
// and the user provider does not implement it, Build fails. Existing
// UserProvider implementations are unaffected while the feature is off.
//
// CanAssumeRole reports whether userID, in tenantID, currently holds role.
// It MUST return true for the account's primary role (the one
// [UserRecord.Role] carries) as well as for any other role the account
// holds. goAuth calls it both when a session switches into a role and, on
// every refresh while role switching is enabled, to confirm the session's
// current role is still held -- including a session that never switched --
// so a provider that answers false for the primary role ends every session
// at its next refresh.
//
// The tenantID is always the one goAuth resolved itself from the session,
// never a caller-supplied value. A single yes/no check was chosen over an
// "allowed roles" list: there is nothing to enumerate or keep consistent,
// and the same call serves both the switch and the refresh re-check.
//
// Return an error only for a backend failure; an unknown user or an unheld
// role is (false, nil).
//
//	Docs: docs/role_switching.md
type RoleSwitchProvider interface {
	CanAssumeRole(ctx context.Context, tenantID, userID, role string) (bool, error)
}

// RoleSwitchOptions carries the optional inline proof for [Engine.SwitchRole].
// Leave it zero when the target role's step-up policy is already satisfied by
// the session, or to learn what the policy needs ([ErrStepUpRequired] reports
// the accepted factors).
type RoleSwitchOptions struct {
	// MFAType selects an inline second-factor proof: "totp" or
	// "backup_code". WebAuthn is not accepted inline; a session created by
	// a WebAuthn login satisfies a RequireMFA policy on its own.
	MFAType string
	// MFACode is the code for MFAType.
	MFACode string
	// Password re-confirms the account password, which satisfies a
	// recent-authentication policy (RequireMFA false, MaxAge set). It goes
	// through the same verification and rate limiting as
	// [Engine.VerifyPassword].
	Password string
}

// RoleSwitchResult is the outcome of [Engine.SwitchRole]. It is non-nil only
// on success, or alongside [ErrStepUpRequired].
type RoleSwitchResult struct {
	// AccessToken and RefreshToken are the new session's tokens. The
	// presented refresh token is spent; always store these and discard the
	// old pair.
	AccessToken  string
	RefreshToken string
	// Role is the role the new session now carries.
	Role string
	// StepUpRequired is true only together with [ErrStepUpRequired], in
	// which case no switch happened and the tokens are empty.
	StepUpRequired bool
	// StepUpFactors lists the inline factors the caller can supply, limited
	// to those the user actually has: "totp", "backup_code" for a
	// RequireMFA policy, "password" for a recent-authentication policy. It
	// may be empty when only a fresh MFA login can satisfy the policy.
	StepUpFactors []string
}

// UserRecord is the full account record returned by [UserProvider].
// It carries credential hashes, status, role, and versioning counters.
type UserRecord struct {
	UserID            string
	Identifier        string
	TenantID          string
	PasswordHash      string
	TOTPEnabled       bool
	Status            AccountStatus
	Role              string
	PermissionVersion uint32
	RoleVersion       uint32
	AccountVersion    uint32
}

// TOTPProvision holds the raw TOTP secret and otpauth:// URI returned by
// [Engine.ProvisionTOTP].
type TOTPProvision struct {
	Secret string
	URI    string
}

// TOTPSetup holds the base32-encoded TOTP secret and QR code URL returned
// by [Engine.GenerateTOTPSetup].
type TOTPSetup struct {
	SecretBase32 string
	QRCodeURL    string
}

// TOTPRecord is retrieved from [UserProvider.GetTOTPSecret]. It carries
// the encrypted secret, enabled/verified flags, and the last-used HOTP
// counter for replay protection.
type TOTPRecord struct {
	Secret          []byte
	Enabled         bool
	Verified        bool
	LastUsedCounter int64
}

// LoginOptions carries per-login options for [Engine.LoginWithOptions].
//
// RememberMe requests a durable session that may live up to
// [Config.Session.MaxSessionDuration] (or its per-mode default). When false,
// the session uses the shorter default lifetime. The flag survives the MFA
// hop: a challenge started via LoginWithOptions keeps it through
// [Engine.ConfirmLoginMFA].
//
//	Docs: docs/session.md, docs/flows.md#login-without-mfa
type LoginOptions struct {
	RememberMe bool
}

// LoginResult is returned by [Engine.LoginWithResult] and
// [Engine.ConfirmLoginMFA]. It includes tokens when authentication
// succeeds, or MFA metadata when a second factor is required.
type LoginResult struct {
	AccessToken  string
	RefreshToken string

	MFARequired bool
	MFAType     string
	MFASession  string
	// MFATypes lists every second factor the user can complete the challenge
	// with (e.g. "webauthn", "totp"). MFAType is always MFATypes[0], the
	// preferred factor. Empty when MFARequired is false.
	MFATypes []string

	// NewAccount is true when [Engine.LoginWithExternalIdentity] created the
	// account in this call. Always false for every other login.
	NewAccount bool
	// LinkedIdentity is true when [Engine.LoginWithExternalIdentity] linked
	// the external identity to an existing account in this call, because its
	// verified email matched and Config.ExternalAuth.AutoLinkVerifiedEmail
	// is on. Always false for every other login.
	LinkedIdentity bool

	// ExternalSignup is non-nil when [Engine.LoginWithExternalIdentity] was
	// called with ExternalLoginOptions.DeferSignup and the identity has no
	// account: nothing was created, no session or token was issued, and the
	// ticket's Handle is what [Engine.CompleteExternalSignup] or
	// [Engine.CancelExternalSignup] takes. Always nil for every other login.
	ExternalSignup *ExternalSignupTicket
}

// ExternalSignupTicket is the pause between "the ID token was verified and the
// identity has no account" and "the account is created", returned in
// [LoginResult.ExternalSignup] when sign-up is deferred. The application runs
// its own step (an age check, terms acceptance) and then completes or cancels
// the ticket.
//
// Handle is a single-use bearer secret: whoever holds it can create the account
// for this identity. Keep it out of logs, audit trails and URLs; goAuth stores
// only its hash and never prints it. The ticket's String and slog form redact it.
//
//	Docs: docs/external_identity.md
type ExternalSignupTicket struct {
	// Handle is opaque. It is accepted once, within SignupTicketTTL.
	Handle string
	// Provider and Subject identify the person at the provider.
	Provider string
	Subject  string
	// Email is the address the provider verified; the account is created with
	// it as its identifier.
	Email          string
	EmailVerified  bool
	IsPrivateEmail bool
	// DisplayName is the (trimmed, capped) name passed to step one.
	DisplayName string
	// ExpiresAt is when the handle stops being accepted, by the engine's clock.
	ExpiresAt time.Time
}

// String describes the ticket without its handle.
func (t ExternalSignupTicket) String() string {
	return "ExternalSignupTicket{Provider:" + t.Provider + " Handle:[redacted]}"
}

// GoString is String, so %#v does not print the handle either.
func (t ExternalSignupTicket) GoString() string { return t.String() }

// LogValue implements slog.LogValuer: a ticket logged as a value carries its
// provider and expiry, never the handle.
func (t ExternalSignupTicket) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("provider", t.Provider),
		slog.Time("expires_at", t.ExpiresAt),
		slog.String("handle", "[redacted]"),
	)
}

// ExternalSignupOptions carries the inputs of [Engine.CompleteExternalSignup].
//
//	Docs: docs/external_identity.md
type ExternalSignupOptions struct {
	// DisplayName, when non-empty, replaces the name given to step one.
	DisplayName string
	// RememberMe has the meaning it has in [LoginOptions], including the
	// session-profile rules. It is read at step two, not remembered from step
	// one.
	RememberMe bool
}

// ExternalIdentity is a link between a local account and an identity at an
// external provider such as Google or Sign in with Apple.
//
// The pair (Provider, Subject) identifies the person at the provider and is
// stable; Email is not (providers let users change it), so it is stored for
// display and never used to find an account after the link exists.
//
//	Docs: docs/external_identity.md
type ExternalIdentity struct {
	// Provider is the name from Config.ExternalAuth.Providers.
	Provider string
	// Subject is the provider's stable user identifier (the token's sub).
	Subject string
	// Email is the address the provider reported, trimmed and otherwise as
	// sent. It may be empty (Sign in with Apple omits it after the first
	// sign-in).
	Email string
	// EmailVerified is whether the provider vouched for Email.
	EmailVerified bool
	// IsPrivateEmail is true for an Apple private-relay address.
	IsPrivateEmail bool
	// DisplayName is the name the application supplied; Apple sends it to the
	// client only once, so goAuth never sees it in a token.
	DisplayName string
	// LinkedAt is when the link was made.
	LinkedAt time.Time
}

// ExternalIdentityProvider is an optional capability interface a
// [UserProvider] can additionally implement to enable external sign-in. It is
// detected via type assertion at [Builder.Build]; when
// [Config.ExternalAuth] is enabled and the user provider does not implement
// it, Build fails. Existing UserProvider implementations are unaffected while
// the feature is off.
//
// Every method is scoped to tenantID, which goAuth takes from the request
// context (the default tenant "0" when none is attached). An identity linked
// in one tenant must not be found in another.
//
// Storage contract: (tenant_id, provider, subject) is unique, so one external
// identity belongs to at most one account per tenant, and the same user may
// hold several identities.
//
//	Docs: docs/external_identity.md
type ExternalIdentityProvider interface {
	// GetUserByExternalIdentity returns the account the identity is linked
	// to within tenantID. It must return [ErrUserNotFound] when there is
	// none, and must not return an account of another tenant.
	GetUserByExternalIdentity(ctx context.Context, tenantID, provider, subject string) (UserRecord, error)

	// CreateUserWithExternalIdentity creates a password-less account
	// (input.PasswordHash is empty) and links identity to it as one atomic
	// step: either both exist afterwards or neither does. It must return
	// [ErrProviderDuplicateIdentifier] when the identifier (the email) is
	// already taken and [ErrExternalIdentityInUse] when the identity is
	// already linked; goAuth retries the sign-in once on either, because a
	// concurrent first sign-in of the same person produces them.
	CreateUserWithExternalIdentity(ctx context.Context, input CreateUserInput, identity ExternalIdentity) (UserRecord, error)

	// LinkExternalIdentity links identity to the account userID in tenantID.
	// It must return [ErrExternalIdentityInUse] when the identity is linked
	// to a different account, and succeed without change when it is already
	// linked to this one.
	LinkExternalIdentity(ctx context.Context, tenantID, userID string, identity ExternalIdentity) error

	// UnlinkExternalIdentity removes the link. Removing one that does not
	// exist is not an error.
	UnlinkExternalIdentity(ctx context.Context, tenantID, userID, provider, subject string) error

	// ListExternalIdentities returns every identity linked to the account
	// (empty slice when none).
	ListExternalIdentities(ctx context.Context, tenantID, userID string) ([]ExternalIdentity, error)
}

// EmailChangeProvider is the optional user-provider capability that
// [Config.EmailChange] needs, detected by type assertion at [Builder.Build].
// Every method is tenant-scoped.
//
//	Docs: docs/email_change.md
type EmailChangeProvider interface {
	// UpdateIdentifier sets the user's identifier to newIdentifier only if it
	// is currently oldIdentifier (compare-and-set), atomically, and bumps the
	// account's AccountVersion in the same step. It must return
	// [ErrProviderDuplicateIdentifier] when newIdentifier is taken in the
	// tenant, [ErrEmailChangeStale] when the current identifier is not
	// oldIdentifier, and [ErrUserNotFound] when the user does not exist in the
	// tenant. It does not touch external identity links, which are keyed by
	// (provider, subject) and not by email.
	UpdateIdentifier(ctx context.Context, tenantID, userID, oldIdentifier, newIdentifier string) error
}

// EmailChangeRequest is what [Engine.RequestEmailChange] returns. The
// application sends Code to the NEW address and keeps VerificationID for the
// confirm step (it may also hand it to the browser). VerificationID is safe to
// log; Code is a secret and must not be.
//
//	Docs: docs/email_change.md
type EmailChangeRequest struct {
	VerificationID string
	Code           string
}

// ConfirmEmailChangeOptions carries the optional inputs of
// [Engine.ConfirmEmailChange].
//
//	Docs: docs/email_change.md
type ConfirmEmailChangeOptions struct {
	// KeepSessionID is the caller's current session, when it confirms while
	// signed in. Unless Config.EmailChange.KeepOtherSessions is set, every
	// other session of the user is revoked and this one is kept. It is ignored
	// (and everything is revoked) unless it belongs to the same user and
	// tenant.
	KeepSessionID string
}

// EmailChangeResult is the outcome of a confirmed email change.
//
//	Docs: docs/email_change.md
type EmailChangeResult struct {
	UserID string
	// OldEmail is the address that was replaced. The application SHOULD notify
	// it: it is the only way the previous owner learns the account moved.
	OldEmail string
	NewEmail string
	// SessionsRevoked reports whether the user's other sessions were revoked.
	SessionsRevoked bool
	// WasUnverified is true when the account was still pending verification
	// when the change was requested. Its old address was never proven to belong
	// to the user, so the application MUST NOT send the old-address notice
	// (OldEmail is not a verified owner); the confirmed code proved the new
	// address, so the account is now Active and no verification mail is needed.
	WasUnverified bool
}

// ExternalLoginOptions carries the per-sign-in inputs of
// [Engine.LoginWithExternalIdentity].
//
//	Docs: docs/external_identity.md
type ExternalLoginOptions struct {
	// Nonce is the raw nonce the server issued for this sign-in and the
	// client put in its request to the provider. Required. The token's nonce
	// claim must equal it, or equal its lowercase hex SHA-256 (the form Sign
	// in with Apple's native flow carries).
	Nonce string
	// DisplayName is passed to the user provider when this sign-in creates an
	// account. Optional.
	DisplayName string
	// RememberMe has the meaning it has in [LoginOptions], including the
	// session-profile rules.
	RememberMe bool
	// DeferSignup, with Config.ExternalAuth.AllowSignup, stops the sign-in at
	// the point where an account would be created: nothing is created and the
	// result carries an [ExternalSignupTicket] (LoginResult.ExternalSignup)
	// instead of tokens. Every other branch (an existing link, an auto-link, a
	// refusal) is unchanged. Without AllowSignup it has no effect: an identity
	// with no account is [ErrExternalAccountNotFound].
	DeferSignup bool
}

// BackupCodeRecord stores the SHA-256 hash of a single backup code.
// The plaintext is never persisted.
type BackupCodeRecord struct {
	Hash [32]byte
}

// WebAuthnCredential is a stored WebAuthn/FIDO2 credential record.
// It is goAuth's own persistence shape: providers store and return it
// without importing any WebAuthn library types.
//
// CredentialID and PublicKey are opaque byte strings produced during
// registration and must be persisted byte-exact. The flag fields capture
// the authenticator state at registration/last use and are required for
// spec-mandated validation (backup-eligibility consistency); SignCount
// supports cloned-authenticator detection.
//
//	Docs: docs/webauthn.md
type WebAuthnCredential struct {
	CredentialID    []byte
	PublicKey       []byte
	AttestationType string
	Transports      []string
	UserPresent     bool
	UserVerified    bool
	BackupEligible  bool
	BackupState     bool
	AAGUID          []byte
	SignCount       uint32
	Attachment      string
	CreatedAt       time.Time
	LastUsedAt      time.Time
}

// WebAuthnCredentialProvider is an optional capability interface a
// [UserProvider] can additionally implement to enable WebAuthn support.
// It is detected via type assertion at [Builder.Build]; when
// [Config.WebAuthn] is enabled and the user provider does not implement
// it, Build fails. Existing UserProvider implementations are unaffected.
//
//	Docs: docs/webauthn.md
type WebAuthnCredentialProvider interface {
	// GetWebAuthnCredentials returns every credential registered for the
	// user (empty slice when none).
	GetWebAuthnCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error)
	// AddWebAuthnCredential persists a newly registered credential.
	AddWebAuthnCredential(ctx context.Context, userID string, credential WebAuthnCredential) error
	// UpdateWebAuthnCredentialSignCount stores the authenticator's new
	// signature counter (and implies last-used) after a successful assertion.
	UpdateWebAuthnCredentialSignCount(ctx context.Context, userID string, credentialID []byte, signCount uint32) error
	// RemoveWebAuthnCredential deletes the credential with the given ID.
	// Removing an unknown credential must return an error.
	RemoveWebAuthnCredential(ctx context.Context, userID string, credentialID []byte) error
}

// WebAuthnRegistrationChallenge is returned by
// [Engine.BeginWebAuthnRegistration]. OptionsJSON is the
// CredentialCreationOptions JSON to pass to the browser's
// navigator.credentials.create call; CeremonyID identifies the pending
// ceremony and must be echoed to [Engine.FinishWebAuthnRegistration].
type WebAuthnRegistrationChallenge struct {
	CeremonyID  string
	OptionsJSON []byte
}

// CreateUserInput is the input for [UserProvider.CreateUser].
type CreateUserInput struct {
	Identifier        string
	PasswordHash      string
	Role              string
	TenantID          string
	Status            AccountStatus
	PermissionVersion uint32
	RoleVersion       uint32
	AccountVersion    uint32
}

// CreateAccountRequest is the input for [Engine.CreateAccount].
// Identifier and Password are required; Role defaults to
// [Config.Account.DefaultRole] when empty. RememberMe only applies when
// [Config.Account.AutoLogin] is enabled and requests a durable session for
// the auto-issued tokens (see [LoginOptions]).
type CreateAccountRequest struct {
	Identifier string
	Password   string
	Role       string
	RememberMe bool
}

// CreateAccountResult is returned by [Engine.CreateAccount]. It includes
// the new UserID and, when AutoLogin is enabled, access+refresh tokens.
type CreateAccountResult struct {
	UserID       string
	Role         string
	AccessToken  string
	RefreshToken string
}

// SecurityReport is a read-only snapshot of the engine’s security posture,
// returned by [Engine.SecurityReport].
//
//	Docs: docs/security.md
type SecurityReport struct {
	ProductionMode               bool
	SigningAlgorithm             string
	ValidationMode               ValidationMode
	StrictMode                   bool
	AccessTTL                    time.Duration
	RefreshTTL                   time.Duration
	Argon2                       PasswordConfigReport
	TOTPEnabled                  bool
	BackupEnabled                bool
	DeviceBindingEnabled         bool
	RefreshRotationEnabled       bool
	RefreshReuseDetectionEnabled bool
	SessionCapsActive            bool
	RateLimitingActive           bool
	EmailVerificationActive      bool
	PasswordResetActive          bool
}

// PasswordConfigReport contains the Argon2 parameters active in the engine.
type PasswordConfigReport struct {
	Memory      uint32
	Time        uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// AuditEvent is a structured audit record emitted by the engine.
//
//	Docs: docs/audit.md
type AuditEvent = internalaudit.Event

// AuditSink receives [AuditEvent] values from the engine’s audit dispatcher.
//
//	Docs: docs/audit.md
type AuditSink = internalaudit.Sink

// NoOpSink is an [AuditSink] that silently discards all events.
type NoOpSink = internalaudit.NoOpSink

// ChannelSink is a buffered channel-based [AuditSink].
//
//	Docs: docs/audit.md
type ChannelSink = internalaudit.ChannelSink

// JSONWriterSink is an [AuditSink] that writes JSON-encoded events to an
// [io.Writer].
//
//	Docs: docs/audit.md
type JSONWriterSink = internalaudit.JSONWriterSink

// SlogAuditSink is an [AuditSink] that writes structured audit records
// through a [slog.Logger].
//
//	Docs: docs/audit.md
type SlogAuditSink = internalaudit.SlogSink

// NewChannelSink creates a [ChannelSink] with the given buffer capacity.
//
//	Docs: docs/audit.md
func NewChannelSink(buffer int) *ChannelSink {
	return internalaudit.NewChannelSink(buffer)
}

// NewJSONWriterSink creates a [JSONWriterSink] that writes to w.
//
//	Docs: docs/audit.md
func NewJSONWriterSink(w io.Writer) *JSONWriterSink {
	return internalaudit.NewJSONWriterSink(w)
}

// NewSlogAuditSink creates a [SlogAuditSink] backed by logger.
//
//	Docs: docs/audit.md
func NewSlogAuditSink(logger *slog.Logger) *SlogAuditSink {
	return internalaudit.NewSlogSink(logger)
}

// MetricID identifies a specific counter or histogram bucket in the
// in-process metrics system.
//
//	Docs: docs/metrics.md
type MetricID = internalmetrics.MetricID

const (
	// MetricLoginSuccess is an exported constant or variable used by the authentication engine.
	MetricLoginSuccess = MetricID(internalmetrics.MetricLoginSuccess)
	// MetricLoginFailure is an exported constant or variable used by the authentication engine.
	MetricLoginFailure = MetricID(internalmetrics.MetricLoginFailure)
	// MetricLoginRateLimited is an exported constant or variable used by the authentication engine.
	MetricLoginRateLimited = MetricID(internalmetrics.MetricLoginRateLimited)
	// MetricRefreshSuccess is an exported constant or variable used by the authentication engine.
	MetricRefreshSuccess = MetricID(internalmetrics.MetricRefreshSuccess)
	// MetricRefreshFailure is an exported constant or variable used by the authentication engine.
	MetricRefreshFailure = MetricID(internalmetrics.MetricRefreshFailure)
	// MetricRefreshReuseDetected is an exported constant or variable used by the authentication engine.
	MetricRefreshReuseDetected = MetricID(internalmetrics.MetricRefreshReuseDetected)
	// MetricReplayDetected is an exported constant or variable used by the authentication engine.
	MetricReplayDetected = MetricID(internalmetrics.MetricReplayDetected)
	// MetricDeviceIPMismatch is an exported constant or variable used by the authentication engine.
	MetricDeviceIPMismatch = MetricID(internalmetrics.MetricDeviceIPMismatch)
	// MetricDeviceUAMismatch is an exported constant or variable used by the authentication engine.
	MetricDeviceUAMismatch = MetricID(internalmetrics.MetricDeviceUAMismatch)
	// MetricDeviceRejected is an exported constant or variable used by the authentication engine.
	MetricDeviceRejected = MetricID(internalmetrics.MetricDeviceRejected)
	// MetricTOTPRequired is an exported constant or variable used by the authentication engine.
	MetricTOTPRequired = MetricID(internalmetrics.MetricTOTPRequired)
	// MetricTOTPFailure is an exported constant or variable used by the authentication engine.
	MetricTOTPFailure = MetricID(internalmetrics.MetricTOTPFailure)
	// MetricTOTPSuccess is an exported constant or variable used by the authentication engine.
	MetricTOTPSuccess = MetricID(internalmetrics.MetricTOTPSuccess)
	// MetricMFALoginRequired is an exported constant or variable used by the authentication engine.
	MetricMFALoginRequired = MetricID(internalmetrics.MetricMFALoginRequired)
	// MetricMFALoginSuccess is an exported constant or variable used by the authentication engine.
	MetricMFALoginSuccess = MetricID(internalmetrics.MetricMFALoginSuccess)
	// MetricMFALoginFailure is an exported constant or variable used by the authentication engine.
	MetricMFALoginFailure = MetricID(internalmetrics.MetricMFALoginFailure)
	// MetricMFAReplayAttempt is an exported constant or variable used by the authentication engine.
	MetricMFAReplayAttempt = MetricID(internalmetrics.MetricMFAReplayAttempt)
	// MetricBackupCodeUsed is an exported constant or variable used by the authentication engine.
	MetricBackupCodeUsed = MetricID(internalmetrics.MetricBackupCodeUsed)
	// MetricBackupCodeFailed is an exported constant or variable used by the authentication engine.
	MetricBackupCodeFailed = MetricID(internalmetrics.MetricBackupCodeFailed)
	// MetricBackupCodeRegenerated is an exported constant or variable used by the authentication engine.
	MetricBackupCodeRegenerated = MetricID(internalmetrics.MetricBackupCodeRegenerated)
	// MetricRateLimitHit is an exported constant or variable used by the authentication engine.
	MetricRateLimitHit = MetricID(internalmetrics.MetricRateLimitHit)
	// MetricLimiterCheck is an exported constant or variable used by the authentication engine.
	MetricLimiterCheck = MetricID(internalmetrics.MetricLimiterCheck)
	// MetricLimiterTrigger is an exported constant or variable used by the authentication engine.
	MetricLimiterTrigger = MetricID(internalmetrics.MetricLimiterTrigger)
	// MetricLimiterFailOpen is an exported constant or variable used by the authentication engine.
	MetricLimiterFailOpen = MetricID(internalmetrics.MetricLimiterFailOpen)
	// MetricLockoutTrigger is an exported constant or variable used by the authentication engine.
	MetricLockoutTrigger = MetricID(internalmetrics.MetricLockoutTrigger)
	// MetricSessionCreated is an exported constant or variable used by the authentication engine.
	MetricSessionCreated = MetricID(internalmetrics.MetricSessionCreated)
	// MetricSessionInvalidated is an exported constant or variable used by the authentication engine.
	MetricSessionInvalidated = MetricID(internalmetrics.MetricSessionInvalidated)
	// MetricLogout is an exported constant or variable used by the authentication engine.
	MetricLogout = MetricID(internalmetrics.MetricLogout)
	// MetricLogoutAll is an exported constant or variable used by the authentication engine.
	MetricLogoutAll = MetricID(internalmetrics.MetricLogoutAll)
	// MetricAccountCreationSuccess is an exported constant or variable used by the authentication engine.
	MetricAccountCreationSuccess = MetricID(internalmetrics.MetricAccountCreationSuccess)
	// MetricAccountCreationDuplicate is an exported constant or variable used by the authentication engine.
	MetricAccountCreationDuplicate = MetricID(internalmetrics.MetricAccountCreationDuplicate)
	// MetricAccountCreationRateLimited is an exported constant or variable used by the authentication engine.
	MetricAccountCreationRateLimited = MetricID(internalmetrics.MetricAccountCreationRateLimited)
	// MetricPasswordChangeSuccess is an exported constant or variable used by the authentication engine.
	MetricPasswordChangeSuccess = MetricID(internalmetrics.MetricPasswordChangeSuccess)
	// MetricPasswordChangeInvalidOld is an exported constant or variable used by the authentication engine.
	MetricPasswordChangeInvalidOld = MetricID(internalmetrics.MetricPasswordChangeInvalidOld)
	// MetricPasswordChangeReuseRejected is an exported constant or variable used by the authentication engine.
	MetricPasswordChangeReuseRejected = MetricID(internalmetrics.MetricPasswordChangeReuseRejected)
	// MetricPasswordResetRequest is an exported constant or variable used by the authentication engine.
	MetricPasswordResetRequest = MetricID(internalmetrics.MetricPasswordResetRequest)
	// MetricPasswordResetConfirmSuccess is an exported constant or variable used by the authentication engine.
	MetricPasswordResetConfirmSuccess = MetricID(internalmetrics.MetricPasswordResetConfirmSuccess)
	// MetricPasswordResetConfirmFailure is an exported constant or variable used by the authentication engine.
	MetricPasswordResetConfirmFailure = MetricID(internalmetrics.MetricPasswordResetConfirmFailure)
	// MetricPasswordResetAttemptsExceeded is an exported constant or variable used by the authentication engine.
	MetricPasswordResetAttemptsExceeded = MetricID(internalmetrics.MetricPasswordResetAttemptsExceeded)
	// MetricEmailVerificationRequest is an exported constant or variable used by the authentication engine.
	MetricEmailVerificationRequest = MetricID(internalmetrics.MetricEmailVerificationRequest)
	// MetricEmailVerificationSuccess is an exported constant or variable used by the authentication engine.
	MetricEmailVerificationSuccess = MetricID(internalmetrics.MetricEmailVerificationSuccess)
	// MetricEmailVerificationFailure is an exported constant or variable used by the authentication engine.
	MetricEmailVerificationFailure = MetricID(internalmetrics.MetricEmailVerificationFailure)
	// MetricEmailVerificationAttemptsExceeded is an exported constant or variable used by the authentication engine.
	MetricEmailVerificationAttemptsExceeded = MetricID(internalmetrics.MetricEmailVerificationAttemptsExceeded)
	// MetricAccountDisabled is an exported constant or variable used by the authentication engine.
	MetricAccountDisabled = MetricID(internalmetrics.MetricAccountDisabled)
	// MetricAccountLocked is an exported constant or variable used by the authentication engine.
	MetricAccountLocked = MetricID(internalmetrics.MetricAccountLocked)
	// MetricAccountDeleted is an exported constant or variable used by the authentication engine.
	MetricAccountDeleted = MetricID(internalmetrics.MetricAccountDeleted)
	// MetricValidateLatency is an exported constant or variable used by the authentication engine.
	MetricValidateLatency = MetricID(internalmetrics.MetricValidateLatency)

	metricIDCount = internalmetrics.MetricIDCount
)

// Metrics holds atomic counters and optional latency histograms.
//
//	Docs: docs/metrics.md
type Metrics = internalmetrics.Metrics

// MetricsSnapshot is a point-in-time deep copy of all metrics.
//
//	Docs: docs/metrics.md
type MetricsSnapshot = internalmetrics.Snapshot

// NewMetrics creates a new [Metrics] instance configured by the given
// [MetricsConfig]. When Enabled is false, all operations are no-ops.
//
//	Docs: docs/metrics.md
func NewMetrics(cfg MetricsConfig) *Metrics {
	return internalmetrics.New(internalmetrics.Config{
		Enabled:       cfg.Enabled,
		EnableLatency: cfg.EnableLatencyHistograms,
	})
}
