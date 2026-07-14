package flows

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthn ceremony purposes (flow-local mirror of the store constants).
const (
	WebAuthnPurposeRegistration byte = 1
	WebAuthnPurposeLogin        byte = 2
)

// WebAuthnSessionRecord is a flow-local pending-ceremony record.
type WebAuthnSessionRecord struct {
	UserID      string
	TenantID    string
	Purpose     byte
	SessionJSON []byte
}

// WebAuthnEvents carries audit event names used by WebAuthn flows.
type WebAuthnEvents struct {
	RegisterSuccess string
	RegisterFailure string
}

// WebAuthnErrors carries host-level sentinel errors used by WebAuthn flows.
type WebAuthnErrors struct {
	EngineNotReady     error
	Disabled           error
	Invalid            error
	CeremonyExpired    error
	CloneDetected      error
	CredentialNotFound error
	Unavailable        error
	UserNotFound       error
}

// WebAuthnDeps captures WebAuthn ceremony dependencies.
type WebAuthnDeps struct {
	Enabled                    bool
	RequireForLogin            bool
	RejectClonedAuthenticators bool
	CeremonyTTL                time.Duration

	WebAuthn *webauthn.WebAuthn

	TenantIDFromContext func(context.Context) string
	Now                 func() time.Time
	NewCeremonyID       func() (string, error)

	GetUserByID               func(string) (LoginUserRecord, error)
	GetCredentials            func(context.Context, string) ([]webauthn.Credential, error)
	AddCredential             func(context.Context, string, webauthn.Credential) error
	UpdateCredentialSignCount func(context.Context, string, []byte, uint32) error

	SaveSession          func(context.Context, string, *WebAuthnSessionRecord, time.Duration) error
	ConsumeSession       func(context.Context, string) (*WebAuthnSessionRecord, error)
	MapSessionStoreError func(error) error

	GetMFAChallenge  func(context.Context, string) (*MFALoginChallengeRecord, error)
	MapMFAStoreError func(error) error

	MetricInc func(int)
	EmitAudit func(context.Context, string, bool, string, string, string, error, func() map[string]string)

	Events WebAuthnEvents
	Errors WebAuthnErrors
}

// webAuthnFlowUser adapts a goAuth user + stored credentials to the
// webauthn.User interface. The user handle is the stable user ID.
type webAuthnFlowUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u webAuthnFlowUser) WebAuthnID() []byte                         { return u.id }
func (u webAuthnFlowUser) WebAuthnName() string                       { return u.name }
func (u webAuthnFlowUser) WebAuthnDisplayName() string                { return u.displayName }
func (u webAuthnFlowUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func webAuthnUserFor(user LoginUserRecord, credentials []webauthn.Credential) webAuthnFlowUser {
	name := user.Identifier
	if name == "" {
		name = user.UserID
	}
	return webAuthnFlowUser{
		id:          []byte(user.UserID),
		name:        name,
		displayName: name,
		credentials: credentials,
	}
}

func (deps *WebAuthnDeps) applyDefaults() {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.MetricInc == nil {
		deps.MetricInc = func(int) {}
	}
	if deps.EmitAudit == nil {
		deps.EmitAudit = func(context.Context, string, bool, string, string, string, error, func() map[string]string) {}
	}
	if deps.TenantIDFromContext == nil {
		deps.TenantIDFromContext = func(context.Context) string { return "" }
	}
	if deps.MapSessionStoreError == nil {
		deps.MapSessionStoreError = func(error) error { return deps.Errors.Unavailable }
	}
	if deps.MapMFAStoreError == nil {
		deps.MapMFAStoreError = func(error) error { return deps.Errors.Unavailable }
	}
}

func (deps *WebAuthnDeps) ceremonyTTL() time.Duration {
	if deps.CeremonyTTL > 0 {
		return deps.CeremonyTTL
	}
	return 2 * time.Minute
}

// RunBeginWebAuthnRegistration starts a credential-registration ceremony for
// the user and returns the CredentialCreation options JSON plus the ceremony
// ID the caller must echo back to finish.
func RunBeginWebAuthnRegistration(ctx context.Context, userID string, deps WebAuthnDeps) ([]byte, string, error) {
	deps.applyDefaults()
	if !deps.Enabled {
		return nil, "", deps.Errors.Disabled
	}
	if deps.WebAuthn == nil || deps.GetUserByID == nil || deps.GetCredentials == nil ||
		deps.SaveSession == nil || deps.NewCeremonyID == nil {
		return nil, "", deps.Errors.EngineNotReady
	}
	if userID == "" {
		return nil, "", deps.Errors.UserNotFound
	}

	user, err := deps.GetUserByID(userID)
	if err != nil {
		return nil, "", deps.Errors.UserNotFound
	}

	credentials, err := deps.GetCredentials(ctx, userID)
	if err != nil {
		return nil, "", deps.Errors.Unavailable
	}

	exclusions := make([]protocol.CredentialDescriptor, 0, len(credentials))
	for _, cred := range credentials {
		exclusions = append(exclusions, cred.Descriptor())
	}

	options, session, err := deps.WebAuthn.BeginRegistration(
		webAuthnUserFor(user, credentials),
		webauthn.WithExclusions(exclusions),
	)
	if err != nil {
		return nil, "", deps.Errors.Unavailable
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return nil, "", deps.Errors.Unavailable
	}
	ceremonyID, err := deps.NewCeremonyID()
	if err != nil {
		return nil, "", deps.Errors.Unavailable
	}

	record := &WebAuthnSessionRecord{
		UserID:      userID,
		TenantID:    deps.TenantIDFromContext(ctx),
		Purpose:     WebAuthnPurposeRegistration,
		SessionJSON: sessionJSON,
	}
	if err := deps.SaveSession(ctx, ceremonyID, record, deps.ceremonyTTL()); err != nil {
		return nil, "", deps.MapSessionStoreError(err)
	}

	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, "", deps.Errors.Unavailable
	}
	return optionsJSON, ceremonyID, nil
}

// RunFinishWebAuthnRegistration verifies the authenticator's attestation
// response and returns the credential to persist. The ceremony session is
// consumed regardless of outcome (single use).
func RunFinishWebAuthnRegistration(
	ctx context.Context,
	userID string,
	ceremonyID string,
	responseJSON []byte,
	deps WebAuthnDeps,
) (*webauthn.Credential, error) {
	deps.applyDefaults()
	if !deps.Enabled {
		return nil, deps.Errors.Disabled
	}
	if deps.WebAuthn == nil || deps.GetUserByID == nil || deps.GetCredentials == nil ||
		deps.ConsumeSession == nil || deps.AddCredential == nil {
		return nil, deps.Errors.EngineNotReady
	}
	if userID == "" || ceremonyID == "" || len(responseJSON) == 0 {
		return nil, deps.Errors.Invalid
	}

	tenantID := deps.TenantIDFromContext(ctx)
	failAudit := func(cause error, reason string) {
		deps.EmitAudit(ctx, deps.Events.RegisterFailure, false, userID, tenantID, "", cause, func() map[string]string {
			return map[string]string{"reason": reason}
		})
	}

	record, err := deps.ConsumeSession(ctx, ceremonyID)
	if err != nil {
		mapped := deps.MapSessionStoreError(err)
		failAudit(mapped, "ceremony_session")
		return nil, mapped
	}
	if record.Purpose != WebAuthnPurposeRegistration || record.UserID != userID ||
		(tenantID != "" && record.TenantID != "" && record.TenantID != tenantID) {
		failAudit(deps.Errors.CeremonyExpired, "ceremony_mismatch")
		return nil, deps.Errors.CeremonyExpired
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(record.SessionJSON, &session); err != nil {
		failAudit(deps.Errors.Unavailable, "ceremony_corrupt")
		return nil, deps.Errors.Unavailable
	}

	user, err := deps.GetUserByID(userID)
	if err != nil {
		failAudit(deps.Errors.UserNotFound, "user_lookup")
		return nil, deps.Errors.UserNotFound
	}
	credentials, err := deps.GetCredentials(ctx, userID)
	if err != nil {
		failAudit(deps.Errors.Unavailable, "credential_lookup")
		return nil, deps.Errors.Unavailable
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(responseJSON)
	if err != nil {
		failAudit(deps.Errors.Invalid, "attestation_parse")
		return nil, deps.Errors.Invalid
	}

	credential, err := deps.WebAuthn.CreateCredential(webAuthnUserFor(user, credentials), session, parsed)
	if err != nil {
		failAudit(deps.Errors.Invalid, "attestation_verify")
		return nil, deps.Errors.Invalid
	}

	for _, existing := range credentials {
		if bytes.Equal(existing.ID, credential.ID) {
			failAudit(deps.Errors.Invalid, "credential_duplicate")
			return nil, deps.Errors.Invalid
		}
	}

	if err := deps.AddCredential(ctx, userID, *credential); err != nil {
		failAudit(deps.Errors.Unavailable, "credential_store")
		return nil, deps.Errors.Unavailable
	}

	deps.EmitAudit(ctx, deps.Events.RegisterSuccess, true, userID, tenantID, "", nil, nil)
	return credential, nil
}

// RunBeginWebAuthnLogin starts the assertion ceremony for a pending MFA login
// challenge and returns the CredentialRequest options JSON. The ceremony
// session is keyed by the challenge ID; confirming the login consumes it.
func RunBeginWebAuthnLogin(ctx context.Context, challengeID string, deps WebAuthnDeps) ([]byte, error) {
	deps.applyDefaults()
	if !deps.Enabled || !deps.RequireForLogin {
		return nil, deps.Errors.Disabled
	}
	if deps.WebAuthn == nil || deps.GetUserByID == nil || deps.GetCredentials == nil ||
		deps.SaveSession == nil || deps.GetMFAChallenge == nil {
		return nil, deps.Errors.EngineNotReady
	}
	if challengeID == "" {
		return nil, deps.Errors.Invalid
	}

	challenge, err := deps.GetMFAChallenge(ctx, challengeID)
	if err != nil {
		return nil, deps.MapMFAStoreError(err)
	}
	if tenant := deps.TenantIDFromContext(ctx); tenant != "" && challenge.TenantID != "" && tenant != challenge.TenantID {
		return nil, deps.Errors.Invalid
	}

	user, err := deps.GetUserByID(challenge.UserID)
	if err != nil {
		return nil, deps.Errors.UserNotFound
	}
	credentials, err := deps.GetCredentials(ctx, challenge.UserID)
	if err != nil {
		return nil, deps.Errors.Unavailable
	}
	if len(credentials) == 0 {
		return nil, deps.Errors.CredentialNotFound
	}

	options, session, err := deps.WebAuthn.BeginLogin(webAuthnUserFor(user, credentials))
	if err != nil {
		return nil, deps.Errors.Unavailable
	}
	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return nil, deps.Errors.Unavailable
	}

	record := &WebAuthnSessionRecord{
		UserID:      challenge.UserID,
		TenantID:    challenge.TenantID,
		Purpose:     WebAuthnPurposeLogin,
		SessionJSON: sessionJSON,
	}
	if err := deps.SaveSession(ctx, challengeID, record, deps.ceremonyTTL()); err != nil {
		return nil, deps.MapSessionStoreError(err)
	}

	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, deps.Errors.Unavailable
	}
	return optionsJSON, nil
}

// RunConfirmWebAuthnAssertion verifies an assertion response for the pending
// login ceremony keyed by challengeID. It consumes the ceremony session
// (single use), enforces sign-count regression policy, and persists the new
// sign count. Called from the MFA confirm flow; challenge attempt limiting
// stays with the caller.
func RunConfirmWebAuthnAssertion(
	ctx context.Context,
	challengeID string,
	userID string,
	assertionJSON []byte,
	deps WebAuthnDeps,
) error {
	deps.applyDefaults()
	if !deps.Enabled {
		return deps.Errors.Disabled
	}
	if deps.WebAuthn == nil || deps.GetUserByID == nil || deps.GetCredentials == nil ||
		deps.ConsumeSession == nil || deps.UpdateCredentialSignCount == nil {
		return deps.Errors.EngineNotReady
	}
	if challengeID == "" || userID == "" || len(assertionJSON) == 0 {
		return deps.Errors.Invalid
	}

	record, err := deps.ConsumeSession(ctx, challengeID)
	if err != nil {
		return deps.MapSessionStoreError(err)
	}
	if record.Purpose != WebAuthnPurposeLogin || record.UserID != userID {
		return deps.Errors.CeremonyExpired
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(record.SessionJSON, &session); err != nil {
		return deps.Errors.Unavailable
	}

	user, err := deps.GetUserByID(userID)
	if err != nil {
		return deps.Errors.UserNotFound
	}
	credentials, err := deps.GetCredentials(ctx, userID)
	if err != nil {
		return deps.Errors.Unavailable
	}
	if len(credentials) == 0 {
		return deps.Errors.CredentialNotFound
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(assertionJSON)
	if err != nil {
		return deps.Errors.Invalid
	}

	credential, err := deps.WebAuthn.ValidateLogin(webAuthnUserFor(user, credentials), session, parsed)
	if err != nil {
		return deps.Errors.Invalid
	}

	if credential.Authenticator.CloneWarning && deps.RejectClonedAuthenticators {
		return deps.Errors.CloneDetected
	}

	if err := deps.UpdateCredentialSignCount(ctx, userID, credential.ID, credential.Authenticator.SignCount); err != nil {
		return deps.Errors.Unavailable
	}
	return nil
}
