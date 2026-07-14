package goAuth

import (
	"context"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/MrEthical07/goAuth/internal"
	internalflows "github.com/MrEthical07/goAuth/internal/flows"
	"github.com/MrEthical07/goAuth/internal/stores"
)

// webAuthnRP aliases the WebAuthn relying-party handle so engine.go stays
// free of library imports.
type webAuthnRP = webauthn.WebAuthn

const (
	auditEventWebAuthnRegisterSuccess   = "webauthn_register_success"
	auditEventWebAuthnRegisterFailure   = "webauthn_register_failure"
	auditEventWebAuthnCredentialRemoved = "webauthn_credential_removed"
)

// BeginWebAuthnRegistration starts a WebAuthn credential-registration
// ceremony for the user. The returned OptionsJSON is passed to the browser's
// navigator.credentials.create; the authenticator's response is completed
// with [Engine.FinishWebAuthnRegistration] using the returned CeremonyID.
//
// The caller is responsible for authenticating the user before starting a
// registration ceremony (same contract as [Engine.ProvisionTOTP]).
//
//	Flow:        WebAuthn registration (step 1 of 2)
//	Docs:        docs/webauthn.md
//	Security:    ceremony is single-use and expires after WebAuthn.CeremonyTTL.
func (e *Engine) BeginWebAuthnRegistration(ctx context.Context, userID string) (*WebAuthnRegistrationChallenge, error) {
	e.ensureFlowDeps()
	optionsJSON, ceremonyID, err := e.flows.BeginWebAuthnRegistration(ctx, userID)
	if err != nil {
		return nil, mapToAuthError(err)
	}
	return &WebAuthnRegistrationChallenge{
		CeremonyID:  ceremonyID,
		OptionsJSON: optionsJSON,
	}, nil
}

// FinishWebAuthnRegistration verifies the authenticator's attestation
// response (raw JSON from navigator.credentials.create) and persists the new
// credential via the [WebAuthnCredentialProvider]. Returns the stored
// credential record.
//
//	Flow:        WebAuthn registration (step 2 of 2)
//	Docs:        docs/webauthn.md
//	Security:    origin/RPID checks per config; ceremony consumed on any outcome.
func (e *Engine) FinishWebAuthnRegistration(ctx context.Context, userID, ceremonyID string, responseJSON []byte) (*WebAuthnCredential, error) {
	e.ensureFlowDeps()
	credential, err := e.flows.FinishWebAuthnRegistration(ctx, userID, ceremonyID, responseJSON)
	if err != nil {
		return nil, mapToAuthError(err)
	}
	stored := fromLibWebAuthnCredential(*credential, time.Now())
	return &stored, nil
}

// ListWebAuthnCredentials returns the user's registered WebAuthn credentials.
//
//	Docs: docs/webauthn.md
func (e *Engine) ListWebAuthnCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error) {
	e.ensureFlowDeps()
	if e == nil || !e.config.WebAuthn.Enabled || e.webauthnProvider == nil {
		return nil, ErrWebAuthnDisabled
	}
	if userID == "" {
		return nil, mapToAuthError(ErrUserNotFound)
	}
	credentials, err := e.webauthnProvider.GetWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, ErrWebAuthnUnavailable
	}
	return credentials, nil
}

// RemoveWebAuthnCredential deletes one of the user's registered credentials.
// Removing an unknown credential returns [ErrWebAuthnCredentialNotFound].
//
//	Docs: docs/webauthn.md
func (e *Engine) RemoveWebAuthnCredential(ctx context.Context, userID string, credentialID []byte) error {
	e.ensureFlowDeps()
	if e == nil || !e.config.WebAuthn.Enabled || e.webauthnProvider == nil {
		return ErrWebAuthnDisabled
	}
	if userID == "" || len(credentialID) == 0 {
		return ErrWebAuthnCredentialNotFound
	}
	credentials, err := e.webauthnProvider.GetWebAuthnCredentials(ctx, userID)
	if err != nil {
		return ErrWebAuthnUnavailable
	}
	found := false
	for _, credential := range credentials {
		if bytesEqual(credential.CredentialID, credentialID) {
			found = true
			break
		}
	}
	if !found {
		return ErrWebAuthnCredentialNotFound
	}
	if err := e.webauthnProvider.RemoveWebAuthnCredential(ctx, userID, credentialID); err != nil {
		return ErrWebAuthnUnavailable
	}
	e.emitAudit(ctx, auditEventWebAuthnCredentialRemoved, true, userID, tenantIDFromContext(ctx), "", nil, nil)
	return nil
}

// BeginWebAuthnLogin starts the assertion ceremony for a pending MFA login
// challenge (the MFASession returned by a login whose MFATypes includes
// "webauthn"). The returned JSON is passed to navigator.credentials.get;
// the assertion response completes the login via
// [Engine.ConfirmLoginMFAWithType] with mfaType "webauthn" and the raw
// response JSON as the code argument.
//
//	Flow:        WebAuthn MFA login (assertion options)
//	Docs:        docs/webauthn.md, docs/mfa.md
//	Security:    bound to the MFA challenge; single-use; expires with CeremonyTTL.
func (e *Engine) BeginWebAuthnLogin(ctx context.Context, challengeID string) ([]byte, error) {
	e.ensureFlowDeps()
	optionsJSON, err := e.flows.BeginWebAuthnLogin(ctx, challengeID)
	if err != nil {
		return nil, mapToAuthError(err)
	}
	return optionsJSON, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// toLibWebAuthnCredential reconstructs the library credential shape from the
// provider's stored record. Flags must round-trip exactly: the library's
// login validation compares the stored backup-eligibility flag against the
// assertion's authenticator data.
func toLibWebAuthnCredential(c WebAuthnCredential) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
	for _, t := range c.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}
	return webauthn.Credential{
		ID:              c.CredentialID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       transports,
		Flags: webauthn.CredentialFlags{
			UserPresent:    c.UserPresent,
			UserVerified:   c.UserVerified,
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:     c.AAGUID,
			SignCount:  c.SignCount,
			Attachment: protocol.AuthenticatorAttachment(c.Attachment),
		},
	}
}

func fromLibWebAuthnCredential(credential webauthn.Credential, now time.Time) WebAuthnCredential {
	transports := make([]string, 0, len(credential.Transport))
	for _, t := range credential.Transport {
		transports = append(transports, string(t))
	}
	return WebAuthnCredential{
		CredentialID:    credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		Transports:      transports,
		UserPresent:     credential.Flags.UserPresent,
		UserVerified:    credential.Flags.UserVerified,
		BackupEligible:  credential.Flags.BackupEligible,
		BackupState:     credential.Flags.BackupState,
		AAGUID:          credential.Authenticator.AAGUID,
		SignCount:       credential.Authenticator.SignCount,
		Attachment:      string(credential.Authenticator.Attachment),
		CreatedAt:       now,
		LastUsedAt:      now,
	}
}

func mapWebAuthnSessionStoreError(err error) error {
	if errors.Is(err, stores.ErrWebAuthnSessionNotFound) {
		return ErrWebAuthnCeremonyExpired
	}
	return ErrWebAuthnUnavailable
}

func (e *Engine) webauthnFlowDeps() internalflows.WebAuthnDeps {
	var cfg Config
	if e != nil {
		cfg = e.config
	}

	deps := internalflows.WebAuthnDeps{
		Enabled:                    cfg.WebAuthn.Enabled,
		RequireForLogin:            cfg.WebAuthn.RequireForLogin,
		RejectClonedAuthenticators: cfg.WebAuthn.RejectClonedAuthenticators,
		CeremonyTTL:                cfg.WebAuthn.CeremonyTTL,
		TenantIDFromContext:        tenantIDFromContext,
		Now:                        time.Now,
		MapSessionStoreError:       mapWebAuthnSessionStoreError,
		MapMFAStoreError:           mapMFALoginStoreError,
		Errors: internalflows.WebAuthnErrors{
			EngineNotReady:     ErrEngineNotReady,
			Disabled:           ErrWebAuthnDisabled,
			Invalid:            ErrWebAuthnInvalid,
			CeremonyExpired:    ErrWebAuthnCeremonyExpired,
			CloneDetected:      ErrWebAuthnCloneDetected,
			CredentialNotFound: ErrWebAuthnCredentialNotFound,
			Unavailable:        ErrWebAuthnUnavailable,
			UserNotFound:       ErrUserNotFound,
		},
		Events: internalflows.WebAuthnEvents{
			RegisterSuccess: auditEventWebAuthnRegisterSuccess,
			RegisterFailure: auditEventWebAuthnRegisterFailure,
		},
	}
	if e == nil {
		return deps
	}

	deps.WebAuthn = e.webauthnRP
	deps.MetricInc = func(id int) { e.metricInc(MetricID(id)) }
	deps.EmitAudit = e.emitAudit
	deps.NewCeremonyID = func() (string, error) {
		id, err := internal.NewSessionID()
		if err != nil {
			return "", err
		}
		return id.String(), nil
	}

	if e.userProvider != nil {
		deps.GetUserByID = func(userID string) (internalflows.LoginUserRecord, error) {
			user, err := e.userProvider.GetUserByID(userID)
			if err != nil {
				return internalflows.LoginUserRecord{}, err
			}
			return toFlowLoginUser(user), nil
		}
	}
	if e.webauthnProvider != nil {
		deps.GetCredentials = func(ctx context.Context, userID string) ([]webauthn.Credential, error) {
			records, err := e.webauthnProvider.GetWebAuthnCredentials(ctx, userID)
			if err != nil {
				return nil, err
			}
			credentials := make([]webauthn.Credential, 0, len(records))
			for _, record := range records {
				credentials = append(credentials, toLibWebAuthnCredential(record))
			}
			return credentials, nil
		}
		deps.AddCredential = func(ctx context.Context, userID string, credential webauthn.Credential) error {
			return e.webauthnProvider.AddWebAuthnCredential(ctx, userID, fromLibWebAuthnCredential(credential, time.Now()))
		}
		deps.UpdateCredentialSignCount = e.webauthnProvider.UpdateWebAuthnCredentialSignCount
	}
	if e.webauthnSessions != nil {
		deps.SaveSession = func(ctx context.Context, ceremonyID string, record *internalflows.WebAuthnSessionRecord, ttl time.Duration) error {
			return e.webauthnSessions.Save(ctx, ceremonyID, &stores.WebAuthnSession{
				UserID:      record.UserID,
				TenantID:    record.TenantID,
				Purpose:     record.Purpose,
				SessionJSON: record.SessionJSON,
			}, ttl)
		}
		deps.ConsumeSession = func(ctx context.Context, ceremonyID string) (*internalflows.WebAuthnSessionRecord, error) {
			record, err := e.webauthnSessions.Consume(ctx, ceremonyID)
			if err != nil {
				return nil, err
			}
			return &internalflows.WebAuthnSessionRecord{
				UserID:      record.UserID,
				TenantID:    record.TenantID,
				Purpose:     record.Purpose,
				SessionJSON: record.SessionJSON,
			}, nil
		}
	}
	if e.mfaLoginStore != nil {
		deps.GetMFAChallenge = func(ctx context.Context, challengeID string) (*internalflows.MFALoginChallengeRecord, error) {
			record, err := e.mfaLoginStore.Get(ctx, challengeID)
			if err != nil {
				return nil, err
			}
			return &internalflows.MFALoginChallengeRecord{
				UserID:     record.UserID,
				TenantID:   record.TenantID,
				ExpiresAt:  record.ExpiresAt,
				Attempts:   record.Attempts,
				RememberMe: record.RememberMe,
			}, nil
		}
	}
	return deps
}
