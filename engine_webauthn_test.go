package goAuth

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/descope/virtualwebauthn"
)

// webauthnMockProvider extends the shared mockUserProvider with the
// WebAuthnCredentialProvider capability.
type webauthnMockProvider struct {
	*mockUserProvider
	credMu      sync.Mutex
	credentials map[string][]WebAuthnCredential
	credErr     error
}

func newWebAuthnMockProvider(t *testing.T) *webauthnMockProvider {
	t.Helper()
	return &webauthnMockProvider{
		mockUserProvider: newHardeningUserProvider(t),
		credentials:      map[string][]WebAuthnCredential{},
	}
}

func (m *webauthnMockProvider) GetWebAuthnCredentials(_ context.Context, userID string) ([]WebAuthnCredential, error) {
	m.credMu.Lock()
	defer m.credMu.Unlock()
	if m.credErr != nil {
		return nil, m.credErr
	}
	out := make([]WebAuthnCredential, len(m.credentials[userID]))
	copy(out, m.credentials[userID])
	return out, nil
}

func (m *webauthnMockProvider) AddWebAuthnCredential(_ context.Context, userID string, credential WebAuthnCredential) error {
	m.credMu.Lock()
	defer m.credMu.Unlock()
	if m.credErr != nil {
		return m.credErr
	}
	m.credentials[userID] = append(m.credentials[userID], credential)
	return nil
}

func (m *webauthnMockProvider) UpdateWebAuthnCredentialSignCount(_ context.Context, userID string, credentialID []byte, signCount uint32) error {
	m.credMu.Lock()
	defer m.credMu.Unlock()
	for i := range m.credentials[userID] {
		if bytes.Equal(m.credentials[userID][i].CredentialID, credentialID) {
			m.credentials[userID][i].SignCount = signCount
			return nil
		}
	}
	return errors.New("credential not found")
}

func (m *webauthnMockProvider) RemoveWebAuthnCredential(_ context.Context, userID string, credentialID []byte) error {
	m.credMu.Lock()
	defer m.credMu.Unlock()
	records := m.credentials[userID]
	for i := range records {
		if bytes.Equal(records[i].CredentialID, credentialID) {
			m.credentials[userID] = append(records[:i], records[i+1:]...)
			return nil
		}
	}
	return errors.New("credential not found")
}

func (m *webauthnMockProvider) setSignCount(userID string, credentialID []byte, signCount uint32) {
	m.credMu.Lock()
	defer m.credMu.Unlock()
	for i := range m.credentials[userID] {
		if bytes.Equal(m.credentials[userID][i].CredentialID, credentialID) {
			m.credentials[userID][i].SignCount = signCount
		}
	}
}

func webauthnTestConfig() Config {
	cfg := accountTestConfig()
	cfg.WebAuthn.Enabled = true
	cfg.WebAuthn.RPID = "example.com"
	cfg.WebAuthn.RPDisplayName = "Example"
	cfg.WebAuthn.RPOrigins = []string{"https://example.com"}
	cfg.WebAuthn.RequireForLogin = true
	return cfg
}

func webauthnTestRP() virtualwebauthn.RelyingParty {
	return virtualwebauthn.RelyingParty{ID: "example.com", Name: "Example", Origin: "https://example.com"}
}

func registerWebAuthnCredential(
	t *testing.T,
	engine *Engine,
	rp virtualwebauthn.RelyingParty,
	authenticator virtualwebauthn.Authenticator,
	credential virtualwebauthn.Credential,
	userID string,
) *WebAuthnCredential {
	t.Helper()
	ctx := context.Background()

	challenge, err := engine.BeginWebAuthnRegistration(ctx, userID)
	if err != nil {
		t.Fatalf("BeginWebAuthnRegistration failed: %v", err)
	}
	options, err := virtualwebauthn.ParseAttestationOptions(string(challenge.OptionsJSON))
	if err != nil {
		t.Fatalf("parse attestation options: %v", err)
	}
	response := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *options)
	stored, err := engine.FinishWebAuthnRegistration(ctx, userID, challenge.CeremonyID, []byte(response))
	if err != nil {
		t.Fatalf("FinishWebAuthnRegistration failed: %v", err)
	}
	return stored
}

func beginWebAuthnAssertion(
	t *testing.T,
	engine *Engine,
	rp virtualwebauthn.RelyingParty,
	authenticator virtualwebauthn.Authenticator,
	credential virtualwebauthn.Credential,
	challengeID string,
) string {
	t.Helper()
	optionsJSON, err := engine.BeginWebAuthnLogin(context.Background(), challengeID)
	if err != nil {
		t.Fatalf("BeginWebAuthnLogin failed: %v", err)
	}
	options, err := virtualwebauthn.ParseAssertionOptions(string(optionsJSON))
	if err != nil {
		t.Fatalf("parse assertion options: %v", err)
	}
	return virtualwebauthn.CreateAssertionResponse(rp, authenticator, credential, *options)
}

func TestWebAuthnBuildRequiresProviderCapability(t *testing.T) {
	cfg := webauthnTestConfig()
	up := newHardeningUserProvider(t) // plain UserProvider, no capability
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	_, err := New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"perm.read"}).
		WithRoles(map[string][]string{"member": {}, "admin": {"perm.read"}}).
		WithUserProvider(up).
		Build()
	if err == nil || !strings.Contains(err.Error(), "WebAuthnCredentialProvider") {
		t.Fatalf("expected capability build failure, got %v", err)
	}
}

func TestWebAuthnDisabledSurfaceReturnsDisabled(t *testing.T) {
	cfg := accountTestConfig() // webauthn not enabled
	up := newWebAuthnMockProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	if _, err := engine.BeginWebAuthnRegistration(context.Background(), "u1"); !errors.Is(err, ErrWebAuthnDisabled) {
		t.Fatalf("expected ErrWebAuthnDisabled, got %v", err)
	}
	if _, err := engine.ListWebAuthnCredentials(context.Background(), "u1"); !errors.Is(err, ErrWebAuthnDisabled) {
		t.Fatalf("expected ErrWebAuthnDisabled from list, got %v", err)
	}
}

func TestWebAuthnRegistrationAndMFALoginEndToEnd(t *testing.T) {
	cfg := webauthnTestConfig()
	up := newWebAuthnMockProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := context.Background()

	rp := webauthnTestRP()
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	stored := registerWebAuthnCredential(t, engine, rp, authenticator, credential, "u1")
	if len(stored.CredentialID) == 0 || len(stored.PublicKey) == 0 {
		t.Fatalf("stored credential missing material: %+v", stored)
	}

	list, err := engine.ListWebAuthnCredentials(ctx, "u1")
	if err != nil || len(list) != 1 {
		t.Fatalf("expected one stored credential, got %d (err=%v)", len(list), err)
	}

	// Login now requires the webauthn factor.
	result, err := engine.LoginWithResult(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if !result.MFARequired || result.MFAType != "webauthn" {
		t.Fatalf("expected webauthn MFA requirement, got %+v", result)
	}
	if len(result.MFATypes) != 1 || result.MFATypes[0] != "webauthn" {
		t.Fatalf("expected MFATypes [webauthn], got %v", result.MFATypes)
	}

	assertion := beginWebAuthnAssertion(t, engine, rp, authenticator, credential, result.MFASession)
	confirmed, err := engine.ConfirmLoginMFAWithType(ctx, result.MFASession, assertion, "webauthn")
	if err != nil {
		t.Fatalf("webauthn MFA confirm failed: %v", err)
	}
	if confirmed.AccessToken == "" || confirmed.RefreshToken == "" {
		t.Fatal("expected tokens after webauthn confirm")
	}

	if _, err := engine.Validate(ctx, confirmed.AccessToken, ModeStrict); err != nil {
		t.Fatalf("strict validation of webauthn-confirmed session failed: %v", err)
	}
}

func TestWebAuthnAssertionFromWrongOriginRejected(t *testing.T) {
	cfg := webauthnTestConfig()
	up := newWebAuthnMockProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := context.Background()

	rp := webauthnTestRP()
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	registerWebAuthnCredential(t, engine, rp, authenticator, credential, "u1")

	result, err := engine.LoginWithResult(ctx, "alice", "correct-password-123")
	if err != nil || !result.MFARequired {
		t.Fatalf("expected MFA-required login, got %+v (err=%v)", result, err)
	}

	evilRP := virtualwebauthn.RelyingParty{ID: "example.com", Name: "Example", Origin: "https://evil.example.net"}
	assertion := beginWebAuthnAssertion(t, engine, evilRP, authenticator, credential, result.MFASession)
	if _, err := engine.ConfirmLoginMFAWithType(ctx, result.MFASession, assertion, "webauthn"); !errors.Is(err, ErrMFALoginInvalid) {
		t.Fatalf("expected wrong-origin assertion to fail with ErrMFALoginInvalid, got %v", err)
	}
}

func TestWebAuthnCeremonyIsSingleUse(t *testing.T) {
	cfg := webauthnTestConfig()
	up := newWebAuthnMockProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := context.Background()

	rp := webauthnTestRP()
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	registerWebAuthnCredential(t, engine, rp, authenticator, credential, "u1")

	result, err := engine.LoginWithResult(ctx, "alice", "correct-password-123")
	if err != nil || !result.MFARequired {
		t.Fatalf("expected MFA-required login, got %+v (err=%v)", result, err)
	}

	// A failed confirm consumes the ceremony session...
	assertion := beginWebAuthnAssertion(t, engine, rp, authenticator, credential, result.MFASession)
	if _, err := engine.ConfirmLoginMFAWithType(ctx, result.MFASession, "not-json", "webauthn"); !errors.Is(err, ErrMFALoginInvalid) {
		t.Fatalf("expected garbage assertion to fail invalid, got %v", err)
	}
	// ...so replaying even a valid response without a fresh Begin is rejected.
	if _, err := engine.ConfirmLoginMFAWithType(ctx, result.MFASession, assertion, "webauthn"); !errors.Is(err, ErrWebAuthnCeremonyExpired) {
		t.Fatalf("expected consumed ceremony to fail with ErrWebAuthnCeremonyExpired, got %v", err)
	}

	// A fresh Begin issues a new challenge and the login still completes.
	assertion = beginWebAuthnAssertion(t, engine, rp, authenticator, credential, result.MFASession)
	if _, err := engine.ConfirmLoginMFAWithType(ctx, result.MFASession, assertion, "webauthn"); err != nil {
		t.Fatalf("expected fresh ceremony to succeed, got %v", err)
	}
}

func TestWebAuthnConfirmWithoutBeginFailsWithoutConsumingAttempts(t *testing.T) {
	cfg := webauthnTestConfig()
	cfg.TOTP.MFALoginMaxAttempts = 2
	up := newWebAuthnMockProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := context.Background()

	rp := webauthnTestRP()
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	registerWebAuthnCredential(t, engine, rp, authenticator, credential, "u1")

	result, err := engine.LoginWithResult(ctx, "alice", "correct-password-123")
	if err != nil || !result.MFARequired {
		t.Fatalf("expected MFA-required login, got %+v (err=%v)", result, err)
	}

	// Confirm without BeginWebAuthnLogin: ceremony never existed.
	for i := 0; i < 3; i++ {
		if _, err := engine.ConfirmLoginMFAWithType(ctx, result.MFASession, `{"id":"x"}`, "webauthn"); !errors.Is(err, ErrWebAuthnCeremonyExpired) {
			t.Fatalf("expected ErrWebAuthnCeremonyExpired, got %v", err)
		}
	}

	// The challenge survived those failures (no attempts consumed): the
	// real ceremony still completes.
	assertion := beginWebAuthnAssertion(t, engine, rp, authenticator, credential, result.MFASession)
	if _, err := engine.ConfirmLoginMFAWithType(ctx, result.MFASession, assertion, "webauthn"); err != nil {
		t.Fatalf("expected login to complete after non-consuming failures, got %v", err)
	}
}

func TestWebAuthnSignCountRegressionRejected(t *testing.T) {
	cfg := webauthnTestConfig()
	up := newWebAuthnMockProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := context.Background()

	rp := webauthnTestRP()
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	credential.Counter = 10
	stored := registerWebAuthnCredential(t, engine, rp, authenticator, credential, "u1")

	// Simulate the server having seen a much later counter (as after logins
	// from the genuine device): the next assertion regresses.
	up.setSignCount("u1", stored.CredentialID, 1000)

	result, err := engine.LoginWithResult(ctx, "alice", "correct-password-123")
	if err != nil || !result.MFARequired {
		t.Fatalf("expected MFA-required login, got %+v (err=%v)", result, err)
	}
	assertion := beginWebAuthnAssertion(t, engine, rp, authenticator, credential, result.MFASession)
	if _, err := engine.ConfirmLoginMFAWithType(ctx, result.MFASession, assertion, "webauthn"); !errors.Is(err, ErrWebAuthnCloneDetected) {
		t.Fatalf("expected ErrWebAuthnCloneDetected on counter regression, got %v", err)
	}
}

func TestWebAuthnAndTOTPUserGetsBothFactors(t *testing.T) {
	cfg := webauthnTestConfig()
	cfg.TOTP.Enabled = true
	cfg.TOTP.Issuer = "goAuth-test"
	cfg.TOTP.RequireForLogin = true
	up := newWebAuthnMockProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := context.Background()

	// Enroll TOTP for u1 through the engine so the secret is genuine.
	secret := enableUserTOTP(t, engine, "u1", cfg)

	rp := webauthnTestRP()
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	registerWebAuthnCredential(t, engine, rp, authenticator, credential, "u1")

	result, err := engine.LoginWithResult(ctx, "alice", "correct-password-123")
	if err != nil || !result.MFARequired {
		t.Fatalf("expected MFA-required login, got %+v (err=%v)", result, err)
	}
	if result.MFAType != "webauthn" {
		t.Fatalf("expected webauthn preferred, got %q", result.MFAType)
	}
	if len(result.MFATypes) != 2 || result.MFATypes[0] != "webauthn" || result.MFATypes[1] != "totp" {
		t.Fatalf("expected MFATypes [webauthn totp], got %v", result.MFATypes)
	}

	// The user can still confirm with TOTP.
	code := codeForOffset(t, secret, cfg.TOTP, 1)
	confirmed, err := engine.ConfirmLoginMFAWithType(ctx, result.MFASession, code, "totp")
	if err != nil {
		t.Fatalf("totp confirm failed: %v", err)
	}
	if confirmed.AccessToken == "" {
		t.Fatal("expected tokens after totp confirm")
	}
}

func TestWebAuthnUserWithoutCredentialLoginUnchanged(t *testing.T) {
	cfg := webauthnTestConfig()
	up := newWebAuthnMockProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	// No credentials registered: login proceeds without MFA.
	access, refresh, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("expected direct token issuance")
	}
}

func TestWebAuthnRemoveCredential(t *testing.T) {
	cfg := webauthnTestConfig()
	up := newWebAuthnMockProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := context.Background()

	rp := webauthnTestRP()
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	stored := registerWebAuthnCredential(t, engine, rp, authenticator, credential, "u1")

	if err := engine.RemoveWebAuthnCredential(ctx, "u1", stored.CredentialID); err != nil {
		t.Fatalf("remove failed: %v", err)
	}
	if err := engine.RemoveWebAuthnCredential(ctx, "u1", stored.CredentialID); !errors.Is(err, ErrWebAuthnCredentialNotFound) {
		t.Fatalf("expected ErrWebAuthnCredentialNotFound on second remove, got %v", err)
	}
	list, err := engine.ListWebAuthnCredentials(ctx, "u1")
	if err != nil || len(list) != 0 {
		t.Fatalf("expected empty credential list, got %d (err=%v)", len(list), err)
	}
}

func TestWebAuthnRegistrationCeremonyMismatchedUserRejected(t *testing.T) {
	cfg := webauthnTestConfig()
	up := newWebAuthnMockProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()
	ctx := context.Background()

	rp := webauthnTestRP()
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	challenge, err := engine.BeginWebAuthnRegistration(ctx, "u1")
	if err != nil {
		t.Fatalf("begin registration failed: %v", err)
	}
	options, err := virtualwebauthn.ParseAttestationOptions(string(challenge.OptionsJSON))
	if err != nil {
		t.Fatalf("parse attestation options: %v", err)
	}
	response := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *options)

	// Finishing under a different user must not attach the credential.
	if _, err := engine.FinishWebAuthnRegistration(ctx, "u2", challenge.CeremonyID, []byte(response)); !errors.Is(err, ErrWebAuthnCeremonyExpired) {
		t.Fatalf("expected mismatched-user finish to fail, got %v", err)
	}
	list, _ := engine.ListWebAuthnCredentials(ctx, "u2")
	if len(list) != 0 {
		t.Fatal("credential must not be attached to the wrong user")
	}
}
