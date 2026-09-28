package goAuth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// These tests prove go-webauthn v0.17.4 -> v0.18.x compatibility for
// goAuth's own usage, using fixtures captured from an actual v0.17.4
// ceremony (see testdata/webauthn_v0.17 and the generator noted in the PR
// description). goAuth requests no WebAuthn extensions, so the fixtures
// deliberately carry none.

type fixtureCredential struct {
	CredentialID    []byte    `json:"credential_id"`
	PublicKey       []byte    `json:"public_key"`
	AttestationType string    `json:"attestation_type"`
	Transports      []string  `json:"transports"`
	UserPresent     bool      `json:"user_present"`
	UserVerified    bool      `json:"user_verified"`
	BackupEligible  bool      `json:"backup_eligible"`
	BackupState     bool      `json:"backup_state"`
	AAGUID          []byte    `json:"aaguid"`
	SignCount       uint32    `json:"sign_count"`
	Attachment      string    `json:"attachment"`
	CreatedAt       time.Time `json:"created_at"`
	LastUsedAt      time.Time `json:"last_used_at"`
}

func loadFixtureJSON(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile("testdata/webauthn_v0.17/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
}

// TestWebAuthnV017CredentialStillAuthenticatesUnderV018 proves that a
// credential registered under go-webauthn v0.17.4 (and stored the way
// goAuth persists it, via WebAuthnCredential -- never a library type)
// still completes a login assertion after the v0.18 upgrade. This is what
// every existing consumer's database holds today.
func TestWebAuthnV017CredentialStillAuthenticatesUnderV018(t *testing.T) {
	var fc fixtureCredential
	loadFixtureJSON(t, "webauthn_credential_v0.17.json", &fc)

	var vwaCred virtualwebauthn.Credential
	loadFixtureJSON(t, "authenticator_credential_v0.17.json", &vwaCred)

	cfg := webauthnTestConfig()
	up := newWebAuthnMockProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	up.credentials["u1"] = []WebAuthnCredential{{
		CredentialID:    fc.CredentialID,
		PublicKey:       fc.PublicKey,
		AttestationType: fc.AttestationType,
		Transports:      fc.Transports,
		UserPresent:     fc.UserPresent,
		UserVerified:    fc.UserVerified,
		BackupEligible:  fc.BackupEligible,
		BackupState:     fc.BackupState,
		AAGUID:          fc.AAGUID,
		SignCount:       fc.SignCount,
		Attachment:      fc.Attachment,
		CreatedAt:       fc.CreatedAt,
		LastUsedAt:      fc.LastUsedAt,
	}}

	rp := webauthnTestRP()
	authenticator := virtualwebauthn.NewAuthenticator()
	authenticator.AddCredential(vwaCred)

	ctx := context.Background()
	loginResult, err := engine.LoginWithResult(ctx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if !loginResult.MFARequired || loginResult.MFAType != "webauthn" {
		t.Fatalf("expected a webauthn MFA challenge, got %+v", loginResult)
	}

	assertionResponse := beginWebAuthnAssertion(t, engine, rp, authenticator, vwaCred, loginResult.MFASession)

	final, err := engine.ConfirmLoginMFAWithType(ctx, loginResult.MFASession, assertionResponse, "webauthn")
	if err != nil {
		t.Fatalf("login assertion against a v0.17.4-registered credential failed under v0.18: %v", err)
	}
	if final.AccessToken == "" || final.RefreshToken == "" {
		t.Fatal("expected tokens from a successful webauthn login")
	}
}

// TestWebAuthnV017SessionDecodesAndFinishesUnderV018 answers the "rolling
// deploy" question directly: does a SessionData record written by
// go-webauthn v0.17.4 (json.Marshal'd, exactly as goAuth stores it in
// Redis under the awn: prefix) still decode and finish successfully when
// read back by v0.18.2? goAuth requests no extensions, and pins
// ExtensionsUnsolicitedOutputPolicyIgnore, so per the v0.18 MIGRATION.md
// (SS3.2) this should be unaffected -- this test proves it empirically
// rather than assuming it.
func TestWebAuthnV017SessionDecodesAndFinishesUnderV018(t *testing.T) {
	sessionJSON, err := os.ReadFile("testdata/webauthn_v0.17/session_registration_v0.17.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	responseJSON, err := os.ReadFile("testdata/webauthn_v0.17/attestation_response_v0.17.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &session); err != nil {
		t.Fatalf("a v0.17.4-encoded SessionData record failed to decode under v0.18: %v", err)
	}
	// The fixture's expiry is frozen at generation time; move it forward so
	// this test isolates the version-compatibility question (decode +
	// finish) from wall-clock ceremony expiry, which is bounded by
	// CeremonyTTL and unrelated to the v0.17 -> v0.18 upgrade.
	session.Expires = time.Now().Add(2 * time.Minute)

	w, err := webauthn.New(&webauthn.Config{
		RPID:                              "example.com",
		RPDisplayName:                     "Example",
		RPOrigins:                         []string{"https://example.com"},
		ExtensionsUnsolicitedOutputPolicy: protocol.UnsolicitedOutputPolicyIgnore,
	})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(responseJSON)
	if err != nil {
		t.Fatalf("parse v0.17.4 attestation response: %v", err)
	}

	user := flowUserFixture{id: []byte("user-fixture-1"), name: "fixture@example.com"}
	if _, err := w.CreateCredential(user, session, parsed); err != nil {
		t.Fatalf("a registration ceremony begun under v0.17.4 (session decoded cleanly) failed to finish under v0.18: %v", err)
	}
}

// TestWebAuthnV017SessionRejectsUnsolicitedOutputWithoutIgnorePolicy shows
// what WOULD happen across the same rolling-deploy window if goAuth had not
// pinned ExtensionsUnsolicitedOutputPolicyIgnore: v0.18's new default
// (Reject) has no "requested" list to check against in a v0.17-decoded
// session, so any client-volunteered extension output fails the ceremony.
// This test doesn't exercise goAuth's own code (which pins Ignore); it
// documents why the pin matters using the same fixtures.
func TestWebAuthnV017SessionRejectsUnsolicitedOutputWithoutIgnorePolicy(t *testing.T) {
	sessionJSON, err := os.ReadFile("testdata/webauthn_v0.17/session_registration_v0.17.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &session); err != nil {
		t.Fatalf("decode: %v", err)
	}
	session.Expires = time.Now().Add(2 * time.Minute)

	w, err := webauthn.New(&webauthn.Config{
		RPID:          "example.com",
		RPDisplayName: "Example",
		RPOrigins:     []string{"https://example.com"},
		// Default policy: UnsolicitedOutputPolicyReject (the zero value).
	})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}

	responseJSON, err := os.ReadFile("testdata/webauthn_v0.17/attestation_response_v0.17.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(responseJSON, &raw); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	// Simulate a client (e.g. a password manager) volunteering an output
	// for an extension nothing requested.
	raw["clientExtensionResults"] = map[string]any{"credProps": map[string]any{"rk": true}}
	patched, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal patched response: %v", err)
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(patched)
	if err != nil {
		t.Fatalf("parse patched response: %v", err)
	}

	user := flowUserFixture{id: []byte("user-fixture-1"), name: "fixture@example.com"}
	if _, err := w.CreateCredential(user, session, parsed); err == nil {
		t.Fatal("expected the default (Reject) policy to fail a ceremony whose v0.17-decoded session cannot confirm the output was requested")
	}
}

// TestWebAuthnOptionsJSONUnchangedAcrossUpgrade diffs the golden
// BeginRegistration/BeginLogin OptionsJSON captured from go-webauthn
// v0.17.4 (testdata/webauthn_v0.17) against freshly generated v0.18.2
// output for the identical config, RP, and user. The only field allowed to
// differ is the per-ceremony random "challenge" -- everything else
// (algorithm list, timeouts, attestation preference, authenticatorSelection,
// allowCredentials shape) must be byte-for-byte identical, which is what
// makes the golden JSON still valid navigator.credentials.create/get input
// after the upgrade.
func TestWebAuthnOptionsJSONUnchangedAcrossUpgrade(t *testing.T) {
	w, err := webauthn.New(&webauthn.Config{
		RPID:                  "example.com",
		RPDisplayName:         "Example",
		RPOrigins:             []string{"https://example.com"},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: 2 * time.Minute, TimeoutUVD: 2 * time.Minute},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: 2 * time.Minute, TimeoutUVD: 2 * time.Minute},
		},
		ExtensionsUnsolicitedOutputPolicy: protocol.UnsolicitedOutputPolicyIgnore,
	})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}

	user := flowUserFixture{id: []byte("user-fixture-1"), name: "fixture@example.com"}

	t.Run("registration", func(t *testing.T) {
		options, _, err := w.BeginRegistration(user)
		if err != nil {
			t.Fatalf("BeginRegistration: %v", err)
		}
		gotJSON, err := json.Marshal(options)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		wantJSON, err := os.ReadFile("testdata/webauthn_v0.17/options_registration_v0.17.json")
		if err != nil {
			t.Fatalf("read golden: %v", err)
		}
		diffOptionsJSON(t, wantJSON, gotJSON, []string{"publicKey", "challenge"})
	})

	t.Run("login", func(t *testing.T) {
		cred := webauthn.Credential{
			ID:        mustDecodeBase64URL(t, "fgRp4OcEF1BS0cgmITrcpGAdzn-SThGXbJ1byDOMoVY"),
			PublicKey: []byte{1, 2, 3, 4},
			Transport: []protocol.AuthenticatorTransport{protocol.Internal},
		}
		userWithCred := flowUserFixture{id: []byte("user-fixture-1"), name: "fixture@example.com", credentials: []webauthn.Credential{cred}}
		options, _, err := w.BeginLogin(userWithCred)
		if err != nil {
			t.Fatalf("BeginLogin: %v", err)
		}
		gotJSON, err := json.Marshal(options)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		wantJSON, err := os.ReadFile("testdata/webauthn_v0.17/options_login_v0.17.json")
		if err != nil {
			t.Fatalf("read golden: %v", err)
		}
		diffOptionsJSON(t, wantJSON, gotJSON, []string{"publicKey", "challenge"})
	})
}

func mustDecodeBase64URL(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode base64url: %v", err)
	}
	return b
}

// diffOptionsJSON deep-compares two OptionsJSON payloads after deleting the
// field at ignorePath (a nested map key path), and fails with the specific
// mismatching fields rather than a raw JSON blob.
func diffOptionsJSON(t *testing.T, wantJSON, gotJSON []byte, ignorePath []string) {
	t.Helper()

	var want, got map[string]any
	if err := json.Unmarshal(wantJSON, &want); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	if err := json.Unmarshal(gotJSON, &got); err != nil {
		t.Fatalf("unmarshal generated: %v", err)
	}

	deleteNested(want, ignorePath)
	deleteNested(got, ignorePath)

	wantNorm, _ := json.Marshal(want)
	gotNorm, _ := json.Marshal(got)
	if string(wantNorm) != string(gotNorm) {
		t.Fatalf("OptionsJSON shape changed between v0.17.4 and v0.18.2 (excluding %v):\nv0.17.4: %s\nv0.18.2: %s", ignorePath, wantNorm, gotNorm)
	}
}

func deleteNested(m map[string]any, path []string) {
	if len(path) == 0 {
		return
	}
	if len(path) == 1 {
		delete(m, path[0])
		return
	}
	next, ok := m[path[0]].(map[string]any)
	if !ok {
		return
	}
	deleteNested(next, path[1:])
}

type flowUserFixture struct {
	id          []byte
	name        string
	credentials []webauthn.Credential
}

func (u flowUserFixture) WebAuthnID() []byte          { return u.id }
func (u flowUserFixture) WebAuthnName() string        { return u.name }
func (u flowUserFixture) WebAuthnDisplayName() string { return u.name }
func (u flowUserFixture) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}
