// Command gen captures the testdata/webauthn_v0.17 fixtures from an actual
// go-webauthn v0.17.4 ceremony, and can run the reverse-direction check: does
// a ceremony written by go-webauthn v0.18.2 (goAuth v0.6.0) still decode and
// finish under v0.17.4 (goAuth v0.5.x)? That proves whether rolling *back*
// from v0.6.0 to v0.5.x is safe for in-flight WebAuthn ceremonies.
//
// This is a separate Go module, pinned to go-webauthn v0.17.4 and
// virtualwebauthn v1.0.5, so v0.17.4 never enters goAuth's own module graph.
//
// Usage:
//
//	go run . [-out DIR]                 generate testdata/webauthn_v0.17 fixtures (default)
//	go run . -verify-reverse DIR         verify v0.18-written fixtures decode/finish under v0.17.4
//
// See README.md in this directory.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// flowUser mirrors goAuth's internal/flows.webAuthnFlowUser shape.
type flowUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u flowUser) WebAuthnID() []byte                         { return u.id }
func (u flowUser) WebAuthnName() string                       { return u.name }
func (u flowUser) WebAuthnDisplayName() string                { return u.displayName }
func (u flowUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// storedCredential mirrors goAuth's own WebAuthnCredential (types.go), which
// is what actually persists in a consumer's database -- never a library type.
type storedCredential struct {
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

func fromLibCredential(c webauthn.Credential, now time.Time) storedCredential {
	transports := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		transports = append(transports, string(t))
	}
	return storedCredential{
		CredentialID:    c.ID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transports:      transports,
		UserPresent:     c.Flags.UserPresent,
		UserVerified:    c.Flags.UserVerified,
		BackupEligible:  c.Flags.BackupEligible,
		BackupState:     c.Flags.BackupState,
		AAGUID:          c.Authenticator.AAGUID,
		SignCount:       c.Authenticator.SignCount,
		Attachment:      string(c.Authenticator.Attachment),
		CreatedAt:       now,
		LastUsedAt:      now,
	}
}

func newRP() (webauthn.WebAuthn, virtualwebauthn.RelyingParty, error) {
	rp := virtualwebauthn.RelyingParty{ID: "example.com", Name: "Example", Origin: "https://example.com"}

	cfg := &webauthn.Config{
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
	}
	w, err := webauthn.New(cfg)
	if err != nil {
		return webauthn.WebAuthn{}, virtualwebauthn.RelyingParty{}, err
	}
	return *w, rp, nil
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func writeJSON(path string, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	must(err)
	must(os.WriteFile(path, data, 0o644))
	fmt.Println("wrote", path)
}

func generate(outDir string) {
	must(os.MkdirAll(outDir, 0o755))

	w, rp, err := newRP()
	must(err)

	user := flowUser{id: []byte("user-fixture-1"), name: "fixture@example.com", displayName: "fixture@example.com"}

	// ---- Registration ceremony ----
	options, session, err := w.BeginRegistration(user)
	must(err)

	optionsJSON, err := json.Marshal(options)
	must(err)
	writeJSON(outDir+"/options_registration_v0.17.json", json.RawMessage(optionsJSON))

	sessionJSON, err := json.Marshal(session)
	must(err)
	writeJSON(outDir+"/session_registration_v0.17.json", json.RawMessage(sessionJSON))

	authenticator := virtualwebauthn.NewAuthenticator()
	vwaCred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authenticator.AddCredential(vwaCred)

	parsedOptions, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	must(err)
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, vwaCred, *parsedOptions)
	writeJSON(outDir+"/attestation_response_v0.17.json", json.RawMessage(attestationResponse))

	parsed, err := protocol.ParseCredentialCreationResponseBytes([]byte(attestationResponse))
	must(err)
	credential, err := w.CreateCredential(user, *session, parsed)
	must(err)

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	stored := fromLibCredential(*credential, now)
	writeJSON(outDir+"/webauthn_credential_v0.17.json", stored)

	// The virtual authenticator's key material: reused later to sign a NEW
	// assertion with the SAME credential, proving the credential itself
	// (as goAuth stores it) still authenticates under v0.18.
	writeJSON(outDir+"/authenticator_credential_v0.17.json", vwaCred)

	// ---- Login ceremony (options JSON only, for the golden diff) ----
	userWithCred := flowUser{id: user.id, name: user.name, displayName: user.displayName, credentials: []webauthn.Credential{*credential}}
	loginOptions, loginSession, err := w.BeginLogin(userWithCred)
	must(err)
	loginOptionsJSON, err := json.Marshal(loginOptions)
	must(err)
	writeJSON(outDir+"/options_login_v0.17.json", json.RawMessage(loginOptionsJSON))

	loginSessionJSON, err := json.Marshal(loginSession)
	must(err)
	writeJSON(outDir+"/session_login_v0.17.json", json.RawMessage(loginSessionJSON))

	fmt.Println("done")
}

// verifyReverse reads the v0.18-written fixtures from dir (produced by
// TestGenerateReverseRollingDeployFixtures -update in the main module) and
// attempts to decode the SessionData and finish the registration ceremony
// using go-webauthn v0.17.4 -- the version a rollback from v0.6.0 to v0.5.x
// would run.
func verifyReverse(dir string) {
	w, _, err := newRP()
	must(err)

	sessionData, err := os.ReadFile(dir + "/session_registration_v0.18.json")
	must(err)

	var session webauthn.SessionData
	if err := json.Unmarshal(sessionData, &session); err != nil {
		fmt.Println("REVERSE DECODE: FAIL --", err)
		os.Exit(1)
	}
	fmt.Println("REVERSE DECODE: OK -- v0.18-written SessionData decodes under v0.17.4")

	// The fixture's expiry is frozen at capture time; move it forward so
	// this isolates decode+finish compatibility from wall-clock expiry
	// (bounded separately by CeremonyTTL).
	session.Expires = time.Now().Add(2 * time.Minute)

	responseData, err := os.ReadFile(dir + "/attestation_response_v0.18.json")
	must(err)

	user := flowUser{id: []byte("user-fixture-1"), name: "fixture@example.com"}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(responseData)
	if err != nil {
		fmt.Println("REVERSE PARSE RESPONSE: FAIL --", err)
		os.Exit(1)
	}

	if _, err := w.CreateCredential(user, session, parsed); err != nil {
		fmt.Println("REVERSE FINISH: FAIL --", err)
		os.Exit(1)
	}
	fmt.Println("REVERSE FINISH: OK -- a registration ceremony begun under v0.18.2 finishes under v0.17.4")
}

func main() {
	outDir := flag.String("out", ".", "directory to write the v0.17 fixtures into")
	verifyDir := flag.String("verify-reverse", "", "directory holding v0.18-written fixtures to verify decode/finish under v0.17.4, instead of generating")
	flag.Parse()

	if *verifyDir != "" {
		verifyReverse(*verifyDir)
		return
	}
	generate(*outDir)
}
