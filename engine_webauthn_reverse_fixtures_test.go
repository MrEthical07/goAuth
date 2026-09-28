package goAuth

import (
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// update regenerates the reverse rolling-deploy fixtures in
// testdata/webauthn_v0.18/ from the CURRENT go-webauthn version (v0.18.2).
// These are consumed by testdata/webauthn_v0.17/gen's -verify-reverse mode,
// which attempts to decode and finish them under go-webauthn v0.17.4 --
// simulating a rollback from v0.6.0 to v0.5.x mid-ceremony. Regenerate with:
//
//	go test -run TestGenerateReverseRollingDeployFixtures -update .
var update = flag.Bool("update", false, "regenerate the reverse rolling-deploy fixtures")

func TestGenerateReverseRollingDeployFixtures(t *testing.T) {
	if !*update {
		t.Skip("run with -update to regenerate testdata/webauthn_v0.18 fixtures")
	}

	outDir := "testdata/webauthn_v0.18"
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", outDir, err)
	}

	rp := webauthnTestRP()

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

	options, session, err := w.BeginRegistration(user)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	sessionJSON, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	writeFixture(t, outDir+"/session_registration_v0.18.json", sessionJSON)

	optionsJSON, err := json.MarshalIndent(options, "", "  ")
	if err != nil {
		t.Fatalf("marshal options: %v", err)
	}
	writeFixture(t, outDir+"/options_registration_v0.18.json", optionsJSON)

	authenticator := virtualwebauthn.NewAuthenticator()
	vwaCred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authenticator.AddCredential(vwaCred)

	parsedOptions, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	if err != nil {
		t.Fatalf("parse attestation options: %v", err)
	}
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, vwaCred, *parsedOptions)
	writeFixture(t, outDir+"/attestation_response_v0.18.json", []byte(attestationResponse))

	credJSON, err := json.MarshalIndent(vwaCred, "", "  ")
	if err != nil {
		t.Fatalf("marshal authenticator credential: %v", err)
	}
	writeFixture(t, outDir+"/authenticator_credential_v0.18.json", credJSON)

	t.Logf("wrote reverse rolling-deploy fixtures to %s", outDir)
}

func writeFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
	}
}
