package goAuth

import (
	"strings"
	"testing"

	"github.com/MrEthical07/goAuth/internal/flows"
)

// Hardening for the run-2 record "uuid-strategy-credential-logged-in-audit-
// metadata". With a UUID strategy the record ID is the whole secret, so a
// confirm failure that leaves the record live must not put it in an audit
// event. Token and OTP strategies keep recording the ID: it names the record
// and is not the secret.

// challengeIDFields returns every verification_id / reset_id style metadata
// value recorded, keyed by field name.
func challengeIDFields(t *testing.T, env *ecEnv) map[string][]string {
	t.Helper()
	env.engine.Close()
	env.sink.mu.Lock()
	defer env.sink.mu.Unlock()
	out := map[string][]string{}
	for _, ev := range env.sink.events {
		for k, v := range ev.Metadata {
			if strings.HasPrefix(k, "verification_id") || strings.HasPrefix(k, "reset_id") {
				out[k] = append(out[k], v)
			}
		}
	}
	return out
}

// FAILED-BEFORE (hardening): a UUID-mode confirm failure audited the whole
// secret under verification_id.
func TestUUIDVerificationFailureAuditsAFingerprintNotTheSecret(t *testing.T) {
	env, _ := newPendingEnv(t, rsConfig(func(c *Config) {
		c.EmailVerification = testEmailVerificationConfig(VerificationUUID)
	}))
	ctx := env.ctx()
	challenge, err := env.engine.RequestEmailVerification(ctx, rsIdentifier)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(challenge, ":", 3)
	tenant, id := parts[0], parts[1]

	// The record is live in every one of these.
	if err := env.engine.ConfirmEmailVerification(ctx, "other:"+id+":"+parts[2]); err == nil {
		t.Fatal("a challenge of another tenant was accepted")
	}
	wrongCode := "11111111-1111-4111-8111-111111111111"
	if err := env.engine.ConfirmEmailVerificationCode(ctx, id, wrongCode); err == nil {
		t.Fatal("a wrong code was accepted")
	}

	fields := challengeIDFields(t, env)
	if len(fields["verification_id"]) != 0 {
		t.Errorf("verification_id recorded in UUID mode: %v", fields["verification_id"])
	}
	want := map[string]bool{flows.ChallengeFingerprint("other", id): true, flows.ChallengeFingerprint(tenant, id): true}
	got := fields["verification_id_fp"]
	if len(got) != 2 {
		t.Fatalf("verification_id_fp values = %v, want 2", got)
	}
	for _, fp := range got {
		if len(fp) != 12 || !want[fp] {
			t.Errorf("fingerprint %q is not the 12-character fingerprint of the tenant and ID", fp)
		}
		if strings.Contains(id, fp) {
			t.Errorf("fingerprint %q is part of the ID", fp)
		}
	}
	env.sink.mu.Lock()
	defer env.sink.mu.Unlock()
	for _, ev := range env.sink.events {
		for k, v := range ev.Metadata {
			if strings.Contains(v, id) || strings.Contains(v, parts[2]) {
				t.Errorf("%s metadata %q holds the secret", ev.EventType, k)
			}
		}
	}
}

func TestTokenVerificationFailureStillAuditsTheID(t *testing.T) {
	env, _ := newPendingEnv(t, rsConfig(func(c *Config) {
		c.EmailVerification = testEmailVerificationConfig(VerificationToken)
	}))
	ctx := env.ctx()
	_, challenge, _, err := generateEmailVerificationChallenge(VerificationToken, 6, "0")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(challenge, ":", 3)
	if err := env.engine.ConfirmEmailVerification(ctx, "other:"+parts[1]+":"+parts[2]); err == nil {
		t.Fatal("a challenge with no record was accepted")
	}
	fields := challengeIDFields(t, env)
	if got := fields["verification_id"]; len(got) != 1 || got[0] != parts[1] {
		t.Errorf("verification_id = %v, want [%s]", got, parts[1])
	}
	if len(fields["verification_id_fp"]) != 0 {
		t.Errorf("a token strategy recorded a fingerprint: %v", fields["verification_id_fp"])
	}
}

// FAILED-BEFORE (hardening): a UUID-mode reset failure audited the whole
// secret under reset_id.
func TestUUIDResetFailureAuditsAFingerprintNotTheSecret(t *testing.T) {
	env := newECEnv(t, nil, rsMultiTenant(), rsConfig(func(c *Config) {
		c.PasswordReset = testResetConfig(ResetUUID)
	}))
	challenge, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
	if err != nil {
		t.Fatal(err)
	}
	// The record is live in tenant-a; the caller says it is in tenant-b.
	other := WithTenantID(env.ctx(), "tenant-b")
	if err := env.engine.ConfirmPasswordReset(other, challenge, "new-password-123"); err == nil {
		t.Fatal("a challenge was accepted from another tenant")
	}

	fields := challengeIDFields(t, env)
	if len(fields["reset_id"]) != 0 {
		t.Errorf("reset_id recorded in UUID mode: %v", fields["reset_id"])
	}
	got := fields["reset_id_fp"]
	if len(got) == 0 {
		t.Fatal("no reset_id_fp recorded")
	}
	for _, fp := range got {
		if fp != flows.ChallengeFingerprint("tenant-b", challenge) {
			t.Errorf("fingerprint %q, want the fingerprint of tenant-b and the ID", fp)
		}
	}
	env.sink.mu.Lock()
	defer env.sink.mu.Unlock()
	for _, ev := range env.sink.events {
		for k, v := range ev.Metadata {
			if strings.Contains(v, challenge) {
				t.Errorf("%s metadata %q holds the secret", ev.EventType, k)
			}
		}
	}
}

func TestTokenResetFailureStillAuditsTheID(t *testing.T) {
	env := newECEnv(t, nil, rsMultiTenant(), rsConfig(func(c *Config) {
		c.PasswordReset = testResetConfig(ResetToken)
	}))
	challenge, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
	if err != nil {
		t.Fatal(err)
	}
	other := WithTenantID(env.ctx(), "tenant-b")
	if err := env.engine.ConfirmPasswordReset(other, challenge, "new-password-123"); err == nil {
		t.Fatal("a challenge was accepted from another tenant")
	}
	fields := challengeIDFields(t, env)
	if len(fields["reset_id"]) == 0 {
		t.Error("a token strategy no longer records reset_id")
	}
	if len(fields["reset_id_fp"]) != 0 {
		t.Errorf("a token strategy recorded a fingerprint: %v", fields["reset_id_fp"])
	}
}
