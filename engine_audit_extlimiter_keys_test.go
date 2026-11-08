package goAuth

import (
	"strings"
	"testing"
)

// FAILED-BEFORE (R2-21 residual): an external sign-in from a client address of
// 256 KiB left rl:extlogin:ip:<address> in Redis for the whole window.
func TestExternalSignInNeverStoresTheClientAddressInAKey(t *testing.T) {
	env := newExtEnv(t)
	env.link("google", "sub-1", extLocalUserID)
	hugeIP := strings.Repeat("9", 256<<10)

	ctx := WithClientIP(env.ctx(), hugeIP)
	token, nonce := env.idp.token(extTokenSpec{provider: "google", sub: "sub-1"})
	if _, err := env.engine.LoginWithExternalIdentity(ctx, "google", token, ExternalLoginOptions{Nonce: nonce}); err != nil {
		t.Fatalf("sign-in: %v", err)
	}

	sawSource := false
	for _, key := range env.mr.Keys() {
		if len(key) > 256 {
			t.Errorf("key %.60s... is %d bytes", key, len(key))
		}
		if strings.Contains(key, "9999") {
			t.Errorf("key carries the client address: %.60s", key)
		}
		if strings.HasPrefix(key, "rl:extlogin:ip:") {
			sawSource = true
		}
	}
	// The sign-in succeeded, so its buckets were reset; the source bucket was
	// reserved before verification, which the command log shows.
	if !env.cmds.touches("rl:extlogin:ip:") && !sawSource {
		t.Fatal("the source bucket was never used: the test is not exercising the key")
	}
	env.cmds.mu.Lock()
	defer env.cmds.mu.Unlock()
	for _, args := range env.cmds.cmds {
		for _, a := range args[1:] {
			if s, ok := a.(string); ok && strings.HasPrefix(s, "rl:extlogin:") && len(s) > 256 {
				t.Errorf("command %v names a %d-byte limiter key", args[0], len(s))
			}
		}
	}
}
