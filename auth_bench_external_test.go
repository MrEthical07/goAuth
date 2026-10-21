package goAuth

import (
	"context"
	"testing"
)

// BenchmarkLoginWithExternalIdentity measures a sign-in of an already linked
// identity with warm provider keys. Token signing happens before the timer
// starts; what is timed is verification (signature, claims, nonce, replay
// record), the two limiter reservations, the identity lookup, and the login
// tail (session hardening, session write, access token).
func BenchmarkLoginWithExternalIdentity(b *testing.B) {
	env := newExtEnv(b)
	env.link("google", "bench-sub", extLocalUserID)
	if err := env.engine.WarmExternalKeys(context.Background()); err != nil {
		b.Fatalf("warm: %v", err)
	}

	tokens := make([]string, b.N)
	nonces := make([]string, b.N)
	for i := range tokens {
		tokens[i], nonces[i] = env.idp.token(extTokenSpec{sub: "bench-sub"})
	}
	ctx := WithClientIP(context.Background(), "203.0.113.50")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := env.engine.LoginWithExternalIdentity(ctx, "google", tokens[i], ExternalLoginOptions{Nonce: nonces[i]}); err != nil {
			b.Fatalf("LoginWithExternalIdentity: %v", err)
		}
	}
}
