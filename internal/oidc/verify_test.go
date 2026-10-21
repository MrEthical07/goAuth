package oidc

import (
	"context"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Each case alters a valid claim set and names the exact error it must
// produce. A valid token passes first, so a failure below is caused by the
// alteration alone.
//
// NEW-API: every case.
func TestVerifyClaimsTable(t *testing.T) {
	hashedNonce := func() string {
		sum := sha256.Sum256([]byte(testNonce))
		return hex.EncodeToString(sum[:])
	}()

	cases := []struct {
		name   string
		mutate func(c jwt.MapClaims, f *fixture)
		nonce  string // verifier input; testNonce when empty
		want   error
		check  func(t *testing.T, got *Claims)
	}{
		{name: "valid", check: func(t *testing.T, got *Claims) {
			if got.Subject != "subject-1" || got.Email != "user@example.com" || !got.EmailVerified || got.IsPrivateEmail {
				t.Fatalf("claims = %+v", got)
			}
		}},
		{name: "wrong issuer", mutate: func(c jwt.MapClaims, _ *fixture) { c["iss"] = "https://evil.test" }, want: ErrInvalid},
		{name: "missing issuer", mutate: func(c jwt.MapClaims, _ *fixture) { delete(c, "iss") }, want: ErrInvalid},
		{name: "audience mismatch", mutate: func(c jwt.MapClaims, _ *fixture) { c["aud"] = "someone-else" }, want: ErrInvalid},
		{name: "missing audience", mutate: func(c jwt.MapClaims, _ *fixture) { delete(c, "aud") }, want: ErrInvalid},
		{name: "audience array containing the client, no azp", mutate: func(c jwt.MapClaims, _ *fixture) {
			c["aud"] = []string{testClientID, "other"}
		}, want: ErrInvalid},
		{name: "audience array, azp not configured", mutate: func(c jwt.MapClaims, _ *fixture) {
			c["aud"] = []string{testClientID, "other"}
			c["azp"] = "other"
		}, want: ErrInvalid},
		{name: "audience array with valid azp", mutate: func(c jwt.MapClaims, _ *fixture) {
			c["aud"] = []string{"other", testClientID}
			c["azp"] = testClientID
		}},
		{name: "single-entry audience array without azp", mutate: func(c jwt.MapClaims, _ *fixture) {
			c["aud"] = []string{testClientID}
		}},
		{name: "expired beyond leeway", mutate: func(c jwt.MapClaims, f *fixture) {
			c["exp"] = f.clock.Now().Add(-2 * time.Minute).Unix()
		}, want: ErrInvalid},
		{name: "expired within leeway", mutate: func(c jwt.MapClaims, f *fixture) {
			c["exp"] = f.clock.Now().Add(-30 * time.Second).Unix()
		}},
		{name: "expiring exactly at the leeway edge", mutate: func(c jwt.MapClaims, f *fixture) {
			c["exp"] = f.clock.Now().Add(-DefaultLeeway).Unix()
		}, want: ErrInvalid},
		{name: "missing exp", mutate: func(c jwt.MapClaims, _ *fixture) { delete(c, "exp") }, want: ErrInvalid},
		{name: "exp far in the future", mutate: func(c jwt.MapClaims, f *fixture) {
			c["exp"] = f.clock.Now().Add(72 * time.Hour).Unix()
		}, want: ErrInvalid},
		{name: "missing iat", mutate: func(c jwt.MapClaims, _ *fixture) { delete(c, "iat") }, want: ErrInvalid},
		{name: "iat in the future", mutate: func(c jwt.MapClaims, f *fixture) {
			c["iat"] = f.clock.Now().Add(5 * time.Minute).Unix()
		}, want: ErrInvalid},
		{name: "iat within leeway", mutate: func(c jwt.MapClaims, f *fixture) {
			c["iat"] = f.clock.Now().Add(30 * time.Second).Unix()
		}},
		{name: "nbf in the future", mutate: func(c jwt.MapClaims, f *fixture) {
			c["nbf"] = f.clock.Now().Add(5 * time.Minute).Unix()
		}, want: ErrInvalid},
		{name: "nbf in the past", mutate: func(c jwt.MapClaims, f *fixture) {
			c["nbf"] = f.clock.Now().Add(-time.Minute).Unix()
		}},
		{name: "token nonce missing", mutate: func(c jwt.MapClaims, _ *fixture) { delete(c, "nonce") }, want: ErrInvalid},
		{name: "wrong nonce", mutate: func(c jwt.MapClaims, _ *fixture) { c["nonce"] = "other" }, want: ErrInvalid},
		{name: "empty verifier nonce", nonce: "-", want: ErrInvalid},
		{name: "nonce as sha256 hex", mutate: func(c jwt.MapClaims, _ *fixture) { c["nonce"] = hashedNonce }},
		{name: "nonce as uppercase sha256 hex", mutate: func(c jwt.MapClaims, _ *fixture) {
			c["nonce"] = strings.ToUpper(hashedNonce)
		}, want: ErrInvalid},
		{name: "nonce is the hash of another value", mutate: func(c jwt.MapClaims, _ *fixture) {
			sum := sha256.Sum256([]byte("other"))
			c["nonce"] = hex.EncodeToString(sum[:])
		}, want: ErrInvalid},
		{name: "empty subject", mutate: func(c jwt.MapClaims, _ *fixture) { c["sub"] = "" }, want: ErrInvalid},
		{name: "missing subject", mutate: func(c jwt.MapClaims, _ *fixture) { delete(c, "sub") }, want: ErrInvalid},
		{name: "subject at the limit", mutate: func(c jwt.MapClaims, _ *fixture) { c["sub"] = strings.Repeat("s", 255) }},
		{name: "subject over the limit", mutate: func(c jwt.MapClaims, _ *fixture) { c["sub"] = strings.Repeat("s", 256) }, want: ErrInvalid},
		{name: "email_verified as string true", mutate: func(c jwt.MapClaims, _ *fixture) { c["email_verified"] = "true" }},
		{name: "email_verified as string false", mutate: func(c jwt.MapClaims, _ *fixture) { c["email_verified"] = "false" }, check: func(t *testing.T, got *Claims) {
			if got.EmailVerified {
				t.Fatal("string \"false\" read as verified")
			}
		}},
		{name: "email_verified as bool false", mutate: func(c jwt.MapClaims, _ *fixture) { c["email_verified"] = false }, check: func(t *testing.T, got *Claims) {
			if got.EmailVerified {
				t.Fatal("false read as verified")
			}
		}},
		{name: "email_verified as a number", mutate: func(c jwt.MapClaims, _ *fixture) { c["email_verified"] = 1 }, check: func(t *testing.T, got *Claims) {
			if got.EmailVerified {
				t.Fatal("a number read as verified")
			}
		}},
		{name: "is_private_email as string", mutate: func(c jwt.MapClaims, _ *fixture) { c["is_private_email"] = "true" }, check: func(t *testing.T, got *Claims) {
			if !got.IsPrivateEmail {
				t.Fatal("is_private_email \"true\" not read")
			}
		}},
		{name: "is_private_email as bool", mutate: func(c jwt.MapClaims, _ *fixture) { c["is_private_email"] = true }, check: func(t *testing.T, got *Claims) {
			if !got.IsPrivateEmail {
				t.Fatal("is_private_email true not read")
			}
		}},
		{name: "email is trimmed", mutate: func(c jwt.MapClaims, _ *fixture) { c["email"] = "  User@Example.com \n" }, check: func(t *testing.T, got *Claims) {
			if got.Email != "User@Example.com" {
				t.Fatalf("email = %q: trimmed, never lowercased", got.Email)
			}
		}},
		{name: "no email claim", mutate: func(c jwt.MapClaims, _ *fixture) { delete(c, "email"); delete(c, "email_verified") }, check: func(t *testing.T, got *Claims) {
			if got.Email != "" || got.EmailVerified {
				t.Fatalf("claims = %+v", got)
			}
		}},
		{name: "email over the limit", mutate: func(c jwt.MapClaims, _ *fixture) { c["email"] = strings.Repeat("e", 321) }, want: ErrInvalid},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			claims := f.claims()
			if tc.mutate != nil {
				tc.mutate(claims, f)
			}
			nonce := testNonce
			if tc.nonce == "-" {
				nonce = ""
			}
			got, err := f.v.Verify(context.Background(), "test", f.token(claims), nonce)
			if tc.want != nil {
				if !errors.Is(err, tc.want) || got != nil {
					t.Fatalf("Verify = %+v, %v; want %v", got, err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

// Google publishes tokens under two issuer spellings; both must verify, and a
// near miss must not.
//
// NEW-API.
func TestVerifyAcceptsEveryConfiguredIssuer(t *testing.T) {
	f := newFixture(t, func(c *ProviderConfig, _ *Options) {
		c.Issuers = []string{"https://accounts.google.com", "accounts.google.com"}
	})
	for _, iss := range []string{"https://accounts.google.com", "accounts.google.com"} {
		claims := f.claims()
		claims["iss"] = iss
		claims["sub"] = "sub-" + iss
		if _, err := f.v.Verify(context.Background(), "test", f.token(claims), testNonce); err != nil {
			t.Fatalf("issuer %q: %v", iss, err)
		}
	}
	for _, iss := range []string{"http://accounts.google.com", "accounts.google.com/", "https://accounts.google.com/"} {
		claims := f.claims()
		claims["iss"] = iss
		if _, err := f.v.Verify(context.Background(), "test", f.token(claims), testNonce); !errors.Is(err, ErrInvalid) {
			t.Fatalf("issuer %q = %v, want ErrInvalid", iss, err)
		}
	}
}

// NEW-API.
func TestVerifyHostedDomain(t *testing.T) {
	f := newFixture(t, func(c *ProviderConfig, _ *Options) { c.HostedDomains = []string{"example.com", "Corp.Example"} })
	for hd, ok := range map[string]bool{"example.com": true, "corp.example": true, "evil.com": false, "": false, "example.com.evil.com": false} {
		claims := f.claims()
		claims["sub"] = "s-" + hd
		if hd != "" {
			claims["hd"] = hd
		}
		_, err := f.v.Verify(context.Background(), "test", f.token(claims), testNonce)
		if ok && err != nil {
			t.Fatalf("hd %q: %v", hd, err)
		}
		if !ok && !errors.Is(err, ErrInvalid) {
			t.Fatalf("hd %q = %v, want ErrInvalid", hd, err)
		}
	}
	// Without a configured allow-list the claim is not checked.
	open := newFixture(t)
	claims := open.claims()
	claims["hd"] = "anything.test"
	if _, err := open.v.Verify(context.Background(), "test", open.token(claims), testNonce); err != nil {
		t.Fatalf("hd without allow-list: %v", err)
	}
}

// NEW-API.
func TestVerifyStructureAndSignature(t *testing.T) {
	f := newFixture(t)
	good := f.token(f.claims())
	parts := strings.Split(good, ".")

	otherKey := newRSAKey(t, "kid-1")
	wrongSigner := sign(t, otherKey, "RS256", nil, f.claims())

	hmacToken := func() string {
		// HS256 keyed with the RSA public key's modulus: the classic
		// algorithm-confusion token. The signature is valid for the "secret".
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"kid-1"}`))
		body := parts[1]
		mac := hmac.New(sha256.New, f.key.rsa.PublicKey.N.Bytes())
		mac.Write([]byte(header + "." + body))
		return header + "." + body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}()
	noneToken := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"kid-1"}`)) + "." + parts[1] + "."
	noneWithSig := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"kid-1"}`)) + "." + parts[1] + "." + parts[2]

	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"valid", good, nil},
		{"signature from another key with the same kid", wrongSigner, ErrInvalid},
		{"tampered payload", parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+testIssuer+`","aud":"`+testClientID+`","sub":"admin","iat":1900000000,"exp":1900000600,"nonce":"`+testNonce+`"}`)) + "." + parts[2], ErrInvalid},
		{"truncated signature", parts[0] + "." + parts[1] + "." + parts[2][:20], ErrInvalid},
		{"alg none, empty signature", noneToken, ErrInvalid},
		{"alg none with a signature", noneWithSig, ErrInvalid},
		{"HS256 using the RSA public key as secret", hmacToken, ErrInvalid},
		{"alg not configured (RS512)", sign(t, f.key, "RS512", nil, f.claims()), ErrInvalid},
		{"missing kid", sign(t, f.key, "RS256", map[string]interface{}{"kid": nil}, f.claims()), ErrInvalid},
		{"empty kid", sign(t, f.key, "RS256", map[string]interface{}{"kid": ""}, f.claims()), ErrInvalid},
		{"critical header", sign(t, f.key, "RS256", map[string]interface{}{"crit": []string{"exp"}}, f.claims()), ErrInvalid},
		{"two parts", parts[0] + "." + parts[1], ErrInvalid},
		{"four parts", good + ".x", ErrInvalid},
		{"empty", "", ErrInvalid},
		{"not a token", "garbage", ErrInvalid},
		{"header is not base64", "!!!." + parts[1] + "." + parts[2], ErrInvalid},
		{"header is not json", base64.RawURLEncoding.EncodeToString([]byte("nope")) + "." + parts[1] + "." + parts[2], ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := f.v.Verify(context.Background(), "test", tc.token, testNonce)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) || got != nil {
				t.Fatalf("Verify = %+v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

// NEW-API.
func TestVerifyOversizedToken(t *testing.T) {
	f := newFixture(t)
	claims := f.claims()
	claims["padding"] = strings.Repeat("x", MaxTokenBytes)
	token := f.token(claims)
	if len(token) <= MaxTokenBytes {
		t.Fatalf("token is only %d bytes", len(token))
	}
	if _, err := f.v.Verify(context.Background(), "test", token, testNonce); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized token = %v, want ErrInvalid", err)
	}
	if got := f.idp.fetches.Load(); got != 0 {
		t.Fatalf("an oversized token caused %d key fetches", got)
	}
}

// An EC key and an RSA key may share one key set; each token uses its own.
//
// NEW-API.
func TestVerifyEllipticCurveKey(t *testing.T) {
	f := newFixture(t)
	ec := newECKey(t, "ec-1")
	f.idp.setKeys(f.key, ec)

	token := sign(t, ec, "ES256", nil, f.claims())
	if _, err := f.v.Verify(context.Background(), "test", token, testNonce); err != nil {
		t.Fatalf("ES256 token: %v", err)
	}

	// The EC key must not verify an RS256 token that names it.
	confused := sign(t, f.key, "RS256", map[string]interface{}{"kid": "ec-1"}, f.claims())
	if _, err := f.v.Verify(context.Background(), "test", confused, testNonce); !errors.Is(err, ErrInvalid) {
		t.Fatalf("RS256 token naming an EC key = %v, want ErrInvalid", err)
	}
}

// A key's own declarations must agree with the token.
//
// NEW-API.
func TestVerifyKeyConstraints(t *testing.T) {
	cases := []struct {
		name  string
		patch func(jwk map[string]interface{})
		want  error
	}{
		{"matching alg and use", func(j map[string]interface{}) {}, nil},
		{"no alg declared", func(j map[string]interface{}) { delete(j, "alg") }, nil},
		{"encryption key", func(j map[string]interface{}) { j["use"] = "enc" }, ErrInvalid},
		{"declared for another algorithm", func(j map[string]interface{}) { j["alg"] = "RS384" }, ErrInvalid},
		{"verify operation", func(j map[string]interface{}) { j["key_ops"] = []string{"verify"} }, nil},
		{"sign-only operation", func(j map[string]interface{}) { j["key_ops"] = []string{"sign"} }, ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			jwk := f.key.jwk()
			tc.patch(jwk)
			body := mustJSON(t, map[string]interface{}{"keys": []interface{}{jwk}})
			f.idp.setBody(body)
			_, err := f.v.Verify(context.Background(), "test", f.token(f.claims()), testNonce)
			if tc.want == nil && err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("Verify = %v, want %v", err, tc.want)
			}
		})
	}
}

// NEW-API.
func TestVerifyReplay(t *testing.T) {
	f := newFixture(t)
	token := f.token(f.claims())

	if _, err := f.v.Verify(context.Background(), "test", token, testNonce); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := f.v.Verify(context.Background(), "test", token, testNonce); !errors.Is(err, ErrReplayed) {
		t.Fatalf("second use = %v, want ErrReplayed", err)
	}

	// The record is named after the provider and the token hash, and lives
	// for the remaining validity plus the leeway.
	sum := sha256.Sum256([]byte(token[:strings.LastIndexByte(token, '.')]))
	key := "axt:test:" + hex.EncodeToString(sum[:])
	ttl, ok := f.replay.seen[key]
	if !ok {
		t.Fatalf("no replay record %q; have %v", key, f.replay.seen)
	}
	if want := 10*time.Minute + DefaultLeeway; ttl != want {
		t.Fatalf("replay ttl = %v, want %v", ttl, want)
	}
}

// A token that fails any check must not use up its single-use record, or an
// attacker holding a stolen token could burn it with a wrong nonce.
//
// NEW-API.
func TestVerifyFailureDoesNotConsumeReplayRecord(t *testing.T) {
	f := newFixture(t)
	token := f.token(f.claims())
	if _, err := f.v.Verify(context.Background(), "test", token, "wrong-nonce"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong nonce = %v", err)
	}
	if len(f.replay.seen) != 0 {
		t.Fatalf("a rejected token left replay records: %v", f.replay.seen)
	}
	if _, err := f.v.Verify(context.Background(), "test", token, testNonce); err != nil {
		t.Fatalf("legitimate use after a rejected attempt: %v", err)
	}
}

// The record's lifetime is never below one second, and never unbounded.
//
// NEW-API.
func TestVerifyReplayTTLIsBounded(t *testing.T) {
	f := newFixture(t)
	// Expired 59s ago: inside the leeway, so accepted, with a 1s record.
	claims := f.claims()
	claims["exp"] = f.clock.Now().Add(-59 * time.Second).Unix()
	if _, err := f.v.Verify(context.Background(), "test", f.token(claims), testNonce); err != nil {
		t.Fatalf("token inside leeway: %v", err)
	}
	// Longest accepted lifetime.
	long := f.claims()
	long["sub"] = "long"
	long["exp"] = f.clock.Now().Add(maxTokenLifetime).Unix()
	if _, err := f.v.Verify(context.Background(), "test", f.token(long), testNonce); err != nil {
		t.Fatalf("24h token: %v", err)
	}
	for key, ttl := range f.replay.seen {
		if ttl < time.Second || ttl > maxTokenLifetime+DefaultLeeway {
			t.Fatalf("record %s has ttl %v, outside [1s, %v]", key, ttl, maxTokenLifetime+DefaultLeeway)
		}
	}
}

// NEW-API.
func TestVerifyReplayStoreFailureFailsClosed(t *testing.T) {
	f := newFixture(t)
	f.replay.err = errors.New("redis down")
	if _, err := f.v.Verify(context.Background(), "test", f.token(f.claims()), testNonce); !errors.Is(err, ErrStore) {
		t.Fatalf("Verify = %v, want ErrStore", err)
	}
}

// NEW-API.
func TestVerifyUnknownProvider(t *testing.T) {
	f := newFixture(t)
	if _, err := f.v.Verify(context.Background(), "nope", f.token(f.claims()), testNonce); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("Verify = %v, want ErrUnknownProvider", err)
	}
	if f.v.Has("nope") || !f.v.Has("test") {
		t.Fatal("Has misreports the configured providers")
	}
}

// NEW-API.
func TestNewVerifierValidates(t *testing.T) {
	opts := Options{Client: newTestIdP(t).server.Client(), Replay: newMemReplay()}
	good := ProviderConfig{Name: "p", Kind: KindOIDC, Issuers: []string{"i"}, ClientIDs: []string{"c"}, JWKSURL: "https://x.test/k", Algorithms: []string{"RS256"}}

	for name, mutate := range map[string]func(*ProviderConfig){
		"HS256":   func(c *ProviderConfig) { c.Algorithms = []string{"HS256"} },
		"none":    func(c *ProviderConfig) { c.Algorithms = []string{"none"} },
		"PS256":   func(c *ProviderConfig) { c.Algorithms = []string{"PS256"} },
		"no algs": func(c *ProviderConfig) { c.Algorithms = nil },
		"no id":   func(c *ProviderConfig) { c.ClientIDs = nil },
		"no iss":  func(c *ProviderConfig) { c.Issuers = nil },
	} {
		cfg := good
		mutate(&cfg)
		if _, err := NewVerifier([]ProviderConfig{cfg}, opts); err == nil {
			t.Fatalf("%s: NewVerifier accepted the config", name)
		}
	}
	if _, err := NewVerifier([]ProviderConfig{good}, Options{Client: opts.Client}); err == nil {
		t.Fatal("NewVerifier accepted a missing replay guard")
	}
	if _, err := NewVerifier([]ProviderConfig{good}, Options{Replay: opts.Replay}); err == nil {
		t.Fatal("NewVerifier accepted a missing http client")
	}
	short := opts
	short.KeyRefreshMin, short.KeyMaxStale = time.Minute, time.Second
	if _, err := NewVerifier([]ProviderConfig{good}, short); err == nil {
		t.Fatal("NewVerifier accepted KeyMaxStale below KeyRefreshMin")
	}
	short.KeyMaxStale = 0 // the default (24h) is above the minimum
	if _, err := NewVerifier([]ProviderConfig{good}, short); err != nil {
		t.Fatalf("NewVerifier with a default KeyMaxStale: %v", err)
	}
	if _, err := NewVerifier([]ProviderConfig{good}, opts); err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
}

// The algorithm allow-list is enforced by itself, not only through the key's
// own "alg" member: a key that declares no algorithm must not verify a token
// signed with an algorithm the provider is not configured for.
//
// NEW-API.
func TestVerifyAlgorithmAllowListIndependentOfKeyAlg(t *testing.T) {
	f := newFixture(t)
	jwk := f.key.jwk()
	delete(jwk, "alg")
	f.idp.setBody(mustJSON(t, map[string]interface{}{"keys": []interface{}{jwk}}))

	for _, alg := range []string{"RS384", "RS512"} {
		if _, err := f.v.Verify(context.Background(), "test", sign(t, f.key, alg, nil, f.claims()), testNonce); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s token = %v, want ErrInvalid", alg, err)
		}
	}
	if _, err := f.v.Verify(context.Background(), "test", f.token(f.claims()), testNonce); err != nil {
		t.Fatalf("RS256 token: %v", err)
	}
}

// A signature has more than one valid spelling. A variant of a used token must
// be refused as a replay (or as malformed), never accepted as a second use.
//
// FAILED-BEFORE the fix that keys the record on the signed part: hashing the
// whole token string accepted the ECDSA variant a second time.
func TestVerifyReplayCannotBeBypassedBySignatureVariants(t *testing.T) {
	f := newFixture(t)
	ec := newECKey(t, "ec-1")
	f.idp.setKeys(f.key, ec)

	original := sign(t, ec, "ES256", nil, f.claims())
	if _, err := f.v.Verify(context.Background(), "test", original, testNonce); err != nil {
		t.Fatalf("first use: %v", err)
	}

	parts := strings.Split(original, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("signature: %v (%d bytes)", err, len(sig))
	}
	// (r, n-s) verifies for the same message.
	s := new(big.Int).SetBytes(sig[32:])
	flipped := new(big.Int).Sub(elliptic.P256().Params().N, s)
	malleated := append(append([]byte{}, sig[:32]...), flipped.FillBytes(make([]byte, 32))...)
	variant := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(malleated)
	if variant == original {
		t.Fatal("test did not produce a different token")
	}
	if _, err := f.v.Verify(context.Background(), "test", variant, testNonce); !errors.Is(err, ErrReplayed) {
		t.Fatalf("malleated signature = %v, want ErrReplayed", err)
	}

	// A non-canonical spelling of the same signature bytes is malformed.
	rsaTok := f.token(f.claims())
	rp := strings.Split(rsaTok, ".")
	last := rp[2][len(rp[2])-1]
	alt := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", last)
	if alt < 0 {
		t.Fatal("unexpected signature alphabet")
	}
	// Flip the lowest bit, which is padding in a signature of 256 bytes.
	altChar := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[alt^1]
	nonCanonical := rp[0] + "." + rp[1] + "." + rp[2][:len(rp[2])-1] + string(altChar)
	if _, err := f.v.Verify(context.Background(), "test", nonCanonical, testNonce); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-canonical base64url signature = %v, want ErrInvalid", err)
	}
}
