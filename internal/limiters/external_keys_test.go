package limiters

import (
	"strings"
	"testing"
)

// FAILED-BEFORE (R2-21 residual): the external sign-in limiter built its keys
// from the raw client address and the provider's subject, so an address or a
// subject of N bytes cost N bytes of Redis memory for the whole window.
func TestExternalKeysNeverCarryCallerSizedInput(t *testing.T) {
	_, rdb := newRoleSwitchTestRedis(t)
	l := NewExternalLimiter(rdb, ExternalConfig{})
	huge := strings.Repeat("A", 256<<10)

	// "rl:extlogin:sub:" and three 64-digit digests with their separators.
	const maxKeyLen = len("rl:extlogin:sub:") + 3*64 + 2
	keys := map[string]string{
		"ip":              l.SourceKey("tenant", huge),
		"ip, huge tenant": l.SourceKey(huge, "203.0.113.7"),
		"subject":         l.SubjectKey("tenant", "google", huge),
		"provider":        l.SubjectKey("tenant", huge, "sub"),
		"tenant":          l.SubjectKey(huge, "google", "sub"),
	}
	for name, key := range keys {
		if len(key) > maxKeyLen {
			t.Errorf("%s key is %d bytes for a 256 KiB input", name, len(key))
		}
		if strings.Contains(key, "AAAA") {
			t.Errorf("%s key carries caller input: %.60s", name, key)
		}
	}
}

// The same string is the same bucket, and a different one is not: hashing
// must not merge or split anything the raw key kept apart or together.
func TestExternalKeysShareABucketExactlyWhenTheInputsAreEqual(t *testing.T) {
	_, rdb := newRoleSwitchTestRedis(t)
	l := NewExternalLimiter(rdb, ExternalConfig{})

	again := NewExternalLimiter(rdb, ExternalConfig{})
	if l.SourceKey("t1", "203.0.113.7") != again.SourceKey("t1", "203.0.113.7") ||
		l.SubjectKey("t1", "google", "sub") != again.SubjectKey("t1", "google", "sub") {
		t.Fatal("equal inputs gave different keys")
	}
	distinct := []string{
		l.SourceKey("t1", "203.0.113.7"),
		l.SourceKey("t2", "203.0.113.7"),
		l.SourceKey("t1", "203.0.113.8"),
		l.SubjectKey("t1", "google", "sub"),
		l.SubjectKey("t2", "google", "sub"),
		l.SubjectKey("t1", "apple", "sub"),
		l.SubjectKey("t1", "google", "sub2"),
		// The separator no longer decides where one segment ends.
		l.SubjectKey("t1", "google:sub", "x"),
		l.SubjectKey("t1", "google", "sub:x"),
	}
	seen := map[string]bool{}
	for _, k := range distinct {
		if seen[k] {
			t.Fatalf("two different inputs share the key %s", k)
		}
		seen[k] = true
	}
	if l.SourceKey("t1", "") != "" {
		t.Fatal("an unknown address must still have no bucket")
	}
}
