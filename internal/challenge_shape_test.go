package internal

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Every ID a generator produces must pass the shape rule for it: a valid ID
// must never be refused.
func TestChallengeShapeAcceptsEveryGeneratedID(t *testing.T) {
	for i := 0; i < 500; i++ {
		sid, err := NewSessionID()
		if err != nil {
			t.Fatal(err)
		}
		if !ValidSessionIDText(sid.String()) {
			t.Fatalf("session ID %q refused", sid.String())
		}

		if id := uuid.New().String(); !ValidUUIDText(id) || !ValidUUIDCode(id) {
			t.Fatalf("uuid %q refused", id)
		}

		secret, err := NewResetSecret()
		if err != nil {
			t.Fatal(err)
		}
		token, err := EncodeResetToken(sid.String(), secret)
		if err != nil {
			t.Fatal(err)
		}
		if !ValidResetTokenText(token) {
			t.Fatalf("reset token %q refused", token)
		}

		handle, err := NewSignupHandle()
		if err != nil {
			t.Fatal(err)
		}
		if !ValidSignupHandleText(handle) {
			t.Fatalf("sign-up handle %q refused", handle)
		}
	}
}

func TestChallengeShapeRefusesWhatNoGeneratorProduces(t *testing.T) {
	big := strings.Repeat("A", 1<<20)
	sid, _ := NewSessionID()
	good := sid.String()
	cases := map[string]bool{
		"session id 1 MiB":            ValidSessionIDText(big),
		"session id empty":            ValidSessionIDText(""),
		"session id one short":        ValidSessionIDText(good[:21]),
		"session id one long":         ValidSessionIDText(good + "A"),
		"session id outside alphabet": ValidSessionIDText(good[:21] + "+"),
		"session id non-canonical":    ValidSessionIDText(good[:21] + "B"),
		"uuid 1 MiB":                  ValidUUIDText(big),
		"uuid upper case":             ValidUUIDText(strings.ToUpper(uuid.New().String())),
		"uuid no hyphens":             ValidUUIDText(strings.ReplaceAll(uuid.New().String(), "-", "")),
		"uuid urn":                    ValidUUIDText("urn:uuid:" + uuid.New().String()),
		"uuid code 1 MiB":             ValidUUIDCode(big),
		"uuid code braces":            ValidUUIDCode("{" + uuid.New().String() + "}"),
		"token 1 MiB":                 ValidResetTokenText(big),
		"token one short":             ValidResetTokenText(strings.Repeat("A", 63)),
		"token outside alphabet":      ValidResetTokenText(strings.Repeat("A", 63) + "="),
		"handle 1 MiB":                ValidSignupHandleText(big),
		"handle empty":                ValidSignupHandleText(""),
		"handle non-canonical":        ValidSignupHandleText(strings.Repeat("A", 42) + "B"),
	}
	for name, accepted := range cases {
		if accepted {
			t.Errorf("%s: accepted", name)
		}
	}
	if !ValidUUIDCode(strings.ToUpper(uuid.New().String())) {
		t.Error("an upper-case UUID code is accepted today and must stay accepted")
	}
}
