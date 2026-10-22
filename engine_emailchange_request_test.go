package goAuth

import (
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// All tests in this file are NEW-API (RequestEmailChange).

func TestRequestEmailChangeHappyPath(t *testing.T) {
	env := newECEnv(t, nil)

	req, err := env.request("  " + ecNewEmail + "  ")
	if err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	tenant, rawID, ok := strings.Cut(req.VerificationID, ":")
	if !ok || tenant != env.tenant || rawID == "" {
		t.Fatalf("VerificationID %q does not carry the tenant", req.VerificationID)
	}
	if len(req.Code) != 6 || strings.Trim(req.Code, "0123456789") != "" {
		t.Fatalf("OTP code = %q, want 6 digits", req.Code)
	}

	// One challenge, one pointer; the account itself is untouched.
	if keys := env.changeKeys(); !reflect.DeepEqual(keys, []string{"aec:" + env.tenant + ":" + rawID, "aecp:" + env.tenant + ":" + rsUserID}) {
		t.Fatalf("keys = %v", keys)
	}
	if got := env.user(rsUserID); got.Identifier != rsIdentifier || got.AccountVersion != 1 {
		t.Fatalf("the account changed at request time: %+v", got)
	}
	if ttl := env.mr.TTL("aec:" + env.tenant + ":" + rawID); ttl <= 9*time.Minute || ttl > 10*time.Minute {
		t.Fatalf("challenge TTL = %v, want ~10m", ttl)
	}

	ev := env.waitForAudit(auditEventEmailChangeRequested, "")
	if !ev.Success || ev.UserID != rsUserID {
		t.Fatalf("audit event = %+v", ev)
	}
	if ev.Metadata["new_email"] != "n***@example.com" || ev.Metadata["old_email"] != "t***@example.com" {
		t.Fatalf("masked addresses = %v", ev.Metadata)
	}
}

func TestRequestEmailChangeSecretsNeverReachAuditOrLogs(t *testing.T) {
	env := newECEnv(t, nil)
	req := env.mustRequest(ecNewEmail)
	env.mustConfirm(req, ConfirmEmailChangeOptions{})
	// A failure too: a wrong code on a fresh challenge.
	again := env.mustRequestFrom(ecNewEmail, "second.address@example.com")
	_, _ = env.engine.ConfirmEmailChange(env.ctx(), again.VerificationID, "000000", ConfirmEmailChangeOptions{})

	audit := env.auditJSON()
	for name, secret := range map[string]string{"code": req.Code, "second code": again.Code} {
		if strings.Contains(audit, secret) {
			t.Fatalf("the %s appears in the audit trail: %s", name, audit)
		}
		if env.logs.Contains(secret) {
			t.Fatalf("the %s appears in the logs", name)
		}
	}
	for _, addr := range []string{ecNewEmail, "second.address@example.com", rsIdentifier} {
		if strings.Contains(audit, addr) {
			t.Fatalf("the full address %q appears in the audit trail: %s", addr, audit)
		}
	}
}

// mustRequestFrom changes the account's identifier in the provider first, as a
// completed earlier change would have, so a second request has something to
// replace.
func (env *ecEnv) mustRequestFrom(currentEmail, newEmail string) *EmailChangeRequest {
	env.t.Helper()
	u := env.user(rsUserID)
	u.Identifier = currentEmail
	env.setUser(u)
	return env.mustRequest(newEmail)
}

func TestRequestEmailChangeRefusesNonActiveAccounts(t *testing.T) {
	cases := []struct {
		status AccountStatus
		want   *AuthError
	}{
		{AccountPendingVerification, ErrAccountUnverified},
		{AccountDisabled, ErrAccountDisabled},
		{AccountLocked, ErrAccountLocked},
		{AccountDeleted, ErrAccountDeleted},
	}
	for _, tc := range cases {
		t.Run(tc.want.Message, func(t *testing.T) {
			env := newECEnv(t, nil)
			u := env.user(rsUserID)
			u.Status = tc.status
			env.setUser(u)

			_, err := env.request(ecNewEmail)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if keys := env.changeKeys(); len(keys) != 0 {
				t.Fatalf("a refused request stored %v", keys)
			}
			env.waitForAudit(auditEventEmailChangeFailure, "status")
		})
	}
}

func TestRequestEmailChangeValidatesTheNewAddress(t *testing.T) {
	env := newECEnv(t, func(c *EmailChangeConfig) { c.RequestMaxAttempts = 100 })

	bad := map[string]string{
		"empty":             "",
		"spaces":            "   ",
		"no at sign":        "not-an-email",
		"display name":      "Someone <someone@example.com>",
		"angle brackets":    "<someone@example.com>",
		"inner space":       "some one@example.com",
		"control character": "some\x00one@example.com",
		"newline":           "someone@example.com\nBcc: x@y.z",
		"too long":          strings.Repeat("a", 250) + "@example.com",
	}
	for name, addr := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := env.request(addr)
			if !errors.Is(err, ErrEmailChangeInvalid) {
				t.Fatalf("RequestEmailChange(%q) = %v, want ErrEmailChangeInvalid", addr, err)
			}
		})
	}
	if keys := env.changeKeys(); len(keys) != 0 {
		t.Fatalf("invalid requests stored %v", keys)
	}

	for _, same := range []string{rsIdentifier, strings.ToUpper(rsIdentifier), "  " + rsIdentifier + " ", "Teacher@EXAMPLE.com"} {
		if _, err := env.request(same); !errors.Is(err, ErrEmailChangeInvalid) {
			t.Fatalf("a request for the current address %q = %v, want ErrEmailChangeInvalid", same, err)
		}
	}
	env.waitForAudit(auditEventEmailChangeFailure, "same_email")
	env.waitForAudit(auditEventEmailChangeFailure, "invalid_email")
}

// A request must not reveal whether the new address already has an account:
// the same result, the same audit trail and the same Redis footprint either
// way, and the provider is never asked.
func TestRequestEmailChangeDoesNotRevealWhetherTheAddressIsTaken(t *testing.T) {
	run := func(taken bool) (string, []string, []map[string]string, int) {
		env := newECEnv(t, nil)
		env.addOther("u-taken", "taken@example.com")
		target := "free@example.com"
		if taken {
			target = "taken@example.com"
		}
		identifierCalls := env.up.getByIdentifierCalls + env.up.tenantIdentifierCalls

		req, err := env.request(target)
		if err != nil {
			t.Fatalf("taken=%v: %v", taken, err)
		}
		shape := ecShape(req)

		var keys []string
		for _, k := range env.changeKeys() {
			keys = append(keys, strings.Replace(k, strings.SplitN(req.VerificationID, ":", 2)[1], "<id>", 1))
		}
		var meta []map[string]string
		for _, ev := range env.eventsOf(auditEventEmailChangeRequested) {
			m := map[string]string{"success": ecBool(ev.Success), "user": ev.UserID, "err": ev.Error}
			for k := range ev.Metadata {
				m["key:"+k] = ""
			}
			meta = append(meta, m)
		}
		return shape, keys, meta, env.up.getByIdentifierCalls + env.up.tenantIdentifierCalls - identifierCalls
	}

	freeShape, freeKeys, freeEvents, freeCalls := run(false)
	takenShape, takenKeys, takenEvents, takenCalls := run(true)
	if freeShape != takenShape {
		t.Fatalf("result shape differs: free=%q taken=%q", freeShape, takenShape)
	}
	if !reflect.DeepEqual(freeKeys, takenKeys) {
		t.Fatalf("Redis footprint differs: free=%v taken=%v", freeKeys, takenKeys)
	}
	if !reflect.DeepEqual(freeEvents, takenEvents) {
		t.Fatalf("audit differs: free=%v taken=%v", freeEvents, takenEvents)
	}
	if freeCalls != 0 || takenCalls != 0 {
		t.Fatalf("the provider was asked about the new address (%d, %d lookups)", freeCalls, takenCalls)
	}
}

func ecShape(req *EmailChangeRequest) string {
	tenant, _, _ := strings.Cut(req.VerificationID, ":")
	return tenant + "/" + strings.Repeat("d", len(req.Code))
}

func ecBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func TestRequestEmailChangeRateLimit(t *testing.T) {
	t.Run("per user", func(t *testing.T) {
		env := newECEnv(t, func(c *EmailChangeConfig) { c.RequestMaxAttempts = 2 })
		env.addOther("u2", "second@example.com")
		for i := 0; i < 2; i++ {
			if _, err := env.request("one@example.com"); err != nil {
				t.Fatalf("request %d: %v", i, err)
			}
		}
		_, err := env.request("one@example.com")
		if !errors.Is(err, ErrEmailChangeRateLimited) {
			t.Fatalf("third request = %v, want ErrEmailChangeRateLimited", err)
		}
		requireCode(t, err, CodeAuthEmailChangeRateLimited)

		// Another user is not affected.
		if _, err := env.engine.RequestEmailChange(env.ctx(), "u2", "other@example.com"); err != nil {
			t.Fatalf("another user's request: %v", err)
		}
		env.waitForAudit(auditEventRateLimitTriggered, "")
		env.waitForAudit(auditEventEmailChangeFailure, "rate_limited")
		if keys := env.keys("rl:emailchange:*"); len(keys) != 2 {
			t.Fatalf("limiter keys = %v, want one per user", keys)
		}
	})

	t.Run("honors the window mode", func(t *testing.T) {
		env := newECEnv(t, func(c *EmailChangeConfig) { c.RequestMaxAttempts = 1 },
			rsConfig(func(c *Config) { c.Security.LimiterWindowMode = "sliding" }))
		env.mustRequest("one@example.com")
		if _, err := env.request("one@example.com"); !errors.Is(err, ErrEmailChangeRateLimited) {
			t.Fatalf("second request under sliding windows = %v", err)
		}
		var found bool
		for _, k := range env.keys("*emailchange*") {
			if strings.Contains(k, ":s:") {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected sliding-window limiter keys, got %v", env.keys("*emailchange*"))
		}
	})

	t.Run("a refused request does not reach the provider or the store", func(t *testing.T) {
		env := newECEnv(t, func(c *EmailChangeConfig) { c.RequestMaxAttempts = 1 })
		env.mustRequest("one@example.com")
		before := env.up.tenantIDCalls + env.up.getByIDCalls
		keysBefore := env.changeKeys()
		if _, err := env.request("two@example.com"); !errors.Is(err, ErrEmailChangeRateLimited) {
			t.Fatal(err)
		}
		if env.up.tenantIDCalls+env.up.getByIDCalls != before {
			t.Fatal("a rate-limited request still looked the user up")
		}
		after := env.changeKeys()
		sort.Strings(keysBefore)
		sort.Strings(after)
		if !reflect.DeepEqual(keysBefore, after) {
			t.Fatalf("a rate-limited request changed the store: %v -> %v", keysBefore, after)
		}
	})
}

func TestRequestEmailChangeReplacesThePendingChallenge(t *testing.T) {
	env := newECEnv(t, nil)
	first := env.mustRequest("first@example.com")
	second := env.mustRequest("second@example.com")

	if keys := env.changeKeys(); len(keys) != 2 {
		t.Fatalf("one challenge and one pointer expected, got %v", keys)
	}
	// The first code is dead; it does not even get a wrong-attempt.
	if _, err := env.confirm(first, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
		t.Fatalf("the replaced challenge = %v, want ErrEmailChangeInvalid", err)
	}
	res := env.mustConfirm(second, ConfirmEmailChangeOptions{})
	if res.NewEmail != "second@example.com" {
		t.Fatalf("NewEmail = %q", res.NewEmail)
	}
}

func TestEmailChangeDisabledAndRefusals(t *testing.T) {
	env := newRSEnv(t) // EmailChange left at its zero value
	ctx := env.ctx()
	if _, err := env.engine.RequestEmailChange(ctx, rsUserID, ecNewEmail); !errors.Is(err, ErrEmailChangeDisabled) {
		t.Fatalf("RequestEmailChange = %v", err)
	}
	if _, err := env.engine.ConfirmEmailChange(ctx, "0:abc", "123456", ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeDisabled) {
		t.Fatalf("ConfirmEmailChange = %v", err)
	}
	if err := env.engine.CancelEmailChange(ctx, rsUserID); !errors.Is(err, ErrEmailChangeDisabled) {
		t.Fatalf("CancelEmailChange = %v", err)
	}
	requireCode(t, func() error { _, err := env.engine.RequestEmailChange(ctx, rsUserID, ecNewEmail); return err }(), CodeAuthEmailChangeDisabled)
	if keys := env.keys("*"); len(keys) != 0 {
		t.Fatalf("a disabled feature touched Redis: %v", keys)
	}
}

func TestRequestEmailChangeUserLookup(t *testing.T) {
	t.Run("unknown user", func(t *testing.T) {
		env := newECEnv(t, nil)
		_, err := env.engine.RequestEmailChange(env.ctx(), "nobody", ecNewEmail)
		requireCode(t, err, CodeAuthAccountNotFound)
		_, err = env.engine.RequestEmailChange(env.ctx(), "", ecNewEmail)
		requireCode(t, err, CodeAuthAccountNotFound)
		if keys := env.changeKeys(); len(keys) != 0 {
			t.Fatalf("stored %v", keys)
		}
	})

	t.Run("a provider failure is an outage, not a missing account", func(t *testing.T) {
		env := newECEnv(t, nil)
		env.up.setLookupErr(errors.New("db down"))
		_, err := env.request(ecNewEmail)
		ae := requireCode(t, err, CodeSystemUnavailable)
		if ae.Category != CategorySystem {
			t.Fatalf("category = %s", ae.Category)
		}
		env.waitForAudit(auditEventEmailChangeFailure, "unavailable")
	})
}
