package goAuth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Tests in this file cover the change of address by an account that is still
// pending verification: the confirmed code proves the new address and is the
// verification. All of it is NEW behavior.

// newPendingEnv is an email-change engine whose only user has not verified the
// address they signed up with. Email verification is on, as the feature needs.
func newPendingEnv(t *testing.T, opts ...rsOption) (*ecEnv, *manualClock) {
	t.Helper()
	env, clk := newBoundaryEnv(t, opts...)
	env.setStatus(AccountPendingVerification)
	return env, clk
}

// casAdapter makes the mock provider an AccountStatusCASUpdater.
type casAdapter struct {
	env     *ecEnv
	calls   int
	failErr error
}

func (c *casAdapter) UpdateAccountStatusIf(_ context.Context, _, userID string, expected, next AccountStatus) (bool, error) {
	c.calls++
	if c.failErr != nil {
		return false, c.failErr
	}
	c.env.up.mu.Lock()
	defer c.env.up.mu.Unlock()
	user := c.env.up.users[userID]
	if user.Status != expected {
		return false, nil
	}
	user.Status = next
	user.AccountVersion++
	c.env.up.users[userID] = user
	return true, nil
}

func TestUnverifiedAccountChangesItsAddressAndIsVerifiedByIt(t *testing.T) {
	env, _ := newPendingEnv(t)

	// A verification code mailed to the mistyped address A before the change.
	oldChallenge, err := env.engine.RequestEmailVerification(env.ctx(), rsIdentifier)
	if err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	oldParts := strings.SplitN(oldChallenge, ":", 3)

	req := env.mustRequest(ecNewEmail)
	res := env.mustConfirm(req, ConfirmEmailChangeOptions{})

	if !res.WasUnverified {
		t.Fatalf("WasUnverified = false, result %+v", res)
	}
	if res.OldEmail != rsIdentifier || res.NewEmail != ecNewEmail {
		t.Fatalf("result = %+v", res)
	}
	got := env.user(rsUserID)
	if got.Identifier != ecNewEmail {
		t.Fatalf("identifier = %q, want %q", got.Identifier, ecNewEmail)
	}
	if got.Status != AccountActive {
		t.Fatalf("status = %v, want Active: the code proved the new address", got.Status)
	}

	// A is free again: a new account can register it.
	created, err := env.engine.CreateAccount(env.ctx(), CreateAccountRequest{Identifier: rsIdentifier, Password: "another-password-123"})
	if err != nil {
		t.Fatalf("registering the freed address: %v", err)
	}
	if created.UserID == rsUserID {
		t.Fatal("the freed address was given to the same user")
	}

	// The verification code issued for A before the change no longer redeems.
	err = env.engine.ConfirmEmailVerificationCode(env.ctx(), oldParts[1], oldParts[2])
	if !errors.Is(err, ErrEmailVerificationInvalid) {
		t.Fatalf("a verification code issued for the old address = %v, want ErrEmailVerificationInvalid", err)
	}
}

func TestUnverifiedChangeSupersedesPasswordResetCodes(t *testing.T) {
	env, clk := newPendingEnv(t)
	oldReset, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
	if err != nil {
		t.Fatal(err)
	}
	env.mustConfirm(env.mustRequest(ecNewEmail), ConfirmEmailChangeOptions{})

	if err := env.engine.ConfirmPasswordReset(env.ctx(), oldReset, "brand-new-password-9"); !errors.Is(err, ErrPasswordResetInvalid) {
		t.Fatalf("a reset code issued to the old address = %v, want ErrPasswordResetInvalid", err)
	}
	// Right after, in the very same second, a reset for the new address works.
	_ = clk
	fresh, err := env.engine.RequestPasswordReset(env.ctx(), ecNewEmail)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.engine.ConfirmPasswordReset(env.ctx(), fresh, "brand-new-password-9"); err != nil {
		t.Fatalf("a reset code requested for the new address: %v", err)
	}
}

// The unverified path needs email verification: without it the pending
// account is refused exactly as before.
func TestUnverifiedAccountIsRefusedWhenEmailVerificationIsOff(t *testing.T) {
	env, _ := newBoundaryEnv(t, rsConfig(func(c *Config) { c.EmailVerification.Enabled = false }))
	env.setStatus(AccountPendingVerification)
	if _, err := env.request(ecNewEmail); !errors.Is(err, ErrAccountUnverified) {
		t.Fatalf("RequestEmailChange = %v, want ErrAccountUnverified", err)
	}
}

// Blocking statuses are refused at the request.
func TestUnverifiedChangeBlockingStatusRefused(t *testing.T) {
	for status, want := range map[AccountStatus]error{
		AccountDisabled: ErrAccountDisabled,
		AccountLocked:   ErrAccountLocked,
		AccountDeleted:  ErrAccountDeleted,
	} {
		env, _ := newPendingEnv(t)
		env.setStatus(status)
		if _, err := env.request(ecNewEmail); !errors.Is(err, want) {
			t.Errorf("status %v: RequestEmailChange = %v, want %v", status, err, want)
		}
	}
}

// Repeated requests are rate limited exactly as for a verified account, and a
// new request replaces the pending one.
func TestUnverifiedChangeRequestsAreRateLimited(t *testing.T) {
	env, _ := newPendingEnv(t)
	first := env.mustRequest("first@example.com")
	second := env.mustRequest("second@example.com")
	env.mustRequest("third@example.com")
	if _, err := env.request("fourth@example.com"); !errors.Is(err, ErrEmailChangeRateLimited) {
		t.Fatalf("fourth request = %v, want ErrEmailChangeRateLimited", err)
	}
	if _, err := env.confirm(first, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
		t.Fatalf("a replaced challenge = %v, want ErrEmailChangeInvalid", err)
	}
	if env.mr.Exists("aecu:" + env.tenant + ":" + strings.SplitN(first.VerificationID, ":", 2)[1]) {
		t.Fatal("the replaced challenge left its unverified flag behind")
	}
	_ = second
}

// The new address is claimed only when the code is confirmed: nothing is
// reserved before, so a request for an address that is taken is not told so.
func TestUnverifiedChangeReservesNothingBeforeConfirm(t *testing.T) {
	env, _ := newPendingEnv(t)
	env.addOther("u2", ecNewEmail)
	req, err := env.request(ecNewEmail)
	if err != nil {
		t.Fatalf("a request for a taken address must not say so: %v", err)
	}
	if _, err := env.confirm(req, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailInUse) {
		t.Fatalf("confirm = %v, want ErrEmailInUse", err)
	}
	if got := env.user(rsUserID); got.Identifier != rsIdentifier || got.Status != AccountPendingVerification {
		t.Fatalf("a failed confirm changed the account: %+v", got)
	}
}

// A disable that lands between loading the account and activating it stays in
// force: the address has changed, the account is not activated, and the caller
// is told with the result.
func TestUnverifiedChangeDisableRacingTheConfirmStaysDisabled(t *testing.T) {
	for _, tc := range []struct {
		name string
		cas  bool
	}{{"re-read path", false}, {"compare-and-set path", true}} {
		t.Run(tc.name, func(t *testing.T) {
			env, _ := newPendingEnv(t)
			var cas *casAdapter
			if tc.cas {
				cas = &casAdapter{env: env}
				env.engine.statusCAS = cas
			}
			req := env.mustRequest(ecNewEmail)
			env.up.beforeUpdateIdentifier = func() { env.setStatus(AccountDisabled) }

			res, err := env.confirm(req, ConfirmEmailChangeOptions{})
			if !errors.Is(err, ErrAccountDisabled) {
				t.Fatalf("confirm error = %v, want ErrAccountDisabled", err)
			}
			if res == nil || !res.WasUnverified || res.NewEmail != ecNewEmail {
				t.Fatalf("the address changed, so the result must come with the error: %+v", res)
			}
			got := env.user(rsUserID)
			if got.Identifier != ecNewEmail {
				t.Fatalf("identifier = %q: the change itself was committed", got.Identifier)
			}
			if got.Status != AccountDisabled {
				t.Fatalf("status = %v, want Disabled to stay in force", got.Status)
			}
			if tc.cas && cas.calls != 1 {
				t.Fatalf("UpdateAccountStatusIf called %d times, want 1", cas.calls)
			}
		})
	}
}

// If activation fails after the address changed, the address stays changed and
// the account stays pending; the application can send a verification for the
// new address.
func TestUnverifiedChangeActivationFailureReturnsTheResult(t *testing.T) {
	env, _ := newPendingEnv(t)
	env.engine.statusCAS = &casAdapter{env: env, failErr: errors.New("db down")}
	res, err := env.confirm(env.mustRequest(ecNewEmail), ConfirmEmailChangeOptions{})
	if !errors.Is(err, ErrSystemUnavailable) {
		t.Fatalf("confirm error = %v, want ErrSystemUnavailable", err)
	}
	if res == nil || !res.WasUnverified || res.NewEmail != ecNewEmail {
		t.Fatalf("result = %+v", res)
	}
	if got := env.user(rsUserID); got.Identifier != ecNewEmail || got.Status != AccountPendingVerification {
		t.Fatalf("account = %+v", got)
	}
	// The recovery the docs describe works.
	env.engine.statusCAS = nil
	challenge, err := env.engine.RequestEmailVerification(env.ctx(), ecNewEmail)
	if err != nil {
		t.Fatalf("RequestEmailVerification for the new address: %v", err)
	}
	parts := strings.SplitN(challenge, ":", 3)
	if err := env.engine.ConfirmEmailVerificationCode(env.ctx(), parts[1], parts[2]); err != nil {
		t.Fatalf("verifying the new address: %v", err)
	}
	if got := env.user(rsUserID).Status; got != AccountActive {
		t.Fatalf("status = %v, want Active", got)
	}
}

// An account that became Active in the meantime by a route that leaves the
// version alone (the application's own admin action) takes the ordinary flow:
// the old address counts as proven, so WasUnverified is false.
func TestUnverifiedChallengeConfirmedAfterActivationIsTheOrdinaryFlow(t *testing.T) {
	env, _ := newPendingEnv(t)
	req := env.mustRequest(ecNewEmail)
	env.setStatus(AccountActive)
	res := env.mustConfirm(req, ConfirmEmailChangeOptions{})
	if res.WasUnverified {
		t.Fatal("WasUnverified = true for an account that was Active at the confirm")
	}
	if got := env.user(rsUserID); got.Identifier != ecNewEmail || got.Status != AccountActive {
		t.Fatalf("account = %+v", got)
	}
}

// Verifying through the old address inside goAuth revokes the account's
// sessions, and every revocation drops the pending change: it cannot be
// confirmed afterwards, so it never needs to guess whether the old address
// was proven.
func TestVerificationThroughTheOldAddressCancelsAPendingUnverifiedChange(t *testing.T) {
	env, _ := newPendingEnv(t)
	req := env.mustRequest(ecNewEmail)
	if err := env.engine.EnableAccount(env.ctx(), rsUserID); err != nil {
		t.Fatalf("EnableAccount: %v", err)
	}
	if _, err := env.confirm(req, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
		t.Fatalf("confirm = %v, want ErrEmailChangeInvalid", err)
	}
}

// A challenge requested while the account was Active cannot be used by an
// account that has since become pending: the flag is what allows it.
func TestVerifiedChallengeIsRefusedForAPendingAccount(t *testing.T) {
	env, _ := newBoundaryEnv(t)
	req := env.mustRequest(ecNewEmail)
	env.setStatus(AccountPendingVerification)
	if _, err := env.confirm(req, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrAccountUnverified) {
		t.Fatalf("confirm = %v, want ErrAccountUnverified", err)
	}
}

// A stale account (version moved) is refused as in the verified flow.
func TestUnverifiedChangeStaleIsRefused(t *testing.T) {
	env, _ := newPendingEnv(t)
	req := env.mustRequest(ecNewEmail)
	u := env.user(rsUserID)
	u.AccountVersion++
	env.setUser(u)
	if _, err := env.confirm(req, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeStale) {
		t.Fatalf("confirm = %v, want ErrEmailChangeStale", err)
	}
}

// Sessions follow the rule of the verified flow: the others are revoked, the
// kept one survives, and KeepOtherSessions revokes nothing.
func TestUnverifiedChangeSessions(t *testing.T) {
	t.Run("others revoked, the kept one survives", func(t *testing.T) {
		env, _ := newBoundaryEnv(t)
		_, a := env.login()
		_, b := env.login()
		env.setStatus(AccountPendingVerification)
		res := env.mustConfirm(env.mustRequest(ecNewEmail), ConfirmEmailChangeOptions{KeepSessionID: env.sidOf(a)})
		if !res.WasUnverified || !res.SessionsRevoked {
			t.Fatalf("result = %+v", res)
		}
		if !env.hasSession(env.sidOf(a)) {
			t.Fatal("the kept session was revoked")
		}
		if env.hasSession(env.sidOf(b)) {
			t.Fatal("another session survived")
		}
	})
	t.Run("KeepOtherSessions revokes nothing", func(t *testing.T) {
		clk := newManualClock(clockStart)
		env := newECEnv(t, func(c *EmailChangeConfig) { c.KeepOtherSessions = true }, rsClock(clk))
		env.mr.SetTime(clockStart)
		_, a := env.login()
		_, b := env.login()
		env.setStatus(AccountPendingVerification)
		res := env.mustConfirm(env.mustRequest(ecNewEmail), ConfirmEmailChangeOptions{})
		if res.SessionsRevoked || !env.hasSession(env.sidOf(a)) || !env.hasSession(env.sidOf(b)) {
			t.Fatalf("sessions were touched: %+v", res)
		}
	})
}

// Audit: the requested and confirmed events carry account_was_unverified, and a
// verified account's events do not.
func TestUnverifiedChangeAudit(t *testing.T) {
	env, _ := newPendingEnv(t)
	req := env.mustRequest(ecNewEmail)
	env.mustConfirm(req, ConfirmEmailChangeOptions{})
	for _, name := range []string{auditEventEmailChangeRequested, auditEventEmailChangeConfirmed} {
		events := env.eventsOf(name)
		if len(events) != 1 || events[0].Metadata["account_was_unverified"] != "true" {
			t.Fatalf("%s events = %+v, want one carrying account_was_unverified=true", name, events)
		}
	}
	if strings.Contains(env.auditJSON(), req.Code) {
		t.Fatal("the code reached the audit trail")
	}

	verified, _ := newBoundaryEnv(t)
	verified.mustConfirm(verified.mustRequest(ecNewEmail), ConfirmEmailChangeOptions{})
	for _, name := range []string{auditEventEmailChangeRequested, auditEventEmailChangeConfirmed} {
		for _, ev := range verified.eventsOf(name) {
			if _, ok := ev.Metadata["account_was_unverified"]; ok {
				t.Fatalf("%s of a verified account carries account_was_unverified", name)
			}
		}
	}
}

// Isolation: a pending user's challenge belongs to the tenant it was made in.
func TestUnverifiedChangeTenantIsolation(t *testing.T) {
	env, _ := newPendingEnv(t, rsMultiTenant())
	req := env.mustRequest(ecNewEmail)
	other := WithTenantID(context.Background(), "tenant-b")
	if _, err := env.engine.ConfirmEmailChange(other, req.VerificationID, req.Code, ConfirmEmailChangeOptions{}); !errors.Is(err, ErrEmailChangeInvalid) {
		t.Fatalf("confirm from another tenant = %v, want ErrEmailChangeInvalid", err)
	}
	if got := env.user(rsUserID); got.Identifier != rsIdentifier || got.Status != AccountPendingVerification {
		t.Fatalf("a foreign tenant changed the account: %+v", got)
	}
	res := env.mustConfirm(req, ConfirmEmailChangeOptions{})
	if !res.WasUnverified {
		t.Fatalf("result = %+v", res)
	}
	if got := env.user(rsUserID); got.Status != AccountActive {
		t.Fatalf("status = %v", got.Status)
	}
}

// External identities stay linked, as in the verified flow.
func TestUnverifiedChangeLeavesExternalIdentitiesLinked(t *testing.T) {
	env := newExtEnv(t, extAutoLink(), extSignup(), extConfig(func(c *Config) {
		c.EmailChange = EmailChangeConfig{Enabled: true, Strategy: VerificationOTP, MaxAttempts: 3, VerificationTTL: 10 * time.Minute, RequestMaxAttempts: 3, RequestCooldown: time.Hour}
		c.EmailVerification = testEmailVerificationConfig(VerificationOTP)
	}))
	env.addLocal(UserRecord{UserID: "pend1", Identifier: "pending@example.com", Status: AccountPendingVerification})
	env.link("google", "sub-pending", "pend1")

	req, err := env.engine.RequestEmailChange(env.ctx(), "pend1", "moved@example.com")
	if err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	res, err := env.engine.ConfirmEmailChange(env.ctx(), req.VerificationID, req.Code, ConfirmEmailChangeOptions{})
	if err != nil || !res.WasUnverified {
		t.Fatalf("ConfirmEmailChange = %+v, %v", res, err)
	}
	if uid, ok := env.up.linkedTo(env.tenant, "google", "sub-pending"); !ok || uid != "pend1" {
		t.Fatalf("the external link did not survive: %v %v", uid, ok)
	}
}
