package goAuth

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/redis/go-redis/v9"
)

// afterSetHook runs fn once, right after the first SET of a key that starts
// with prefix has been applied: the point between a request storing its record
// and writing its pointer.
type afterSetHook struct {
	prefix string
	fn     func()
	done   atomic.Bool
}

func (h *afterSetHook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *afterSetHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		err := next(ctx, cmd)
		args := cmd.Args()
		if err == nil && len(args) > 1 && strings.EqualFold(cmd.Name(), "set") {
			if key, ok := args[1].(string); ok && strings.HasPrefix(key, h.prefix) && h.done.CompareAndSwap(false, true) {
				h.fn()
			}
		}
		return err
	}
}

func (h *afterSetHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

// A reset requested for the old address while the email change commits: the
// change tombstones the pointer first, and the request would then write its own
// ID over the tombstone, leaving a valid code for the old address. The request
// notices the address moved and fails; no code is handed out.
func TestEmailChangeCommittingDuringAResetRequestLeavesNoValidCode(t *testing.T) {
	env, _ := newBoundaryEnv(t)
	req := env.mustRequest(ecNewEmail)
	env.rdb.AddHook(&afterSetHook{prefix: "apr:", fn: func() {
		env.mustConfirm(req, ConfirmEmailChangeOptions{})
	}})

	challenge, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
	if !errors.Is(err, ErrPasswordResetUnavailable) {
		t.Fatalf("RequestPasswordReset racing the change = %q, %v; want ErrPasswordResetUnavailable and no code", challenge, err)
	}
	if got := env.user(rsUserID).Identifier; got != ecNewEmail {
		t.Fatalf("the change did not commit during the request: identifier %q", got)
	}
	if ev := env.eventsOf(auditEventPasswordResetRequest); len(ev) == 0 || ev[len(ev)-1].Success {
		t.Fatalf("the refused request must be audited as a failure: %+v", ev)
	}
}

// The same for email verification, through the unverified account's change.
func TestEmailChangeCommittingDuringAVerificationRequestLeavesNoValidCode(t *testing.T) {
	env, _ := newPendingEnv(t)
	req := env.mustRequest(ecNewEmail)
	env.rdb.AddHook(&afterSetHook{prefix: "apv:", fn: func() {
		env.mustConfirm(req, ConfirmEmailChangeOptions{})
	}})

	challenge, err := env.engine.RequestEmailVerification(env.ctx(), rsIdentifier)
	if !errors.Is(err, ErrEmailVerificationUnavailable) {
		t.Fatalf("RequestEmailVerification racing the change = %q, %v; want ErrEmailVerificationUnavailable and no code", challenge, err)
	}
	if got := env.user(rsUserID).Identifier; got != ecNewEmail {
		t.Fatalf("the change did not commit during the request: identifier %q", got)
	}
}

// Without an email change the recheck costs one lookup and changes nothing.
func TestResetRequestWithoutAChangeStillSucceeds(t *testing.T) {
	env, _ := newBoundaryEnv(t)
	challenge, err := env.engine.RequestPasswordReset(env.ctx(), rsIdentifier)
	if err != nil || challenge == "" {
		t.Fatalf("RequestPasswordReset = %q, %v", challenge, err)
	}
}
