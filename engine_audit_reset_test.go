package goAuth

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal/stores"
	"github.com/redis/go-redis/v9"
)

// Regression tests for R2-25 of the v0.8.0 security audit (run 2): every
// RequestPasswordReset wrote an independent record, and completing a reset
// consumed only the presented one.

func newSupersedeEnv(t *testing.T, strategy ResetStrategyType) (*Engine, *mockUserProvider, *redis.Client) {
	t.Helper()
	_, rdb := newTestRedis(t)
	hasher := newTestHasher(t)
	oldHash, err := hasher.Hash("old-password-123")
	if err != nil {
		t.Fatal(err)
	}
	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {UserID: "u1", Identifier: "alice", PasswordHash: oldHash, TenantID: "0"},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}
	cfg := testResetConfig(strategy)
	cfg.EnableRequestLimiter = false
	return newTestResetEngine(t, rdb, up, hasher, cfg), up, rdb
}

func passwordIs(t *testing.T, engine *Engine, up *mockUserProvider, pw string) bool {
	t.Helper()
	ok, err := engine.passwordHash.Verify(pw, up.users["u1"].PasswordHash)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// FAILED-BEFORE (R2-25): the earlier of two outstanding codes stayed redeemable
// after the owner completed a reset with the later one, and replaced the
// owner's new password.
func TestAnEarlierResetCodeFailsAfterALaterRequestAndAfterACompletedReset(t *testing.T) {
	for name, strategy := range map[string]ResetStrategyType{"token": ResetToken, "otp": ResetOTP} {
		t.Run(name, func(t *testing.T) {
			engine, up, _ := newSupersedeEnv(t, strategy)
			ctx := context.Background()

			first, err := engine.RequestPasswordReset(ctx, "alice")
			if err != nil {
				t.Fatal(err)
			}
			second, err := engine.RequestPasswordReset(ctx, "alice")
			if err != nil {
				t.Fatal(err)
			}

			// A later request superseded the first code before anything was redeemed.
			if err := engine.ConfirmPasswordReset(ctx, first, "attacker-password-1"); !errors.Is(err, ErrPasswordResetInvalid) {
				t.Fatalf("the earlier code after a later request: %v, want ErrPasswordResetInvalid", err)
			}
			if passwordIs(t, engine, up, "attacker-password-1") {
				t.Fatal("a superseded code changed the password")
			}

			// The latest code is the owner's; completing it kills the rest.
			if err := engine.ConfirmPasswordReset(ctx, second, "owner-password-1"); err != nil {
				t.Fatalf("the latest code: %v", err)
			}
			if err := engine.ConfirmPasswordReset(ctx, first, "attacker-password-2"); !errors.Is(err, ErrPasswordResetInvalid) {
				t.Fatalf("the earlier code after the owner's reset: %v, want ErrPasswordResetInvalid", err)
			}
			if !passwordIs(t, engine, up, "owner-password-1") {
				t.Fatal("the owner's password was replaced")
			}
			// Replay of the owner's own code stays refused.
			if err := engine.ConfirmPasswordReset(ctx, second, "owner-password-3"); !errors.Is(err, ErrPasswordResetInvalid) {
				t.Fatalf("replay: %v", err)
			}
		})
	}
}

func TestANewRequestAfterACompletedResetIsRedeemable(t *testing.T) {
	engine, up, _ := newSupersedeEnv(t, ResetToken)
	ctx := context.Background()

	c1, _ := engine.RequestPasswordReset(ctx, "alice")
	if err := engine.ConfirmPasswordReset(ctx, c1, "owner-password-1"); err != nil {
		t.Fatal(err)
	}
	c2, err := engine.RequestPasswordReset(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.ConfirmPasswordReset(ctx, c2, "owner-password-2"); err != nil {
		t.Fatalf("a request made after a completed reset must work: %v", err)
	}
	if !passwordIs(t, engine, up, "owner-password-2") {
		t.Fatal("the new password was not stored")
	}
}

// A record without a pointer (issued by a v0.8.0 instance) is redeemable until a
// reset completes; the completion supersedes it too.
func TestCompletedResetSupersedesRecordsWithoutAPointer(t *testing.T) {
	_, rdb := newTestRedis(t)
	store := stores.NewPasswordResetStore(rdb, "apr")
	ctx := context.Background()

	if ok, err := store.IsCurrent(ctx, "t1", "u1", "legacy-id"); err != nil || !ok {
		t.Fatalf("no pointer: ok=%v err=%v, want current", ok, err)
	}
	if err := store.SetCurrent(ctx, "t1", "u1", "new-id", time.Minute); err != nil {
		t.Fatal(err)
	}
	if ok, _ := store.IsCurrent(ctx, "t1", "u1", "legacy-id"); ok {
		t.Fatal("an older record stayed current after a newer request")
	}
	if ok, _ := store.IsCurrent(ctx, "t1", "u1", "new-id"); !ok {
		t.Fatal("the newest record is not current")
	}
	if ok, _ := store.IsCurrent(ctx, "t2", "u1", "legacy-id"); !ok {
		t.Fatal("tenant t2's records were affected by tenant t1")
	}
	if err := store.InvalidateOutstanding(ctx, "t1", "u1", time.Minute); err != nil {
		t.Fatal(err)
	}
	if ok, _ := store.IsCurrent(ctx, "t1", "u1", "new-id"); ok {
		t.Fatal("a record survived a completed reset")
	}
}

// failSetWithPrefix makes the first SET of a key with the given prefix fail, like
// a Redis hiccup while a reset record is stored.
type failSetWithPrefix struct {
	prefix string
	armed  atomic.Bool
}

func (h *failSetWithPrefix) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *failSetWithPrefix) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		args := cmd.Args()
		if strings.EqualFold(cmd.Name(), "set") && len(args) > 1 {
			if key, ok := args[1].(string); ok && strings.HasPrefix(key, h.prefix) && h.armed.CompareAndSwap(true, false) {
				return errors.New("transient redis failure")
			}
		}
		return next(ctx, cmd)
	}
}

func (h *failSetWithPrefix) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

// A request that cannot store its record must not cost the user the code they
// already hold: the earlier code is superseded only once the new record exists.
func TestAFailedResetRequestDoesNotCancelTheEarlierCode(t *testing.T) {
	engine, up, rdb := newSupersedeEnv(t, ResetToken)
	ctx := context.Background()

	held, err := engine.RequestPasswordReset(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	hook := &failSetWithPrefix{prefix: "apr:0:"}
	hook.armed.Store(true)
	rdb.AddHook(hook)
	if _, err := engine.RequestPasswordReset(ctx, "alice"); err == nil {
		t.Fatal("the request that could not store its record succeeded")
	}
	if err := engine.ConfirmPasswordReset(ctx, held, "owner-password-1"); err != nil {
		t.Fatalf("the code held before the failed request: %v", err)
	}
	if !passwordIs(t, engine, up, "owner-password-1") {
		t.Fatal("the password was not changed")
	}
}
