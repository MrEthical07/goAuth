package goAuth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal"
	"github.com/MrEthical07/goAuth/session"
)

func TestSecurityInvariantRefreshReplayInvalidatesSession(t *testing.T) {
	cfg := accountTestConfig()
	up := newHardeningUserProvider(t)
	engine, rdb, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	_, refresh, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	sid, _, err := internal.DecodeRefreshToken(refresh)
	if err != nil {
		t.Fatalf("decode refresh failed: %v", err)
	}

	if _, _, err := engine.Refresh(context.Background(), refresh); err != nil {
		t.Fatalf("first refresh failed: %v", err)
	}
	if _, _, err := engine.Refresh(context.Background(), refresh); !errors.Is(err, ErrRefreshReuse) {
		t.Fatalf("expected ErrRefreshReuse, got %v", err)
	}
	if exists := rdb.Exists(context.Background(), "as:0:"+sid).Val(); exists != 0 {
		t.Fatalf("expected replay to invalidate session key, exists=%d", exists)
	}
}

func TestSecurityInvariantStrictValidationRequiresSession(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeStrict
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	access, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if err := engine.LogoutByAccessToken(context.Background(), access); err != nil {
		t.Fatalf("logout failed: %v", err)
	}

	if _, err := engine.Validate(context.Background(), access, ModeInherit); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestSecurityInvariantJWTOnlyValidationStaysStateless(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeJWTOnly
	cfg.Security.EnableAccountVersionCheck = false
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)

	access, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		done()
		t.Fatalf("login failed: %v", err)
	}

	done() // drop Redis before validate

	if _, err := engine.Validate(context.Background(), access, ModeInherit); err != nil {
		t.Fatalf("expected JWT-only validate without redis, got %v", err)
	}
}

func TestSecurityInvariantDeviceBindingMismatchBlockedInStrictMode(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeStrict
	cfg.DeviceBinding.Enabled = true
	cfg.DeviceBinding.EnforceIPBinding = true
	cfg.DeviceBinding.DetectIPChange = true

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	loginCtx := WithClientIP(context.Background(), "203.0.113.10")
	access, _, err := engine.Login(loginCtx, "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	validateCtx := WithClientIP(context.Background(), "203.0.113.11")
	if _, err := engine.Validate(validateCtx, access, ModeInherit); !errors.Is(err, ErrDeviceBindingRejected) {
		t.Fatalf("expected ErrDeviceBindingRejected, got %v", err)
	}
}

func TestSecurityInvariantPermissionVersionDriftBlockedInStrictMode(t *testing.T) {
	cfg := accountTestConfig()
	cfg.ValidationMode = ModeStrict
	up := newHardeningUserProvider(t)
	engine, rdb, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	access, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	claims, err := engine.jwtManager.ParseAccess(access)
	if err != nil {
		t.Fatalf("parse access failed: %v", err)
	}

	tenantID := tenantIDFromToken(claims.TID)
	sess, err := engine.sessionStore.GetReadOnly(context.Background(), tenantID, claims.SID)
	if err != nil {
		t.Fatalf("get readonly session failed: %v", err)
	}
	sess.PermissionVersion++

	blob, err := session.Encode(sess)
	if err != nil {
		t.Fatalf("encode session failed: %v", err)
	}
	if err := rdb.Set(context.Background(), "as:"+tenantID+":"+claims.SID, blob, engine.sessionLifetime()).Err(); err != nil {
		t.Fatalf("set mutated session failed: %v", err)
	}

	if _, err := engine.Validate(context.Background(), access, ModeInherit); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound on permission version drift, got %v", err)
	}
}

func TestSecurityInvariantResetAndVerificationTokensExpire(t *testing.T) {
	t.Run("password reset token expires", func(t *testing.T) {
		mr, rdb := newTestRedis(t)
		defer mr.Close()

		hasher := newTestHasher(t)
		oldHash, err := hasher.Hash("old-password-123")
		if err != nil {
			t.Fatalf("hash failed: %v", err)
		}

		up := &mockUserProvider{
			users: map[string]UserRecord{
				"u1": {UserID: "u1", Identifier: "alice", PasswordHash: oldHash, TenantID: "0"},
			},
			byIdentifier: map[string]string{"alice": "u1"},
		}

		resetCfg := testResetConfig(ResetToken)
		resetCfg.ResetTTL = time.Second
		engine := newTestResetEngine(t, rdb, up, hasher, resetCfg)

		challenge, err := engine.RequestPasswordReset(context.Background(), "alice")
		if err != nil {
			t.Fatalf("request password reset failed: %v", err)
		}
		resetID, _, err := parsePasswordResetChallenge(ResetToken, challenge, 0)
		if err != nil {
			t.Fatalf("parse reset challenge failed: %v", err)
		}
		if exists := rdb.Exists(context.Background(), "apr:0:"+resetID).Val(); exists != 1 {
			t.Fatalf("expected reset record key to exist, got %d", exists)
		}
		mr.FastForward(2 * time.Second)
		if err := engine.ConfirmPasswordReset(context.Background(), challenge, "new-password-123"); !errors.Is(err, ErrPasswordResetInvalid) {
			t.Fatalf("expected ErrPasswordResetInvalid for expired token, got %v", err)
		}
	})

	t.Run("email verification token expires", func(t *testing.T) {
		mr, rdb := newTestRedis(t)
		defer mr.Close()

		up := &mockUserProvider{
			users: map[string]UserRecord{
				"u1": {UserID: "u1", Identifier: "alice", TenantID: "0", Status: AccountPendingVerification, AccountVersion: 1},
			},
			byIdentifier: map[string]string{"alice": "u1"},
		}

		verifyCfg := testEmailVerificationConfig(VerificationToken)
		verifyCfg.VerificationTTL = time.Second
		engine := newTestEmailVerificationEngine(t, rdb, up, verifyCfg)

		challenge, err := engine.RequestEmailVerification(context.Background(), "alice")
		if err != nil {
			t.Fatalf("request email verification failed: %v", err)
		}
		_, verificationID, _, err := parseEmailVerificationChallenge(VerificationToken, challenge, 0)
		if err != nil {
			t.Fatalf("parse verification challenge failed: %v", err)
		}
		if exists := rdb.Exists(context.Background(), "apv:0:"+verificationID).Val(); exists != 1 {
			t.Fatalf("expected verification record key to exist, got %d", exists)
		}
		mr.FastForward(2 * time.Second)
		if err := engine.ConfirmEmailVerification(context.Background(), challenge); !errors.Is(err, ErrEmailVerificationInvalid) {
			t.Fatalf("expected ErrEmailVerificationInvalid for expired token, got %v", err)
		}
	})
}
