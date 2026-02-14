package goAuth

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestBackupCodeHashIncludesUserIDSalt(t *testing.T) {
	canonical := canonicalizeBackupCode("ABCD-EFGH")
	h1 := backupCodeHash("tenant-user-1", canonical)
	h2 := backupCodeHash("tenant-user-2", canonical)
	if bytes.Equal(h1[:], h2[:]) {
		t.Fatal("expected different backup code hashes for different user IDs")
	}
}

func TestBackupLimiterKeyTenantScoped(t *testing.T) {
	limiter := newBackupCodeLimiter(nil, TOTPConfig{})
	if got := limiter.key("t1", "u1"); got != "abk:t1:u1" {
		t.Fatalf("expected tenant-scoped key abk:t1:u1, got %s", got)
	}
	if got := limiter.key("", "u1"); got != "abk:0:u1" {
		t.Fatalf("expected default tenant key abk:0:u1, got %s", got)
	}
}

func TestBackupCodesGenerateStoresOnlyHashes(t *testing.T) {
	cfg := totpTestConfig()
	up := newHardeningUserProvider(t)

	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	codes, err := engine.GenerateBackupCodes(context.Background(), "u1")
	if err != nil {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}
	if len(codes) != cfg.TOTP.BackupCodeCount {
		t.Fatalf("expected %d codes, got %d", cfg.TOTP.BackupCodeCount, len(codes))
	}

	stored := up.backupCodes["u1"]
	if len(stored) != cfg.TOTP.BackupCodeCount {
		t.Fatalf("expected %d stored hashes, got %d", cfg.TOTP.BackupCodeCount, len(stored))
	}
	for _, code := range codes {
		c := canonicalizeBackupCode(code)
		for _, rec := range stored {
			if string(rec.Hash[:]) == c {
				t.Fatal("stored backup code hash must not equal raw code")
			}
		}
	}
}

func TestBackupCodeConsumeOneTimeAndReplayFail(t *testing.T) {
	cfg := totpTestConfig()
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	codes, err := engine.GenerateBackupCodes(context.Background(), "u1")
	if err != nil {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}

	if err := engine.VerifyBackupCode(context.Background(), "u1", codes[0]); err != nil {
		t.Fatalf("VerifyBackupCode first use failed: %v", err)
	}
	if err := engine.VerifyBackupCode(context.Background(), "u1", codes[0]); !errors.Is(err, ErrBackupCodeInvalid) {
		t.Fatalf("expected replay invalid, got %v", err)
	}
}

func TestBackupCodeConcurrentConsumeOnlyOneSucceeds(t *testing.T) {
	cfg := totpTestConfig()
	cfg.TOTP.BackupCodeMaxAttempts = 50
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	codes, err := engine.GenerateBackupCodes(context.Background(), "u1")
	if err != nil {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}

	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- engine.VerifyBackupCode(context.Background(), "u1", codes[0])
		}()
	}
	wg.Wait()
	close(results)

	success := 0
	fail := 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrBackupCodeInvalid) {
			fail++
		} else {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if success != 1 || fail != 1 {
		t.Fatalf("expected one success and one invalid failure, got success=%d fail=%d", success, fail)
	}
}

func TestBackupCodeRateLimitEnforced(t *testing.T) {
	cfg := totpTestConfig()
	cfg.TOTP.BackupCodeMaxAttempts = 2
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	if _, err := engine.GenerateBackupCodes(context.Background(), "u1"); err != nil {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}

	if err := engine.VerifyBackupCode(context.Background(), "u1", "BAD-CODE-1"); !errors.Is(err, ErrBackupCodeInvalid) {
		t.Fatalf("expected invalid on first failure, got %v", err)
	}
	if err := engine.VerifyBackupCode(context.Background(), "u1", "BAD-CODE-2"); !errors.Is(err, ErrBackupCodeRateLimited) {
		t.Fatalf("expected rate limited on second failure, got %v", err)
	}
	if err := engine.VerifyBackupCode(context.Background(), "u1", "BAD-CODE-3"); !errors.Is(err, ErrBackupCodeRateLimited) {
		t.Fatalf("expected rate limited after cap reached, got %v", err)
	}
}

func TestBackupCodesRegenerationReplacesOldSet(t *testing.T) {
	cfg := totpTestConfig()
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	first, err := engine.GenerateBackupCodes(context.Background(), "u1")
	if err != nil {
		t.Fatalf("first GenerateBackupCodes failed: %v", err)
	}
	secret := enableUserTOTP(t, engine, "u1", cfg)
	second, err := engine.RegenerateBackupCodes(context.Background(), "u1", codeForOffset(t, secret, cfg.TOTP, 1))
	if err != nil {
		t.Fatalf("RegenerateBackupCodes failed: %v", err)
	}

	if err := engine.VerifyBackupCode(context.Background(), "u1", first[0]); !errors.Is(err, ErrBackupCodeInvalid) {
		t.Fatalf("old code should be invalid after regeneration, got %v", err)
	}
	if err := engine.VerifyBackupCode(context.Background(), "u1", second[0]); err != nil {
		t.Fatalf("new code should be valid, got %v", err)
	}
}

func TestBackupCodesSecondGenerateRequiresTOTPVerification(t *testing.T) {
	cfg := totpTestConfig()
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	if _, err := engine.GenerateBackupCodes(context.Background(), "u1"); err != nil {
		t.Fatalf("first GenerateBackupCodes failed: %v", err)
	}
	if _, err := engine.GenerateBackupCodes(context.Background(), "u1"); !errors.Is(err, ErrBackupCodeRegenerationRequiresTOTP) {
		t.Fatalf("expected ErrBackupCodeRegenerationRequiresTOTP, got %v", err)
	}
}

func TestMFALoginBackupFallbackWorks(t *testing.T) {
	cfg := totpTestConfig()
	cfg.TOTP.RequireForLogin = true
	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	_ = enableUserTOTP(t, engine, "u1", cfg)
	backupCodes, err := engine.GenerateBackupCodes(context.Background(), "u1")
	if err != nil {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}

	loginResult, err := engine.LoginWithResult(context.Background(), "alice", "correct-password-123")
	if err != nil {
		t.Fatalf("LoginWithResult failed: %v", err)
	}
	if !loginResult.MFARequired {
		t.Fatal("expected MFA required")
	}

	confirmed, err := engine.ConfirmLoginMFAWithType(context.Background(), loginResult.MFASession, backupCodes[0], "backup")
	if err != nil {
		t.Fatalf("ConfirmLoginMFAWithType backup failed: %v", err)
	}
	if confirmed.AccessToken == "" || confirmed.RefreshToken == "" {
		t.Fatal("expected tokens after backup MFA success")
	}
}

func TestPasswordResetCanUseBackupCodeWhenRequired(t *testing.T) {
	cfg := totpTestConfig()
	cfg.PasswordReset.Enabled = true
	cfg.PasswordReset.Strategy = ResetToken
	cfg.TOTP.RequireForPasswordReset = true

	up := newHardeningUserProvider(t)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	defer done()

	_ = enableUserTOTP(t, engine, "u1", cfg)
	backupCodes, err := engine.GenerateBackupCodes(context.Background(), "u1")
	if err != nil {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}

	challenge, err := engine.RequestPasswordReset(context.Background(), "alice")
	if err != nil {
		t.Fatalf("RequestPasswordReset failed: %v", err)
	}

	if err := engine.ConfirmPasswordResetWithBackupCode(context.Background(), challenge, "new-password-123", backupCodes[0]); err != nil {
		t.Fatalf("ConfirmPasswordResetWithBackupCode failed: %v", err)
	}
}

func TestBackupCodeNotLeakedInAuditEvents(t *testing.T) {
	cfg := totpTestConfig()
	cfg.Audit.Enabled = true
	cfg.Audit.BufferSize = 32
	cfg.Audit.DropIfFull = true

	up := newHardeningUserProvider(t)
	sink := newCaptureSink(32)
	engine, done := buildAuditTestEngine(t, cfg, sink, up)
	defer done()

	codes, err := engine.GenerateBackupCodes(context.Background(), "u1")
	if err != nil {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}
	code := codes[0]
	if err := engine.VerifyBackupCode(context.Background(), "u1", code); err != nil {
		t.Fatalf("VerifyBackupCode failed: %v", err)
	}

	deadline := time.After(2 * time.Second)
	seen := 0
	for seen < 2 {
		select {
		case ev := <-sink.events:
			seen++
			if ev.Error == code {
				t.Fatal("raw backup code leaked in audit error field")
			}
			for _, v := range ev.Metadata {
				if v == code || canonicalizeBackupCode(v) == canonicalizeBackupCode(code) {
					t.Fatal("raw backup code leaked in audit metadata")
				}
			}
		case <-deadline:
			t.Fatalf("timed out waiting for audit events, seen=%d", seen)
		}
	}
}
