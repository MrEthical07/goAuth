package goAuth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/internal/rate"
	"github.com/MrEthical07/goAuth/password"
	"github.com/MrEthical07/goAuth/session"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

type mockUserProvider struct {
	users        map[string]UserRecord
	byIdentifier map[string]string
	totpRecords  map[string]TOTPRecord
	backupCodes  map[string][]BackupCodeRecord
	updateErr    error
	createErr    error
	statusErr    error
	mu           sync.Mutex

	allowDuplicateAcrossTenants bool
	skipStatusVersionBump       bool

	getByIdentifierCalls    int
	getByIDCalls            int
	updatePasswordCalls     int
	createCalls             int
	updateStatusCalls       int
	getTOTPSecretCalls      int
	enableTOTPCalls         int
	disableTOTPCalls        int
	markTOTPVerifiedCalls   int
	updateTOTPCounterCalls  int
	getBackupCodesCalls     int
	replaceBackupCodesCalls int
	consumeBackupCodeCalls  int
}

func (m *mockUserProvider) GetUserByIdentifier(identifier string) (UserRecord, error) {
	m.getByIdentifierCalls++

	userID, ok := m.byIdentifier[identifier]
	if !ok {
		return UserRecord{}, errors.New("not found")
	}

	user, ok := m.users[userID]
	if !ok {
		return UserRecord{}, errors.New("not found")
	}

	return user, nil
}

func (m *mockUserProvider) GetUserByID(userID string) (UserRecord, error) {
	m.getByIDCalls++

	user, ok := m.users[userID]
	if !ok {
		return UserRecord{}, errors.New("not found")
	}

	return user, nil
}

func (m *mockUserProvider) UpdatePasswordHash(userID string, newHash string) error {
	m.updatePasswordCalls++

	if m.updateErr != nil {
		return m.updateErr
	}

	user, ok := m.users[userID]
	if !ok {
		return errors.New("not found")
	}

	user.PasswordHash = newHash
	m.users[userID] = user
	return nil
}

func (m *mockUserProvider) CreateUser(ctx context.Context, input CreateUserInput) (UserRecord, error) {
	m.createCalls++

	if m.createErr != nil {
		return UserRecord{}, m.createErr
	}

	if m.users == nil {
		m.users = make(map[string]UserRecord)
	}
	if m.byIdentifier == nil {
		m.byIdentifier = make(map[string]string)
	}

	for _, existing := range m.users {
		if existing.Identifier != input.Identifier {
			continue
		}

		if !m.allowDuplicateAcrossTenants || existing.TenantID == input.TenantID {
			return UserRecord{}, ErrProviderDuplicateIdentifier
		}
	}

	userID := fmt.Sprintf("u%d", len(m.users)+1)
	user := UserRecord{
		UserID:            userID,
		Identifier:        input.Identifier,
		TenantID:          input.TenantID,
		PasswordHash:      input.PasswordHash,
		Status:            input.Status,
		Role:              input.Role,
		PermissionVersion: input.PermissionVersion,
		RoleVersion:       input.RoleVersion,
		AccountVersion:    input.AccountVersion,
	}

	m.users[userID] = user
	if _, exists := m.byIdentifier[input.Identifier]; !exists {
		m.byIdentifier[input.Identifier] = userID
	}

	return user, nil
}

func (m *mockUserProvider) UpdateAccountStatus(ctx context.Context, userID string, status AccountStatus) (UserRecord, error) {
	m.updateStatusCalls++

	if m.statusErr != nil {
		return UserRecord{}, m.statusErr
	}

	user, ok := m.users[userID]
	if !ok {
		return UserRecord{}, errors.New("not found")
	}

	user.Status = status
	if !m.skipStatusVersionBump {
		user.AccountVersion++
		if user.AccountVersion == 0 {
			user.AccountVersion = 1
		}
	}
	m.users[userID] = user
	return user, nil
}

func (m *mockUserProvider) GetTOTPSecret(ctx context.Context, userID string) (*TOTPRecord, error) {
	m.getTOTPSecretCalls++
	if m.totpRecords == nil {
		return &TOTPRecord{}, nil
	}
	record, ok := m.totpRecords[userID]
	if !ok {
		return &TOTPRecord{}, nil
	}
	cloned := record
	if len(record.Secret) > 0 {
		cloned.Secret = append([]byte(nil), record.Secret...)
	}
	return &cloned, nil
}

func (m *mockUserProvider) EnableTOTP(ctx context.Context, userID string, secret []byte) error {
	m.enableTOTPCalls++

	user, ok := m.users[userID]
	if !ok {
		return errors.New("not found")
	}
	if m.totpRecords == nil {
		m.totpRecords = make(map[string]TOTPRecord)
	}

	record := m.totpRecords[userID]
	if len(secret) > 0 {
		record.Secret = append([]byte(nil), secret...)
	}
	wasEnabled := user.TOTPEnabled
	record.Enabled = record.Verified
	user.TOTPEnabled = record.Enabled
	if wasEnabled != user.TOTPEnabled {
		user.AccountVersion++
		if user.AccountVersion == 0 {
			user.AccountVersion = 1
		}
	}
	m.totpRecords[userID] = record
	m.users[userID] = user
	return nil
}

func (m *mockUserProvider) DisableTOTP(ctx context.Context, userID string) error {
	m.disableTOTPCalls++

	user, ok := m.users[userID]
	if !ok {
		return errors.New("not found")
	}
	wasEnabled := user.TOTPEnabled
	user.TOTPEnabled = false
	if wasEnabled {
		user.AccountVersion++
		if user.AccountVersion == 0 {
			user.AccountVersion = 1
		}
	}
	if m.totpRecords != nil {
		delete(m.totpRecords, userID)
	}
	m.users[userID] = user
	return nil
}

func (m *mockUserProvider) MarkTOTPVerified(ctx context.Context, userID string) error {
	m.markTOTPVerifiedCalls++

	user, ok := m.users[userID]
	if !ok {
		return errors.New("not found")
	}
	if m.totpRecords == nil {
		m.totpRecords = make(map[string]TOTPRecord)
	}
	record := m.totpRecords[userID]
	if len(record.Secret) == 0 {
		return errors.New("not found")
	}
	record.Verified = true
	m.totpRecords[userID] = record
	m.users[userID] = user
	return nil
}

func (m *mockUserProvider) UpdateTOTPLastUsedCounter(ctx context.Context, userID string, counter int64) error {
	m.updateTOTPCounterCalls++

	if m.totpRecords == nil {
		return errors.New("not found")
	}
	record, ok := m.totpRecords[userID]
	if !ok {
		return errors.New("not found")
	}
	record.LastUsedCounter = counter
	m.totpRecords[userID] = record
	return nil
}

func (m *mockUserProvider) GetBackupCodes(ctx context.Context, userID string) ([]BackupCodeRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getBackupCodesCalls++

	if m.backupCodes == nil {
		return []BackupCodeRecord{}, nil
	}
	records := m.backupCodes[userID]
	out := make([]BackupCodeRecord, len(records))
	copy(out, records)
	return out, nil
}

func (m *mockUserProvider) ReplaceBackupCodes(ctx context.Context, userID string, codes []BackupCodeRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.replaceBackupCodesCalls++

	if _, ok := m.users[userID]; !ok {
		return errors.New("not found")
	}
	if m.backupCodes == nil {
		m.backupCodes = make(map[string][]BackupCodeRecord)
	}
	next := make([]BackupCodeRecord, len(codes))
	copy(next, codes)
	m.backupCodes[userID] = next
	return nil
}

func (m *mockUserProvider) ConsumeBackupCode(ctx context.Context, userID string, codeHash [32]byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.consumeBackupCodeCalls++

	if m.backupCodes == nil {
		return false, nil
	}
	records := m.backupCodes[userID]
	matchIndex := -1
	for i := range records {
		if subtle.ConstantTimeCompare(records[i].Hash[:], codeHash[:]) == 1 && matchIndex == -1 {
			matchIndex = i
		}
	}
	if matchIndex < 0 {
		return false, nil
	}
	records = append(records[:matchIndex], records[matchIndex+1:]...)
	m.backupCodes[userID] = records
	return true, nil
}

func newTestHasher(t *testing.T) *password.Argon2 {
	t.Helper()

	h, err := password.NewArgon2(password.Config{
		Memory:      65536,
		Time:        3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	})
	if err != nil {
		t.Fatalf("NewArgon2 failed: %v", err)
	}
	return h
}

func newTestRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run failed: %v", err)
	}

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return mr, client
}

func newTestEngine(t *testing.T, rdb *redis.Client, up UserProvider, hasher *password.Argon2) *Engine {
	t.Helper()

	return &Engine{
		userProvider: up,
		passwordHash: hasher,
		sessionStore: session.NewStore(rdb, "as", false, false, 0),
		rateLimiter: rate.New(rdb, rate.Config{
			EnableIPThrottle:        false,
			EnableRefreshThrottle:   true,
			MaxLoginAttempts:        5,
			LoginCooldownDuration:   time.Minute,
			MaxRefreshAttempts:      20,
			RefreshCooldownDuration: time.Minute,
		}),
	}
}

func TestChangePasswordSuccessInvalidatesSessionsAndResetsLimiter(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	ctx := context.Background()
	hasher := newTestHasher(t)
	oldHash, err := hasher.Hash("old-password-123")
	if err != nil {
		t.Fatalf("Hash old password failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {
				UserID:            "u1",
				Identifier:        "alice",
				PasswordHash:      oldHash,
				Role:              "member",
				PermissionVersion: 1,
				RoleVersion:       1,
			},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine := newTestEngine(t, rdb, up, hasher)

	if err := rdb.SAdd(ctx, "au:0:u1", "s1", "s2").Err(); err != nil {
		t.Fatalf("seed index failed: %v", err)
	}
	if err := rdb.Set(ctx, "as:0:s1", "v", time.Hour).Err(); err != nil {
		t.Fatalf("seed session s1 failed: %v", err)
	}
	if err := rdb.Set(ctx, "as:0:s2", "v", time.Hour).Err(); err != nil {
		t.Fatalf("seed session s2 failed: %v", err)
	}
	if err := rdb.Set(ctx, "al:alice", "3", time.Hour).Err(); err != nil {
		t.Fatalf("seed limiter failed: %v", err)
	}

	if err := engine.ChangePassword(ctx, "u1", "old-password-123", "new-password-123"); err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	updated := up.users["u1"]
	if updated.PasswordHash == oldHash {
		t.Fatal("expected password hash to change")
	}

	ok, err := hasher.Verify("new-password-123", updated.PasswordHash)
	if err != nil || !ok {
		t.Fatalf("new hash verify failed, ok=%v err=%v", ok, err)
	}

	if rdb.Exists(ctx, "as:0:s1").Val() != 0 || rdb.Exists(ctx, "as:0:s2").Val() != 0 {
		t.Fatal("expected all user sessions to be deleted")
	}
	if rdb.Exists(ctx, "au:0:u1").Val() != 0 {
		t.Fatal("expected user session index to be deleted")
	}
	if rdb.Exists(ctx, "al:alice").Val() != 0 {
		t.Fatal("expected login limiter key to be reset")
	}
}

func TestChangePasswordWrongOldPassword(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	ctx := context.Background()
	hasher := newTestHasher(t)
	oldHash, err := hasher.Hash("correct-old-pass")
	if err != nil {
		t.Fatalf("Hash old password failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {
				UserID:       "u1",
				Identifier:   "alice",
				PasswordHash: oldHash,
			},
		},
		byIdentifier: map[string]string{"alice": "u1"},
	}

	engine := newTestEngine(t, rdb, up, hasher)

	if err := rdb.SAdd(ctx, "au:0:u1", "s1").Err(); err != nil {
		t.Fatalf("seed index failed: %v", err)
	}
	if err := rdb.Set(ctx, "as:0:s1", "v", time.Hour).Err(); err != nil {
		t.Fatalf("seed session failed: %v", err)
	}

	err = engine.ChangePassword(ctx, "u1", "wrong-old-pass", "new-pass-123")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	if up.users["u1"].PasswordHash != oldHash {
		t.Fatal("expected hash to remain unchanged on wrong old password")
	}
	if rdb.Exists(ctx, "as:0:s1").Val() != 1 {
		t.Fatal("expected sessions to remain when password change fails")
	}
}

func TestChangePasswordRejectsReuse(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	ctx := context.Background()
	hasher := newTestHasher(t)
	hash, err := hasher.Hash("same-pass-123")
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {UserID: "u1", PasswordHash: hash},
		},
	}

	engine := newTestEngine(t, rdb, up, hasher)

	err = engine.ChangePassword(ctx, "u1", "same-pass-123", "same-pass-123")
	if !errors.Is(err, ErrPasswordReuse) {
		t.Fatalf("expected ErrPasswordReuse, got %v", err)
	}
}

func TestChangePasswordRejectsShortNewPassword(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	ctx := context.Background()
	hasher := newTestHasher(t)
	hash, err := hasher.Hash("valid-old-pass")
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {UserID: "u1", PasswordHash: hash},
		},
	}

	engine := newTestEngine(t, rdb, up, hasher)

	err = engine.ChangePassword(ctx, "u1", "valid-old-pass", "short")
	if !errors.Is(err, ErrPasswordPolicy) {
		t.Fatalf("expected ErrPasswordPolicy, got %v", err)
	}
}

func TestChangePasswordUsesUserTenantForInvalidation(t *testing.T) {
	mr, rdb := newTestRedis(t)
	defer mr.Close()

	ctx := WithTenantID(context.Background(), "0")
	hasher := newTestHasher(t)
	oldHash, err := hasher.Hash("old-password-123")
	if err != nil {
		t.Fatalf("Hash old password failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {
				UserID:       "u1",
				Identifier:   "alice",
				TenantID:     "42",
				PasswordHash: oldHash,
			},
		},
	}

	engine := newTestEngine(t, rdb, up, hasher)

	if err := rdb.SAdd(ctx, "au:42:u1", "s1").Err(); err != nil {
		t.Fatalf("seed index failed: %v", err)
	}
	if err := rdb.Set(ctx, "as:42:s1", "v", time.Hour).Err(); err != nil {
		t.Fatalf("seed session failed: %v", err)
	}

	if err := engine.ChangePassword(ctx, "u1", "old-password-123", "new-password-123"); err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	if rdb.Exists(ctx, "as:42:s1").Val() != 0 {
		t.Fatal("expected tenant-specific session to be deleted")
	}
	if rdb.Exists(ctx, "au:42:u1").Val() != 0 {
		t.Fatal("expected tenant-specific user session index to be deleted")
	}
}

func TestChangePasswordKeepsUpdatedHashWhenInvalidationFails(t *testing.T) {
	mr, rdb := newTestRedis(t)
	ctx := context.Background()
	hasher := newTestHasher(t)
	oldHash, err := hasher.Hash("old-password-123")
	if err != nil {
		t.Fatalf("Hash old password failed: %v", err)
	}

	up := &mockUserProvider{
		users: map[string]UserRecord{
			"u1": {
				UserID:       "u1",
				Identifier:   "alice",
				PasswordHash: oldHash,
			},
		},
	}

	engine := newTestEngine(t, rdb, up, hasher)

	if err := rdb.SAdd(ctx, "au:0:u1", "s1").Err(); err != nil {
		t.Fatalf("seed index failed: %v", err)
	}
	if err := rdb.Set(ctx, "as:0:s1", "v", time.Hour).Err(); err != nil {
		t.Fatalf("seed session failed: %v", err)
	}

	// Simulate Redis outage between password DB update and session invalidation.
	mr.Close()

	err = engine.ChangePassword(ctx, "u1", "old-password-123", "new-password-123")
	if err == nil {
		t.Fatal("expected ChangePassword to fail when Redis is unavailable")
	}
	if !errors.Is(err, ErrSessionInvalidationFailed) {
		t.Fatalf("expected ErrSessionInvalidationFailed, got %v", err)
	}

	updated := up.users["u1"]
	if updated.PasswordHash == oldHash {
		t.Fatal("expected password hash to remain updated despite invalidation failure")
	}

	ok, verifyErr := hasher.Verify("new-password-123", updated.PasswordHash)
	if verifyErr != nil || !ok {
		t.Fatalf("expected updated hash to verify with new password, ok=%v err=%v", ok, verifyErr)
	}
}
