package test

import (
	"context"

	goAuth "github.com/MrEthical07/goAuth"
	"github.com/redis/go-redis/v9"
)

// ExampleNew demonstrates engine construction with production-style dependencies.
func ExampleNew() {
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	provider := &exampleUserProvider{}

	engine, _ := goAuth.New().
		WithRedis(rdb).
		WithPermissions([]string{"user.read", "user.write"}).
		WithRoles(map[string][]string{"admin": {"user.read", "user.write"}}).
		WithUserProvider(provider).
		Build()
	_ = engine
}

// ExampleEngine_Login shows a typical login entrypoint call and structured error handling.
func ExampleEngine_Login() {
	var engine *goAuth.Engine
	_, _, err := engine.Login(context.Background(), "alice@example.com", "password")
	if err != nil {
		_ = err
	}
}

// ExampleEngine_MetricsSnapshot shows how to read in-process metrics counters.
func ExampleEngine_MetricsSnapshot() {
	var engine *goAuth.Engine
	snapshot := engine.MetricsSnapshot()
	_ = snapshot
}

type exampleUserProvider struct{}

func (e *exampleUserProvider) GetUserByIdentifier(identifier string) (goAuth.UserRecord, error) {
	return goAuth.UserRecord{}, nil
}
func (e *exampleUserProvider) GetUserByID(userID string) (goAuth.UserRecord, error) {
	return goAuth.UserRecord{}, nil
}
func (e *exampleUserProvider) UpdatePasswordHash(userID string, newHash string) error { return nil }
func (e *exampleUserProvider) CreateUser(ctx context.Context, input goAuth.CreateUserInput) (goAuth.UserRecord, error) {
	return goAuth.UserRecord{}, nil
}
func (e *exampleUserProvider) UpdateAccountStatus(ctx context.Context, userID string, status goAuth.AccountStatus) (goAuth.UserRecord, error) {
	return goAuth.UserRecord{}, nil
}
func (e *exampleUserProvider) GetTOTPSecret(ctx context.Context, userID string) (*goAuth.TOTPRecord, error) {
	return &goAuth.TOTPRecord{}, nil
}
func (e *exampleUserProvider) EnableTOTP(ctx context.Context, userID string, secret []byte) error {
	return nil
}
func (e *exampleUserProvider) DisableTOTP(ctx context.Context, userID string) error { return nil }
func (e *exampleUserProvider) MarkTOTPVerified(ctx context.Context, userID string) error {
	return nil
}
func (e *exampleUserProvider) UpdateTOTPLastUsedCounter(ctx context.Context, userID string, counter int64) error {
	return nil
}
func (e *exampleUserProvider) GetBackupCodes(ctx context.Context, userID string) ([]goAuth.BackupCodeRecord, error) {
	return nil, nil
}
func (e *exampleUserProvider) ReplaceBackupCodes(ctx context.Context, userID string, codes []goAuth.BackupCodeRecord) error {
	return nil
}
func (e *exampleUserProvider) ConsumeBackupCode(ctx context.Context, userID string, codeHash [32]byte) (bool, error) {
	return false, nil
}
