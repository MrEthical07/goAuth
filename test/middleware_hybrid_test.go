package test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	goAuth "github.com/MrEthical07/goAuth"
	"github.com/MrEthical07/goAuth/middleware"
	"github.com/MrEthical07/goAuth/password"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// hybridTestProvider serves a single seeded user; every other lookup fails.
type hybridTestProvider struct {
	exampleUserProvider
	record goAuth.UserRecord
}

func (p *hybridTestProvider) GetUserByIdentifier(identifier string) (goAuth.UserRecord, error) {
	if identifier == p.record.Identifier {
		return p.record, nil
	}
	return goAuth.UserRecord{}, errors.New("user not found")
}

func (p *hybridTestProvider) GetUserByID(userID string) (goAuth.UserRecord, error) {
	if userID == p.record.UserID {
		return p.record, nil
	}
	return goAuth.UserRecord{}, errors.New("user not found")
}

func newHybridMiddlewareEngine(t *testing.T) (*goAuth.Engine, string, func()) {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis run failed: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	cleanup := func() {
		_ = rdb.Close()
		mr.Close()
	}

	hasher, err := password.NewArgon2(password.Config{
		Memory:      16 * 1024,
		Time:        1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	})
	if err != nil {
		cleanup()
		t.Fatalf("hasher init failed: %v", err)
	}
	hash, err := hasher.Hash("correct-password-123")
	if err != nil {
		cleanup()
		t.Fatalf("hash failed: %v", err)
	}

	provider := &hybridTestProvider{record: goAuth.UserRecord{
		UserID:            "u1",
		Identifier:        "alice",
		TenantID:          "0",
		PasswordHash:      hash,
		Status:            goAuth.AccountActive,
		Role:              "member",
		PermissionVersion: 1,
		RoleVersion:       1,
		AccountVersion:    1,
	}}

	engine, err := goAuth.New().
		WithConfig(goAuth.DefaultConfig()).
		WithRedis(rdb).
		WithPermissions([]string{"user.read"}).
		WithRoles(map[string][]string{"member": {}}).
		WithUserProvider(provider).
		Build()
	if err != nil {
		cleanup()
		t.Fatalf("Build failed: %v", err)
	}

	access, _, err := engine.Login(context.Background(), "alice", "correct-password-123")
	if err != nil {
		cleanup()
		t.Fatalf("login failed: %v", err)
	}

	return engine, access, cleanup
}

func okHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := middleware.AuthResultFromContext(r.Context()); !ok {
			t.Error("expected AuthResult in request context")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

func serveWithToken(handler http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestGuardHybridModeAllowsValidToken(t *testing.T) {
	engine, access, cleanup := newHybridMiddlewareEngine(t)
	defer cleanup()

	guarded := middleware.Guard(engine, goAuth.ModeHybrid)(okHandler(t))
	if rec := serveWithToken(guarded, access); rec.Code != http.StatusOK {
		t.Fatalf("Guard(ModeHybrid) expected 200, got %d", rec.Code)
	}
}

func TestRequireHybridAllowsValidToken(t *testing.T) {
	engine, access, cleanup := newHybridMiddlewareEngine(t)
	defer cleanup()

	guarded := middleware.RequireHybrid(engine)(okHandler(t))
	if rec := serveWithToken(guarded, access); rec.Code != http.StatusOK {
		t.Fatalf("RequireHybrid expected 200, got %d", rec.Code)
	}

	if rec := serveWithToken(guarded, "not-a-token"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("RequireHybrid expected 401 for invalid token, got %d", rec.Code)
	}
}
