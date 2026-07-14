package flows

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/jwt"
	gjwt "github.com/golang-jwt/jwt/v5"
)

type stubLogoutStore struct {
	deleted   []string
	deleteErr error
}

func (s *stubLogoutStore) Delete(_ context.Context, tenantID, sessionID string) error {
	s.deleted = append(s.deleted, tenantID+"/"+sessionID)
	return s.deleteErr
}

func (s *stubLogoutStore) DeleteAllForUser(context.Context, string, string) error { return nil }

func logoutDepsForTest(store *stubLogoutStore, claims *jwt.AccessClaims, parseErr error) LogoutDeps {
	return LogoutDeps{
		ParseAccessAllowExpired: func(string) (*jwt.AccessClaims, error) { return claims, parseErr },
		TenantIDFromContext:     func(context.Context) string { return "0" },
		TenantIDFromToken: func(tid string) string {
			if tid == "" {
				return "0"
			}
			return tid
		},
		Now:          time.Now,
		SessionStore: store,
	}
}

func TestRunLogoutByAccessTokenMarksExpiredToken(t *testing.T) {
	store := &stubLogoutStore{}
	claims := &jwt.AccessClaims{
		SID: "s1",
		TID: "t1",
		RegisteredClaims: gjwt.RegisteredClaims{
			ExpiresAt: gjwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	}

	result := RunLogoutByAccessToken(context.Background(), "token", logoutDepsForTest(store, claims, nil))
	if result.Err != nil {
		t.Fatalf("expected success, got %v", result.Err)
	}
	if !result.TokenExpired {
		t.Fatal("expected TokenExpired to be set for a past-exp token")
	}
	if len(store.deleted) != 1 || store.deleted[0] != "t1/s1" {
		t.Fatalf("expected session t1/s1 deleted, got %v", store.deleted)
	}
}

func TestRunLogoutByAccessTokenLiveTokenNotMarkedExpired(t *testing.T) {
	store := &stubLogoutStore{}
	claims := &jwt.AccessClaims{
		SID: "s1",
		RegisteredClaims: gjwt.RegisteredClaims{
			ExpiresAt: gjwt.NewNumericDate(time.Now().Add(time.Minute)),
		},
	}

	result := RunLogoutByAccessToken(context.Background(), "token", logoutDepsForTest(store, claims, nil))
	if result.Err != nil {
		t.Fatalf("expected success, got %v", result.Err)
	}
	if result.TokenExpired {
		t.Fatal("live token must not be marked expired")
	}
}

func TestRunLogoutByAccessTokenParseFailure(t *testing.T) {
	store := &stubLogoutStore{}
	parseErr := errors.New("bad token")

	result := RunLogoutByAccessToken(context.Background(), "token", logoutDepsForTest(store, nil, parseErr))
	if !errors.Is(result.Err, parseErr) {
		t.Fatalf("expected parse error, got %v", result.Err)
	}
	if result.SessionID != "" {
		t.Fatalf("expected empty session id on parse failure, got %q", result.SessionID)
	}
	if len(store.deleted) != 0 {
		t.Fatalf("expected no deletions on parse failure, got %v", store.deleted)
	}
}
