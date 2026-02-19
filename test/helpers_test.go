//go:build integration
// +build integration

package test

import (
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/permission"
	"github.com/MrEthical07/goAuth/session"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newIntegrationStore(t *testing.T) (*session.Store, *redis.Client, func()) {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis run failed: %v", err)
	}

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := session.NewStore(rdb, "as", false, false, 0)

	return store, rdb, func() {
		_ = rdb.Close()
		mr.Close()
	}
}

func makeSession(tenantID, userID, sessionID string, refreshHash [32]byte) *session.Session {
	mask := permission.Mask64(1)
	now := time.Now()

	return &session.Session{
		SessionID:         sessionID,
		UserID:            userID,
		TenantID:          tenantID,
		Role:              "member",
		Mask:              &mask,
		PermissionVersion: 1,
		RoleVersion:       1,
		AccountVersion:    1,
		Status:            0,
		RefreshHash:       refreshHash,
		CreatedAt:         now.Unix(),
		ExpiresAt:         now.Add(time.Hour).Unix(),
	}
}

func hashByte(b byte) [32]byte {
	var out [32]byte
	for i := 0; i < len(out); i++ {
		out[i] = b
	}
	return out
}
