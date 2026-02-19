package session

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/permission"
)

func TestDecodeRejectsUnsupportedSchemaVersion(t *testing.T) {
	_, err := Decode([]byte{99})
	if err == nil || !strings.Contains(err.Error(), "unsupported session schema version") {
		t.Fatalf("expected unsupported schema version error, got %v", err)
	}
}

func TestGetReadOnlyMigratesLegacySchemaToCurrent(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()

	mask := permission.Mask64(1)
	now := time.Now()
	legacy := &Session{
		SchemaVersion:     4,
		SessionID:         "sid-legacy",
		UserID:            "u-legacy",
		TenantID:          "t-legacy",
		Role:              "member",
		Mask:              &mask,
		PermissionVersion: 1,
		RoleVersion:       1,
		AccountVersion:    1,
		Status:            0,
		RefreshHash:       [32]byte{7},
		CreatedAt:         now.Unix(),
		ExpiresAt:         now.Add(time.Hour).Unix(),
	}

	key := store.key(legacy.TenantID, legacy.SessionID)
	if err := rdb.Set(context.Background(), key, encodeLegacyV4Session(t, legacy), time.Hour).Err(); err != nil {
		t.Fatalf("seed legacy session failed: %v", err)
	}

	sess, err := store.GetReadOnly(context.Background(), legacy.TenantID, legacy.SessionID)
	if err != nil {
		t.Fatalf("get readonly failed: %v", err)
	}
	if sess.SchemaVersion != CurrentSchemaVersion {
		t.Fatalf("expected migrated schema version %d, got %d", CurrentSchemaVersion, sess.SchemaVersion)
	}

	raw, err := rdb.Get(context.Background(), key).Bytes()
	if err != nil {
		t.Fatalf("read migrated blob failed: %v", err)
	}
	if len(raw) == 0 || raw[0] != CurrentSchemaVersion {
		t.Fatalf("expected stored schema byte %d, got %v", CurrentSchemaVersion, raw)
	}
}

func encodeLegacyV4Session(tb testing.TB, sess *Session) []byte {
	tb.Helper()

	maskBytes, err := permission.EncodeMask(sess.Mask)
	if err != nil {
		tb.Fatalf("encode mask failed: %v", err)
	}
	if len(maskBytes) > 255 {
		tb.Fatalf("mask too large: %d", len(maskBytes))
	}

	var buf bytes.Buffer
	buf.WriteByte(4)

	buf.WriteByte(byte(len(sess.UserID)))
	buf.WriteString(sess.UserID)

	buf.WriteByte(byte(len(sess.TenantID)))
	buf.WriteString(sess.TenantID)

	buf.WriteByte(byte(len(sess.Role)))
	buf.WriteString(sess.Role)

	if err := binary.Write(&buf, binary.BigEndian, sess.PermissionVersion); err != nil {
		tb.Fatalf("write permission version failed: %v", err)
	}
	if err := binary.Write(&buf, binary.BigEndian, sess.RoleVersion); err != nil {
		tb.Fatalf("write role version failed: %v", err)
	}
	if err := binary.Write(&buf, binary.BigEndian, sess.AccountVersion); err != nil {
		tb.Fatalf("write account version failed: %v", err)
	}
	buf.WriteByte(sess.Status)

	buf.WriteByte(byte(len(maskBytes)))
	buf.Write(maskBytes)
	buf.Write(sess.RefreshHash[:])

	if err := binary.Write(&buf, binary.BigEndian, sess.CreatedAt); err != nil {
		tb.Fatalf("write createdAt failed: %v", err)
	}
	if err := binary.Write(&buf, binary.BigEndian, sess.ExpiresAt); err != nil {
		tb.Fatalf("write expiresAt failed: %v", err)
	}

	return buf.Bytes()
}
