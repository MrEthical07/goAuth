package stores

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestWebAuthnSessionEncodeDecodeRoundTrip(t *testing.T) {
	record := &WebAuthnSession{
		UserID:      "user-1",
		TenantID:    "tenant-1",
		Purpose:     WebAuthnPurposeRegistration,
		SessionJSON: []byte(`{"challenge":"abc","user_id":"dXNlci0x"}`),
	}

	encoded, err := encodeWebAuthnSession(record)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	if encoded[0] != webAuthnSessionVersion1 {
		t.Fatalf("expected version 1 record, got %d", encoded[0])
	}

	decoded, err := decodeWebAuthnSession(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decoded.UserID != record.UserID || decoded.TenantID != record.TenantID ||
		decoded.Purpose != record.Purpose || !bytes.Equal(decoded.SessionJSON, record.SessionJSON) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", decoded, record)
	}
}

func TestWebAuthnSessionDecodeRejectsCorruptRecords(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		{},
		{99, WebAuthnPurposeLogin},          // unknown version
		{webAuthnSessionVersion1},           // truncated after version
		{webAuthnSessionVersion1, 1, 0, 50}, // user length longer than payload
	} {
		if _, err := decodeWebAuthnSession(data); err == nil {
			t.Fatalf("expected decode failure for %v", data)
		}
	}
}

func TestWebAuthnSessionStoreConsumeIsSingleUse(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := NewWebAuthnSessionStore(client, "")
	ctx := context.Background()

	record := &WebAuthnSession{
		UserID:      "u1",
		Purpose:     WebAuthnPurposeLogin,
		SessionJSON: []byte(`{"challenge":"x"}`),
	}
	if err := store.Save(ctx, "cer-1", record, time.Minute); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	got, err := store.Consume(ctx, "cer-1")
	if err != nil {
		t.Fatalf("consume failed: %v", err)
	}
	if got.UserID != "u1" || got.Purpose != WebAuthnPurposeLogin {
		t.Fatalf("unexpected record: %+v", got)
	}

	if _, err := store.Consume(ctx, "cer-1"); !errors.Is(err, ErrWebAuthnSessionNotFound) {
		t.Fatalf("expected single-use consumption, got %v", err)
	}
}

func TestWebAuthnSessionStoreTTLExpiry(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := NewWebAuthnSessionStore(client, "")
	ctx := context.Background()

	record := &WebAuthnSession{UserID: "u1", Purpose: WebAuthnPurposeLogin, SessionJSON: []byte("{}")}
	if err := store.Save(ctx, "cer-ttl", record, time.Minute); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	mr.FastForward(2 * time.Minute)

	if _, err := store.Consume(ctx, "cer-ttl"); !errors.Is(err, ErrWebAuthnSessionNotFound) {
		t.Fatalf("expected expired session to be gone, got %v", err)
	}
}
