package audit

import (
	"encoding/json"
	"testing"
	"time"
)

// TestEventJSONGoldenBytesStableAcrossGoVersions proves that the JSON this
// package's JSONWriterSink emits for an audit event is byte-for-byte
// identical between Go 1.26.5 (v0.5.1's pinned toolchain) and the current
// toolchain, despite Go 1.27's encoding/json v2 backend. Downstream log
// consumers parsing goAuth's audit stream must not see the wire shape
// change across a Go version upgrade.
func TestEventJSONGoldenBytesStableAcrossGoVersions(t *testing.T) {
	const want = `{"timestamp":"2023-11-14T23:13:20Z","event_type":"login_success","user_id":"user-golden","tenant_id":"tenant-golden","session_id":"sid-golden","ip":"203.0.113.7","success":true,"metadata":{"identifier":"alice@example.com","reason":"ok"}}`

	event := Event{
		Timestamp: time.Unix(1700003600, 0).UTC(),
		EventType: "login_success",
		UserID:    "user-golden",
		TenantID:  "tenant-golden",
		SessionID: "sid-golden",
		IP:        "203.0.113.7",
		Success:   true,
		Metadata:  map[string]string{"identifier": "alice@example.com", "reason": "ok"},
	}

	got, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if string(got) != want {
		t.Fatalf("audit event JSON changed across Go versions:\n got:  %s\n want: %s", got, want)
	}
}
