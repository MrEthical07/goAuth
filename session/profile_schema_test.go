package session

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MrEthical07/goAuth/permission"
	"github.com/redis/go-redis/v9"
)

// The v5 golden record from TestEncodeGoldenBytesStableAcrossGoVersions. The
// v6 fixture below is derived from it by hand, not by running Encode: a v6
// record is the v5 record with the version byte set to 6 and a
// length-prefixed profile name appended after ExpiresAt.
const (
	goldenV5Hex = "050b757365722d676f6c64656e0d74656e616e742d676f6c64656e066d656d62657200000007000000030000000901080102030405060708aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc000000006553f100000000006553ff10"

	// goldenV6Hex is goldenV5Hex with the version byte 06, then the profile
	// "mobile": length 06, then 6d6f62696c65.
	goldenV6Hex = "060b757365722d676f6c64656e0d74656e616e742d676f6c64656e066d656d62657200000007000000030000000901080102030405060708aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc000000006553f100000000006553ff10066d6f62696c65"
)

func goldenSession() *Session {
	mask := permission.Mask64(0x0102030405060708)
	return &Session{
		SessionID:         "sid-golden",
		UserID:            "user-golden",
		TenantID:          "tenant-golden",
		Role:              "member",
		Mask:              &mask,
		PermissionVersion: 7,
		RoleVersion:       3,
		AccountVersion:    9,
		Status:            1,
		RefreshHash:       fixedBytes32(0xAA),
		IPHash:            fixedBytes32(0xBB),
		UserAgentHash:     fixedBytes32(0xCC),
		CreatedAt:         1700000000,
		ExpiresAt:         1700003600,
	}
}

func TestEncodeProfileSessionGoldenBytes(t *testing.T) {
	sess := goldenSession()
	sess.Profile = "mobile"

	got, err := Encode(sess)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if gotHex := hex.EncodeToString(got); gotHex != goldenV6Hex {
		t.Fatalf("v6 wire bytes changed:\n got:  %s\n want: %s", gotHex, goldenV6Hex)
	}

	decoded, err := Decode(got)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.SchemaVersion != ProfileSchemaVersion || decoded.Profile != "mobile" {
		t.Fatalf("decoded version/profile = %d/%q", decoded.SchemaVersion, decoded.Profile)
	}
	if decoded.CreatedAt != sess.CreatedAt || decoded.ExpiresAt != sess.ExpiresAt ||
		decoded.RefreshHash != sess.RefreshHash || decoded.IPHash != sess.IPHash ||
		decoded.UserAgentHash != sess.UserAgentHash || decoded.AccountVersion != 9 || decoded.Status != 1 {
		t.Fatalf("v6 round trip lost fields: %+v", decoded)
	}
}

// A session without a profile keeps encoding as the golden v5 record.
func TestEncodeLegacySessionStaysV5(t *testing.T) {
	got, err := Encode(goldenSession())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if gotHex := hex.EncodeToString(got); gotHex != goldenV5Hex {
		t.Fatalf("v5 wire bytes changed:\n got:  %s\n want: %s", gotHex, goldenV5Hex)
	}
	if CurrentSchemaVersion != 5 {
		t.Fatalf("CurrentSchemaVersion = %d; it must stay 5 so legacy sessions keep their format", CurrentSchemaVersion)
	}
}

func TestEncodeDecodeProfileValidation(t *testing.T) {
	v6, _ := hex.DecodeString(goldenV6Hex)
	tail := len(v6) - 7 // offset of the profile length byte

	cases := []struct {
		name   string
		mutate func() ([]byte, error)
		want   string
	}{
		{"encode name too long", func() ([]byte, error) {
			s := goldenSession()
			s.Profile = strings.Repeat("a", MaxProfileNameLen+1)
			return Encode(s)
		}, "profile name too long"},
		{"encode v5 tag with profile", func() ([]byte, error) {
			s := goldenSession()
			s.SchemaVersion = 5
			s.Profile = "web"
			return Encode(s)
		}, "unsupported session schema version"},
		{"encode v6 tag without profile", func() ([]byte, error) {
			s := goldenSession()
			s.SchemaVersion = 6
			return Encode(s)
		}, "unsupported session schema version"},
		{"decode empty profile", func() ([]byte, error) {
			b := append([]byte(nil), v6[:tail]...)
			_, err := Decode(append(b, 0))
			return nil, err
		}, "invalid session profile name length"},
		{"decode profile too long", func() ([]byte, error) {
			b := append([]byte(nil), v6[:tail]...)
			b = append(b, MaxProfileNameLen+1)
			b = append(b, bytes.Repeat([]byte{'a'}, MaxProfileNameLen+1)...)
			_, err := Decode(b)
			return nil, err
		}, "invalid session profile name length"},
		{"decode profile truncated", func() ([]byte, error) {
			_, err := Decode(v6[:len(v6)-2])
			return nil, err
		}, "unexpected EOF"},
		{"decode profile missing", func() ([]byte, error) {
			_, err := Decode(v6[:tail])
			return nil, err
		}, "unexpected EOF"},
		{"decode unknown version", func() ([]byte, error) {
			b := append([]byte(nil), v6...)
			b[0] = 7
			_, err := Decode(b)
			return nil, err
		}, "unsupported session schema version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.mutate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func seedRaw(t *testing.T, rdb *redis.Client, store *Store, sess *Session, version uint8, ttl time.Duration) (string, []byte) {
	t.Helper()
	sess.SchemaVersion = 0
	blob, err := Encode(sess)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if blob[0] != version {
		t.Fatalf("seed blob version = %d, want %d", blob[0], version)
	}
	key := store.key(sess.TenantID, sess.SessionID)
	if err := rdb.Set(context.Background(), key, blob, ttl).Err(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return key, blob
}

// Migration never turns v5 into v6 and never rewrites v6: the stored bytes
// are identical after every read path.
func TestSchemaMigrationLeavesV5AndV6Alone(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile string
		version uint8
	}{
		{"v5 legacy", "", 5},
		{"v6 profile", "mobile", 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, rdb, done := newSessionStoreTest(t)
			defer done()
			store.WithProfiles(map[string]ProfilePolicy{"mobile": {IdleTimeout: 24 * time.Hour, AbsoluteLifetime: 48 * time.Hour}})
			ctx := context.Background()

			sess := testSession()
			sess.Profile = tc.profile
			sess.ExpiresAt = time.Now().Add(48 * time.Hour).Unix()
			key, blob := seedRaw(t, rdb, store, sess, tc.version, 24*time.Hour)

			assertUnchanged := func(step string) {
				t.Helper()
				got, err := rdb.Get(ctx, key).Bytes()
				if err != nil {
					t.Fatalf("%s: read back: %v", step, err)
				}
				if !bytes.Equal(got, blob) {
					t.Fatalf("%s rewrote the stored session (version %d -> %d)", step, blob[0], got[0])
				}
			}

			got, err := store.GetReadOnly(ctx, sess.TenantID, sess.SessionID)
			if err != nil || got.SchemaVersion != tc.version || got.Profile != tc.profile {
				t.Fatalf("GetReadOnly = (%+v, %v)", got, err)
			}
			assertUnchanged("GetReadOnly")

			many, err := store.GetManyReadOnly(ctx, sess.TenantID, []string{sess.SessionID})
			if err != nil || len(many) != 1 || many[0].SchemaVersion != tc.version {
				t.Fatalf("GetManyReadOnly = (%v, %v)", many, err)
			}
			assertUnchanged("GetManyReadOnly")

			got, err = store.Get(ctx, sess.TenantID, sess.SessionID, 7*24*time.Hour)
			if err != nil || got.SchemaVersion != tc.version || got.Profile != tc.profile {
				t.Fatalf("Get = (%+v, %v)", got, err)
			}
			assertUnchanged("Get")
		})
	}
}

// A legacy record older than v5 still migrates, and only up to v5.
func TestSchemaMigrationStopsAtV5(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	mask := permission.Mask64(1)
	now := time.Now()
	legacy := &Session{
		SchemaVersion: 4, SessionID: "sid-v4", UserID: "u", TenantID: "t", Role: "member", Mask: &mask,
		PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1, RefreshHash: [32]byte{7},
		CreatedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}
	key := store.key("t", "sid-v4")
	if err := rdb.Set(ctx, key, encodeLegacyV4Session(t, legacy), time.Hour).Err(); err != nil {
		t.Fatal(err)
	}
	for _, read := range []func() (*Session, error){
		func() (*Session, error) { return store.GetReadOnly(ctx, "t", "sid-v4") },
		func() (*Session, error) { return store.Get(ctx, "t", "sid-v4", time.Hour) },
	} {
		if _, err := read(); err != nil {
			t.Fatalf("read: %v", err)
		}
		raw, _ := rdb.Get(ctx, key).Bytes()
		if raw[0] != 5 {
			t.Fatalf("migrated to version %d, want 5", raw[0])
		}
	}
}

// Refresh keeps a v5 record v5 and a v6 record v6 with its profile intact.
func TestRotateRefreshHashKeepsSchemaVersion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile string
		version uint8
	}{
		{"v5 legacy", "", 5},
		{"v6 profile", "mobile", 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, rdb, done := newSessionStoreTest(t)
			defer done()
			store.WithProfiles(map[string]ProfilePolicy{"mobile": {IdleTimeout: 24 * time.Hour, AbsoluteLifetime: 48 * time.Hour}})
			ctx := context.Background()

			sess := testSession()
			sess.Profile = tc.profile
			sess.ExpiresAt = time.Now().Add(48 * time.Hour).Unix()
			key, before := seedRaw(t, rdb, store, sess, tc.version, 24*time.Hour)

			next := [32]byte{9}
			got, err := store.RotateRefreshHash(ctx, sess.TenantID, sess.SessionID, sess.RefreshHash, next)
			if err != nil {
				t.Fatalf("RotateRefreshHash: %v", err)
			}
			if got.SchemaVersion != tc.version || got.Profile != tc.profile || got.RefreshHash != next {
				t.Fatalf("rotated session = %+v", got)
			}
			after, _ := rdb.Get(ctx, key).Bytes()
			if after[0] != tc.version || len(after) != len(before) {
				t.Fatalf("stored record changed shape: version %d len %d -> version %d len %d", before[0], len(before), after[0], len(after))
			}
			if !bytes.HasSuffix(after, before[len(before)-1-len(tc.profile):]) {
				t.Fatalf("profile bytes did not survive rotation")
			}
		})
	}
}

// Both Lua copies of the blob parser must read v6 the same way: expose the
// profile and CreatedAt, and reject a malformed profile as an invalid blob.
func TestLuaParserHandlesV6Blobs(t *testing.T) {
	for _, script := range []struct {
		name, src string
	}{{"rotate", rotateRefreshScript}, {"swap", swapSessionScript}} {
		for _, want := range []string{"version > 6", "profile = profile", "created_at = created_at", "profile_len < 1 or profile_len > 32"} {
			if !strings.Contains(script.src, want) {
				t.Fatalf("%s script parser is missing %q", script.name, want)
			}
		}
	}
	if !strings.Contains(rotateRefreshScript, strings.TrimSpace(luaSessionParser)) {
		t.Fatal("swap script parser has drifted from rotateRefreshScript")
	}

	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	sess := testSession()
	sess.Profile = "mobile"
	sess.ExpiresAt = time.Now().Add(time.Hour).Unix()
	key, blob := seedRaw(t, rdb, store, sess, 6, time.Hour)

	// A corrupt profile length makes the blob unparseable for both scripts.
	corrupt := append([]byte(nil), blob[:len(blob)-1-len("mobile")]...)
	corrupt = append(corrupt, 0)
	if err := rdb.Set(ctx, key, corrupt, time.Hour).Err(); err != nil {
		t.Fatal(err)
	}
	_, err := store.RotateRefreshHash(ctx, sess.TenantID, sess.SessionID, sess.RefreshHash, [32]byte{9})
	if !errors.Is(err, ErrRefreshSessionCorrupt) {
		t.Fatalf("rotate over a corrupt v6 blob = %v, want ErrRefreshSessionCorrupt", err)
	}

	next := swapTarget(sess, "sid-next")
	next.Profile = "mobile"
	err = store.SwapSession(ctx, sess.TenantID, sess.SessionID, sess.RefreshHash, next, nil)
	if !errors.Is(err, ErrRefreshSessionCorrupt) {
		t.Fatalf("swap over a corrupt v6 blob = %v, want ErrRefreshSessionCorrupt", err)
	}
	if errors.Is(err, redis.Nil) {
		t.Fatal("a corrupt blob must not read as not found")
	}
}

// The migration step itself must leave v5 and v6 records alone, whichever
// read path reaches it (a rotation reaches it for every session it returns).
func TestMaybeMigrateSessionSchemaOnlyLiftsOlderRecords(t *testing.T) {
	store, rdb, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	for _, tc := range []struct {
		name    string
		profile string
		version uint8
	}{{"v5", "", 5}, {"v6", "mobile", 6}} {
		sess := testSession()
		sess.SessionID = "sid-" + tc.name
		sess.Profile = tc.profile
		key, blob := seedRaw(t, rdb, store, sess, tc.version, time.Hour)

		decoded, err := Decode(blob)
		if err != nil {
			t.Fatalf("%s: decode: %v", tc.name, err)
		}
		if err := store.maybeMigrateSessionSchema(ctx, key, decoded, blob); err != nil {
			t.Fatalf("%s: migrate: %v", tc.name, err)
		}
		after, _ := rdb.Get(ctx, key).Bytes()
		if !bytes.Equal(after, blob) || decoded.SchemaVersion != tc.version || decoded.Profile != tc.profile {
			t.Fatalf("%s: migration touched the record (version %d -> %d, profile %q)", tc.name, blob[0], after[0], decoded.Profile)
		}
	}
}
