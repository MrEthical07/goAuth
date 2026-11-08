package goAuth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/MrEthical07/goAuth/password"
)

// Regression tests for R2-18 / C2 of the v0.8.1 verification audit (run 3): an
// unknown identifier costs one verification at the configured cost, but an
// account whose stored hash was made under cheaper parameters, or is not Argon2
// at all, was rejected faster, so the response time told the account exists.
// The tests count verifications through verifyHashFn and read the parameters of
// the hash each one ran against; none of them measures time.

const (
	hcConfigured = "m=16384,t=2,p=1" // what the engine is configured with
	hcCheap      = "m=8192,t=1,p=1"  // an older, cheaper setting
	hcPassword   = "correct-password-123"
	// Not Argon2: a bcrypt-shaped string a host imported.
	hcForeignHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
)

type hcEnv struct {
	engine *Engine
	up     *mockUserProvider
	hashes *[]string // the encoded hash of every verification, in order
}

func hcHash(t *testing.T, memory, time uint32, pw string) string {
	t.Helper()
	h, err := password.NewArgon2(password.Config{Memory: memory, Time: time, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := h.Hash(pw)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

// newHashCostEnv configures Argon2 at hcConfigured with UpgradeOnLogin and
// registers four accounts: alice (hash under the cheaper setting), bob (hash at
// the configured cost), carol (a hash that is not Argon2) and dave (a hash under
// the cheaper setting, for tests that need a second one).
func newHashCostEnv(t *testing.T) *hcEnv {
	t.Helper()
	cfg := accountTestConfig()
	cfg.Password = PasswordConfig{Memory: 16 * 1024, Time: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32, UpgradeOnLogin: true}
	cfg.Security.EnableLoginFailureLimiter = false
	up := newHardeningUserProvider(t)
	cheap, current := hcHash(t, 8*1024, 1, hcPassword), hcHash(t, 16*1024, 2, hcPassword)
	set := func(id, identifier, hash string) {
		up.users[id] = UserRecord{UserID: id, Identifier: identifier, TenantID: "0", PasswordHash: hash, Status: AccountActive, Role: "member", PermissionVersion: 1, RoleVersion: 1, AccountVersion: 1}
		up.byIdentifier[identifier] = id
	}
	set("u1", "alice", cheap)
	set("u2", "bob", current)
	set("u3", "carol", hcForeignHash)
	set("u4", "dave", cheap)
	engine, _, done := newCreateAccountEngine(t, cfg, up)
	t.Cleanup(done)
	return &hcEnv{engine: engine, up: up, hashes: captureVerifiedHashes(engine)}
}

// run performs fn and returns the parameter string of every verification it ran.
func (env *hcEnv) run(t *testing.T, fn func()) []string {
	t.Helper()
	*env.hashes = (*env.hashes)[:0]
	fn()
	var out []string
	for _, h := range *env.hashes {
		if strings.HasPrefix(h, "$argon2") && strings.Count(h, "$") == 5 {
			out = append(out, phcParams(t, h))
		} else {
			out = append(out, "(not argon2)")
		}
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (env *hcEnv) wantRuns(t *testing.T, name string, got []string, want ...string) {
	t.Helper()
	if !equalStrings(got, want) {
		t.Fatalf("%s: verifications ran at %v, want %v", name, got, want)
	}
}

// FAILED-BEFORE (R2-18 / C2): the wrong-password rejection of a cheap or
// non-Argon2 hash ran one verification, and an unparseable one ran no work at
// all, while an unknown identifier ran one at the configured cost.
func TestLoginRejectionCostsAtLeastTheConfiguredCost(t *testing.T) {
	env := newHashCostEnv(t)
	ctx := context.Background()
	login := func(identifier, pw string) func() {
		return func() {
			if _, _, err := env.engine.Login(ctx, identifier, pw); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("Login(%s) = %v, want ErrInvalidCredentials", identifier, err)
			}
		}
	}

	// The controls the others are measured against.
	env.wantRuns(t, "unknown identifier", env.run(t, login("nobody", "wrong-password-xyz")), hcConfigured)
	env.wantRuns(t, "current-cost hash", env.run(t, login("bob", "wrong-password-xyz")), hcConfigured)

	// Cheaper: the real verification at the stored cost, then a dummy at the
	// configured one.
	env.wantRuns(t, "cheap hash", env.run(t, login("alice", "wrong-password-xyz")), hcCheap, hcConfigured)
	// Not Argon2: the real verification fails to parse, the dummy pays the cost.
	env.wantRuns(t, "non-argon2 hash", env.run(t, login("carol", "wrong-password-xyz")), "(not argon2)", hcConfigured)
}

// A correct password is never padded, and a successful login still upgrades the
// hash; once upgraded, a wrong password costs one verification like any other.
func TestCorrectPasswordAgainstACheapHashRunsNoExtraDummy(t *testing.T) {
	env := newHashCostEnv(t)
	ctx := context.Background()

	got := env.run(t, func() {
		if _, _, err := env.engine.Login(ctx, "dave", hcPassword); err != nil {
			t.Fatalf("Login: %v", err)
		}
	})
	env.wantRuns(t, "correct password, cheap hash", got, hcCheap)

	env.up.mu.Lock()
	upgraded := phcParams(t, env.up.users["u4"].PasswordHash)
	env.up.mu.Unlock()
	if upgraded != hcConfigured {
		t.Fatalf("UpgradeOnLogin left the hash at %s, want %s", upgraded, hcConfigured)
	}
	got = env.run(t, func() {
		if _, _, err := env.engine.Login(ctx, "dave", "wrong-password-xyz"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("Login = %v", err)
		}
	})
	env.wantRuns(t, "wrong password after the upgrade", got, hcConfigured)
}

// VerifyPassword and ChangePassword share the helper: their wrong-password
// branches pad a cheap or non-Argon2 hash the same way, and leave a current one
// alone.
func TestVerifyAndChangePasswordRejectionsAreAlsoPadded(t *testing.T) {
	env := newHashCostEnv(t)
	ctx := context.Background()

	cases := []struct {
		name string
		user string
		want []string
	}{
		{"current-cost hash", "u2", []string{hcConfigured}},
		{"cheap hash", "u1", []string{hcCheap, hcConfigured}},
		{"non-argon2 hash", "u3", []string{"(not argon2)", hcConfigured}},
	}
	for _, tc := range cases {
		got := env.run(t, func() {
			if err := env.engine.VerifyPassword(ctx, tc.user, "wrong-password-xyz"); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("VerifyPassword(%s) = %v, want ErrInvalidCredentials", tc.name, err)
			}
		})
		env.wantRuns(t, "VerifyPassword, "+tc.name, got, tc.want...)

		got = env.run(t, func() {
			if err := env.engine.ChangePassword(ctx, tc.user, "wrong-password-xyz", "another-password-456"); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("ChangePassword(%s) = %v, want ErrInvalidCredentials", tc.name, err)
			}
		})
		env.wantRuns(t, "ChangePassword, "+tc.name, got, tc.want...)
	}

	// A correct password for a cheap hash is not padded on either path.
	got := env.run(t, func() {
		if err := env.engine.VerifyPassword(ctx, "u1", hcPassword); err != nil {
			t.Fatalf("VerifyPassword: %v", err)
		}
	})
	env.wantRuns(t, "VerifyPassword, correct password", got, hcCheap)
}
