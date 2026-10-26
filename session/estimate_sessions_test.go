package session

import (
	"context"
	"testing"
	"time"
)

// FAILED-BEFORE (R2-29): the tenant cap reconciliation scanned
// "<prefix>:<tenant>:*" unescaped, so the keys of a tenant whose ID extends
// another's ("a" and "a:b") counted against the shorter one, and a tenant ID
// holding a glob character matched other tenants.
func TestEstimateActiveSessionsCountsOnlyTheTenantsOwnKeys(t *testing.T) {
	store, _, done := newSessionStoreTest(t)
	defer done()
	ctx := context.Background()

	seed := func(tenant, sid string) {
		t.Helper()
		sess := testSession()
		sess.TenantID = tenant
		sess.SessionID = sid
		sess.UserID = "u-" + sid
		if err := store.Save(ctx, sess, time.Hour); err != nil {
			t.Fatalf("seed %s/%s: %v", tenant, sid, err)
		}
	}
	seed("a", "s1")
	seed("a:b", "s2")
	seed("a:b", "s3")
	seed("a:b:c", "s4")
	seed("x*", "s5")
	seed("xy", "s6")
	seed("[ab]", "s7")
	seed("a", "s8")
	seed("b", "s9")

	for tenant, want := range map[string]int{
		"a":     2, // not a:b, a:b:c
		"a:b":   2,
		"a:b:c": 1,
		"x*":    1, // not xy
		"xy":    1,
		"[ab]":  1, // not a or b
		"b":     1,
		"none":  0,
	} {
		got, err := store.EstimateActiveSessions(ctx, tenant)
		if err != nil {
			t.Fatalf("tenant %q: %v", tenant, err)
		}
		if got != want {
			t.Fatalf("tenant %q: counted %d sessions, want %d", tenant, got, want)
		}
	}
}

func TestEscapeGlobEscapesEverySpecialCharacter(t *testing.T) {
	if got := escapeGlob(`as:a*b?[c]\d:`); got != `as:a\*b\?\[c\]\\d:` {
		t.Fatalf("got %q", got)
	}
	if got := escapeGlob("as:plain:"); got != "as:plain:" {
		t.Fatalf("got %q", got)
	}
}
