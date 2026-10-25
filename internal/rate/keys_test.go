package rate

import "testing"

func TestCanonicalIPGroupsSpellingsOfOneClient(t *testing.T) {
	same := [][]string{
		{"203.0.113.7", "::ffff:203.0.113.7", "203.0.113.7:51234", "[::ffff:203.0.113.7]:443"},
		{"2001:db8:1:2::1", "2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:DB8:1:2::9%eth0", "[2001:db8:1:2::5]:8080"},
	}
	for _, group := range same {
		want := loginIPKey("t", group[0])
		for _, spelling := range group[1:] {
			if got := loginIPKey("t", spelling); got != want {
				t.Fatalf("%q must share a budget with %q", spelling, group[0])
			}
		}
	}

	different := [][2]string{
		{"203.0.113.7", "203.0.113.8"},
		{"2001:db8:1:2::1", "2001:db8:1:3::1"},
		{"203.0.113.7", "2001:db8:1:2::1"},
	}
	for _, pair := range different {
		if loginIPKey("t", pair[0]) == loginIPKey("t", pair[1]) {
			t.Fatalf("%q and %q must not share a budget", pair[0], pair[1])
		}
	}
	if loginIPKey("t1", "203.0.113.7") == loginIPKey("t2", "203.0.113.7") {
		t.Fatal("budgets are per tenant")
	}
	if got := canonicalIP("not-an-ip"); got != "not-an-ip" {
		t.Fatalf("a non-address keeps counting under its own string, got %q", got)
	}
}
