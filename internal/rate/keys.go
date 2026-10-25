package rate

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
)

func safeID(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func loginUserKey(tenantID, identifier string) string {
	return "rl:login:fail:" + safeID(tenantID) + ":" + safeID(identifier)
}

// loginIPKey is the budget of one client address within a tenant. The address
// is canonicalized first, so spellings of one address (an IPv4-mapped IPv6
// form, a port, a zone) and the addresses of one IPv6 /64 -- the unit a single
// subscriber is normally given -- share a budget instead of each getting a
// fresh one.
func loginIPKey(tenantID, ip string) string {
	return "rl:login:ip:" + safeID(tenantID) + ":" + safeID(canonicalIP(ip))
}

// canonicalIP returns the form of a client address that budgets are keyed by.
// A string that is not an address is returned as it is, so it still counts
// against something.
func canonicalIP(raw string) string {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		ap, perr := netip.ParseAddrPort(raw)
		if perr != nil {
			return raw
		}
		addr = ap.Addr()
	}
	addr = addr.WithZone("").Unmap()
	if addr.Is6() {
		if prefix, err := addr.Prefix(64); err == nil {
			return prefix.String()
		}
	}
	return addr.String()
}

// loginAccountKey is the budget of one resolved account, whatever spelling of
// its identifier the caller used.
func loginAccountKey(tenantID, userID string) string {
	return "rl:login:user:" + safeID(tenantID) + ":" + safeID(userID)
}
