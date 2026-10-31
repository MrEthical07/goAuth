package stores

import "time"

func normalizeTenantID(tenantID string) string {
	if tenantID == "" {
		return "0"
	}
	return tenantID
}

// nowFn returns f, or the wall clock when f is nil. Every store keeps an
// optional time source so an engine built with a test clock can move it.
func nowFn(f func() time.Time) func() time.Time {
	if f == nil {
		return time.Now
	}
	return f
}

// PointerState is where a challenge record stands against its owner's
// "newest record" pointer.
type PointerState int

const (
	// PointerAbsent: the owner has no pointer. The record was issued by an
	// instance that does not write them (a rolling deploy), or the pointer
	// has expired together with every record it could supersede.
	PointerAbsent PointerState = iota
	// PointerCurrent: the pointer names this record.
	PointerCurrent
	// PointerSuperseded: the pointer names another record or a tombstone.
	PointerSuperseded
)
