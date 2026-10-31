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
