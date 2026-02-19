package limiters

func normalizeTenantID(tenantID string) string {
	if tenantID == "" {
		return "0"
	}
	return tenantID
}
