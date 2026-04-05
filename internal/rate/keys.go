package rate

func loginUserKey(tenantID, identifier string) string {
	return "rl:login:fail:" + tenantID + ":" + identifier
}
