package rate

func loginUserKey(username string) string {
	return "al:" + username
}

func loginIPKey(ip string) string {
	return "ali:" + ip
}

func refreshKey(sessionID string) string {
	return "ar:" + sessionID
}
