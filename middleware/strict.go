package middleware

import (
	"net/http"

	goAuth "github.com/MrEthical07/goAuth"
)

// RequireStrict describes the requirestrict operation and its observable behavior.
//
// RequireStrict may return an error when input validation, dependency calls, or security checks fail.
// RequireStrict does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func RequireStrict(engine *goAuth.Engine) func(http.Handler) http.Handler {
	return Guard(engine, goAuth.ModeStrict)
}
