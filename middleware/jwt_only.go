package middleware

import (
	"net/http"

	goAuth "github.com/MrEthical07/goAuth"
)

// RequireJWTOnly describes the requirejwtonly operation and its observable behavior.
//
// RequireJWTOnly may return an error when input validation, dependency calls, or security checks fail.
// RequireJWTOnly does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func RequireJWTOnly(engine *goAuth.Engine) func(http.Handler) http.Handler {
	return Guard(engine, goAuth.ModeJWTOnly)
}
