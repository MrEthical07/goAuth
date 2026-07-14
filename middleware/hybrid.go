package middleware

import (
	"net/http"

	goAuth "github.com/MrEthical07/goAuth"
)

// RequireHybrid returns middleware that overrides the validation mode to
// [goAuth.ModeHybrid] for the wrapped handler. Hybrid routes validate the
// JWT statelessly (signature, claims, clock skew — zero Redis); use
// [RequireStrict] on routes that need session-backed revocation checks.
//
//	Docs: docs/middleware.md, docs/jwt.md
func RequireHybrid(engine *goAuth.Engine) func(http.Handler) http.Handler {
	return Guard(engine, goAuth.ModeHybrid)
}
