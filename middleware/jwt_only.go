package middleware

import (
	"net/http"

	goAuth "github.com/MrEthical07/goAuth"
)

// RequireJWTOnly returns middleware that overrides the validation mode to
// [goAuth.ModeJWTOnly] for the wrapped handler, skipping Redis entirely.
//
//	Docs: docs/middleware.md, docs/jwt.md
func RequireJWTOnly(engine *goAuth.Engine) func(http.Handler) http.Handler {
	return Guard(engine, goAuth.ModeJWTOnly)
}
