package middleware

import (
	"net/http"

	goAuth "github.com/MrEthical07/goAuth"
)

// RequireStrict returns middleware that overrides the validation mode to
// [goAuth.ModeStrict] for the wrapped handler, forcing a Redis session
// lookup on every request.
//
//	Docs: docs/middleware.md, docs/jwt.md
func RequireStrict(engine *goAuth.Engine) func(http.Handler) http.Handler {
	return Guard(engine, goAuth.ModeStrict)
}
