package middleware

import (
	"net/http"

	goAuth "github.com/MrEthical07/goAuth"
)

func RequireStrict(engine *goAuth.Engine) func(http.Handler) http.Handler {
	return Guard(engine, goAuth.ModeStrict)
}
