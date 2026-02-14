package middleware

import (
	"net/http"

	goAuth "github.com/MrEthical07/goAuth"
)

func RequireJWTOnly(engine *goAuth.Engine) func(http.Handler) http.Handler {
	return Guard(engine, goAuth.ModeJWTOnly)
}
