package middleware

import (
	"context"
	"net/http"
	"strings"

	goAuth "github.com/MrEthical07/goAuth"
)

type authResultContextKey struct{}

func AuthResultFromContext(ctx context.Context) (*goAuth.AuthResult, bool) {
	res, ok := ctx.Value(authResultContextKey{}).(*goAuth.AuthResult)
	return res, ok
}

func Guard(engine *goAuth.Engine, routeMode goAuth.RouteMode) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if engine == nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			token, ok := bearerToken(r.Header.Get("Authorization"))
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			res, err := engine.Validate(r.Context(), token, routeMode)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), authResultContextKey{}, res)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func bearerToken(value string) (string, bool) {
	const bearer = "Bearer "
	if !strings.HasPrefix(value, bearer) {
		return "", false
	}

	token := value[len(bearer):]
	if token == "" {
		return "", false
	}

	return token, true
}
