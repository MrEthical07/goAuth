package test

import (
	"context"
	"net/http"
	"testing"

	goAuth "github.com/MrEthical07/goAuth"
	"github.com/MrEthical07/goAuth/middleware"
)

// This test intentionally guards public API compile-compat for consumers.
func TestPublicAPISurfaceCompile(t *testing.T) {
	_ = goAuth.New

	var _ *goAuth.Engine
	var _ goAuth.Config
	var _ goAuth.AuthResult
	var _ goAuth.LoginResult
	var _ goAuth.CreateAccountRequest
	var _ goAuth.CreateAccountResult
	var _ goAuth.UserProvider
	var _ goAuth.AuditSink

	var _ error = goAuth.ErrUnauthorized
	var _ error = goAuth.ErrSessionNotFound
	var _ error = goAuth.ErrInvalidCredentials
	var _ error = goAuth.ErrRefreshReuse
	var _ error = goAuth.ErrRefreshInvalid
	var _ error = goAuth.ErrTokenInvalid

	var _ func(*goAuth.Engine, goAuth.RouteMode) func(http.Handler) http.Handler = middleware.Guard
	var _ func(*goAuth.Engine) func(http.Handler) http.Handler = middleware.RequireJWTOnly
	var _ func(*goAuth.Engine) func(http.Handler) http.Handler = middleware.RequireStrict

	var _ func(*goAuth.Engine, context.Context, string, string) (string, string, error) = (*goAuth.Engine).Login
	var _ func(*goAuth.Engine, context.Context, string) (string, string, error) = (*goAuth.Engine).Refresh
	var _ func(*goAuth.Engine, context.Context, string, goAuth.RouteMode) (*goAuth.AuthResult, error) = (*goAuth.Engine).Validate
	var _ func(*goAuth.Engine, context.Context, string) error = (*goAuth.Engine).Logout
}
