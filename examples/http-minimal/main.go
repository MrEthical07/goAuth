// Package main demonstrates a minimal HTTP integration with goAuth.
//
// It starts a local HTTP server on :8080 backed by miniredis (no external
// Redis required) and an in-memory user provider stub.
//
// Endpoints:
//
//	POST /login     — JSON {"username":"...", "password":"..."}
//	POST /refresh   — rotates tokens via the refresh-token cookie
//	POST /logout    — destroys the current session (by access token)
//	GET  /protected — middleware-guarded route (requires valid access token)
//
// Run:
//
//	go run ./examples/http-minimal
//
// Then:
//
//	# login (stores refresh cookie in cookie jar)
//	curl -i -c jar.txt -X POST localhost:8080/login \
//	  -H 'Content-Type: application/json' \
//	  -d '{"username":"alice@example.com","password":"correct-horse"}'
//
//	# call protected (uses access token from login response)
//	curl -i localhost:8080/protected -H "Authorization: Bearer <ACCESS_TOKEN>"
//
//	# refresh (uses cookie jar)
//	curl -i -b jar.txt -c jar.txt -X POST localhost:8080/refresh
//
//	# logout (invalidates session by access token, clears refresh cookie)
//	curl -i -b jar.txt -c jar.txt -X POST localhost:8080/logout \
//	  -H "Authorization: Bearer <ACCESS_TOKEN>"
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	goAuth "github.com/MrEthical07/goAuth"
	"github.com/MrEthical07/goAuth/middleware"
	"github.com/MrEthical07/goAuth/password"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func main() {
	// ---------- infrastructure ----------
	mr, err := miniredis.Run()
	if err != nil {
		log.Fatal(err)
	}
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	// ---------- config + provider seed ----------
	cfg := goAuth.DefaultConfig()

	hasher, err := password.NewArgon2(toPasswordConfig(cfg.Password)) // cfg.Password is expected to be password.Config
	if err != nil {
		log.Fatal("argon2 init:", err)
	}

	seedHash, err := hasher.Hash("correct-horse")
	if err != nil {
		log.Fatal("argon2 hash:", err)
	}

	provider := newStubProvider()
	provider.PutUser(goAuth.UserRecord{
		UserID:            "user-1",
		Identifier:        "alice@example.com",
		PasswordHash:      seedHash,
		Role:              "admin",
		Status:            goAuth.AccountActive,
		PermissionVersion: 1,
		RoleVersion:       1,
		AccountVersion:    1,
	})

	// ---------- build engine ----------
	engine, err := goAuth.New().
		WithConfig(cfg).
		WithRedis(rdb).
		WithPermissions([]string{"user.read", "user.write", "admin.panel"}).
		WithRoles(map[string][]string{
			"user":  {"user.read"},
			"admin": {"user.read", "user.write", "admin.panel"},
		}).
		WithUserProvider(provider).
		Build()
	if err != nil {
		log.Fatal("engine build:", err)
	}
	defer engine.Close()

	// ---------- routes ----------
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", loginHandler(engine))
	mux.HandleFunc("POST /refresh", refreshHandler(engine))
	mux.HandleFunc("POST /logout", logoutHandler(engine))

	// Protected route uses Guard middleware (mode inherited from route config).
	protected := middleware.Guard(engine, goAuth.ModeInherit)(
		http.HandlerFunc(protectedHandler),
	)
	mux.Handle("GET /protected", protected)

	fmt.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func loginHandler(engine *goAuth.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		ctx := withRequestContext(r)

		access, refresh, err := engine.Login(ctx, body.Username, body.Password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		setRefreshCookie(w, r, refresh)
		writeJSON(w, http.StatusOK, map[string]string{"access_token": access})
	}
}

func refreshHandler(engine *goAuth.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("refresh_token")
		if err != nil || cookie.Value == "" {
			http.Error(w, "missing refresh token", http.StatusUnauthorized)
			return
		}

		ctx := withRequestContext(r)

		access, refresh, err := engine.Refresh(ctx, cookie.Value)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		setRefreshCookie(w, r, refresh)
		writeJSON(w, http.StatusOK, map[string]string{"access_token": access})
	}
}

func logoutHandler(engine *goAuth.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			return
		}

		if err := engine.LogoutByAccessToken(withRequestContext(r), token); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		clearRefreshCookie(w, r)
		w.WriteHeader(http.StatusNoContent)
	}
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	result, ok := middleware.AuthResultFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "hello, authenticated user",
		"user_id": result.UserID,
	})
}

// ---------------------------------------------------------------------------
// Request context helpers
// ---------------------------------------------------------------------------

func withRequestContext(r *http.Request) context.Context {
	ctx := r.Context()

	// Best-effort IP extraction for local demo.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ctx = goAuth.WithClientIP(ctx, host)
	ctx = goAuth.WithUserAgent(ctx, r.UserAgent())

	return ctx
}

func bearerToken(h string) string {
	const pfx = "Bearer "
	if len(h) >= len(pfx) && h[:len(pfx)] == pfx {
		return h[len(pfx):]
	}
	return h
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

func setRefreshCookie(w http.ResponseWriter, r *http.Request, token string) {
	// For localhost demo on plain HTTP, Secure cookies won't be sent.
	secure := r.TLS != nil

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    token,
		Path:     "/",
		MaxAge:   int((7 * 24 * time.Hour).Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearRefreshCookie(w http.ResponseWriter, r *http.Request) {
	secure := r.TLS != nil
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------------------
// Stub UserProvider — in-memory demo store.
// Replace with your real database-backed implementation.
// ---------------------------------------------------------------------------

type stubProvider struct {
	mu      sync.RWMutex
	byID    map[string]goAuth.UserRecord
	byIdent map[string]string
}

func newStubProvider() *stubProvider {
	return &stubProvider{
		byID:    make(map[string]goAuth.UserRecord),
		byIdent: make(map[string]string),
	}
}

func (p *stubProvider) PutUser(u goAuth.UserRecord) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.byID[u.UserID] = u
	p.byIdent[u.Identifier] = u.UserID
}

func (p *stubProvider) GetUserByIdentifier(identifier string) (goAuth.UserRecord, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	id, ok := p.byIdent[identifier]
	if !ok {
		return goAuth.UserRecord{}, fmt.Errorf("user not found")
	}
	u, ok := p.byID[id]
	if !ok {
		return goAuth.UserRecord{}, fmt.Errorf("user not found")
	}
	return u, nil
}

func (p *stubProvider) GetUserByID(userID string) (goAuth.UserRecord, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	u, ok := p.byID[userID]
	if !ok {
		return goAuth.UserRecord{}, fmt.Errorf("user not found")
	}
	return u, nil
}

func (p *stubProvider) UpdatePasswordHash(userID string, newHash string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	u, ok := p.byID[userID]
	if !ok {
		return fmt.Errorf("user not found")
	}
	u.PasswordHash = newHash
	p.byID[userID] = u
	return nil
}

// CreateUser is included because your interface likely requires it.
// In a real app, your DB layer would create the user and store the hash.
func (p *stubProvider) CreateUser(_ context.Context, input goAuth.CreateUserInput) (goAuth.UserRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	u := goAuth.UserRecord{
		UserID:            "user-new",
		Identifier:        input.Identifier,
		PasswordHash:      input.PasswordHash,
		Role:              input.Role,
		Status:            input.Status,
		PermissionVersion: input.PermissionVersion,
		RoleVersion:       input.RoleVersion,
		AccountVersion:    input.AccountVersion,
	}
	p.byID[u.UserID] = u
	p.byIdent[u.Identifier] = u.UserID
	return u, nil
}

func (p *stubProvider) UpdateAccountStatus(_ context.Context, userID string, status goAuth.AccountStatus) (goAuth.UserRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	u, ok := p.byID[userID]
	if !ok {
		return goAuth.UserRecord{}, fmt.Errorf("user not found")
	}
	u.Status = status
	p.byID[userID] = u
	return u, nil
}

// ---- MFA / TOTP / Backup codes ----
// These are stubbed for the minimal demo. Production implementations should
// persist secrets/codes in your database and enforce policy.

func (p *stubProvider) GetTOTPSecret(_ context.Context, _ string) (*goAuth.TOTPRecord, error) {
	return nil, fmt.Errorf("totp not configured")
}

func (p *stubProvider) EnableTOTP(_ context.Context, _ string, _ []byte) error { return nil }
func (p *stubProvider) DisableTOTP(_ context.Context, _ string) error          { return nil }
func (p *stubProvider) MarkTOTPVerified(_ context.Context, _ string) error     { return nil }
func (p *stubProvider) UpdateTOTPLastUsedCounter(_ context.Context, _ string, _ int64) error {
	return nil
}

func (p *stubProvider) GetBackupCodes(_ context.Context, _ string) ([]goAuth.BackupCodeRecord, error) {
	return nil, nil
}

func (p *stubProvider) ReplaceBackupCodes(_ context.Context, _ string, _ []goAuth.BackupCodeRecord) error {
	return nil
}

func (p *stubProvider) ConsumeBackupCode(_ context.Context, _ string, _ [32]byte) (bool, error) {
	return false, nil
}

func toPasswordConfig(pc goAuth.PasswordConfig) password.Config {
	return password.Config{
		Memory:      pc.Memory,
		Time:        pc.Time,
		Parallelism: pc.Parallelism,
		SaltLength:  pc.SaltLength,
		KeyLength:   pc.KeyLength,
	}
}
