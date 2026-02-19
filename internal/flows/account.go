package flows

import (
	"context"
	"errors"
	"time"

	"github.com/MrEthical07/goAuth/session"
)

type AccountCreateRequest struct {
	Identifier string
	Password   string
	Role       string
}

type AccountCreateResult struct {
	UserID       string
	Role         string
	AccessToken  string
	RefreshToken string
}

type AccountUserRecord struct {
	UserID            string
	Identifier        string
	TenantID          string
	PasswordHash      string
	Status            uint8
	Role              string
	PermissionVersion uint32
	RoleVersion       uint32
	AccountVersion    uint32
}

type AccountCreateUserInput struct {
	Identifier        string
	PasswordHash      string
	Role              string
	TenantID          string
	Status            uint8
	PermissionVersion uint32
	RoleVersion       uint32
	AccountVersion    uint32
}

type AccountMetrics struct {
	AccountCreationSuccess     int
	AccountCreationDuplicate   int
	AccountCreationRateLimited int
}

type AccountEvents struct {
	AccountCreationSuccess     string
	AccountCreationFailure     string
	AccountCreationDuplicate   string
	AccountCreationRateLimited string
}

type AccountErrors struct {
	EngineNotReady              error
	AccountCreationDisabled     error
	AccountCreationUnavailable  error
	AccountCreationInvalid      error
	AccountRoleInvalid          error
	AccountCreationRateLimited  error
	PasswordPolicy              error
	AccountExists               error
	ProviderDuplicateIdentifier error
	SessionCreationFailed       error
}

type AccountDeps struct {
	Enabled                  bool
	AutoLogin                bool
	RefreshTTL               time.Duration
	MultiTenantEnabled       bool
	DefaultRole              string
	EmailVerificationEnabled bool
	ShouldRequireVerified    bool
	ActiveStatus             uint8
	PendingStatus            uint8

	TenantIDFromContext         func(context.Context) string
	TenantIDFromContextExplicit func(context.Context) (string, bool)
	ClientIPFromContext         func(context.Context) string

	EnforceAccountLimiter func(context.Context, string, string, string) error
	MapLimiterError       func(error) error
	RoleExists            func(string) bool

	HashPassword       func(string) (string, error)
	CreateUser         func(context.Context, AccountCreateUserInput) (AccountUserRecord, error)
	IssueSessionTokens func(context.Context, AccountUserRecord) (string, string, error)

	MetricInc     func(int)
	EmitAudit     func(context.Context, string, bool, string, string, string, error, func() map[string]string)
	EmitRateLimit func(context.Context, string, string, func() map[string]string)

	Metrics AccountMetrics
	Events  AccountEvents
	Errors  AccountErrors
}

type AccountSessionDeps struct {
	TenantIDFromContext func(context.Context) string
	Now                 func() time.Time
	SessionLifetime     func() time.Duration

	GetRoleMask        func(string) (interface{}, bool)
	NewSessionID       func() (string, error)
	NewRefreshSecret   func() ([32]byte, error)
	HashRefreshSecret  func([32]byte) [32]byte
	EncodeRefreshToken func(string, [32]byte) (string, error)
	SaveSession        func(context.Context, *session.Session, time.Duration) error
	IssueAccessToken   func(*session.Session) (string, error)

	MetricInc            func(int)
	SessionCreatedMetric int

	ErrEngineNotReady     error
	ErrAccountRoleInvalid error
}

func RunCreateAccount(ctx context.Context, req AccountCreateRequest, deps AccountDeps) (*AccountCreateResult, error) {
	normalizeAccountDeps(&deps)

	if !deps.Enabled {
		deps.EmitAudit(ctx, deps.Events.AccountCreationFailure, false, "", deps.TenantIDFromContext(ctx), "", deps.Errors.AccountCreationDisabled, func() map[string]string {
			return map[string]string{
				"reason": "feature_disabled",
			}
		})
		return nil, deps.Errors.AccountCreationDisabled
	}
	if deps.HashPassword == nil || deps.CreateUser == nil || deps.EnforceAccountLimiter == nil || deps.RoleExists == nil {
		return nil, deps.Errors.EngineNotReady
	}
	if deps.AutoLogin && deps.RefreshTTL <= 0 {
		return nil, deps.Errors.AccountCreationUnavailable
	}

	tenantID := deps.TenantIDFromContext(ctx)
	if deps.MultiTenantEnabled {
		explicitTenantID, ok := deps.TenantIDFromContextExplicit(ctx)
		if !ok {
			return nil, deps.Errors.AccountCreationInvalid
		}
		tenantID = explicitTenantID
	}

	if req.Identifier == "" {
		deps.EmitAudit(ctx, deps.Events.AccountCreationFailure, false, "", tenantID, "", deps.Errors.AccountCreationInvalid, func() map[string]string {
			return map[string]string{
				"reason": "empty_identifier",
			}
		})
		return nil, deps.Errors.AccountCreationInvalid
	}
	if req.Password == "" {
		deps.EmitAudit(ctx, deps.Events.AccountCreationFailure, false, "", tenantID, "", deps.Errors.PasswordPolicy, func() map[string]string {
			return map[string]string{
				"identifier": req.Identifier,
				"reason":     "empty_password",
			}
		})
		return nil, deps.Errors.PasswordPolicy
	}

	role := req.Role
	if role == "" {
		role = deps.DefaultRole
	}
	if role == "" {
		deps.EmitAudit(ctx, deps.Events.AccountCreationFailure, false, "", tenantID, "", deps.Errors.AccountRoleInvalid, func() map[string]string {
			return map[string]string{
				"identifier": req.Identifier,
				"reason":     "role_missing",
			}
		})
		return nil, deps.Errors.AccountRoleInvalid
	}
	if !deps.RoleExists(role) {
		deps.EmitAudit(ctx, deps.Events.AccountCreationFailure, false, "", tenantID, "", deps.Errors.AccountRoleInvalid, func() map[string]string {
			return map[string]string{
				"identifier": req.Identifier,
				"reason":     "role_invalid",
			}
		})
		return nil, deps.Errors.AccountRoleInvalid
	}

	if err := deps.EnforceAccountLimiter(ctx, tenantID, req.Identifier, deps.ClientIPFromContext(ctx)); err != nil {
		mapped := deps.MapLimiterError(err)
		if errors.Is(mapped, deps.Errors.AccountCreationRateLimited) {
			deps.MetricInc(deps.Metrics.AccountCreationRateLimited)
			deps.EmitAudit(ctx, deps.Events.AccountCreationRateLimited, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"identifier": req.Identifier,
				}
			})
			deps.EmitRateLimit(ctx, "account_creation", tenantID, func() map[string]string {
				return map[string]string{
					"identifier": req.Identifier,
				}
			})
		}
		return nil, mapped
	}

	initialStatus := deps.ActiveStatus
	if deps.EmailVerificationEnabled {
		initialStatus = deps.PendingStatus
	}

	passwordHash, err := deps.HashPassword(req.Password)
	if err != nil {
		deps.EmitAudit(ctx, deps.Events.AccountCreationFailure, false, "", tenantID, "", deps.Errors.PasswordPolicy, func() map[string]string {
			return map[string]string{
				"identifier": req.Identifier,
				"reason":     "hash_policy",
			}
		})
		return nil, deps.Errors.PasswordPolicy
	}

	created, err := deps.CreateUser(ctx, AccountCreateUserInput{
		Identifier:        req.Identifier,
		PasswordHash:      passwordHash,
		Role:              role,
		TenantID:          tenantID,
		Status:            initialStatus,
		PermissionVersion: 1,
		RoleVersion:       1,
		AccountVersion:    1,
	})
	if err != nil {
		if deps.Errors.ProviderDuplicateIdentifier != nil && errors.Is(err, deps.Errors.ProviderDuplicateIdentifier) {
			deps.MetricInc(deps.Metrics.AccountCreationDuplicate)
			deps.EmitAudit(ctx, deps.Events.AccountCreationDuplicate, false, "", tenantID, "", deps.Errors.AccountExists, func() map[string]string {
				return map[string]string{
					"identifier": req.Identifier,
				}
			})
			return nil, deps.Errors.AccountExists
		}
		deps.EmitAudit(ctx, deps.Events.AccountCreationFailure, false, "", tenantID, "", err, func() map[string]string {
			return map[string]string{
				"identifier": req.Identifier,
				"reason":     "provider_create_failed",
			}
		})
		return nil, err
	}

	if created.UserID == "" {
		deps.EmitAudit(ctx, deps.Events.AccountCreationFailure, false, "", tenantID, "", deps.Errors.AccountCreationUnavailable, func() map[string]string {
			return map[string]string{
				"identifier": req.Identifier,
				"reason":     "missing_user_id",
			}
		})
		return nil, deps.Errors.AccountCreationUnavailable
	}
	if created.Role == "" {
		created.Role = role
	}
	if created.TenantID == "" {
		created.TenantID = tenantID
	}
	if created.PermissionVersion == 0 {
		created.PermissionVersion = 1
	}
	if created.RoleVersion == 0 {
		created.RoleVersion = 1
	}
	if created.AccountVersion == 0 {
		created.AccountVersion = 1
	}

	result := &AccountCreateResult{
		UserID: created.UserID,
		Role:   created.Role,
	}

	if deps.AutoLogin {
		if deps.IssueSessionTokens == nil {
			return nil, deps.Errors.EngineNotReady
		}
		if !(deps.ShouldRequireVerified && created.Status == deps.PendingStatus) {
			accessToken, refreshToken, err := deps.IssueSessionTokens(ctx, created)
			if err != nil {
				deps.EmitAudit(ctx, deps.Events.AccountCreationSuccess, false, created.UserID, created.TenantID, "", deps.Errors.SessionCreationFailed, func() map[string]string {
					return map[string]string{
						"identifier": req.Identifier,
						"reason":     "auto_login_failed",
					}
				})
				return result, errors.Join(deps.Errors.SessionCreationFailed, err)
			}
			result.AccessToken = accessToken
			result.RefreshToken = refreshToken
		}
	}

	req.Password = ""
	deps.MetricInc(deps.Metrics.AccountCreationSuccess)
	deps.EmitAudit(ctx, deps.Events.AccountCreationSuccess, true, created.UserID, created.TenantID, "", nil, func() map[string]string {
		return map[string]string{
			"identifier": req.Identifier,
			"role":       created.Role,
		}
	})
	return result, nil
}

func RunIssueAccountSessionTokens(ctx context.Context, user AccountUserRecord, deps AccountSessionDeps) (string, string, error) {
	normalizeAccountSessionDeps(&deps)

	if deps.GetRoleMask == nil ||
		deps.NewSessionID == nil ||
		deps.NewRefreshSecret == nil ||
		deps.HashRefreshSecret == nil ||
		deps.EncodeRefreshToken == nil ||
		deps.SaveSession == nil ||
		deps.IssueAccessToken == nil ||
		deps.SessionLifetime == nil {
		return "", "", deps.ErrEngineNotReady
	}

	mask, ok := deps.GetRoleMask(user.Role)
	if !ok {
		return "", "", deps.ErrAccountRoleInvalid
	}

	sessionID, err := deps.NewSessionID()
	if err != nil {
		return "", "", err
	}
	refreshSecret, err := deps.NewRefreshSecret()
	if err != nil {
		return "", "", err
	}

	tenantID := user.TenantID
	if tenantID == "" {
		tenantID = deps.TenantIDFromContext(ctx)
	}

	now := deps.Now()
	sessionLifetime := deps.SessionLifetime()
	accountVersion := user.AccountVersion
	if accountVersion == 0 {
		accountVersion = 1
	}

	sess := &session.Session{
		SessionID:         sessionID,
		UserID:            user.UserID,
		TenantID:          tenantID,
		Role:              user.Role,
		Mask:              mask,
		PermissionVersion: user.PermissionVersion,
		RoleVersion:       user.RoleVersion,
		AccountVersion:    accountVersion,
		Status:            user.Status,
		RefreshHash:       deps.HashRefreshSecret(refreshSecret),
		CreatedAt:         now.Unix(),
		ExpiresAt:         now.Add(sessionLifetime).Unix(),
	}

	if err := deps.SaveSession(ctx, sess, sessionLifetime); err != nil {
		return "", "", err
	}
	deps.MetricInc(deps.SessionCreatedMetric)

	accessToken, err := deps.IssueAccessToken(sess)
	if err != nil {
		return "", "", err
	}
	refreshToken, err := deps.EncodeRefreshToken(sessionID, refreshSecret)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func normalizeAccountDeps(deps *AccountDeps) {
	if deps.TenantIDFromContext == nil {
		deps.TenantIDFromContext = func(context.Context) string { return "" }
	}
	if deps.TenantIDFromContextExplicit == nil {
		deps.TenantIDFromContextExplicit = func(context.Context) (string, bool) { return "", false }
	}
	if deps.ClientIPFromContext == nil {
		deps.ClientIPFromContext = func(context.Context) string { return "" }
	}
	if deps.MapLimiterError == nil {
		deps.MapLimiterError = func(error) error { return deps.Errors.AccountCreationUnavailable }
	}
	if deps.MetricInc == nil {
		deps.MetricInc = func(int) {}
	}
	if deps.EmitAudit == nil {
		deps.EmitAudit = func(context.Context, string, bool, string, string, string, error, func() map[string]string) {}
	}
	if deps.EmitRateLimit == nil {
		deps.EmitRateLimit = func(context.Context, string, string, func() map[string]string) {}
	}
}

func normalizeAccountSessionDeps(deps *AccountSessionDeps) {
	if deps.TenantIDFromContext == nil {
		deps.TenantIDFromContext = func(context.Context) string { return "" }
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.MetricInc == nil {
		deps.MetricInc = func(int) {}
	}
}
