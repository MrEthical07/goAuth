package goAuth

import (
	"context"
	"errors"
	"time"

	"github.com/MrEthical07/goAuth/internal"
	"github.com/MrEthical07/goAuth/internal/limiters"
	"github.com/MrEthical07/goAuth/session"
)

// CreateAccount describes the createaccount operation and its observable behavior.
//
// CreateAccount may return an error when input validation, dependency calls, or security checks fail.
// CreateAccount does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) CreateAccount(ctx context.Context, req CreateAccountRequest) (*CreateAccountResult, error) {
	if !e.config.Account.Enabled {
		e.emitAudit(ctx, auditEventAccountCreationFailure, false, "", tenantIDFromContext(ctx), "", ErrAccountCreationDisabled, func() map[string]string {
			return map[string]string{
				"reason": "feature_disabled",
			}
		})
		return nil, ErrAccountCreationDisabled
	}
	if e.passwordHash == nil || e.userProvider == nil || e.accountLimiter == nil {
		return nil, ErrEngineNotReady
	}
	if e.config.Account.AutoLogin && e.config.JWT.RefreshTTL <= 0 {
		return nil, ErrAccountCreationUnavailable
	}

	tenantID := tenantIDFromContext(ctx)
	if e.config.MultiTenant.Enabled {
		explicitTenantID, ok := tenantIDFromContextExplicit(ctx)
		if !ok {
			return nil, ErrAccountCreationInvalid
		}
		tenantID = explicitTenantID
	}

	if req.Identifier == "" {
		e.emitAudit(ctx, auditEventAccountCreationFailure, false, "", tenantID, "", ErrAccountCreationInvalid, func() map[string]string {
			return map[string]string{
				"reason": "empty_identifier",
			}
		})
		return nil, ErrAccountCreationInvalid
	}
	if req.Password == "" {
		e.emitAudit(ctx, auditEventAccountCreationFailure, false, "", tenantID, "", ErrPasswordPolicy, func() map[string]string {
			return map[string]string{
				"identifier": req.Identifier,
				"reason":     "empty_password",
			}
		})
		return nil, ErrPasswordPolicy
	}

	role := req.Role
	if role == "" {
		role = e.config.Account.DefaultRole
	}
	if role == "" {
		e.emitAudit(ctx, auditEventAccountCreationFailure, false, "", tenantID, "", ErrAccountRoleInvalid, func() map[string]string {
			return map[string]string{
				"identifier": req.Identifier,
				"reason":     "role_missing",
			}
		})
		return nil, ErrAccountRoleInvalid
	}
	if _, ok := e.roleManager.GetMask(role); !ok {
		e.emitAudit(ctx, auditEventAccountCreationFailure, false, "", tenantID, "", ErrAccountRoleInvalid, func() map[string]string {
			return map[string]string{
				"identifier": req.Identifier,
				"reason":     "role_invalid",
			}
		})
		return nil, ErrAccountRoleInvalid
	}

	if err := e.accountLimiter.Enforce(ctx, tenantID, req.Identifier, clientIPFromContext(ctx)); err != nil {
		mapped := mapAccountLimiterError(err)
		if errors.Is(mapped, ErrAccountCreationRateLimited) {
			e.metricInc(MetricAccountCreationRateLimited)
			e.emitAudit(ctx, auditEventAccountCreationRateLimited, false, "", tenantID, "", mapped, func() map[string]string {
				return map[string]string{
					"identifier": req.Identifier,
				}
			})
			e.emitRateLimit(ctx, "account_creation", tenantID, func() map[string]string {
				return map[string]string{
					"identifier": req.Identifier,
				}
			})
		}
		return nil, mapped
	}

	initialStatus := AccountActive
	if e.config.EmailVerification.Enabled {
		initialStatus = AccountPendingVerification
	}

	passwordHash, err := e.passwordHash.Hash(req.Password)
	if err != nil {
		e.emitAudit(ctx, auditEventAccountCreationFailure, false, "", tenantID, "", ErrPasswordPolicy, func() map[string]string {
			return map[string]string{
				"identifier": req.Identifier,
				"reason":     "hash_policy",
			}
		})
		return nil, ErrPasswordPolicy
	}

	created, err := e.userProvider.CreateUser(ctx, CreateUserInput{
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
		if errors.Is(err, ErrProviderDuplicateIdentifier) {
			e.metricInc(MetricAccountCreationDuplicate)
			e.emitAudit(ctx, auditEventAccountCreationDuplicate, false, "", tenantID, "", ErrAccountExists, func() map[string]string {
				return map[string]string{
					"identifier": req.Identifier,
				}
			})
			return nil, ErrAccountExists
		}
		e.emitAudit(ctx, auditEventAccountCreationFailure, false, "", tenantID, "", err, func() map[string]string {
			return map[string]string{
				"identifier": req.Identifier,
				"reason":     "provider_create_failed",
			}
		})
		return nil, err
	}

	if created.UserID == "" {
		e.emitAudit(ctx, auditEventAccountCreationFailure, false, "", tenantID, "", ErrAccountCreationUnavailable, func() map[string]string {
			return map[string]string{
				"identifier": req.Identifier,
				"reason":     "missing_user_id",
			}
		})
		return nil, ErrAccountCreationUnavailable
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

	result := &CreateAccountResult{
		UserID: created.UserID,
		Role:   created.Role,
	}

	if e.config.Account.AutoLogin {
		if !(e.shouldRequireVerified() && created.Status == AccountPendingVerification) {
			accessToken, refreshToken, err := e.issueSessionTokens(ctx, created)
			if err != nil {
				e.emitAudit(ctx, auditEventAccountCreationSuccess, false, created.UserID, created.TenantID, "", ErrSessionCreationFailed, func() map[string]string {
					return map[string]string{
						"identifier": req.Identifier,
						"reason":     "auto_login_failed",
					}
				})
				return result, errors.Join(ErrSessionCreationFailed, err)
			}
			result.AccessToken = accessToken
			result.RefreshToken = refreshToken
		}
	}

	req.Password = ""
	e.metricInc(MetricAccountCreationSuccess)
	e.emitAudit(ctx, auditEventAccountCreationSuccess, true, created.UserID, created.TenantID, "", nil, func() map[string]string {
		return map[string]string{
			"identifier": req.Identifier,
			"role":       created.Role,
		}
	})
	return result, nil
}

func (e *Engine) issueSessionTokens(ctx context.Context, user UserRecord) (string, string, error) {
	mask, ok := e.roleManager.GetMask(user.Role)
	if !ok {
		return "", "", ErrAccountRoleInvalid
	}

	sid, err := internal.NewSessionID()
	if err != nil {
		return "", "", err
	}
	sessionID := sid.String()

	refreshSecret, err := internal.NewRefreshSecret()
	if err != nil {
		return "", "", err
	}

	tenantID := user.TenantID
	if tenantID == "" {
		tenantID = tenantIDFromContext(ctx)
	}

	now := time.Now()
	sessionLifetime := e.sessionLifetime()
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
		Status:            uint8(user.Status),
		RefreshHash:       internal.HashRefreshSecret(refreshSecret),
		CreatedAt:         now.Unix(),
		ExpiresAt:         now.Add(sessionLifetime).Unix(),
	}

	if err := e.sessionStore.Save(ctx, sess, sessionLifetime); err != nil {
		return "", "", err
	}
	e.metricInc(MetricSessionCreated)

	accessToken, err := e.issueAccessToken(sess)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := internal.EncodeRefreshToken(sessionID, refreshSecret)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func mapAccountLimiterError(err error) error {
	switch {
	case errors.Is(err, limiters.ErrAccountRateLimited):
		return ErrAccountCreationRateLimited
	case errors.Is(err, limiters.ErrAccountRedisUnavailable):
		return ErrAccountCreationUnavailable
	default:
		return ErrAccountCreationUnavailable
	}
}
