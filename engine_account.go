package goAuth

import (
	"context"
	"errors"
	"time"

	"github.com/MrEthical07/goAuth/internal"
	internalflows "github.com/MrEthical07/goAuth/internal/flows"
	"github.com/MrEthical07/goAuth/internal/limiters"
)

// CreateAccount describes the createaccount operation and its observable behavior.
//
// CreateAccount may return an error when input validation, dependency calls, or security checks fail.
// CreateAccount does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (e *Engine) CreateAccount(ctx context.Context, req CreateAccountRequest) (*CreateAccountResult, error) {
	result, err := internalflows.RunCreateAccount(ctx, toFlowAccountCreateRequest(req), e.accountFlowDeps())
	out := fromFlowAccountCreateResult(result)
	if err != nil {
		return out, err
	}
	return out, nil
}

func (e *Engine) issueSessionTokens(ctx context.Context, user UserRecord) (string, string, error) {
	return internalflows.RunIssueAccountSessionTokens(ctx, toFlowAccountUser(user), e.accountSessionDeps())
}

func (e *Engine) accountFlowDeps() internalflows.AccountDeps {
	var cfg Config
	if e != nil {
		cfg = e.config
	}

	deps := internalflows.AccountDeps{
		Enabled:                     cfg.Account.Enabled,
		AutoLogin:                   cfg.Account.AutoLogin,
		RefreshTTL:                  cfg.JWT.RefreshTTL,
		MultiTenantEnabled:          cfg.MultiTenant.Enabled,
		DefaultRole:                 cfg.Account.DefaultRole,
		EmailVerificationEnabled:    cfg.EmailVerification.Enabled,
		ShouldRequireVerified:       e != nil && e.shouldRequireVerified(),
		ActiveStatus:                uint8(AccountActive),
		PendingStatus:               uint8(AccountPendingVerification),
		TenantIDFromContext:         tenantIDFromContext,
		TenantIDFromContextExplicit: tenantIDFromContextExplicit,
		ClientIPFromContext:         clientIPFromContext,
		MapLimiterError:             mapAccountLimiterError,
		MetricInc: func(id int) {
			e.metricInc(MetricID(id))
		},
		EmitAudit:     e.emitAudit,
		EmitRateLimit: e.emitRateLimit,
		Metrics: internalflows.AccountMetrics{
			AccountCreationSuccess:     int(MetricAccountCreationSuccess),
			AccountCreationDuplicate:   int(MetricAccountCreationDuplicate),
			AccountCreationRateLimited: int(MetricAccountCreationRateLimited),
		},
		Events: internalflows.AccountEvents{
			AccountCreationSuccess:     auditEventAccountCreationSuccess,
			AccountCreationFailure:     auditEventAccountCreationFailure,
			AccountCreationDuplicate:   auditEventAccountCreationDuplicate,
			AccountCreationRateLimited: auditEventAccountCreationRateLimited,
		},
		Errors: internalflows.AccountErrors{
			EngineNotReady:              ErrEngineNotReady,
			AccountCreationDisabled:     ErrAccountCreationDisabled,
			AccountCreationUnavailable:  ErrAccountCreationUnavailable,
			AccountCreationInvalid:      ErrAccountCreationInvalid,
			AccountRoleInvalid:          ErrAccountRoleInvalid,
			AccountCreationRateLimited:  ErrAccountCreationRateLimited,
			PasswordPolicy:              ErrPasswordPolicy,
			AccountExists:               ErrAccountExists,
			ProviderDuplicateIdentifier: ErrProviderDuplicateIdentifier,
			SessionCreationFailed:       ErrSessionCreationFailed,
		},
	}

	if e != nil && e.accountLimiter != nil {
		deps.EnforceAccountLimiter = e.accountLimiter.Enforce
	}
	if e != nil && e.roleManager != nil {
		deps.RoleExists = func(role string) bool {
			_, ok := e.roleManager.GetMask(role)
			return ok
		}
	}
	if e != nil && e.passwordHash != nil {
		deps.HashPassword = e.passwordHash.Hash
	}
	if e != nil && e.userProvider != nil {
		deps.CreateUser = func(ctx context.Context, input internalflows.AccountCreateUserInput) (internalflows.AccountUserRecord, error) {
			record, err := e.userProvider.CreateUser(ctx, CreateUserInput{
				Identifier:        input.Identifier,
				PasswordHash:      input.PasswordHash,
				Role:              input.Role,
				TenantID:          input.TenantID,
				Status:            AccountStatus(input.Status),
				PermissionVersion: input.PermissionVersion,
				RoleVersion:       input.RoleVersion,
				AccountVersion:    input.AccountVersion,
			})
			if err != nil {
				return internalflows.AccountUserRecord{}, err
			}
			return toFlowAccountUser(record), nil
		}
	}
	if e != nil {
		deps.IssueSessionTokens = func(ctx context.Context, user internalflows.AccountUserRecord) (string, string, error) {
			return e.issueSessionTokens(ctx, fromFlowAccountUser(user))
		}
	}

	return deps
}

func (e *Engine) accountSessionDeps() internalflows.AccountSessionDeps {
	deps := internalflows.AccountSessionDeps{
		TenantIDFromContext: tenantIDFromContext,
		Now:                 time.Now,
		NewSessionID: func() (string, error) {
			sid, err := internal.NewSessionID()
			if err != nil {
				return "", err
			}
			return sid.String(), nil
		},
		NewRefreshSecret:   internal.NewRefreshSecret,
		HashRefreshSecret:  internal.HashRefreshSecret,
		EncodeRefreshToken: internal.EncodeRefreshToken,
		MetricInc: func(id int) {
			e.metricInc(MetricID(id))
		},
		SessionCreatedMetric:  int(MetricSessionCreated),
		ErrEngineNotReady:     ErrEngineNotReady,
		ErrAccountRoleInvalid: ErrAccountRoleInvalid,
	}

	if e != nil && e.roleManager != nil {
		deps.GetRoleMask = e.roleManager.GetMask
	}
	if e != nil {
		deps.SessionLifetime = e.sessionLifetime
		deps.IssueAccessToken = e.issueAccessToken
	}
	if e != nil && e.sessionStore != nil {
		deps.SaveSession = e.sessionStore.Save
	}

	return deps
}

func toFlowAccountCreateRequest(req CreateAccountRequest) internalflows.AccountCreateRequest {
	return internalflows.AccountCreateRequest{
		Identifier: req.Identifier,
		Password:   req.Password,
		Role:       req.Role,
	}
}

func fromFlowAccountCreateResult(result *internalflows.AccountCreateResult) *CreateAccountResult {
	if result == nil {
		return nil
	}
	return &CreateAccountResult{
		UserID:       result.UserID,
		Role:         result.Role,
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
	}
}

func toFlowAccountUser(user UserRecord) internalflows.AccountUserRecord {
	return internalflows.AccountUserRecord{
		UserID:            user.UserID,
		Identifier:        user.Identifier,
		TenantID:          user.TenantID,
		PasswordHash:      user.PasswordHash,
		Status:            uint8(user.Status),
		Role:              user.Role,
		PermissionVersion: user.PermissionVersion,
		RoleVersion:       user.RoleVersion,
		AccountVersion:    user.AccountVersion,
	}
}

func fromFlowAccountUser(user internalflows.AccountUserRecord) UserRecord {
	return UserRecord{
		UserID:            user.UserID,
		Identifier:        user.Identifier,
		TenantID:          user.TenantID,
		PasswordHash:      user.PasswordHash,
		Status:            AccountStatus(user.Status),
		Role:              user.Role,
		PermissionVersion: user.PermissionVersion,
		RoleVersion:       user.RoleVersion,
		AccountVersion:    user.AccountVersion,
	}
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
