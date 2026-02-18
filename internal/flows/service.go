package flows

import (
	"context"
	"time"

	"github.com/MrEthical07/goAuth/session"
)

// Service is the centralized flow runner built once by the root engine.
type Service struct {
	deps Deps
}

// New returns a flow service with immutable dependency wiring.
func New(deps Deps) Service {
	return Service{deps: deps}
}

// Initialized reports whether the service has been wired with flow deps.
func (s Service) Initialized() bool {
	return s.deps.Validate.ParseAccess != nil
}

func (s Service) Refresh(ctx context.Context, refreshToken string) RefreshResult {
	return RunRefresh(ctx, refreshToken, s.deps.Refresh)
}

func (s Service) Validate(ctx context.Context, tokenStr string, routeMode int) ValidateResult {
	return RunValidate(ctx, tokenStr, routeMode, s.deps.Validate)
}

func (s Service) LogoutInTenant(ctx context.Context, tenantID, sessionID string) error {
	return RunLogoutInTenant(ctx, tenantID, sessionID, s.deps.Logout)
}

func (s Service) LogoutAllInTenant(ctx context.Context, tenantID, userID string) error {
	return RunLogoutAllInTenant(ctx, tenantID, userID, s.deps.Logout)
}

func (s Service) LogoutByAccessToken(ctx context.Context, tokenStr string) LogoutByAccessResult {
	return RunLogoutByAccessToken(ctx, tokenStr, s.deps.Logout)
}

func (s Service) CreateAccount(ctx context.Context, req AccountCreateRequest) (*AccountCreateResult, error) {
	return RunCreateAccount(ctx, req, s.deps.Account)
}

func (s Service) IssueAccountSessionTokens(ctx context.Context, user AccountUserRecord) (string, string, error) {
	return RunIssueAccountSessionTokens(ctx, user, s.deps.AccountSession)
}

func (s Service) UpdateAccountStatusAndInvalidate(ctx context.Context, userID string, status uint8) error {
	return RunUpdateAccountStatusAndInvalidate(ctx, userID, status, s.deps.AccountStatus)
}

func (s Service) GenerateBackupCodes(ctx context.Context, userID string) ([]string, error) {
	return RunGenerateBackupCodes(ctx, userID, s.deps.BackupCode)
}

func (s Service) RegenerateBackupCodes(ctx context.Context, userID, totpCode string) ([]string, error) {
	return RunRegenerateBackupCodes(ctx, userID, totpCode, s.deps.BackupCode)
}

func (s Service) VerifyBackupCode(ctx context.Context, userID, code string) error {
	return RunVerifyBackupCode(ctx, userID, code, s.deps.BackupCode)
}

func (s Service) VerifyBackupCodeInTenant(ctx context.Context, tenantID, userID, code string) error {
	return RunVerifyBackupCodeInTenant(ctx, tenantID, userID, code, s.deps.BackupCode)
}

func (s Service) ValidateDeviceBinding(ctx context.Context, sess DeviceBindingSession) error {
	return RunValidateDeviceBinding(ctx, sess, s.deps.DeviceBinding)
}

func (s Service) RequestEmailVerification(ctx context.Context, identifier string) (string, error) {
	return RunRequestEmailVerification(ctx, identifier, s.deps.EmailVerification)
}

func (s Service) ConfirmEmailVerification(ctx context.Context, challenge string) error {
	return RunConfirmEmailVerification(ctx, challenge, s.deps.EmailVerification)
}

func (s Service) GetActiveSessionCount(ctx context.Context, userID string) (int, error) {
	return RunGetActiveSessionCount(ctx, userID, s.deps.Introspection)
}

func (s Service) ListActiveSessions(ctx context.Context, userID string) ([]*session.Session, error) {
	return RunListActiveSessions(ctx, userID, s.deps.Introspection)
}

func (s Service) GetSessionInfo(ctx context.Context, tenantID, sessionID string) (*session.Session, error) {
	return RunGetSessionInfo(ctx, tenantID, sessionID, s.deps.Introspection)
}

func (s Service) ActiveSessionEstimate(ctx context.Context) (int, error) {
	return RunActiveSessionEstimate(ctx, s.deps.Introspection)
}

func (s Service) Health(ctx context.Context) (bool, time.Duration) {
	return RunHealth(ctx, s.deps.Introspection)
}

func (s Service) GetLoginAttempts(ctx context.Context, identifier string) (int, error) {
	return RunGetLoginAttempts(ctx, identifier, s.deps.Introspection)
}

func (s Service) LoginWithResult(ctx context.Context, username, password string) (*LoginResult, error) {
	return RunLoginWithResult(ctx, username, password, s.deps.Login)
}

func (s Service) ConfirmLoginMFAWithType(ctx context.Context, challengeID, code, mfaType string) (*LoginResult, error) {
	return RunConfirmLoginMFAWithType(ctx, challengeID, code, mfaType, s.deps.Login)
}

func (s Service) CreateMFALoginChallenge(ctx context.Context, userID, tenantID string) (string, error) {
	return RunCreateMFALoginChallenge(ctx, userID, tenantID, s.deps.Login)
}

func (s Service) IssueLoginSessionTokens(
	ctx context.Context,
	username string,
	user LoginUserRecord,
	tenantID string,
) (string, string, error) {
	return RunIssueLoginSessionTokens(ctx, username, user, tenantID, s.deps.Login)
}

func (s Service) RequestPasswordReset(ctx context.Context, identifier string) (string, error) {
	return RunRequestPasswordReset(ctx, identifier, s.deps.PasswordReset)
}

func (s Service) ConfirmPasswordResetWithMFA(ctx context.Context, challenge, newPassword, mfaType, mfaCode string) error {
	return RunConfirmPasswordResetWithMFA(ctx, challenge, newPassword, mfaType, mfaCode, s.deps.PasswordReset)
}

func (s Service) GenerateTOTPSetup(ctx context.Context, userID string) (*TOTPSetup, error) {
	return RunGenerateTOTPSetup(ctx, userID, s.deps.TOTP)
}

func (s Service) ProvisionTOTP(ctx context.Context, userID string) (*TOTPProvision, error) {
	return RunProvisionTOTP(ctx, userID, s.deps.TOTP)
}

func (s Service) ConfirmTOTPSetup(ctx context.Context, userID, code string) error {
	return RunConfirmTOTPSetup(ctx, userID, code, s.deps.TOTP)
}

func (s Service) VerifyTOTP(ctx context.Context, userID, code string) error {
	return RunVerifyTOTP(ctx, userID, code, s.deps.TOTP)
}

func (s Service) DisableTOTP(ctx context.Context, userID string) error {
	return RunDisableTOTP(ctx, userID, s.deps.TOTP)
}

func (s Service) VerifyTOTPForUser(ctx context.Context, user TOTPUser, code string) error {
	return RunVerifyTOTPForUser(ctx, user, code, s.deps.TOTP)
}
