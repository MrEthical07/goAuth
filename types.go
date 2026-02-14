package goAuth

import "context"

type AccountStatus uint8

const (
	AccountActive AccountStatus = iota
	AccountPendingVerification
	AccountDisabled
	AccountLocked
	AccountDeleted

	StatusPendingVerification = AccountPendingVerification
)

type PermissionMask interface {
	Has(bit int) bool
	Set(bit int)
	Raw() any
}

type User struct {
	ID             string
	TenantID       string
	PasswordHash   string
	PermissionMask PermissionMask
	Role           string
	PermVersion    uint32
	RoleVersion    uint32
}

type AuthResult struct {
	UserID   string
	TenantID string

	Role string

	Mask interface{}

	Permissions []string
}

type UserStore interface {
	GetByIdentifier(ctx context.Context, identifier string) (*User, error)
	UpdatePermissionMask(ctx context.Context, userID string, mask PermissionMask) error
}

type RoleStore interface {
	GetRoleMask(ctx context.Context, tenantID, role string) (PermissionMask, uint32, error)
}

type KeyBuilder interface {
	SessionKey(tenantID, sessionID string) string
	UserVersionKey(tenantID, userID string) string
	RoleVersionKey(tenantID, role string) string
}

type UserProvider interface {
	GetUserByIdentifier(identifier string) (UserRecord, error)
	GetUserByID(userID string) (UserRecord, error)
	UpdatePasswordHash(userID string, newHash string) error
	CreateUser(ctx context.Context, input CreateUserInput) (UserRecord, error)
	UpdateAccountStatus(ctx context.Context, userID string, status AccountStatus) (UserRecord, error)
	GetTOTPSecret(ctx context.Context, userID string) (*TOTPRecord, error)
	EnableTOTP(ctx context.Context, userID string, secret []byte) error
	DisableTOTP(ctx context.Context, userID string) error
	MarkTOTPVerified(ctx context.Context, userID string) error
	UpdateTOTPLastUsedCounter(ctx context.Context, userID string, counter int64) error
	GetBackupCodes(ctx context.Context, userID string) ([]BackupCodeRecord, error)
	ReplaceBackupCodes(ctx context.Context, userID string, codes []BackupCodeRecord) error
	ConsumeBackupCode(ctx context.Context, userID string, codeHash [32]byte) (bool, error)
}

type UserRecord struct {
	UserID            string
	Identifier        string
	TenantID          string
	PasswordHash      string
	TOTPEnabled       bool
	Status            AccountStatus
	Role              string
	PermissionVersion uint32
	RoleVersion       uint32
	AccountVersion    uint32
}

type TOTPProvision struct {
	Secret string
	URI    string
}

type TOTPSetup struct {
	SecretBase32 string
	QRCodeURL    string
}

type TOTPRecord struct {
	Secret          []byte
	Enabled         bool
	Verified        bool
	LastUsedCounter int64
}

type LoginResult struct {
	AccessToken  string
	RefreshToken string

	MFARequired bool
	MFAType     string
	MFASession  string
}

type BackupCodeRecord struct {
	Hash [32]byte
}

type CreateUserInput struct {
	Identifier        string
	PasswordHash      string
	Role              string
	TenantID          string
	Status            AccountStatus
	PermissionVersion uint32
	RoleVersion       uint32
	AccountVersion    uint32
}

type CreateAccountRequest struct {
	Identifier string
	Password   string
	Role       string
}

type CreateAccountResult struct {
	UserID       string
	Role         string
	AccessToken  string
	RefreshToken string
}
