package goAuth

import "context"

// AccountStatus defines a public type used by goAuth APIs.
//
// AccountStatus instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type AccountStatus uint8

const (
	// AccountActive is an exported constant or variable used by the authentication engine.
	AccountActive AccountStatus = iota
	// AccountPendingVerification is an exported constant or variable used by the authentication engine.
	AccountPendingVerification
	// AccountDisabled is an exported constant or variable used by the authentication engine.
	AccountDisabled
	// AccountLocked is an exported constant or variable used by the authentication engine.
	AccountLocked
	// AccountDeleted is an exported constant or variable used by the authentication engine.
	AccountDeleted

	// StatusPendingVerification is an exported constant or variable used by the authentication engine.
	StatusPendingVerification = AccountPendingVerification
)

// PermissionMask defines a public type used by goAuth APIs.
//
// PermissionMask instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type PermissionMask interface {
	Has(bit int) bool
	Set(bit int)
	Raw() any
}

// User defines a public type used by goAuth APIs.
//
// User instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type User struct {
	ID             string
	TenantID       string
	PasswordHash   string
	PermissionMask PermissionMask
	Role           string
	PermVersion    uint32
	RoleVersion    uint32
}

// AuthResult defines a public type used by goAuth APIs.
//
// AuthResult instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type AuthResult struct {
	UserID   string
	TenantID string

	Role string

	Mask interface{}

	Permissions []string
}

// UserStore defines a public type used by goAuth APIs.
//
// UserStore instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type UserStore interface {
	GetByIdentifier(ctx context.Context, identifier string) (*User, error)
	UpdatePermissionMask(ctx context.Context, userID string, mask PermissionMask) error
}

// RoleStore defines a public type used by goAuth APIs.
//
// RoleStore instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type RoleStore interface {
	GetRoleMask(ctx context.Context, tenantID, role string) (PermissionMask, uint32, error)
}

// KeyBuilder defines a public type used by goAuth APIs.
//
// KeyBuilder instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type KeyBuilder interface {
	SessionKey(tenantID, sessionID string) string
	UserVersionKey(tenantID, userID string) string
	RoleVersionKey(tenantID, role string) string
}

// UserProvider defines a public type used by goAuth APIs.
//
// UserProvider instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
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

// UserRecord defines a public type used by goAuth APIs.
//
// UserRecord instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
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

// TOTPProvision defines a public type used by goAuth APIs.
//
// TOTPProvision instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type TOTPProvision struct {
	Secret string
	URI    string
}

// TOTPSetup defines a public type used by goAuth APIs.
//
// TOTPSetup instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type TOTPSetup struct {
	SecretBase32 string
	QRCodeURL    string
}

// TOTPRecord defines a public type used by goAuth APIs.
//
// TOTPRecord instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type TOTPRecord struct {
	Secret          []byte
	Enabled         bool
	Verified        bool
	LastUsedCounter int64
}

// LoginResult defines a public type used by goAuth APIs.
//
// LoginResult instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type LoginResult struct {
	AccessToken  string
	RefreshToken string

	MFARequired bool
	MFAType     string
	MFASession  string
}

// BackupCodeRecord defines a public type used by goAuth APIs.
//
// BackupCodeRecord instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type BackupCodeRecord struct {
	Hash [32]byte
}

// CreateUserInput defines a public type used by goAuth APIs.
//
// CreateUserInput instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
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

// CreateAccountRequest defines a public type used by goAuth APIs.
//
// CreateAccountRequest instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type CreateAccountRequest struct {
	Identifier string
	Password   string
	Role       string
}

// CreateAccountResult defines a public type used by goAuth APIs.
//
// CreateAccountResult instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type CreateAccountResult struct {
	UserID       string
	Role         string
	AccessToken  string
	RefreshToken string
}
