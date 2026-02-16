package goAuth

import (
	"context"
	"io"
	"time"

	internalaudit "github.com/MrEthical07/goAuth/internal/audit"
	internalmetrics "github.com/MrEthical07/goAuth/internal/metrics"
)

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

// SecurityReport defines a public type used by goAuth APIs.
type SecurityReport struct {
	ProductionMode               bool
	SigningAlgorithm             string
	ValidationMode               ValidationMode
	StrictMode                   bool
	AccessTTL                    time.Duration
	RefreshTTL                   time.Duration
	Argon2                       PasswordConfigReport
	TOTPEnabled                  bool
	BackupEnabled                bool
	DeviceBindingEnabled         bool
	RefreshRotationEnabled       bool
	RefreshReuseDetectionEnabled bool
	SessionCapsActive            bool
	RateLimitingActive           bool
	EmailVerificationActive      bool
	PasswordResetActive          bool
}

// PasswordConfigReport defines a public type used by goAuth APIs.
type PasswordConfigReport struct {
	Memory      uint32
	Time        uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// AuditEvent defines a public type used by goAuth APIs.
type AuditEvent = internalaudit.Event

// AuditSink defines a public type used by goAuth APIs.
type AuditSink = internalaudit.Sink

// NoOpSink defines a public type used by goAuth APIs.
type NoOpSink = internalaudit.NoOpSink

// ChannelSink defines a public type used by goAuth APIs.
type ChannelSink = internalaudit.ChannelSink

// JSONWriterSink defines a public type used by goAuth APIs.
type JSONWriterSink = internalaudit.JSONWriterSink

// NewChannelSink describes the newchannelsink operation and its observable behavior.
func NewChannelSink(buffer int) *ChannelSink {
	return internalaudit.NewChannelSink(buffer)
}

// NewJSONWriterSink describes the newjsonwritersink operation and its observable behavior.
func NewJSONWriterSink(w io.Writer) *JSONWriterSink {
	return internalaudit.NewJSONWriterSink(w)
}

// MetricID defines a public type used by goAuth APIs.
type MetricID = internalmetrics.MetricID

const (
	// MetricLoginSuccess is an exported constant or variable used by the authentication engine.
	MetricLoginSuccess = MetricID(internalmetrics.MetricLoginSuccess)
	// MetricLoginFailure is an exported constant or variable used by the authentication engine.
	MetricLoginFailure = MetricID(internalmetrics.MetricLoginFailure)
	// MetricLoginRateLimited is an exported constant or variable used by the authentication engine.
	MetricLoginRateLimited = MetricID(internalmetrics.MetricLoginRateLimited)
	// MetricRefreshSuccess is an exported constant or variable used by the authentication engine.
	MetricRefreshSuccess = MetricID(internalmetrics.MetricRefreshSuccess)
	// MetricRefreshFailure is an exported constant or variable used by the authentication engine.
	MetricRefreshFailure = MetricID(internalmetrics.MetricRefreshFailure)
	// MetricRefreshReuseDetected is an exported constant or variable used by the authentication engine.
	MetricRefreshReuseDetected = MetricID(internalmetrics.MetricRefreshReuseDetected)
	// MetricReplayDetected is an exported constant or variable used by the authentication engine.
	MetricReplayDetected = MetricID(internalmetrics.MetricReplayDetected)
	// MetricRefreshRateLimited is an exported constant or variable used by the authentication engine.
	MetricRefreshRateLimited = MetricID(internalmetrics.MetricRefreshRateLimited)
	// MetricDeviceIPMismatch is an exported constant or variable used by the authentication engine.
	MetricDeviceIPMismatch = MetricID(internalmetrics.MetricDeviceIPMismatch)
	// MetricDeviceUAMismatch is an exported constant or variable used by the authentication engine.
	MetricDeviceUAMismatch = MetricID(internalmetrics.MetricDeviceUAMismatch)
	// MetricDeviceRejected is an exported constant or variable used by the authentication engine.
	MetricDeviceRejected = MetricID(internalmetrics.MetricDeviceRejected)
	// MetricTOTPRequired is an exported constant or variable used by the authentication engine.
	MetricTOTPRequired = MetricID(internalmetrics.MetricTOTPRequired)
	// MetricTOTPFailure is an exported constant or variable used by the authentication engine.
	MetricTOTPFailure = MetricID(internalmetrics.MetricTOTPFailure)
	// MetricTOTPSuccess is an exported constant or variable used by the authentication engine.
	MetricTOTPSuccess = MetricID(internalmetrics.MetricTOTPSuccess)
	// MetricMFALoginRequired is an exported constant or variable used by the authentication engine.
	MetricMFALoginRequired = MetricID(internalmetrics.MetricMFALoginRequired)
	// MetricMFALoginSuccess is an exported constant or variable used by the authentication engine.
	MetricMFALoginSuccess = MetricID(internalmetrics.MetricMFALoginSuccess)
	// MetricMFALoginFailure is an exported constant or variable used by the authentication engine.
	MetricMFALoginFailure = MetricID(internalmetrics.MetricMFALoginFailure)
	// MetricMFAReplayAttempt is an exported constant or variable used by the authentication engine.
	MetricMFAReplayAttempt = MetricID(internalmetrics.MetricMFAReplayAttempt)
	// MetricBackupCodeUsed is an exported constant or variable used by the authentication engine.
	MetricBackupCodeUsed = MetricID(internalmetrics.MetricBackupCodeUsed)
	// MetricBackupCodeFailed is an exported constant or variable used by the authentication engine.
	MetricBackupCodeFailed = MetricID(internalmetrics.MetricBackupCodeFailed)
	// MetricBackupCodeRegenerated is an exported constant or variable used by the authentication engine.
	MetricBackupCodeRegenerated = MetricID(internalmetrics.MetricBackupCodeRegenerated)
	// MetricRateLimitHit is an exported constant or variable used by the authentication engine.
	MetricRateLimitHit = MetricID(internalmetrics.MetricRateLimitHit)
	// MetricSessionCreated is an exported constant or variable used by the authentication engine.
	MetricSessionCreated = MetricID(internalmetrics.MetricSessionCreated)
	// MetricSessionInvalidated is an exported constant or variable used by the authentication engine.
	MetricSessionInvalidated = MetricID(internalmetrics.MetricSessionInvalidated)
	// MetricLogout is an exported constant or variable used by the authentication engine.
	MetricLogout = MetricID(internalmetrics.MetricLogout)
	// MetricLogoutAll is an exported constant or variable used by the authentication engine.
	MetricLogoutAll = MetricID(internalmetrics.MetricLogoutAll)
	// MetricAccountCreationSuccess is an exported constant or variable used by the authentication engine.
	MetricAccountCreationSuccess = MetricID(internalmetrics.MetricAccountCreationSuccess)
	// MetricAccountCreationDuplicate is an exported constant or variable used by the authentication engine.
	MetricAccountCreationDuplicate = MetricID(internalmetrics.MetricAccountCreationDuplicate)
	// MetricAccountCreationRateLimited is an exported constant or variable used by the authentication engine.
	MetricAccountCreationRateLimited = MetricID(internalmetrics.MetricAccountCreationRateLimited)
	// MetricPasswordChangeSuccess is an exported constant or variable used by the authentication engine.
	MetricPasswordChangeSuccess = MetricID(internalmetrics.MetricPasswordChangeSuccess)
	// MetricPasswordChangeInvalidOld is an exported constant or variable used by the authentication engine.
	MetricPasswordChangeInvalidOld = MetricID(internalmetrics.MetricPasswordChangeInvalidOld)
	// MetricPasswordChangeReuseRejected is an exported constant or variable used by the authentication engine.
	MetricPasswordChangeReuseRejected = MetricID(internalmetrics.MetricPasswordChangeReuseRejected)
	// MetricPasswordResetRequest is an exported constant or variable used by the authentication engine.
	MetricPasswordResetRequest = MetricID(internalmetrics.MetricPasswordResetRequest)
	// MetricPasswordResetConfirmSuccess is an exported constant or variable used by the authentication engine.
	MetricPasswordResetConfirmSuccess = MetricID(internalmetrics.MetricPasswordResetConfirmSuccess)
	// MetricPasswordResetConfirmFailure is an exported constant or variable used by the authentication engine.
	MetricPasswordResetConfirmFailure = MetricID(internalmetrics.MetricPasswordResetConfirmFailure)
	// MetricPasswordResetAttemptsExceeded is an exported constant or variable used by the authentication engine.
	MetricPasswordResetAttemptsExceeded = MetricID(internalmetrics.MetricPasswordResetAttemptsExceeded)
	// MetricEmailVerificationRequest is an exported constant or variable used by the authentication engine.
	MetricEmailVerificationRequest = MetricID(internalmetrics.MetricEmailVerificationRequest)
	// MetricEmailVerificationSuccess is an exported constant or variable used by the authentication engine.
	MetricEmailVerificationSuccess = MetricID(internalmetrics.MetricEmailVerificationSuccess)
	// MetricEmailVerificationFailure is an exported constant or variable used by the authentication engine.
	MetricEmailVerificationFailure = MetricID(internalmetrics.MetricEmailVerificationFailure)
	// MetricEmailVerificationAttemptsExceeded is an exported constant or variable used by the authentication engine.
	MetricEmailVerificationAttemptsExceeded = MetricID(internalmetrics.MetricEmailVerificationAttemptsExceeded)
	// MetricAccountDisabled is an exported constant or variable used by the authentication engine.
	MetricAccountDisabled = MetricID(internalmetrics.MetricAccountDisabled)
	// MetricAccountLocked is an exported constant or variable used by the authentication engine.
	MetricAccountLocked = MetricID(internalmetrics.MetricAccountLocked)
	// MetricAccountDeleted is an exported constant or variable used by the authentication engine.
	MetricAccountDeleted = MetricID(internalmetrics.MetricAccountDeleted)
	// MetricValidateLatency is an exported constant or variable used by the authentication engine.
	MetricValidateLatency = MetricID(internalmetrics.MetricValidateLatency)

	metricIDCount = internalmetrics.MetricIDCount
)

// Metrics defines a public type used by goAuth APIs.
type Metrics = internalmetrics.Metrics

// MetricsSnapshot defines a public type used by goAuth APIs.
type MetricsSnapshot = internalmetrics.Snapshot

// NewMetrics describes the newmetrics operation and its observable behavior.
func NewMetrics(cfg MetricsConfig) *Metrics {
	return internalmetrics.New(internalmetrics.Config{
		Enabled:       cfg.Enabled,
		EnableLatency: cfg.EnableLatencyHistograms,
	})
}
