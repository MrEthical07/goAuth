package goAuth

import (
	"context"
	"io"
	"time"

	internalaudit "github.com/MrEthical07/goAuth/internal/audit"
	internalmetrics "github.com/MrEthical07/goAuth/internal/metrics"
)

// AccountStatus represents the lifecycle state of a user account.
//
//	Docs: docs/functionality-account-status.md
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

// PermissionMask is the interface satisfied by all bitmask widths
// ([permission.Mask64], [permission.Mask128], [permission.Mask256],
// [permission.Mask512]).
//
//	Docs: docs/permission.md
type PermissionMask interface {
	Has(bit int) bool
	Set(bit int)
	Raw() any
}

// User is a minimal user representation used by the legacy [UserStore]
// interface. Prefer [UserRecord] for new integrations.
type User struct {
	ID             string
	TenantID       string
	PasswordHash   string
	PermissionMask PermissionMask
	Role           string
	PermVersion    uint32
	RoleVersion    uint32
}

// AuthResult is returned by [Engine.Validate] and [Engine.ValidateAccess].
// It contains the authenticated user’s ID, tenant, role, decoded permission
// mask, and optionally the permission name list.
//
//	Docs: docs/jwt.md, docs/permission.md
type AuthResult struct {
	UserID   string
	TenantID string

	Role string

	Mask interface{}

	Permissions []string
}

// UserStore is a legacy credential-lookup interface. Prefer [UserProvider]
// for full account lifecycle support.
type UserStore interface {
	GetByIdentifier(ctx context.Context, identifier string) (*User, error)
	UpdatePermissionMask(ctx context.Context, userID string, mask PermissionMask) error
}

// RoleStore is a legacy role-lookup interface.
type RoleStore interface {
	GetRoleMask(ctx context.Context, tenantID, role string) (PermissionMask, uint32, error)
}

// KeyBuilder defines the Redis key layout for sessions and version counters.
type KeyBuilder interface {
	SessionKey(tenantID, sessionID string) string
	UserVersionKey(tenantID, userID string) string
	RoleVersionKey(tenantID, role string) string
}

// UserProvider is the primary interface that callers must implement to
// integrate goAuth with their user database. It covers credential lookup,
// account creation, password updates, TOTP secret management, and backup
// code storage.
//
//	Docs: docs/engine.md, docs/usage.md
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

// UserRecord is the full account record returned by [UserProvider].
// It carries credential hashes, status, role, and versioning counters.
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

// TOTPProvision holds the raw TOTP secret and otpauth:// URI returned by
// [Engine.ProvisionTOTP].
type TOTPProvision struct {
	Secret string
	URI    string
}

// TOTPSetup holds the base32-encoded TOTP secret and QR code URL returned
// by [Engine.GenerateTOTPSetup].
type TOTPSetup struct {
	SecretBase32 string
	QRCodeURL    string
}

// TOTPRecord is retrieved from [UserProvider.GetTOTPSecret]. It carries
// the encrypted secret, enabled/verified flags, and the last-used HOTP
// counter for replay protection.
type TOTPRecord struct {
	Secret          []byte
	Enabled         bool
	Verified        bool
	LastUsedCounter int64
}

// LoginResult is returned by [Engine.LoginWithResult] and
// [Engine.ConfirmLoginMFA]. It includes tokens when authentication
// succeeds, or MFA metadata when a second factor is required.
type LoginResult struct {
	AccessToken  string
	RefreshToken string

	MFARequired bool
	MFAType     string
	MFASession  string
}

// BackupCodeRecord stores the SHA-256 hash of a single backup code.
// The plaintext is never persisted.
type BackupCodeRecord struct {
	Hash [32]byte
}

// CreateUserInput is the input for [UserProvider.CreateUser].
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

// CreateAccountRequest is the input for [Engine.CreateAccount].
// Identifier and Password are required; Role defaults to
// [Config.Account.DefaultRole] when empty.
type CreateAccountRequest struct {
	Identifier string
	Password   string
	Role       string
}

// CreateAccountResult is returned by [Engine.CreateAccount]. It includes
// the new UserID and, when AutoLogin is enabled, access+refresh tokens.
type CreateAccountResult struct {
	UserID       string
	Role         string
	AccessToken  string
	RefreshToken string
}

// SecurityReport is a read-only snapshot of the engine’s security posture,
// returned by [Engine.SecurityReport].
//
//	Docs: docs/security.md
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

// PasswordConfigReport contains the Argon2 parameters active in the engine.
type PasswordConfigReport struct {
	Memory      uint32
	Time        uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// AuditEvent is a structured audit record emitted by the engine.
//
//	Docs: docs/audit.md
type AuditEvent = internalaudit.Event

// AuditSink receives [AuditEvent] values from the engine’s audit dispatcher.
//
//	Docs: docs/audit.md
type AuditSink = internalaudit.Sink

// NoOpSink is an [AuditSink] that silently discards all events.
type NoOpSink = internalaudit.NoOpSink

// ChannelSink is a buffered channel-based [AuditSink].
//
//	Docs: docs/audit.md
type ChannelSink = internalaudit.ChannelSink

// JSONWriterSink is an [AuditSink] that writes JSON-encoded events to an
// [io.Writer].
//
//	Docs: docs/audit.md
type JSONWriterSink = internalaudit.JSONWriterSink

// NewChannelSink creates a [ChannelSink] with the given buffer capacity.
//
//	Docs: docs/audit.md
func NewChannelSink(buffer int) *ChannelSink {
	return internalaudit.NewChannelSink(buffer)
}

// NewJSONWriterSink creates a [JSONWriterSink] that writes to w.
//
//	Docs: docs/audit.md
func NewJSONWriterSink(w io.Writer) *JSONWriterSink {
	return internalaudit.NewJSONWriterSink(w)
}

// MetricID identifies a specific counter or histogram bucket in the
// in-process metrics system.
//
//	Docs: docs/metrics.md
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

// Metrics holds atomic counters and optional latency histograms.
//
//	Docs: docs/metrics.md
type Metrics = internalmetrics.Metrics

// MetricsSnapshot is a point-in-time deep copy of all metrics.
//
//	Docs: docs/metrics.md
type MetricsSnapshot = internalmetrics.Snapshot

// NewMetrics creates a new [Metrics] instance configured by the given
// [MetricsConfig]. When Enabled is false, all operations are no-ops.
//
//	Docs: docs/metrics.md
func NewMetrics(cfg MetricsConfig) *Metrics {
	return internalmetrics.New(internalmetrics.Config{
		Enabled:       cfg.Enabled,
		EnableLatency: cfg.EnableLatencyHistograms,
	})
}
