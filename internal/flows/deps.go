package flows

// Deps groups flow dependency sets. Root engine builds this once and delegates
// request methods to the matching flow implementation.
type Deps struct {
	Refresh           RefreshDeps
	Validate          ValidateDeps
	Logout            LogoutDeps
	Introspection     IntrospectionDeps
	Account           AccountDeps
	AccountSession    AccountSessionDeps
	AccountStatus     UpdateAccountStatusDeps
	BackupCode        BackupCodeDeps
	DeviceBinding     DeviceBindingDeps
	EmailVerification EmailVerificationDeps
	Login             LoginDeps
	PasswordReset     PasswordResetDeps
	TOTP              TOTPDeps
}
