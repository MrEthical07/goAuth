// Package limiters provides domain-specific rate limiters built on top of the
// internal/rate primitives.
//
// # Limiters
//
//   - [AccountCreationLimiter] — per-identifier request limiter for sign-ups.
//   - [BackupCodeLimiter] — per-user failure throttle for backup code attempts.
//   - [EmailVerificationLimiter] — request limiter + confirm failure limiter.
//   - [TOTPLimiter] — hardcoded 5 attempts / 60 s per user.
//   - [PasswordResetLimiter] — request limiter + confirm failure limiter.
//
// All limiters are nil-safe: calling any method on a nil receiver returns nil.
//
// # Architecture boundaries
//
// Each limiter owns its own Redis key namespace and error types. Policy thresholds
// come from Config structs supplied at construction time.
//
// # What this package must NOT do
//
//   - Import goAuth or any sibling internal package except internal/rate.
//   - Make policy decisions beyond counting — flow functions decide consequences.
package limiters
