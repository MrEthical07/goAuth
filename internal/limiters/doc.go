// Package limiters provides domain-specific rate limiters built on top of the
// internal/rate primitives.
//
// # Limiters
//
//   - [AccountCreationLimiter] — per-identifier + per-IP throttle for sign-ups.
//   - [BackupCodeLimiter] — per-user failure throttle for backup code attempts.
//   - [EmailVerificationLimiter] — per-identifier + per-IP for request and confirm.
//   - [TOTPLimiter] — hardcoded 5 attempts / 60 s per user.
//   - [PasswordResetLimiter] — per-identifier + per-IP for request and confirm.
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
