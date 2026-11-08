package goAuth

import "github.com/MrEthical07/goAuth/internal"

// sessionIDTextLen is the length of a session-ID-shaped record ID.
const sessionIDTextLen = 22

// validVerificationIDText reports whether id has the shape the verification
// (and email-change) generator gives the record ID of strategy: a UUID for the
// UUID strategy, a session ID for the token and OTP strategies. The rules live
// in internal/challenge_shape.go; this only picks one per strategy.
func validVerificationIDText(strategy VerificationStrategyType, id string) bool {
	switch strategy {
	case VerificationUUID:
		return internal.ValidUUIDText(id)
	case VerificationToken, VerificationOTP:
		return internal.ValidSessionIDText(id)
	default:
		return false
	}
}

// validResetChallengeText reports whether challenge has the length and
// alphabet the password-reset generator emits for strategy. A strategy this
// does not know passes, and the parser's own default rejects it.
func validResetChallengeText(strategy ResetStrategyType, challenge string, otpDigits int) bool {
	switch strategy {
	case ResetToken:
		return internal.ValidResetTokenText(challenge)
	case ResetUUID:
		return internal.ValidUUIDCode(challenge)
	case ResetOTP:
		// "<22-character reset ID>.<digits>"
		return len(challenge) == sessionIDTextLen+1+otpDigits &&
			challenge[sessionIDTextLen] == '.' &&
			internal.ValidSessionIDText(challenge[:sessionIDTextLen])
	default:
		return true
	}
}
