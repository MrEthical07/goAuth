package internal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// SessionID defines a public type used by goAuth APIs.
//
// SessionID instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type SessionID [16]byte

const (
	refreshTokenRawSize = 48
	refreshSecretSize   = 32
	resetTokenRawSize   = 48
	resetSecretSize     = 32
)

// NewSessionID describes the newsessionid operation and its observable behavior.
//
// NewSessionID may return an error when input validation, dependency calls, or security checks fail.
// NewSessionID does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func NewSessionID() (SessionID, error) {
	var sid SessionID
	_, err := rand.Read(sid[:])
	return sid, err
}

// Bytes describes the bytes operation and its observable behavior.
//
// Bytes may return an error when input validation, dependency calls, or security checks fail.
// Bytes does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (s SessionID) Bytes() []byte {
	return s[:]
}

// String describes the string operation and its observable behavior.
//
// String may return an error when input validation, dependency calls, or security checks fail.
// String does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (s SessionID) String() string {
	// base64url, no padding, compact
	return base64.RawURLEncoding.EncodeToString(s[:])
}

// ParseSessionID describes the parsesessionid operation and its observable behavior.
//
// ParseSessionID may return an error when input validation, dependency calls, or security checks fail.
// ParseSessionID does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func ParseSessionID(sessionID string) (SessionID, error) {
	var sid SessionID

	raw, err := base64.RawURLEncoding.DecodeString(sessionID)
	if err != nil {
		return sid, err
	}
	if len(raw) != len(sid) {
		return sid, errors.New("invalid session id size")
	}

	copy(sid[:], raw)
	return sid, nil
}

// NewRefreshSecret describes the newrefreshsecret operation and its observable behavior.
//
// NewRefreshSecret may return an error when input validation, dependency calls, or security checks fail.
// NewRefreshSecret does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func NewRefreshSecret() ([refreshSecretSize]byte, error) {
	var secret [refreshSecretSize]byte
	_, err := rand.Read(secret[:])
	return secret, err
}

// HashRefreshSecret describes the hashrefreshsecret operation and its observable behavior.
//
// HashRefreshSecret may return an error when input validation, dependency calls, or security checks fail.
// HashRefreshSecret does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func HashRefreshSecret(secret [refreshSecretSize]byte) [32]byte {
	return sha256.Sum256(secret[:])
}

// EncodeRefreshToken describes the encoderefreshtoken operation and its observable behavior.
//
// EncodeRefreshToken may return an error when input validation, dependency calls, or security checks fail.
// EncodeRefreshToken does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func EncodeRefreshToken(sessionID string, secret [refreshSecretSize]byte) (string, error) {
	sid, err := ParseSessionID(sessionID)
	if err != nil {
		return "", err
	}

	var raw [refreshTokenRawSize]byte
	copy(raw[:len(sid)], sid[:])
	copy(raw[len(sid):], secret[:])

	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// DecodeRefreshToken describes the decoderefreshtoken operation and its observable behavior.
//
// DecodeRefreshToken may return an error when input validation, dependency calls, or security checks fail.
// DecodeRefreshToken does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func DecodeRefreshToken(token string) (string, [refreshSecretSize]byte, error) {
	var secret [refreshSecretSize]byte

	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", secret, err
	}
	if len(raw) != refreshTokenRawSize {
		return "", secret, errors.New("invalid refresh token size")
	}

	var sid SessionID
	copy(sid[:], raw[:len(sid)])
	copy(secret[:], raw[len(sid):])

	return sid.String(), secret, nil
}

// NewResetSecret describes the newresetsecret operation and its observable behavior.
//
// NewResetSecret may return an error when input validation, dependency calls, or security checks fail.
// NewResetSecret does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func NewResetSecret() ([resetSecretSize]byte, error) {
	var secret [resetSecretSize]byte
	_, err := rand.Read(secret[:])
	return secret, err
}

// HashResetSecret describes the hashresetsecret operation and its observable behavior.
//
// HashResetSecret may return an error when input validation, dependency calls, or security checks fail.
// HashResetSecret does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func HashResetSecret(secret [resetSecretSize]byte) [32]byte {
	return sha256.Sum256(secret[:])
}

// HashResetBytes describes the hashresetbytes operation and its observable behavior.
//
// HashResetBytes may return an error when input validation, dependency calls, or security checks fail.
// HashResetBytes does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func HashResetBytes(secret []byte) [32]byte {
	return sha256.Sum256(secret)
}

// EncodeResetToken describes the encoderesettoken operation and its observable behavior.
//
// EncodeResetToken may return an error when input validation, dependency calls, or security checks fail.
// EncodeResetToken does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func EncodeResetToken(resetID string, secret [resetSecretSize]byte) (string, error) {
	rid, err := ParseSessionID(resetID)
	if err != nil {
		return "", err
	}

	var raw [resetTokenRawSize]byte
	copy(raw[:len(rid)], rid[:])
	copy(raw[len(rid):], secret[:])

	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// DecodeResetToken describes the decoderesettoken operation and its observable behavior.
//
// DecodeResetToken may return an error when input validation, dependency calls, or security checks fail.
// DecodeResetToken does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func DecodeResetToken(token string) (string, [resetSecretSize]byte, error) {
	var secret [resetSecretSize]byte

	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", secret, err
	}
	if len(raw) != resetTokenRawSize {
		return "", secret, errors.New("invalid reset token size")
	}

	var rid SessionID
	copy(rid[:], raw[:len(rid)])
	copy(secret[:], raw[len(rid):])

	return rid.String(), secret, nil
}

// NewOTP describes the newotp operation and its observable behavior.
//
// NewOTP may return an error when input validation, dependency calls, or security checks fail.
// NewOTP does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func NewOTP(digits int) (string, error) {
	if digits < 6 || digits > 10 {
		return "", errors.New("invalid otp digits")
	}

	var b strings.Builder
	b.Grow(digits)

	max := big.NewInt(10)
	for i := 0; i < digits; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b.WriteByte(byte('0' + n.Int64()))
	}

	otp := b.String()
	if len(otp) != digits {
		return "", fmt.Errorf("invalid otp generation length")
	}
	return otp, nil
}
