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

type SessionID [16]byte

const (
	refreshTokenRawSize = 48
	refreshSecretSize   = 32
	resetTokenRawSize   = 48
	resetSecretSize     = 32
)

func NewSessionID() (SessionID, error) {
	var sid SessionID
	_, err := rand.Read(sid[:])
	return sid, err
}

func (s SessionID) Bytes() []byte {
	return s[:]
}

func (s SessionID) String() string {
	// base64url, no padding, compact
	return base64.RawURLEncoding.EncodeToString(s[:])
}

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

func NewRefreshSecret() ([refreshSecretSize]byte, error) {
	var secret [refreshSecretSize]byte
	_, err := rand.Read(secret[:])
	return secret, err
}

func HashRefreshSecret(secret [refreshSecretSize]byte) [32]byte {
	return sha256.Sum256(secret[:])
}

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

func NewResetSecret() ([resetSecretSize]byte, error) {
	var secret [resetSecretSize]byte
	_, err := rand.Read(secret[:])
	return secret, err
}

func HashResetSecret(secret [resetSecretSize]byte) [32]byte {
	return sha256.Sum256(secret[:])
}

func HashResetBytes(secret []byte) [32]byte {
	return sha256.Sum256(secret)
}

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
