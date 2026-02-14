package goAuth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const totpSecretBytes = 20

type totpManager struct {
	config TOTPConfig
}

func newTOTPManager(cfg TOTPConfig) *totpManager {
	if cfg.Algorithm == "" {
		cfg.Algorithm = "SHA1"
	}
	return &totpManager{config: cfg}
}

func (m *totpManager) GenerateSecret() ([]byte, string, error) {
	if m == nil {
		return nil, "", ErrEngineNotReady
	}
	raw := make([]byte, totpSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", err
	}

	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return raw, enc.EncodeToString(raw), nil
}

func (m *totpManager) ProvisionURI(secretBase32, account string) string {
	issuer := m.config.Issuer
	label := url.PathEscape(issuer + ":" + account)

	v := url.Values{}
	v.Set("secret", secretBase32)
	v.Set("issuer", issuer)
	v.Set("period", strconv.Itoa(m.config.Period))
	v.Set("digits", strconv.Itoa(m.config.Digits))
	v.Set("algorithm", strings.ToUpper(m.config.Algorithm))

	return "otpauth://totp/" + label + "?" + v.Encode()
}

func (m *totpManager) VerifyCode(secret []byte, code string, now time.Time) (bool, int64, error) {
	if m == nil {
		return false, 0, ErrEngineNotReady
	}

	trimmed := strings.TrimSpace(code)
	if len(trimmed) != int(m.config.Digits) || !isNumericString(trimmed) {
		return false, 0, nil
	}

	if len(secret) == 0 {
		return false, 0, errors.New("empty totp secret")
	}

	baseCounter := now.Unix() / int64(m.config.Period)
	for step := -m.config.Skew; step <= m.config.Skew; step++ {
		counter := baseCounter + int64(step)
		if counter < 0 {
			continue
		}
		generated, err := hotpCode(secret, counter, m.config.Digits, m.config.Algorithm)
		if err != nil {
			return false, 0, err
		}
		if subtle.ConstantTimeCompare([]byte(generated), []byte(trimmed)) == 1 {
			return true, counter, nil
		}
	}

	return false, 0, nil
}

func hotpCode(secret []byte, counter int64, digits int, algorithm string) (string, error) {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))

	hf, err := hmacFunc(algorithm)
	if err != nil {
		return "", err
	}
	mac := hmac.New(hf, secret)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	bin := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)

	mod := 1
	for i := 0; i < digits; i++ {
		mod *= 10
	}

	code := bin % mod
	return fmt.Sprintf("%0*d", digits, code), nil
}

func hmacFunc(algorithm string) (func() hash.Hash, error) {
	switch strings.ToUpper(algorithm) {
	case "", "SHA1":
		return sha1.New, nil
	case "SHA256":
		return sha256.New, nil
	case "SHA512":
		return sha512.New, nil
	default:
		return nil, errors.New("unsupported totp algorithm")
	}
}
