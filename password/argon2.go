package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	minMemoryKB    uint32 = 8 * 1024
	minTimeCost    uint32 = 1
	minParallelism uint8  = 1
	minSaltLength  uint32 = 16
	minKeyLength   uint32 = 16
	minPassBytes          = 10
	algorithmID           = "argon2id"
)

// Config defines a public type used by goAuth APIs.
//
// Config instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type Config struct {
	Memory      uint32
	Time        uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// Argon2 defines a public type used by goAuth APIs.
//
// Argon2 instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type Argon2 struct {
	config Config
}

type parsedPHC struct {
	memory      uint32
	time        uint32
	parallelism uint8
	salt        []byte
	hash        []byte
	keyLength   uint32
}

// NewArgon2 describes the newargon2 operation and its observable behavior.
//
// NewArgon2 may return an error when input validation, dependency calls, or security checks fail.
// NewArgon2 does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func NewArgon2(cfg Config) (*Argon2, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	return &Argon2{config: cfg}, nil
}

// Hash describes the hash operation and its observable behavior.
//
// Hash may return an error when input validation, dependency calls, or security checks fail.
// Hash does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (a *Argon2) Hash(password string) (string, error) {
	// Password processing uses raw string bytes exactly as provided (no Unicode normalization).
	if len(password) < minPassBytes {
		return "", errors.New("password must be at least 10 bytes")
	}

	salt := make([]byte, a.config.SaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		a.config.Time,
		a.config.Memory,
		a.config.Parallelism,
		a.config.KeyLength,
	)

	saltEncoded := base64.StdEncoding.EncodeToString(salt)
	hashEncoded := base64.StdEncoding.EncodeToString(hash)

	return fmt.Sprintf(
		"$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		algorithmID,
		argon2.Version,
		a.config.Memory,
		a.config.Time,
		a.config.Parallelism,
		saltEncoded,
		hashEncoded,
	), nil
}

// Verify describes the verify operation and its observable behavior.
//
// Verify may return an error when input validation, dependency calls, or security checks fail.
// Verify does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (a *Argon2) Verify(password string, encodedHash string) (bool, error) {
	parsed, err := parsePHC(encodedHash)
	if err != nil {
		return false, err
	}

	computed := argon2.IDKey(
		[]byte(password),
		parsed.salt,
		parsed.time,
		parsed.memory,
		parsed.parallelism,
		parsed.keyLength,
	)

	return subtle.ConstantTimeCompare(computed, parsed.hash) == 1, nil
}

// NeedsUpgrade describes the needsupgrade operation and its observable behavior.
//
// NeedsUpgrade may return an error when input validation, dependency calls, or security checks fail.
// NeedsUpgrade does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (a *Argon2) NeedsUpgrade(encodedHash string) (bool, error) {
	parsed, err := parsePHC(encodedHash)
	if err != nil {
		return false, err
	}

	if a.config.Memory > parsed.memory {
		return true, nil
	}
	if a.config.Time > parsed.time {
		return true, nil
	}
	if a.config.Parallelism > parsed.parallelism {
		return true, nil
	}
	if a.config.KeyLength != parsed.keyLength {
		return true, nil
	}

	return false, nil
}

func parsePHC(encodedHash string) (*parsedPHC, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" {
		return nil, errors.New("invalid PHC format")
	}

	if parts[1] != algorithmID {
		return nil, errors.New("unsupported algorithm")
	}

	versionPart := parts[2]
	if !strings.HasPrefix(versionPart, "v=") {
		return nil, errors.New("missing argon2 version")
	}

	version, err := strconv.Atoi(strings.TrimPrefix(versionPart, "v="))
	if err != nil {
		return nil, errors.New("invalid argon2 version")
	}
	if version != argon2.Version {
		return nil, errors.New("unsupported argon2 version")
	}

	params, err := parseParams(parts[3])
	if err != nil {
		return nil, err
	}

	salt, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, errors.New("invalid salt encoding")
	}
	if len(salt) < int(minSaltLength) {
		return nil, errors.New("invalid salt length")
	}

	hash, err := base64.StdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, errors.New("invalid hash encoding")
	}
	if len(hash) == 0 {
		return nil, errors.New("invalid hash length")
	}

	return &parsedPHC{
		memory:      params.memory,
		time:        params.time,
		parallelism: params.parallelism,
		salt:        salt,
		hash:        hash,
		keyLength:   uint32(len(hash)),
	}, nil
}

type parsedParams struct {
	memory      uint32
	time        uint32
	parallelism uint8
}

func parseParams(part string) (*parsedParams, error) {
	pairs := strings.Split(part, ",")
	if len(pairs) != 3 {
		return nil, errors.New("invalid parameter format")
	}

	var (
		memorySet, timeSet, parallelismSet bool
		params                             parsedParams
	)

	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return nil, errors.New("invalid parameter entry")
		}

		switch kv[0] {
		case "m":
			v, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil || v < uint64(minMemoryKB) {
				return nil, errors.New("invalid memory parameter")
			}
			params.memory = uint32(v)
			memorySet = true
		case "t":
			v, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil || v < uint64(minTimeCost) {
				return nil, errors.New("invalid time parameter")
			}
			params.time = uint32(v)
			timeSet = true
		case "p":
			v, err := strconv.ParseUint(kv[1], 10, 8)
			if err != nil || v < uint64(minParallelism) {
				return nil, errors.New("invalid parallelism parameter")
			}
			params.parallelism = uint8(v)
			parallelismSet = true
		default:
			return nil, errors.New("unsupported parameter")
		}
	}

	if !memorySet || !timeSet || !parallelismSet {
		return nil, errors.New("missing parameters")
	}

	return &params, nil
}

func validateConfig(cfg Config) error {
	if cfg.Memory < minMemoryKB {
		return errors.New("password memory must be >= 8192 KB")
	}
	if cfg.Time < minTimeCost {
		return errors.New("password time must be >= 1")
	}
	if cfg.Parallelism < minParallelism {
		return errors.New("password parallelism must be >= 1")
	}
	if cfg.SaltLength < minSaltLength {
		return errors.New("password salt length must be >= 16")
	}
	if cfg.KeyLength < minKeyLength {
		return errors.New("password key length must be >= 16")
	}

	return nil
}
