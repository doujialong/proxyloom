package auth

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
	PasswordMemoryKiB   uint32 = 64 * 1024
	PasswordIterations  uint32 = 3
	PasswordParallelism uint8  = 1
	PasswordSaltBytes          = 16
	PasswordHashBytes   uint32 = 32
)

var ErrInvalidPasswordHash = errors.New("invalid Argon2id password hash")

type PasswordParams struct {
	MemoryKiB   uint32 `json:"memory_kib"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	SaltBytes   int    `json:"salt_bytes"`
	HashBytes   uint32 `json:"hash_bytes"`
}

func DefaultPasswordParams() PasswordParams {
	return PasswordParams{
		MemoryKiB: PasswordMemoryKiB, Iterations: PasswordIterations,
		Parallelism: PasswordParallelism, SaltBytes: PasswordSaltBytes,
		HashBytes: PasswordHashBytes,
	}
}

func HashPassword(password string, random io.Reader, params PasswordParams) (string, error) {
	if len(password) == 0 || len(password) > 1024 {
		return "", fmt.Errorf("administrator password must be non-empty and contain at most 1024 bytes")
	}
	if err := validatePasswordParams(params); err != nil {
		return "", err
	}
	if random == nil {
		random = rand.Reader
	}
	salt := make([]byte, params.SaltBytes)
	if _, err := io.ReadFull(random, salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	derived := argon2.IDKey([]byte(password), salt, params.Iterations, params.MemoryKiB, params.Parallelism, params.HashBytes)
	defer wipe(derived)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, params.MemoryKiB, params.Iterations, params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(derived)), nil
}

func VerifyPassword(encoded, password string) (bool, error) {
	params, salt, expected, err := parsePasswordHash(encoded)
	if err != nil {
		return false, err
	}
	defer wipe(expected)
	actual := argon2.IDKey([]byte(password), salt, params.Iterations, params.MemoryKiB, params.Parallelism, uint32(len(expected)))
	defer wipe(actual)
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func parsePasswordHash(encoded string) (PasswordParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return PasswordParams{}, nil, nil, ErrInvalidPasswordHash
	}
	var params PasswordParams
	values := strings.Split(parts[3], ",")
	if len(values) != 3 {
		return PasswordParams{}, nil, nil, ErrInvalidPasswordHash
	}
	memory, errMemory := parseUintParam(values[0], "m=", 32)
	iterations, errIterations := parseUintParam(values[1], "t=", 32)
	parallelism, errParallelism := parseUintParam(values[2], "p=", 8)
	if errMemory != nil || errIterations != nil || errParallelism != nil {
		return PasswordParams{}, nil, nil, ErrInvalidPasswordHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return PasswordParams{}, nil, nil, ErrInvalidPasswordHash
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return PasswordParams{}, nil, nil, ErrInvalidPasswordHash
	}
	params = PasswordParams{
		MemoryKiB: uint32(memory), Iterations: uint32(iterations), Parallelism: uint8(parallelism),
		SaltBytes: len(salt), HashBytes: uint32(len(hash)),
	}
	if err := validatePasswordParams(params); err != nil {
		wipe(hash)
		return PasswordParams{}, nil, nil, ErrInvalidPasswordHash
	}
	return params, salt, hash, nil
}

func parseUintParam(value, prefix string, bits int) (uint64, error) {
	if !strings.HasPrefix(value, prefix) {
		return 0, ErrInvalidPasswordHash
	}
	return strconv.ParseUint(strings.TrimPrefix(value, prefix), 10, bits)
}

func validatePasswordParams(params PasswordParams) error {
	if params.MemoryKiB < PasswordMemoryKiB || params.MemoryKiB > 1024*1024 ||
		params.Iterations < PasswordIterations || params.Iterations > 20 ||
		params.Parallelism < PasswordParallelism || params.Parallelism > 16 ||
		params.SaltBytes < PasswordSaltBytes || params.SaltBytes > 64 ||
		params.HashBytes < PasswordHashBytes || params.HashBytes > 64 {
		return fmt.Errorf("Argon2id parameters are outside the supported security bounds")
	}
	return nil
}
