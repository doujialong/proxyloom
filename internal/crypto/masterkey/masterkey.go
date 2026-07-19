package masterkey

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	FormatPrefix = "plmk1"
	KeyBytes     = 32
	MaxFileBytes = 256
	RuntimeUID   = 65532
	RuntimeGID   = 65532
)

var (
	ErrAlreadyExists = errors.New("master key file already exists")
	ErrSymlink       = errors.New("master key path contains a symbolic link")
	ErrPermissions   = errors.New("master key file permissions must be 0600")
	ErrOwner         = errors.New("master key file owner is invalid")
	ErrFormat        = errors.New("master key file format is invalid")
)

type Key struct {
	ID       string
	Material [KeyBytes]byte
}

type GenerateOptions struct {
	Random       io.Reader
	SetOwnership bool
	OwnerUID     int
	OwnerGID     int
}

type LoadOptions struct {
	ExpectedUID int
	ExpectedGID int
}

func RuntimeGenerateOptions() GenerateOptions {
	return GenerateOptions{
		Random:       rand.Reader,
		SetOwnership: true,
		OwnerUID:     RuntimeUID,
		OwnerGID:     RuntimeGID,
	}
}

func RuntimeLoadOptions() LoadOptions {
	return LoadOptions{ExpectedUID: RuntimeUID, ExpectedGID: RuntimeGID}
}

func Generate(path string, options GenerateOptions) (result Key, err error) {
	if path == "" {
		return Key{}, fmt.Errorf("master key path is required")
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if err := rejectFinalSymlink(path); err != nil {
		return Key{}, err
	}
	if _, err := os.Lstat(path); err == nil {
		return Key{}, ErrAlreadyExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return Key{}, fmt.Errorf("inspect master key path: %w", err)
	}

	uuidBytes := make([]byte, 16)
	if _, err := io.ReadFull(options.Random, uuidBytes); err != nil {
		return Key{}, fmt.Errorf("generate master key ID: %w", err)
	}
	uuidBytes[6] = uuidBytes[6]&0x0f | 0x40
	uuidBytes[8] = uuidBytes[8]&0x3f | 0x80
	if _, err := io.ReadFull(options.Random, result.Material[:]); err != nil {
		return Key{}, fmt.Errorf("generate master key material: %w", err)
	}
	result.ID = formatUUID(uuidBytes)
	content := Encode(result)

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return Key{}, ErrAlreadyExists
		}
		return Key{}, fmt.Errorf("create master key: %w", err)
	}
	removeOnError := true
	defer func() {
		if removeOnError {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()

	if _, err = io.WriteString(file, content); err != nil {
		return Key{}, fmt.Errorf("write master key: %w", err)
	}
	if err = file.Sync(); err != nil {
		return Key{}, fmt.Errorf("sync master key: %w", err)
	}
	if options.SetOwnership {
		if err = file.Chown(options.OwnerUID, options.OwnerGID); err != nil {
			return Key{}, fmt.Errorf("set master key owner: %w", err)
		}
	}
	if err = file.Chmod(0o600); err != nil {
		return Key{}, fmt.Errorf("set master key permissions: %w", err)
	}
	if err = file.Close(); err != nil {
		return Key{}, fmt.Errorf("close master key: %w", err)
	}
	removeOnError = false
	return result, nil
}

func Load(path string, options LoadOptions) (Key, error) {
	if path == "" {
		return Key{}, fmt.Errorf("master key path is required")
	}
	if err := rejectFinalSymlink(path); err != nil {
		return Key{}, err
	}
	file, err := openNoFollow(path)
	if err != nil {
		return Key{}, fmt.Errorf("open master key: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return Key{}, fmt.Errorf("stat master key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Key{}, fmt.Errorf("%w: expected a regular file", ErrFormat)
	}
	if info.Mode().Perm() != 0o600 {
		return Key{}, ErrPermissions
	}
	if err := validateOwner(info, options); err != nil {
		return Key{}, err
	}
	if info.Size() <= 0 || info.Size() > MaxFileBytes {
		return Key{}, fmt.Errorf("%w: invalid file size", ErrFormat)
	}

	content, err := io.ReadAll(io.LimitReader(file, MaxFileBytes+1))
	if err != nil {
		return Key{}, fmt.Errorf("read master key: %w", err)
	}
	return Parse(string(content))
}

func Encode(key Key) string {
	return FormatPrefix + ":" + key.ID + ":" + base64.RawURLEncoding.EncodeToString(key.Material[:]) + "\n"
}

func Parse(content string) (Key, error) {
	if !strings.HasSuffix(content, "\n") || strings.Count(content, "\n") != 1 {
		return Key{}, fmt.Errorf("%w: expected one trailing newline", ErrFormat)
	}
	parts := strings.Split(strings.TrimSuffix(content, "\n"), ":")
	if len(parts) != 3 || parts[0] != FormatPrefix || !validUUID(parts[1]) {
		return Key{}, ErrFormat
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(decoded) != KeyBytes {
		return Key{}, fmt.Errorf("%w: invalid key material", ErrFormat)
	}
	var key Key
	key.ID = parts[1]
	copy(key.Material[:], decoded)
	return key, nil
}

func rejectFinalSymlink(path string) error {
	info, err := os.Lstat(filepath.Clean(path))
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return ErrSymlink
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect master key path: %w", err)
	}
	return nil
}

func formatUUID(value []byte) string {
	encoded := hex.EncodeToString(value)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	if compact != strings.ToLower(compact) {
		return false
	}
	decoded, err := hex.DecodeString(compact)
	return err == nil && len(decoded) == 16
}
