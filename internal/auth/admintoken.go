package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	adminTokenPrefix = "plat1:"
	adminTokenBytes  = 32
)

var ErrInvalidTokenFile = errors.New("invalid admin token file")

type Token struct {
	material [adminTokenBytes]byte
}

type GenerateOptions struct {
	Random       io.Reader
	SetOwnership bool
	OwnerUID     int
	OwnerGID     int
}

func Generate(path string, options GenerateOptions) error {
	if path == "" {
		return fmt.Errorf("admin token path is required")
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("admin token path is a symbolic link")
		}
		return fmt.Errorf("admin token file already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect admin token path: %w", err)
	}
	material := make([]byte, adminTokenBytes)
	if _, err := io.ReadFull(options.Random, material); err != nil {
		return fmt.Errorf("generate admin token: %w", err)
	}
	defer wipe(material)
	content := adminTokenPrefix + base64.RawURLEncoding.EncodeToString(material) + "\n"
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create admin token: %w", err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := io.WriteString(file, content); err != nil {
		return fmt.Errorf("write admin token: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync admin token: %w", err)
	}
	if options.SetOwnership {
		if err := file.Chown(options.OwnerUID, options.OwnerGID); err != nil {
			return fmt.Errorf("set admin token owner: %w", err)
		}
	}
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("set admin token permissions: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close admin token: %w", err)
	}
	remove = false
	return nil
}

func Load(path string) (*Token, error) {
	if path == "" {
		return nil, fmt.Errorf("admin token path is required")
	}
	file, err := openAdminNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("open admin token: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat admin token: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 128 {
		return nil, ErrInvalidTokenFile
	}
	content, err := io.ReadAll(io.LimitReader(file, 129))
	if err != nil {
		return nil, fmt.Errorf("read admin token: %w", err)
	}
	if !strings.HasSuffix(string(content), "\n") || strings.Count(string(content), "\n") != 1 || !strings.HasPrefix(string(content), adminTokenPrefix) {
		return nil, ErrInvalidTokenFile
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(string(content), adminTokenPrefix), "\n")
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != adminTokenBytes {
		wipe(decoded)
		return nil, ErrInvalidTokenFile
	}
	token := &Token{}
	copy(token.material[:], decoded)
	wipe(decoded)
	return token, nil
}

func (t *Token) VerifyBearer(header string) bool {
	if t == nil || !strings.HasPrefix(header, "Bearer ") {
		return false
	}
	provided, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(header, "Bearer "))
	if err != nil || len(provided) != adminTokenBytes {
		wipe(provided)
		return false
	}
	matched := subtle.ConstantTimeCompare(t.material[:], provided) == 1
	wipe(provided)
	return matched
}

func (t *Token) BearerValue() string {
	if t == nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(t.material[:])
}

func (t *Token) Close() {
	if t == nil {
		return
	}
	wipe(t.material[:])
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
