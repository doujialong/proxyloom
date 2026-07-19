package auth

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateLoadAndVerifyAdminToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.token")
	if err := Generate(path, GenerateOptions{Random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 32))}); err != nil {
		t.Fatal(err)
	}
	if err := Generate(path, GenerateOptions{}); err == nil {
		t.Fatal("Generate() overwrote an existing token")
	}
	token, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	if !token.VerifyBearer("Bearer "+encoded) || token.VerifyBearer("Bearer invalid") {
		t.Fatal("admin bearer verification mismatch")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() accepted broad permissions")
	}
}
