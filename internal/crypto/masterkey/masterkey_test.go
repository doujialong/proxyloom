package masterkey

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	random := bytes.NewReader(append(make([]byte, 16), bytes.Repeat([]byte{0x5a}, KeyBytes)...))
	generated, err := Generate(path, GenerateOptions{Random: random})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if generated.ID != "00000000-0000-4000-8000-000000000000" {
		t.Fatalf("key ID = %q", generated.ID)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	loaded, err := Load(path, LoadOptions{ExpectedUID: -1, ExpectedGID: -1})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded != generated {
		t.Fatalf("loaded key differs: %+v vs %+v", loaded, generated)
	}
}

func TestGenerateRefusesExistingFileAndPreservesIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Generate(path, GenerateOptions{Random: bytes.NewReader(make([]byte, 48))})
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("Generate() error = %v", err)
	}
	content, _ := os.ReadFile(path)
	if string(content) != "existing" {
		t.Fatalf("existing content changed: %q", content)
	}
}

func TestGenerateRemovesPartialFileOnRandomFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	_, err := Generate(path, GenerateOptions{Random: bytes.NewReader(make([]byte, 20))})
	if err == nil {
		t.Fatal("Generate() succeeded with short random input")
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial file remains: %v", statErr)
	}
}

func TestMasterKeyRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "master.key")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(link, GenerateOptions{}); !errors.Is(err, ErrSymlink) {
		t.Fatalf("Generate(symlink) error = %v", err)
	}
	if _, err := Load(link, LoadOptions{ExpectedUID: -1, ExpectedGID: -1}); !errors.Is(err, ErrSymlink) {
		t.Fatalf("Load(symlink) error = %v", err)
	}
}

func TestLoadRejectsWidePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	key := Key{ID: "00000000-0000-4000-8000-000000000000"}
	if err := os.WriteFile(path, []byte(Encode(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, LoadOptions{ExpectedUID: -1, ExpectedGID: -1}); !errors.Is(err, ErrPermissions) {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadRejectsUnexpectedOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	key := Key{ID: "00000000-0000-4000-8000-000000000000"}
	if err := os.WriteFile(path, []byte(Encode(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, LoadOptions{ExpectedUID: os.Getuid() + 1, ExpectedGID: -1}); !errors.Is(err, ErrOwner) {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestParseRejectsMalformedFiles(t *testing.T) {
	validMaterial := base64Material(0x42)
	tests := []string{
		"",
		"plmk1:00000000-0000-4000-8000-000000000000:" + validMaterial,
		"plmk2:00000000-0000-4000-8000-000000000000:" + validMaterial + "\n",
		"plmk1:NOT-A-UUID:" + validMaterial + "\n",
		"plmk1:00000000-0000-4000-8000-000000000000:short\n",
		"plmk1:00000000-0000-4000-8000-000000000000:" + validMaterial + "\n\n",
	}
	for index, input := range tests {
		if _, err := Parse(input); !errors.Is(err, ErrFormat) {
			t.Fatalf("Parse(test %d) error = %v", index, err)
		}
	}
}

func base64Material(value byte) string {
	key := Key{ID: "00000000-0000-4000-8000-000000000000"}
	for index := range key.Material {
		key.Material[index] = value
	}
	parts := strings.Split(strings.TrimSpace(Encode(key)), ":")
	return parts[2]
}
