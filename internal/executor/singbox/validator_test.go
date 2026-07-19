package singbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestValidatorVersionAndCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is not portable to Windows")
	}
	path := filepath.Join(t.TempDir(), "sing-box")
	script := `#!/bin/sh
if [ "$1" = version ]; then
  echo "sing-box version 1.12.25"
  exit 0
fi
if [ "$1" = check ] && grep -q '"outbounds"' "$3"; then
  exit 0
fi
exit 1
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	validator, err := Open(context.Background(), Options{Path: path, TempRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if validator.Version() != ExpectedVersion {
		t.Fatalf("Version() = %q", validator.Version())
	}
	if err := validator.Check(context.Background(), []byte(`{"outbounds":[]}`)); err != nil {
		t.Fatal(err)
	}
	const secret = "must-not-leak"
	err = validator.Check(context.Background(), []byte(secret))
	if !errors.Is(err, ErrValidationFailed) || strings.Contains(err.Error(), secret) {
		t.Fatalf("validation error = %v", err)
	}
}

func TestValidatorRejectsWrongVersionAndTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is not portable to Windows")
	}
	directory := t.TempDir()
	wrong := filepath.Join(directory, "wrong")
	if err := os.WriteFile(wrong, []byte("#!/bin/sh\necho 'sing-box version 1.13.0'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), Options{Path: wrong, TempRoot: directory}); err == nil {
		t.Fatal("wrong sing-box version was accepted")
	}
	slow := filepath.Join(directory, "slow")
	if err := os.WriteFile(slow, []byte("#!/bin/sh\nif [ \"$1\" = version ]; then echo 'sing-box version 1.12.25'; else sleep 2; fi\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	validator, err := Open(context.Background(), Options{Path: slow, TempRoot: directory, Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Check(context.Background(), []byte(`{"outbounds":[]}`)); !errors.Is(err, ErrValidationFailed) {
		t.Fatalf("timeout error = %v", err)
	}
}
