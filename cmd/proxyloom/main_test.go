package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsMissingAndUnknownCommands(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if code := run(args, strings.NewReader(""), &stdout, &stderr); code != 2 {
			t.Fatalf("run(%v) code = %d", args, code)
		}
		if stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("run(%v) stdout=%q stderr=%q", args, stdout.String(), stderr.String())
		}
	}
}

func TestRunInitKeyRefusesExistingFileWithoutPrintingContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	const secret = "must-not-be-printed"
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{"init-key", "--path", path}, strings.NewReader(""), &stdout, &stderr); code != 1 {
		t.Fatalf("run() code = %d", code)
	}
	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, secret) {
		t.Fatalf("command output leaked file content: %q", combined)
	}
	if !strings.Contains(stderr.String(), "already exists") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestReadConfirmedPasswordAcceptsOneByte(t *testing.T) {
	password, err := readConfirmedPassword(strings.NewReader("1\n1\n"), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if string(password) != "1" {
		t.Fatalf("password = %q", password)
	}
	wipeStringBytes(password)

	if _, err := readConfirmedPassword(strings.NewReader("\n\n"), &bytes.Buffer{}); err == nil {
		t.Fatal("empty administrator password was accepted")
	}
}

func TestReadBackupPassphraseAndRestoreConfirmation(t *testing.T) {
	var prompt bytes.Buffer
	passphrase, err := readBackupPassphrase(strings.NewReader("portable secret phrase\nportable secret phrase\n"), &prompt, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(passphrase) != "portable secret phrase" || prompt.Len() == 0 {
		t.Fatalf("backup passphrase result=%q prompt=%q", passphrase, prompt.String())
	}
	wipeStringBytes(passphrase)
	if _, err := readBackupPassphrase(strings.NewReader("portable secret phrase\ndifferent secret phrase\n"), &bytes.Buffer{}, true); err == nil {
		t.Fatal("mismatched backup passphrase confirmation was accepted")
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{"restore", "--input", "fixture.plbk"}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("restore without --confirm code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
