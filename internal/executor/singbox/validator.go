package singbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	ExpectedVersion    = "1.12.25"
	ExpectedVersion13  = "1.13.14"
	DefaultPath        = "/opt/sing-box-1.12.25/sing-box"
	DefaultPath13      = "/opt/sing-box-1.13.14/sing-box"
	DefaultTempRoot    = "/tmp"
	maxDiagnosticBytes = 32 << 10
)

var ErrValidationFailed = errors.New("sing-box target validation failed")

type Options struct {
	Path            string
	TempRoot        string
	Timeout         time.Duration
	ExpectedVersion string
}

type Validator struct {
	path     string
	tempRoot string
	timeout  time.Duration
	version  string
}

func Open(ctx context.Context, options Options) (*Validator, error) {
	if options.Path == "" {
		options.Path = DefaultPath
	}
	if options.TempRoot == "" {
		options.TempRoot = DefaultTempRoot
	}
	if options.Timeout <= 0 {
		options.Timeout = 10 * time.Second
	}
	if options.ExpectedVersion == "" {
		options.ExpectedVersion = ExpectedVersion
	}
	info, err := os.Stat(options.Path)
	if err != nil {
		return nil, fmt.Errorf("inspect sing-box validator: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("sing-box validator must be an executable regular file")
	}
	validator := &Validator{
		path: filepath.Clean(options.Path), tempRoot: filepath.Clean(options.TempRoot),
		timeout: options.Timeout, version: options.ExpectedVersion,
	}
	versionTimeout := options.Timeout
	if versionTimeout < 3*time.Second {
		versionTimeout = 3 * time.Second
	}
	versionContext, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()
	command := exec.CommandContext(versionContext, validator.path, "version")
	command.Env = []string{"HOME=/tmp", "TMPDIR=" + validator.tempRoot, "LANG=C", "LC_ALL=C"}
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("run sing-box version check")
	}
	firstLine := strings.TrimSpace(strings.SplitN(string(output), "\n", 2)[0])
	if firstLine != "sing-box version "+options.ExpectedVersion {
		return nil, fmt.Errorf("sing-box validator version mismatch: expected %s", options.ExpectedVersion)
	}
	return validator, nil
}

func (v *Validator) Check(ctx context.Context, content []byte) error {
	if v == nil || v.path == "" {
		return fmt.Errorf("sing-box validator is not initialized")
	}
	if len(content) == 0 || len(content) > 50<<20 {
		return fmt.Errorf("sing-box validation input is empty or exceeds 50 MiB")
	}
	directory, err := os.MkdirTemp(v.tempRoot, "proxyloom-singbox-check-")
	if err != nil {
		return fmt.Errorf("create sing-box validation directory: %w", err)
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("secure sing-box validation directory: %w", err)
	}
	configPath := filepath.Join(directory, "config.json")
	file, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create sing-box validation config: %w", err)
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return fmt.Errorf("write sing-box validation config: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close sing-box validation config: %w", err)
	}
	checkContext, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	command := exec.CommandContext(checkContext, v.path, "check", "-c", configPath)
	command.Dir = directory
	command.Env = []string{"HOME=" + directory, "TMPDIR=" + directory, "LANG=C", "LC_ALL=C"}
	var diagnostics limitedBuffer
	command.Stdout = &diagnostics
	command.Stderr = &diagnostics
	err = command.Run()
	if checkContext.Err() != nil {
		return fmt.Errorf("%w: validator timed out", ErrValidationFailed)
	}
	if err != nil {
		return fmt.Errorf("%w", ErrValidationFailed)
	}
	return nil
}

func (v *Validator) Version() string {
	if v == nil {
		return ""
	}
	return v.version
}

type limitedBuffer struct {
	buffer bytes.Buffer
}

func (w *limitedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := maxDiagnosticBytes - w.buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = io.Copy(&w.buffer, bytes.NewReader(value))
	}
	return original, nil
}
