//go:build !windows

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

var ErrServiceRunning = errors.New("another ProxyLoom service is using this data directory")

func acquireRuntimeLock(dataDir string) (*os.File, error) {
	path := filepath.Join(dataDir, ".proxyloom.lock")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open runtime lock: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, fmt.Errorf("secure runtime lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrServiceRunning
		}
		return nil, fmt.Errorf("acquire runtime lock: %w", err)
	}
	return file, nil
}

func releaseRuntimeLock(file *os.File) {
	if file == nil {
		return
	}
	_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
	_ = file.Close()
}
