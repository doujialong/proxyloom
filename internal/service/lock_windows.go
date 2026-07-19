//go:build windows

package service

import (
	"errors"
	"os"
)

var ErrServiceRunning = errors.New("another ProxyLoom service is using this data directory")

func acquireRuntimeLock(string) (*os.File, error) {
	return nil, errors.New("runtime data-directory locking is not implemented on Windows")
}

func releaseRuntimeLock(file *os.File) {
	if file != nil {
		_ = file.Close()
	}
}
