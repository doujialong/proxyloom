//go:build linux || darwin

package masterkey

import (
	"fmt"
	"os"
	"syscall"
)

func openNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func validateOwner(info os.FileInfo, options LoadOptions) error {
	if options.ExpectedUID < 0 && options.ExpectedGID < 0 {
		return nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: owner metadata unavailable", ErrOwner)
	}
	if options.ExpectedUID >= 0 && int(stat.Uid) != options.ExpectedUID {
		return ErrOwner
	}
	if options.ExpectedGID >= 0 && int(stat.Gid) != options.ExpectedGID {
		return ErrOwner
	}
	return nil
}
