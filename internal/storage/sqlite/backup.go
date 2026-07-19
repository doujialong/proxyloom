package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

type BackupInfo struct {
	Path          string
	SHA256        string
	Size          int64
	SchemaVersion int
}

func CreateVerifiedBackup(ctx context.Context, database *sql.DB, destination string) (BackupInfo, error) {
	if database == nil {
		return BackupInfo{}, fmt.Errorf("database is required")
	}
	if destination == "" {
		return BackupInfo{}, fmt.Errorf("backup destination is required")
	}
	if _, err := os.Lstat(destination); err == nil {
		return BackupInfo{}, fmt.Errorf("backup destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return BackupInfo{}, fmt.Errorf("inspect backup destination: %w", err)
	}
	if _, err := database.ExecContext(ctx, "VACUUM INTO ?", destination); err != nil {
		return BackupInfo{}, fmt.Errorf("create sqlite backup: %w", err)
	}
	removeOnError := true
	defer func() {
		if removeOnError {
			_ = os.Remove(destination)
		}
	}()
	backupFile, err := os.OpenFile(destination, os.O_RDWR, 0)
	if err != nil {
		return BackupInfo{}, fmt.Errorf("open sqlite backup for sync: %w", err)
	}
	if err := backupFile.Chmod(0o600); err != nil {
		_ = backupFile.Close()
		return BackupInfo{}, fmt.Errorf("set sqlite backup permissions: %w", err)
	}
	if err := backupFile.Sync(); err != nil {
		_ = backupFile.Close()
		return BackupInfo{}, fmt.Errorf("sync sqlite backup: %w", err)
	}
	if err := backupFile.Close(); err != nil {
		return BackupInfo{}, fmt.Errorf("close sqlite backup after sync: %w", err)
	}

	backup, err := sql.Open(DriverName, destination)
	if err != nil {
		return BackupInfo{}, fmt.Errorf("open sqlite backup: %w", err)
	}
	backup.SetMaxOpenConns(1)
	if err := quickCheck(ctx, backup); err != nil {
		_ = backup.Close()
		return BackupInfo{}, fmt.Errorf("verify sqlite backup: %w", err)
	}
	version, err := CurrentVersion(ctx, backup)
	if err != nil {
		_ = backup.Close()
		return BackupInfo{}, fmt.Errorf("read backup schema version: %w", err)
	}
	if err := backup.Close(); err != nil {
		return BackupInfo{}, fmt.Errorf("close sqlite backup: %w", err)
	}

	file, err := os.Open(destination)
	if err != nil {
		return BackupInfo{}, fmt.Errorf("open backup for digest: %w", err)
	}
	hash := sha256.New()
	size, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return BackupInfo{}, fmt.Errorf("digest sqlite backup: %w", copyErr)
	}
	if closeErr != nil {
		return BackupInfo{}, fmt.Errorf("close backup after digest: %w", closeErr)
	}
	removeOnError = false
	return BackupInfo{
		Path:          destination,
		SHA256:        hex.EncodeToString(hash.Sum(nil)),
		Size:          size,
		SchemaVersion: version,
	}, nil
}
