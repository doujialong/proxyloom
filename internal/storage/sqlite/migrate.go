package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const DriverName = "sqlite"

var (
	ErrChecksumMismatch = errors.New("database migration checksum mismatch")
	ErrDatabaseTooNew   = errors.New("database schema is newer than this service")
	ErrMigrationGap     = errors.New("database migration history has a gap")
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type Migration struct {
	Version  int
	Name     string
	SQL      string
	Checksum string
}

type MigrateOptions struct {
	Now           func() time.Time
	BeforeUpgrade func(context.Context, *sql.DB, int, int) error
}

func Migrate(ctx context.Context, database *sql.DB, options MigrateOptions) error {
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	return applyMigrations(ctx, database, migrations, options)
}

func CurrentVersion(ctx context.Context, database *sql.DB) (int, error) {
	if err := ensureMigrationTable(ctx, database); err != nil {
		return 0, err
	}
	var version int
	if err := database.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&version); err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return version, nil
}

func loadMigrations() ([]Migration, error) {
	paths, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return nil, fmt.Errorf("list embedded migrations: %w", err)
	}
	migrations := make([]Migration, 0, len(paths))
	for _, path := range paths {
		base := filepath.Base(path)
		separator := strings.IndexByte(base, '_')
		if separator <= 0 || !strings.HasSuffix(base, ".sql") {
			return nil, fmt.Errorf("invalid migration filename %q", base)
		}
		version, err := strconv.Atoi(base[:separator])
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("invalid migration version in %q", base)
		}
		content, err := migrationFiles.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", base, err)
		}
		digest := sha256.Sum256(content)
		migrations = append(migrations, Migration{
			Version:  version,
			Name:     strings.TrimSuffix(base[separator+1:], ".sql"),
			SQL:      string(content),
			Checksum: hex.EncodeToString(digest[:]),
		})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	for index, migration := range migrations {
		if migration.Version != index+1 {
			return nil, fmt.Errorf("embedded migrations must be contiguous from 1: got version %d at index %d", migration.Version, index)
		}
	}
	return migrations, nil
}

func applyMigrations(ctx context.Context, database *sql.DB, migrations []Migration, options MigrateOptions) error {
	if database == nil {
		return fmt.Errorf("database is required")
	}
	if options.Now == nil {
		return fmt.Errorf("migration clock is required")
	}
	if err := ensureMigrationTable(ctx, database); err != nil {
		return err
	}

	applied, err := appliedMigrations(ctx, database)
	if err != nil {
		return err
	}
	latestKnown := 0
	if len(migrations) > 0 {
		latestKnown = migrations[len(migrations)-1].Version
	}
	current := 0
	versions := make([]int, 0, len(applied))
	for version := range applied {
		versions = append(versions, version)
	}
	sort.Ints(versions)
	if len(versions) > 0 && versions[len(versions)-1] > latestKnown {
		return fmt.Errorf("%w: database=%d service=%d", ErrDatabaseTooNew, versions[len(versions)-1], latestKnown)
	}
	for _, version := range versions {
		checksum := applied[version]
		migration := migrations[version-1]
		if checksum != migration.Checksum {
			return fmt.Errorf("%w at version %d", ErrChecksumMismatch, version)
		}
		if version > current {
			current = version
		}
	}
	for version := 1; version <= current; version++ {
		if _, exists := applied[version]; !exists {
			return fmt.Errorf("%w before version %d", ErrMigrationGap, current)
		}
	}
	if current < latestKnown && current > 0 {
		if options.BeforeUpgrade == nil {
			return fmt.Errorf("verified backup hook is required before upgrading schema %d to %d", current, latestKnown)
		}
		if err := options.BeforeUpgrade(ctx, database, current, latestKnown); err != nil {
			return fmt.Errorf("backup before migration: %w", err)
		}
	}

	for _, migration := range migrations {
		if migration.Version <= current {
			continue
		}
		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", migration.Version, err)
		}
		if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %d (%s): %w", migration.Version, migration.Name, err)
		}
		appliedAt := options.Now().UTC().UnixMilli()
		if _, err := tx.ExecContext(ctx, `
INSERT INTO schema_migrations(version, name, checksum, applied_at)
VALUES (?, ?, ?, ?)`, migration.Version, migration.Name, migration.Checksum, appliedAt); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d: %w", migration.Version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", migration.Version, err)
		}
		current = migration.Version
	}
	return nil
}

func ensureMigrationTable(ctx context.Context, database *sql.DB) error {
	_, err := database.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY CHECK (version > 0),
  name TEXT NOT NULL UNIQUE,
  checksum TEXT NOT NULL CHECK (length(checksum) = 64),
  applied_at INTEGER NOT NULL
)`)
	if err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	return nil
}

func appliedMigrations(ctx context.Context, database *sql.DB) (map[int]string, error) {
	rows, err := database.QueryContext(ctx, "SELECT version, checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, fmt.Errorf("read migration ledger: %w", err)
	}
	defer rows.Close()
	result := make(map[int]string)
	for rows.Next() {
		var version int
		var checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			return nil, fmt.Errorf("scan migration ledger: %w", err)
		}
		result[version] = checksum
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate migration ledger: %w", err)
	}
	return result, nil
}
