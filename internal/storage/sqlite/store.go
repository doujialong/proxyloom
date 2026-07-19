package sqlite

import (
	"context"
	"database/sql"
	"fmt"
)

type Store struct {
	database *sql.DB
}

type OpenOptions struct {
	Migrate MigrateOptions
}

func Open(ctx context.Context, path string, options OpenOptions) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("database path is required")
	}
	database, err := sql.Open(DriverName, path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = database.Close()
		}
	}()
	for _, pragma := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = FULL",
	} {
		if _, err := database.ExecContext(ctx, pragma); err != nil {
			return nil, fmt.Errorf("configure sqlite with %q: %w", pragma, err)
		}
	}
	if err := Migrate(ctx, database, options.Migrate); err != nil {
		return nil, err
	}
	if err := quickCheck(ctx, database); err != nil {
		return nil, err
	}
	closeOnError = false
	return &Store{database: database}, nil
}

func (s *Store) Close() error {
	if s == nil || s.database == nil {
		return nil
	}
	return s.database.Close()
}

func (s *Store) DB() *sql.DB {
	if s == nil {
		return nil
	}
	return s.database
}

func quickCheck(ctx context.Context, database *sql.DB) error {
	var result string
	if err := database.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result); err != nil {
		return fmt.Errorf("sqlite quick_check: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("sqlite quick_check failed: %s", result)
	}
	return nil
}
