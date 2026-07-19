package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var migrationTime = time.Date(2026, 7, 18, 8, 0, 0, 0, time.UTC)

func TestMigrateFromEmptyDatabaseAndReplay(t *testing.T) {
	database := openTestDatabase(t, filepath.Join(t.TempDir(), "proxyloom.db"))
	defer database.Close()
	options := MigrateOptions{Now: func() time.Time { return migrationTime }}
	if err := Migrate(context.Background(), database, options); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if err := Migrate(context.Background(), database, options); err != nil {
		t.Fatalf("Migrate() replay error = %v", err)
	}
	version, err := CurrentVersion(context.Background(), database)
	if err != nil || version != 10 {
		t.Fatalf("CurrentVersion() = %d, %v", version, err)
	}
	var count int
	if err := database.QueryRow("SELECT count(*) FROM schema_migrations").Scan(&count); err != nil || count != 10 {
		t.Fatalf("migration count = %d, %v", count, err)
	}
	var checksum string
	var appliedAt int64
	if err := database.QueryRow("SELECT checksum, applied_at FROM schema_migrations WHERE version = 1").Scan(&checksum, &appliedAt); err != nil {
		t.Fatal(err)
	}
	if len(checksum) != 64 || appliedAt != migrationTime.UnixMilli() {
		t.Fatalf("migration ledger = checksum %q, applied_at %d", checksum, appliedAt)
	}
	for _, table := range []string{
		"application_metadata", "master_key_slots", "instances", "data_keys",
		"master_key_wrappings", "encrypted_blobs", "sources", "source_revisions",
		"refresh_attempts", "raw_documents", "snapshots",
		"fingerprints", "raw_nodes", "canonical_nodes", "node_occurrences", "snapshot_occurrences",
		"jobs", "artifacts", "source_publications", "publication_tokens",
		"administrators", "setup_tokens", "sessions", "audit_events",
		"health_records", "node_health_states", "probe_queue_items",
		"control_probe_records", "health_guard_windows",
		"managed_resources", "managed_outputs", "managed_output_artifacts", "managed_output_tokens",
	} {
		if err := database.QueryRow("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("table %s count = %d, %v", table, count, err)
		}
	}
}

func TestEmbeddedUpgradeFromBootstrapRequiresVerifiedBackup(t *testing.T) {
	database := openTestDatabase(t, ":memory:")
	defer database.Close()
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	options := MigrateOptions{Now: func() time.Time { return migrationTime }}
	if err := applyMigrations(context.Background(), database, migrations[:1], options); err != nil {
		t.Fatalf("apply bootstrap migration: %v", err)
	}
	if err := Migrate(context.Background(), database, options); err == nil || !strings.Contains(err.Error(), "backup hook is required") {
		t.Fatalf("Migrate() without backup error = %v", err)
	}
	backupCalls := 0
	options.BeforeUpgrade = func(_ context.Context, _ *sql.DB, current, target int) error {
		backupCalls++
		if current != 1 || target != 10 {
			t.Fatalf("backup versions = %d -> %d", current, target)
		}
		return nil
	}
	if err := Migrate(context.Background(), database, options); err != nil {
		t.Fatalf("Migrate() with backup error = %v", err)
	}
	if backupCalls != 1 {
		t.Fatalf("backup calls = %d", backupCalls)
	}
}

func TestMigrateRejectsChecksumDrift(t *testing.T) {
	database := openMigratedTestDatabase(t)
	defer database.Close()
	if _, err := database.Exec("UPDATE schema_migrations SET checksum = ? WHERE version = 1", strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	err := Migrate(context.Background(), database, MigrateOptions{Now: func() time.Time { return migrationTime }})
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("Migrate() error = %v", err)
	}
}

func TestSanitizeErrorsMigrationRemovesSensitiveDiagnostics(t *testing.T) {
	database := openTestDatabase(t, ":memory:")
	defer database.Close()
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if err := applyMigrations(context.Background(), database, migrations[:4], MigrateOptions{Now: func() time.Time { return migrationTime }}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("PRAGMA foreign_keys = OFF"); err != nil {
		t.Fatal(err)
	}
	const (
		sourceID   = "00000000-0000-4000-8000-000000000101"
		revisionID = "00000000-0000-4000-8000-000000000102"
		attemptID  = "00000000-0000-4000-8000-000000000103"
		jobID      = "00000000-0000-4000-8000-000000000104"
		configID   = "00000000-0000-4000-8000-000000000105"
	)
	now := migrationTime.UnixMilli()
	if _, err := database.Exec(`
INSERT INTO sources(id, display_name, lifecycle_state, source_health, revision_counter, created_at, updated_at)
VALUES (?, 'sanitize fixture', 'active', 'unknown', 1, ?, ?)`, sourceID, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
INSERT INTO source_revisions(
  id, source_id, revision_number, state, source_type, import_purpose,
  schedule_timezone, private_network_authorized, config_blob_id,
  config_schema_version, created_at, published_at
) VALUES (?, ?, 1, 'published', 'remote', 'node_source', 'UTC', 0, ?, 1, ?, ?)`, revisionID, sourceID, configID, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE sources SET published_revision_id = ? WHERE id = ?`, revisionID, sourceID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
INSERT INTO refresh_attempts(
  id, source_id, source_revision_id, trigger_kind, status, correlation_id, started_at
) VALUES (?, ?, ?, 'manual', 'running', 'sanitize-attempt', ?)`, attemptID, sourceID, revisionID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
UPDATE refresh_attempts
SET status = 'failed', error_code = 'fetch_failed',
    error_detail = 'https://example.test/secret-token', finished_at = ?
WHERE id = ?`, now, attemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
INSERT INTO jobs(
  id, job_type, source_id, source_revision_id, status, dedupe_key,
  attempt, max_attempts, error_code, error_detail, correlation_id,
  due_at, created_at, finished_at
) VALUES (?, 'source_refresh', ?, ?, 'failed', ?, 1, 3, 'fetch_failed',
          'https://example.test/secret-token', 'sanitize-job', ?, ?, ?)`,
		jobID, sourceID, revisionID, sourceID, now, now, now); err != nil {
		t.Fatal(err)
	}
	backupCalls := 0
	err = Migrate(context.Background(), database, MigrateOptions{
		Now: func() time.Time { return migrationTime.Add(time.Second) },
		BeforeUpgrade: func(_ context.Context, _ *sql.DB, current, target int) error {
			backupCalls++
			if current != 4 || target != 10 {
				t.Fatalf("backup versions = %d -> %d", current, target)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if backupCalls != 1 {
		t.Fatalf("backup calls = %d", backupCalls)
	}
	for table, id := range map[string]string{"refresh_attempts": attemptID, "jobs": jobID} {
		var detail string
		if err := database.QueryRow("SELECT error_detail FROM "+table+" WHERE id = ?", id).Scan(&detail); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(detail, "secret-token") || strings.Contains(detail, "example.test") {
			t.Fatalf("%s retained sensitive diagnostics: %q", table, detail)
		}
		if _, err := database.Exec("UPDATE "+table+" SET error_detail = 'changed' WHERE id = ?", id); err == nil {
			t.Fatalf("%s terminal immutability trigger was not restored", table)
		}
	}
}

func TestMigrateRejectsNewerDatabase(t *testing.T) {
	database := openMigratedTestDatabase(t)
	defer database.Close()
	if _, err := database.Exec(
		"INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES (99, 'future', ?, ?)",
		strings.Repeat("f", 64), migrationTime.UnixMilli(),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE schema_migrations SET checksum = ? WHERE version = 1", strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	err := Migrate(context.Background(), database, MigrateOptions{Now: func() time.Time { return migrationTime }})
	if !errors.Is(err, ErrDatabaseTooNew) {
		t.Fatalf("Migrate() error = %v", err)
	}
}

func TestFailedMigrationRollsBackDDLAndLedger(t *testing.T) {
	database := openTestDatabase(t, ":memory:")
	defer database.Close()
	migrations := []Migration{{
		Version:  1,
		Name:     "broken",
		SQL:      "CREATE TABLE should_rollback(id INTEGER); THIS IS NOT SQL;",
		Checksum: strings.Repeat("a", 64),
	}}
	err := applyMigrations(context.Background(), database, migrations, MigrateOptions{Now: func() time.Time { return migrationTime }})
	if err == nil {
		t.Fatal("broken migration succeeded")
	}
	var count int
	if err := database.QueryRow("SELECT count(*) FROM sqlite_master WHERE name = 'should_rollback'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("rolled back table count = %d, %v", count, err)
	}
	if err := database.QueryRow("SELECT count(*) FROM schema_migrations").Scan(&count); err != nil || count != 0 {
		t.Fatalf("rolled back ledger count = %d, %v", count, err)
	}
}

func TestUpgradeRequiresAndRunsVerifiedBackupHook(t *testing.T) {
	database := openTestDatabase(t, ":memory:")
	defer database.Close()
	migrations := []Migration{
		{Version: 1, Name: "one", SQL: "CREATE TABLE one(id INTEGER);", Checksum: strings.Repeat("1", 64)},
		{Version: 2, Name: "two", SQL: "CREATE TABLE two(id INTEGER);", Checksum: strings.Repeat("2", 64)},
	}
	options := MigrateOptions{Now: func() time.Time { return migrationTime }}
	if err := applyMigrations(context.Background(), database, migrations[:1], options); err != nil {
		t.Fatalf("apply first migration: %v", err)
	}
	if err := applyMigrations(context.Background(), database, migrations, options); err == nil || !strings.Contains(err.Error(), "backup hook is required") {
		t.Fatalf("upgrade without backup error = %v", err)
	}
	backupCalls := 0
	options.BeforeUpgrade = func(_ context.Context, _ *sql.DB, current, target int) error {
		backupCalls++
		if current != 1 || target != 2 {
			t.Fatalf("backup versions = %d -> %d", current, target)
		}
		return nil
	}
	if err := applyMigrations(context.Background(), database, migrations, options); err != nil {
		t.Fatalf("upgrade with backup: %v", err)
	}
	if backupCalls != 1 {
		t.Fatalf("backup calls = %d, want 1", backupCalls)
	}
}

func TestCreateVerifiedBackup(t *testing.T) {
	directory := t.TempDir()
	database := openMigratedTestDatabaseAt(t, filepath.Join(directory, "proxyloom.db"))
	defer database.Close()
	if _, err := database.Exec("INSERT INTO application_metadata(key, value) VALUES ('fixture', 'before')"); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "proxyloom.backup.db")
	info, err := CreateVerifiedBackup(context.Background(), database, destination)
	if err != nil {
		t.Fatalf("CreateVerifiedBackup() error = %v", err)
	}
	if info.SchemaVersion != 10 || len(info.SHA256) != 64 || info.Size <= 0 {
		t.Fatalf("backup info = %+v", info)
	}
	fileInfo, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %o, want 600", fileInfo.Mode().Perm())
	}
	if _, err := database.Exec("UPDATE application_metadata SET value = 'after' WHERE key = 'fixture'"); err != nil {
		t.Fatal(err)
	}
	backup, err := sql.Open(DriverName, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	var value string
	if err := backup.QueryRow("SELECT value FROM application_metadata WHERE key = 'fixture'").Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "before" {
		t.Fatalf("backup value = %q", value)
	}
}

func TestSingBox113TargetMigrationPreservesManagedOutputReferences(t *testing.T) {
	database := openTestDatabase(t, ":memory:")
	defer database.Close()
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	options := MigrateOptions{Now: func() time.Time { return migrationTime }}
	if err := applyMigrations(context.Background(), database, migrations[:9], options); err != nil {
		t.Fatal(err)
	}
	const (
		keyID      = "00000000-0000-4000-8000-000000000201"
		blobID     = "00000000-0000-4000-8000-000000000202"
		resourceID = "00000000-0000-4000-8000-000000000203"
		outputID   = "00000000-0000-4000-8000-000000000204"
		artifactID = "00000000-0000-4000-8000-000000000205"
		tokenID    = "00000000-0000-4000-8000-000000000206"
		jobID      = "00000000-0000-4000-8000-000000000207"
	)
	now := migrationTime.UnixMilli()
	statements := []struct {
		query string
		args  []interface{}
	}{
		{`INSERT INTO data_keys(id, purpose, status, created_at) VALUES (?, 'blob', 'active', ?)`, []interface{}{keyID, now}},
		{`INSERT INTO encrypted_blobs(
  id, kind, key_id, nonce, ciphertext_inline, plaintext_size, ciphertext_size,
  content_hmac, public_sha256, created_at
) VALUES (?, 'fixture', ?, zeroblob(12), zeroblob(16), 0, 16, zeroblob(32), ?, ?)`, []interface{}{blobID, keyID, strings.Repeat("a", 64), now}},
		{`INSERT INTO managed_resources(
  id, resource_type, display_name, config_blob_id, revision_number,
  lifecycle_state, created_at, updated_at
) VALUES (?, 'collection', 'fixture', ?, 1, 'active', ?, ?)`, []interface{}{resourceID, blobID, now, now}},
		{`INSERT INTO managed_outputs(
  id, display_name, collection_id, target_profile, output_shape,
  health_filter_enabled, minimum_nodes, maximum_drop_ratio, allocation_blob_id,
  current_artifact_id, next_build_sequence, lifecycle_state, created_at, updated_at
) VALUES (?, 'fixture', ?, 'sing-box-1.12.25', 'outbounds_object', 0, 1, 0.5, ?, ?, 2, 'active', ?, ?)`, []interface{}{outputID, resourceID, blobID, artifactID, now, now}},
		{`INSERT INTO managed_output_artifacts(
  id, output_id, build_sequence, content_blob_id, manifest_blob_id, content_type,
  content_length, public_sha256, node_count, excluded_count, warning_count,
  target_profile, validator_version, created_at
) VALUES (?, ?, 1, ?, ?, 'application/json', 0, ?, 1, 0, 0,
          'sing-box-1.12.25', 'sing-box-1.12.25-check', ?)`, []interface{}{artifactID, outputID, blobID, blobID, strings.Repeat("a", 64), now}},
		{`INSERT INTO managed_output_tokens(
  id, output_id, key_id, token_hmac, created_at
) VALUES (?, ?, ?, zeroblob(32), ?)`, []interface{}{tokenID, outputID, keyID, now}},
		{`INSERT INTO managed_output_build_jobs(
  id, output_id, trigger_kind, status, dedupe_key, attempt, max_attempts,
  correlation_id, due_at, created_at, started_at, finished_at
) VALUES (?, ?, 'manual', 'succeeded', 'fixture-build', 1, 3,
          'fixture-build', ?, ?, ?, ?)`, []interface{}{jobID, outputID, now, now, now, now}},
	}
	for _, statement := range statements {
		if _, err := database.Exec(statement.query, statement.args...); err != nil {
			t.Fatalf("insert migration fixture: %v", err)
		}
	}
	options.BeforeUpgrade = func(context.Context, *sql.DB, int, int) error { return nil }
	if err := applyMigrations(context.Background(), database, migrations, options); err != nil {
		t.Fatalf("upgrade v9 fixture: %v", err)
	}
	for table, id := range map[string]string{
		"managed_outputs": outputID, "managed_output_artifacts": artifactID,
		"managed_output_tokens": tokenID, "managed_output_build_jobs": jobID,
	} {
		var count int
		if err := database.QueryRow("SELECT count(*) FROM "+table+" WHERE id = ?", id).Scan(&count); err != nil || count != 1 {
			t.Fatalf("preserved %s count=%d error=%v", table, count, err)
		}
	}
	rows, err := database.Query("PRAGMA foreign_key_check")
	if err != nil {
		t.Fatal(err)
	}
	if rows.Next() {
		rows.Close()
		t.Fatal("migration left a foreign-key violation")
	}
	rows.Close()
	if _, err := database.Exec(`INSERT INTO managed_outputs(
  id, display_name, collection_id, target_profile, output_shape,
  health_filter_enabled, minimum_nodes, maximum_drop_ratio,
  next_build_sequence, lifecycle_state, created_at, updated_at
) VALUES ('00000000-0000-4000-8000-000000000208', '1.13 fixture', ?,
          'sing-box-1.13.14', 'outbounds_object', 0, 1, 0.5, 1, 'active', ?, ?)`, resourceID, now, now); err != nil {
		t.Fatalf("insert sing-box 1.13 target after migration: %v", err)
	}
	if _, err := database.Exec("UPDATE managed_output_artifacts SET node_count = 2 WHERE id = ?", artifactID); err == nil {
		t.Fatal("artifact immutability trigger was not restored")
	}
	if _, err := database.Exec("UPDATE managed_output_build_jobs SET error_detail = 'changed' WHERE id = ?", jobID); err == nil {
		t.Fatal("terminal output-job immutability trigger was not restored")
	}
}

func openMigratedTestDatabase(t *testing.T) *sql.DB {
	t.Helper()
	return openMigratedTestDatabaseAt(t, filepath.Join(t.TempDir(), "proxyloom.db"))
}

func openMigratedTestDatabaseAt(t *testing.T, path string) *sql.DB {
	t.Helper()
	database := openTestDatabase(t, path)
	if err := Migrate(context.Background(), database, MigrateOptions{Now: func() time.Time { return migrationTime }}); err != nil {
		database.Close()
		t.Fatalf("Migrate() error = %v", err)
	}
	return database
}

func openTestDatabase(t *testing.T, path string) *sql.DB {
	t.Helper()
	database, err := sql.Open(DriverName, path)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	database.SetMaxOpenConns(1)
	if _, err := database.Exec("PRAGMA foreign_keys = ON"); err != nil {
		database.Close()
		t.Fatalf("enable foreign keys: %v", err)
	}
	return database
}
