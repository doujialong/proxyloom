package retention

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/doujialong/proxyloom/internal/storage/blobstore"
	storagesqlite "github.com/doujialong/proxyloom/internal/storage/sqlite"
)

type fakeBlobCollector struct{}

func (fakeBlobCollector) ReconcileGarbage(context.Context, time.Time) (blobstore.GarbageStats, error) {
	return blobstore.GarbageStats{}, nil
}

func (fakeBlobCollector) SweepGarbage(context.Context, time.Time, int) (blobstore.GarbageStats, error) {
	return blobstore.GarbageStats{}, nil
}

func TestPruneOutputArtifactsKeepsNewestAndCurrentRollback(t *testing.T) {
	database := openRetentionDatabase(t, `
CREATE TABLE managed_outputs(id TEXT PRIMARY KEY, current_artifact_id TEXT);
CREATE TABLE managed_output_artifacts(
  id TEXT PRIMARY KEY, output_id TEXT NOT NULL, build_sequence INTEGER NOT NULL
);`)
	defer database.Close()
	if _, err := database.Exec("INSERT INTO managed_outputs VALUES ('output', 'artifact-01')"); err != nil {
		t.Fatal(err)
	}
	for sequence := 1; sequence <= 35; sequence++ {
		if _, err := database.Exec(
			"INSERT INTO managed_output_artifacts VALUES (?, 'output', ?)",
			fmt.Sprintf("artifact-%02d", sequence), sequence,
		); err != nil {
			t.Fatal(err)
		}
	}
	cleaner := newTestCleaner(t, database, Options{OutputHistory: 30, BatchSize: 100})
	deleted, err := cleaner.pruneOutputArtifacts(context.Background())
	if err != nil || deleted != 4 {
		t.Fatalf("pruneOutputArtifacts() = %d, %v", deleted, err)
	}
	var remaining, current int
	if err := database.QueryRow("SELECT count(*) FROM managed_output_artifacts").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow("SELECT count(*) FROM managed_output_artifacts WHERE id = 'artifact-01'").Scan(&current); err != nil {
		t.Fatal(err)
	}
	if remaining != 31 || current != 1 {
		t.Fatalf("remaining/current = %d/%d, want 31/1", remaining, current)
	}
}

func TestPruneSnapshotsDeletesOnlyExpiredGraph(t *testing.T) {
	database := openRetentionDatabase(t, `
CREATE TABLE sources(id TEXT PRIMARY KEY, current_snapshot_id TEXT);
CREATE TABLE snapshots(
  id TEXT PRIMARY KEY, source_id TEXT NOT NULL, raw_document_id TEXT NOT NULL,
  refresh_attempt_id TEXT NOT NULL, accepted_at INTEGER NOT NULL
);
CREATE TABLE source_publications(source_id TEXT PRIMARY KEY, current_artifact_id TEXT NOT NULL);
CREATE TABLE artifacts(id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL);
CREATE TABLE health_records(id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL);
CREATE TABLE node_health_states(latest_record_id TEXT);
CREATE TABLE raw_documents(id TEXT PRIMARY KEY);
CREATE TABLE raw_nodes(id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL);
CREATE TABLE canonical_nodes(raw_node_id TEXT PRIMARY KEY);
CREATE TABLE snapshot_occurrences(snapshot_id TEXT NOT NULL);
CREATE TABLE refresh_attempts(id TEXT PRIMARY KEY, accepted_snapshot_id TEXT);
`)
	defer database.Close()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	if _, err := database.Exec("INSERT INTO sources VALUES ('source', 'snapshot-04')"); err != nil {
		t.Fatal(err)
	}
	for sequence := 1; sequence <= 4; sequence++ {
		snapshotID := fmt.Sprintf("snapshot-%02d", sequence)
		documentID := fmt.Sprintf("document-%02d", sequence)
		attemptID := fmt.Sprintf("attempt-%02d", sequence)
		if _, err := database.Exec("INSERT INTO raw_documents VALUES (?)", documentID); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec("INSERT INTO refresh_attempts VALUES (?, ?)", attemptID, snapshotID); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(
			"INSERT INTO snapshots VALUES (?, 'source', ?, ?, ?)",
			snapshotID, documentID, attemptID, now.Add(time.Duration(sequence)*time.Minute).UnixMilli(),
		); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.Exec(`
INSERT INTO raw_nodes VALUES ('node-old', 'snapshot-01');
INSERT INTO canonical_nodes VALUES ('node-old');
INSERT INTO snapshot_occurrences VALUES ('snapshot-01');
INSERT INTO health_records VALUES ('health-old', 'snapshot-01');
INSERT INTO artifacts VALUES ('artifact-old', 'snapshot-01');
INSERT INTO artifacts VALUES ('artifact-current', 'snapshot-04');
INSERT INTO source_publications VALUES ('source', 'artifact-current');
INSERT INTO refresh_attempts VALUES ('attempt-not-modified', 'snapshot-01');
`); err != nil {
		t.Fatal(err)
	}
	cleaner := newTestCleaner(t, database, Options{
		Now: func() time.Time { return now }, SnapshotHistory: 3,
		SnapshotBatch: 10, SnapshotMaxAge: 30 * 24 * time.Hour,
	})
	deleted, err := cleaner.pruneSnapshots(context.Background(), now)
	if err != nil || deleted != 1 {
		t.Fatalf("pruneSnapshots() = %d, %v", deleted, err)
	}
	for table, want := range map[string]int{
		"snapshots": 3, "raw_documents": 3, "refresh_attempts": 3,
		"raw_nodes": 0, "canonical_nodes": 0, "snapshot_occurrences": 0,
		"health_records": 0, "artifacts": 1,
	} {
		var count int
		if err := database.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != want {
			t.Fatalf("%s count = %d, want %d", table, count, want)
		}
	}
	removed, err := cleaner.pruneSnapshot(context.Background(), "snapshot-04")
	if err != nil || removed {
		t.Fatalf("current pruneSnapshot() = %v, %v", removed, err)
	}
}

func TestPruneInactiveHealthKeepsCurrentNodes(t *testing.T) {
	database := openRetentionDatabase(t, `
CREATE TABLE node_occurrences(id TEXT PRIMARY KEY, lifecycle_state TEXT NOT NULL);
CREATE TABLE probe_queue_items(node_occurrence_id TEXT PRIMARY KEY, status TEXT NOT NULL);
CREATE TABLE node_health_states(node_occurrence_id TEXT PRIMARY KEY);
`)
	defer database.Close()
	if _, err := database.Exec(`
INSERT INTO node_occurrences VALUES ('present', 'present'), ('absent', 'absent');
INSERT INTO probe_queue_items VALUES ('present', 'queued'), ('absent', 'dormant');
INSERT INTO node_health_states VALUES ('present'), ('absent');
`); err != nil {
		t.Fatal(err)
	}
	cleaner := newTestCleaner(t, database, Options{})
	queues, states, err := cleaner.pruneInactiveHealth(context.Background())
	if err != nil || queues != 1 || states != 1 {
		t.Fatalf("pruneInactiveHealth() = %d, %d, %v", queues, states, err)
	}
	for _, table := range []string{"probe_queue_items", "node_health_states"} {
		var count int
		if err := database.QueryRow("SELECT count(*) FROM " + table + " WHERE node_occurrence_id = 'present'").Scan(&count); err != nil || count != 1 {
			t.Fatalf("present %s count = %d, %v", table, count, err)
		}
	}
}

func TestPruneAttemptsKeepsSnapshotOwnerButDeletesReusedHistory(t *testing.T) {
	database := openRetentionDatabase(t, `
CREATE TABLE refresh_attempts(
  id TEXT PRIMARY KEY, source_id TEXT NOT NULL, status TEXT NOT NULL,
  accepted_snapshot_id TEXT, started_at INTEGER NOT NULL
);
CREATE TABLE snapshots(refresh_attempt_id TEXT PRIMARY KEY);
`)
	defer database.Close()
	if _, err := database.Exec(`
INSERT INTO refresh_attempts VALUES
  ('attempt-1', 'source', 'succeeded', 'snapshot', 1),
  ('attempt-2', 'source', 'succeeded', 'snapshot', 2),
  ('attempt-3', 'source', 'succeeded', 'snapshot', 3),
  ('attempt-4', 'source', 'succeeded', 'snapshot', 4);
INSERT INTO snapshots VALUES ('attempt-1');
`); err != nil {
		t.Fatal(err)
	}
	cleaner := newTestCleaner(t, database, Options{JobHistory: 2, BatchSize: 10})
	deleted, err := cleaner.pruneAttempts(context.Background())
	if err != nil || deleted != 1 {
		t.Fatalf("pruneAttempts() = %d, %v", deleted, err)
	}
	for id, want := range map[string]int{"attempt-1": 1, "attempt-2": 0, "attempt-3": 1, "attempt-4": 1} {
		var count int
		if err := database.QueryRow(`SELECT count(*) FROM refresh_attempts WHERE id = ?`, id).Scan(&count); err != nil || count != want {
			t.Fatalf("attempt %s count = %d, %v; want %d", id, count, err, want)
		}
	}
}

func TestPruneOldHealthHonorsAgeAndLatestRecord(t *testing.T) {
	database := openRetentionDatabase(t, `
CREATE TABLE health_records(id TEXT PRIMARY KEY, observed_at INTEGER NOT NULL);
CREATE TABLE node_health_states(latest_record_id TEXT);
CREATE TABLE control_probe_records(id TEXT PRIMARY KEY, observed_at INTEGER NOT NULL);
CREATE TABLE health_guard_windows(window_start INTEGER PRIMARY KEY, window_end INTEGER NOT NULL);
`)
	defer database.Close()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	old := now.Add(-31 * 24 * time.Hour).UnixMilli()
	recent := now.Add(-time.Hour).UnixMilli()
	statements := []struct {
		query string
		args  []interface{}
	}{
		{`INSERT INTO health_records VALUES ('old', ?), ('latest-old', ?), ('recent', ?)`, []interface{}{old, old, recent}},
		{`INSERT INTO node_health_states VALUES ('latest-old')`, nil},
		{`INSERT INTO control_probe_records VALUES ('old-control', ?), ('recent-control', ?)`, []interface{}{old, recent}},
		{`INSERT INTO health_guard_windows VALUES (?, ?), (?, ?)`, []interface{}{old, old + 1, recent, recent + 1}},
	}
	for _, statement := range statements {
		if _, err := database.Exec(statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	cleaner := newTestCleaner(t, database, Options{Now: func() time.Time { return now }, HealthMaxAge: 30 * 24 * time.Hour, BatchSize: 10})
	health, control, guard, err := cleaner.pruneOldHealth(context.Background(), now)
	if err != nil || health != 1 || control != 1 || guard != 1 {
		t.Fatalf("pruneOldHealth() = %d, %d, %d, %v", health, control, guard, err)
	}
	for table, want := range map[string]int{"health_records": 2, "control_probe_records": 1, "health_guard_windows": 1} {
		var count int
		if err := database.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != want {
			t.Fatalf("%s count = %d, %v; want %d", table, count, err, want)
		}
	}
}

func TestPruneMigrationBackupsKeepsNewestTemporarily(t *testing.T) {
	database := openRetentionDatabase(t, `CREATE TABLE fixture(id INTEGER);`)
	defer database.Close()
	directory := t.TempDir()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	files := []struct {
		name string
		age  time.Duration
		size int
	}{
		{"schema-v9-to-v10-old.db", 10 * 24 * time.Hour, 10},
		{"schema-v10-to-v11-middle.db", 24 * time.Hour, 20},
		{"schema-v11-to-v12-new.db", time.Hour, 30},
		{"managed-user-backup.db", 20 * 24 * time.Hour, 40},
	}
	for _, item := range files {
		path := filepath.Join(directory, item.name)
		if err := os.WriteFile(path, make([]byte, item.size), 0o600); err != nil {
			t.Fatal(err)
		}
		modified := now.Add(-item.age)
		if err := os.Chtimes(path, modified, modified); err != nil {
			t.Fatal(err)
		}
	}
	cleaner := newTestCleaner(t, database, Options{
		Now: func() time.Time { return now }, BackupDir: directory,
		BackupHistory: 1, BackupMaxAge: 7 * 24 * time.Hour, BatchSize: 10,
	})
	deleted, bytesDeleted, err := cleaner.pruneMigrationBackups(now)
	if err != nil || deleted != 2 || bytesDeleted != 30 {
		t.Fatalf("pruneMigrationBackups() = %d, %d, %v", deleted, bytesDeleted, err)
	}
	for name, want := range map[string]bool{
		"schema-v9-to-v10-old.db": false, "schema-v10-to-v11-middle.db": false,
		"schema-v11-to-v12-new.db": true, "managed-user-backup.db": true,
	} {
		_, statErr := os.Stat(filepath.Join(directory, name))
		if exists := statErr == nil; exists != want {
			t.Fatalf("backup %s exists=%v, want %v (error %v)", name, exists, want, statErr)
		}
	}
	deleted, bytesDeleted, err = cleaner.pruneMigrationBackups(now.Add(8 * 24 * time.Hour))
	if err != nil || deleted != 1 || bytesDeleted != 30 {
		t.Fatalf("expired pruneMigrationBackups() = %d, %d, %v", deleted, bytesDeleted, err)
	}
}

func newTestCleaner(t *testing.T, database *sql.DB, options Options) *Cleaner {
	t.Helper()
	if options.Now == nil {
		options.Now = func() time.Time { return time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC) }
	}
	if options.BlobGrace == 0 {
		options.BlobGrace = 5 * time.Minute
	}
	cleaner, err := New(database, fakeBlobCollector{}, options)
	if err != nil {
		t.Fatal(err)
	}
	return cleaner
}

func openRetentionDatabase(t *testing.T, schema string) *sql.DB {
	t.Helper()
	database, err := sql.Open(storagesqlite.DriverName, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	if _, err := database.Exec(schema); err != nil {
		database.Close()
		t.Fatal(err)
	}
	return database
}
