package retention

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/doujialong/proxyloom/internal/storage/blobstore"
)

const (
	DefaultOutputHistory   = 30
	DefaultSnapshotHistory = 30
	DefaultJobHistory      = 100
	DefaultBatchSize       = 5000
	DefaultBlobBatch       = 2000
	DefaultSnapshotBatch   = 200
	DefaultInterval        = 5 * time.Minute
	DefaultInitialDelay    = 30 * time.Second
	DefaultBlobGrace       = 5 * time.Minute
	DefaultSnapshotMaxAge  = 30 * 24 * time.Hour
	DefaultHealthMaxAge    = 30 * 24 * time.Hour
	DefaultBackupMaxAge    = 7 * 24 * time.Hour
	DefaultBackupHistory   = 1
)

type blobGarbageCollector interface {
	ReconcileGarbage(context.Context, time.Time) (blobstore.GarbageStats, error)
	SweepGarbage(context.Context, time.Time, int) (blobstore.GarbageStats, error)
}

type Options struct {
	Now             func() time.Time
	Log             func(string, ...interface{})
	Interval        time.Duration
	InitialDelay    time.Duration
	BlobGrace       time.Duration
	OutputHistory   int
	SnapshotHistory int
	JobHistory      int
	BatchSize       int
	BlobBatch       int
	SnapshotBatch   int
	SnapshotMaxAge  time.Duration
	HealthMaxAge    time.Duration
	BackupDir       string
	BackupMaxAge    time.Duration
	BackupHistory   int
}

type Stats struct {
	OutputArtifactsDeleted  int64
	SnapshotsDeleted        int64
	OutputJobsDeleted       int64
	SourceJobsDeleted       int64
	AttemptsDeleted         int64
	InactiveQueuesDeleted   int64
	InactiveStatesDeleted   int64
	FingerprintsDeleted     int64
	HealthRecordsDeleted    int64
	ControlRecordsDeleted   int64
	GuardWindowsDeleted     int64
	MigrationBackupsDeleted int64
	MigrationBackupBytes    int64
	BlobsMarked             int64
	BlobsUnmarked           int64
	BlobsDeleted            int
	BlobBytesDeleted        int64
}

func (s Stats) Changed() bool {
	return s.OutputArtifactsDeleted+s.SnapshotsDeleted+s.OutputJobsDeleted+
		s.SourceJobsDeleted+s.AttemptsDeleted+s.InactiveQueuesDeleted+
		s.InactiveStatesDeleted+s.FingerprintsDeleted+
		s.HealthRecordsDeleted+s.ControlRecordsDeleted+s.GuardWindowsDeleted+
		s.MigrationBackupsDeleted+
		s.BlobsMarked+s.BlobsUnmarked+int64(s.BlobsDeleted) > 0
}

type Cleaner struct {
	database *sql.DB
	blobs    blobGarbageCollector
	options  Options
}

func New(database *sql.DB, blobs blobGarbageCollector, options Options) (*Cleaner, error) {
	if database == nil || blobs == nil {
		return nil, fmt.Errorf("retention database and blob collector are required")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Log == nil {
		options.Log = func(string, ...interface{}) {}
	}
	if options.Interval <= 0 {
		options.Interval = DefaultInterval
	}
	if options.InitialDelay <= 0 {
		options.InitialDelay = DefaultInitialDelay
	}
	if options.BlobGrace <= 0 {
		options.BlobGrace = DefaultBlobGrace
	}
	if options.OutputHistory <= 0 {
		options.OutputHistory = DefaultOutputHistory
	}
	if options.SnapshotHistory <= 0 {
		options.SnapshotHistory = DefaultSnapshotHistory
	}
	if options.JobHistory <= 0 {
		options.JobHistory = DefaultJobHistory
	}
	if options.BatchSize <= 0 {
		options.BatchSize = DefaultBatchSize
	}
	if options.BlobBatch <= 0 {
		options.BlobBatch = DefaultBlobBatch
	}
	if options.SnapshotBatch <= 0 {
		options.SnapshotBatch = DefaultSnapshotBatch
	}
	if options.SnapshotMaxAge <= 0 {
		options.SnapshotMaxAge = DefaultSnapshotMaxAge
	}
	if options.HealthMaxAge <= 0 {
		options.HealthMaxAge = DefaultHealthMaxAge
	}
	if options.BackupMaxAge <= 0 {
		options.BackupMaxAge = DefaultBackupMaxAge
	}
	if options.BackupHistory <= 0 {
		options.BackupHistory = DefaultBackupHistory
	}
	if options.OutputHistory < 1 || options.OutputHistory > 1000 ||
		options.SnapshotHistory < 1 || options.SnapshotHistory > 1000 ||
		options.JobHistory < 1 || options.JobHistory > 10000 ||
		options.BatchSize < 1 || options.BatchSize > 10000 ||
		options.BlobBatch < 1 || options.BlobBatch > 10000 ||
		options.SnapshotBatch < 1 || options.SnapshotBatch > 1000 ||
		options.BackupHistory < 1 || options.BackupHistory > 100 ||
		options.BlobGrace < 2*time.Minute {
		return nil, fmt.Errorf("invalid retention limits or blob grace shorter than the maximum worker lease")
	}
	return &Cleaner{database: database, blobs: blobs, options: options}, nil
}

func (c *Cleaner) Run(ctx context.Context) {
	timer := time.NewTimer(c.options.InitialDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		stats, err := c.RunOnce(ctx)
		if err != nil {
			c.options.Log("retention cleanup failed: %v", err)
		} else if stats.Changed() {
			c.options.Log("retention cleanup: artifacts=%d snapshots=%d output_jobs=%d source_jobs=%d attempts=%d inactive_queues=%d inactive_states=%d fingerprints=%d health_records=%d control_records=%d guard_windows=%d migration_backups=%d migration_backup_bytes=%d blobs_marked=%d blobs_unmarked=%d blobs_deleted=%d blob_bytes_deleted=%d",
				stats.OutputArtifactsDeleted, stats.SnapshotsDeleted, stats.OutputJobsDeleted,
				stats.SourceJobsDeleted, stats.AttemptsDeleted, stats.InactiveQueuesDeleted,
				stats.InactiveStatesDeleted, stats.FingerprintsDeleted, stats.HealthRecordsDeleted,
				stats.ControlRecordsDeleted, stats.GuardWindowsDeleted,
				stats.MigrationBackupsDeleted, stats.MigrationBackupBytes,
				stats.BlobsMarked, stats.BlobsUnmarked, stats.BlobsDeleted, stats.BlobBytesDeleted)
		}
		timer.Reset(c.options.Interval)
	}
}

func (c *Cleaner) RunOnce(ctx context.Context) (Stats, error) {
	if c == nil || c.database == nil || c.blobs == nil {
		return Stats{}, fmt.Errorf("retention cleaner is not initialized")
	}
	now := c.options.Now().UTC()
	if now.IsZero() {
		return Stats{}, fmt.Errorf("retention clock returned zero time")
	}
	var stats Stats
	var err error
	if stats.OutputArtifactsDeleted, err = c.pruneOutputArtifacts(ctx); err != nil {
		return stats, err
	}
	if stats.HealthRecordsDeleted, stats.ControlRecordsDeleted, stats.GuardWindowsDeleted, err = c.pruneOldHealth(ctx, now); err != nil {
		return stats, err
	}
	if stats.SnapshotsDeleted, err = c.pruneSnapshots(ctx, now); err != nil {
		return stats, err
	}
	if stats.OutputJobsDeleted, err = c.pruneOutputJobs(ctx); err != nil {
		return stats, err
	}
	if stats.SourceJobsDeleted, err = c.pruneSourceJobs(ctx); err != nil {
		return stats, err
	}
	if stats.AttemptsDeleted, err = c.pruneAttempts(ctx); err != nil {
		return stats, err
	}
	if stats.InactiveQueuesDeleted, stats.InactiveStatesDeleted, err = c.pruneInactiveHealth(ctx); err != nil {
		return stats, err
	}
	if stats.FingerprintsDeleted, err = c.pruneFingerprints(ctx); err != nil {
		return stats, err
	}
	if stats.MigrationBackupsDeleted, stats.MigrationBackupBytes, err = c.pruneMigrationBackups(now); err != nil {
		return stats, err
	}
	garbage, err := c.blobs.ReconcileGarbage(ctx, now.Add(c.options.BlobGrace))
	if err != nil {
		return stats, err
	}
	stats.BlobsMarked, stats.BlobsUnmarked = garbage.Marked, garbage.Unmarked
	swept, err := c.blobs.SweepGarbage(ctx, now, c.options.BlobBatch)
	if err != nil {
		return stats, err
	}
	stats.BlobsDeleted, stats.BlobBytesDeleted = swept.Deleted, swept.DeletedBytes
	if stats.Changed() {
		var busy, logFrames, checkpointed int
		if checkpointErr := c.database.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed); checkpointErr != nil {
			c.options.Log("retention WAL checkpoint failed: %v", checkpointErr)
		} else if busy != 0 {
			c.options.Log("retention WAL checkpoint deferred: busy=%d log_frames=%d checkpointed=%d", busy, logFrames, checkpointed)
		}
	}
	return stats, nil
}

func (c *Cleaner) pruneMigrationBackups(now time.Time) (int64, int64, error) {
	if c.options.BackupDir == "" {
		return 0, 0, nil
	}
	entries, err := os.ReadDir(c.options.BackupDir)
	if err != nil {
		return 0, 0, fmt.Errorf("list migration backups: %w", err)
	}
	type backup struct {
		name    string
		modTime time.Time
		size    int64
	}
	backups := make([]backup, 0, len(entries))
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() || !strings.HasPrefix(entry.Name(), "schema-v") || !strings.HasSuffix(entry.Name(), ".db") {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return 0, 0, fmt.Errorf("inspect migration backup: %w", infoErr)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		backups = append(backups, backup{name: entry.Name(), modTime: info.ModTime(), size: info.Size()})
	}
	sort.Slice(backups, func(i, j int) bool {
		if !backups[i].modTime.Equal(backups[j].modTime) {
			return backups[i].modTime.After(backups[j].modTime)
		}
		return backups[i].name > backups[j].name
	})
	cutoff := now.Add(-c.options.BackupMaxAge)
	var deleted, deletedBytes int64
	for index, item := range backups {
		if index < c.options.BackupHistory && !item.modTime.Before(cutoff) {
			continue
		}
		if deleted >= int64(c.options.BatchSize) {
			break
		}
		if err := os.Remove(filepath.Join(c.options.BackupDir, item.name)); err != nil {
			return deleted, deletedBytes, fmt.Errorf("remove migration backup: %w", err)
		}
		deleted++
		deletedBytes += item.size
	}
	if deleted > 0 {
		directory, err := os.Open(c.options.BackupDir)
		if err != nil {
			return deleted, deletedBytes, fmt.Errorf("open migration backup directory: %w", err)
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil {
			return deleted, deletedBytes, fmt.Errorf("sync migration backup directory: %w", syncErr)
		}
		if closeErr != nil {
			return deleted, deletedBytes, fmt.Errorf("close migration backup directory: %w", closeErr)
		}
	}
	return deleted, deletedBytes, nil
}

func (c *Cleaner) pruneOutputArtifacts(ctx context.Context) (int64, error) {
	result, err := c.database.ExecContext(ctx, `
DELETE FROM managed_output_artifacts
WHERE id IN (
  SELECT id FROM (
    SELECT a.id, a.output_id, a.build_sequence,
           ROW_NUMBER() OVER (
             PARTITION BY a.output_id ORDER BY a.build_sequence DESC, a.id DESC
           ) AS retention_rank
    FROM managed_output_artifacts a
  ) ranked
  WHERE retention_rank > ?
    AND NOT EXISTS (
      SELECT 1 FROM managed_outputs o WHERE o.current_artifact_id = ranked.id
    )
  ORDER BY output_id, build_sequence
  LIMIT ?
)`, c.options.OutputHistory, c.options.BatchSize)
	if err != nil {
		return 0, fmt.Errorf("prune managed output artifacts: %w", err)
	}
	count, _ := result.RowsAffected()
	return count, nil
}

func (c *Cleaner) pruneSnapshots(ctx context.Context, now time.Time) (int64, error) {
	rows, err := c.database.QueryContext(ctx, `
WITH ranked AS (
  SELECT sn.id, sn.source_id, sn.accepted_at,
         ROW_NUMBER() OVER (
           PARTITION BY sn.source_id ORDER BY sn.accepted_at DESC, sn.id DESC
         ) AS retention_rank
  FROM snapshots sn
)
SELECT ranked.id
FROM ranked JOIN sources source ON source.id = ranked.source_id
WHERE ranked.id <> COALESCE(source.current_snapshot_id, '')
  AND (ranked.retention_rank > ? OR ranked.accepted_at < ?)
  AND NOT EXISTS (
    SELECT 1 FROM source_publications publication
    JOIN artifacts artifact ON artifact.id = publication.current_artifact_id
    WHERE artifact.snapshot_id = ranked.id
  )
  AND NOT EXISTS (
    SELECT 1 FROM health_records record
    JOIN node_health_states state ON state.latest_record_id = record.id
    WHERE record.snapshot_id = ranked.id
  )
ORDER BY ranked.accepted_at, ranked.id
LIMIT ?`, c.options.SnapshotHistory, now.Add(-c.options.SnapshotMaxAge).UnixMilli(), c.options.SnapshotBatch)
	if err != nil {
		return 0, fmt.Errorf("list expired snapshots: %w", err)
	}
	ids := make([]string, 0, c.options.SnapshotBatch)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan expired snapshot: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close expired snapshot rows: %w", err)
	}
	var deleted int64
	for _, id := range ids {
		removed, err := c.pruneSnapshot(ctx, id)
		if err != nil {
			return deleted, err
		}
		if removed {
			deleted++
		}
	}
	return deleted, nil
}

func (c *Cleaner) pruneSnapshot(ctx context.Context, id string) (bool, error) {
	tx, err := c.database.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin snapshot cleanup: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "PRAGMA defer_foreign_keys = ON"); err != nil {
		return false, fmt.Errorf("defer snapshot cleanup foreign keys: %w", err)
	}
	var rawDocumentID, refreshAttemptID string
	err = tx.QueryRowContext(ctx, `
SELECT snapshot.raw_document_id, snapshot.refresh_attempt_id
FROM snapshots snapshot
WHERE snapshot.id = ?
  AND NOT EXISTS (
    SELECT 1 FROM sources source WHERE source.current_snapshot_id = snapshot.id
  )
  AND NOT EXISTS (
    SELECT 1 FROM source_publications publication
    JOIN artifacts artifact ON artifact.id = publication.current_artifact_id
    WHERE artifact.snapshot_id = snapshot.id
  )
  AND NOT EXISTS (
    SELECT 1 FROM health_records record
    JOIN node_health_states state ON state.latest_record_id = record.id
    WHERE record.snapshot_id = snapshot.id
  )`, id).Scan(&rawDocumentID, &refreshAttemptID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("verify expired snapshot: %w", err)
	}
	statements := []struct {
		query string
		args  []interface{}
	}{
		{`DELETE FROM health_records WHERE snapshot_id = ?`, []interface{}{id}},
		{`DELETE FROM canonical_nodes WHERE raw_node_id IN (SELECT id FROM raw_nodes WHERE snapshot_id = ?)`, []interface{}{id}},
		{`DELETE FROM snapshot_occurrences WHERE snapshot_id = ?`, []interface{}{id}},
		{`DELETE FROM raw_nodes WHERE snapshot_id = ?`, []interface{}{id}},
		{`DELETE FROM artifacts WHERE snapshot_id = ?`, []interface{}{id}},
		{`DELETE FROM snapshots WHERE id = ?`, []interface{}{id}},
		{`DELETE FROM refresh_attempts WHERE accepted_snapshot_id = ? OR id = ?`, []interface{}{id, refreshAttemptID}},
		{`DELETE FROM raw_documents WHERE id = ?`, []interface{}{rawDocumentID}},
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
			return false, fmt.Errorf("delete expired snapshot graph: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit snapshot cleanup: %w", err)
	}
	return true, nil
}

func (c *Cleaner) pruneOutputJobs(ctx context.Context) (int64, error) {
	return c.pruneRanked(ctx, `
DELETE FROM managed_output_build_jobs WHERE id IN (
  SELECT id FROM (
    SELECT id, status,
           ROW_NUMBER() OVER (PARTITION BY output_id ORDER BY created_at DESC, id DESC) retention_rank
    FROM managed_output_build_jobs
  ) ranked
  WHERE retention_rank > ? AND status IN ('succeeded', 'failed', 'dead')
  LIMIT ?
)`, "managed output build jobs")
}

func (c *Cleaner) pruneSourceJobs(ctx context.Context) (int64, error) {
	return c.pruneRanked(ctx, `
DELETE FROM jobs WHERE id IN (
  SELECT id FROM (
    SELECT id, status,
           ROW_NUMBER() OVER (PARTITION BY source_id ORDER BY created_at DESC, id DESC) retention_rank
    FROM jobs
  ) ranked
  WHERE retention_rank > ? AND status IN ('succeeded', 'failed', 'cancelled', 'dead')
  LIMIT ?
)`, "source refresh jobs")
}

func (c *Cleaner) pruneAttempts(ctx context.Context) (int64, error) {
	return c.pruneRanked(ctx, `
DELETE FROM refresh_attempts WHERE id IN (
  SELECT id FROM (
    SELECT id, status, accepted_snapshot_id,
           ROW_NUMBER() OVER (PARTITION BY source_id ORDER BY started_at DESC, id DESC) retention_rank
    FROM refresh_attempts
  ) ranked
	  WHERE retention_rank > ? AND status <> 'running'
	    AND NOT EXISTS (
	      SELECT 1 FROM snapshots snapshot WHERE snapshot.refresh_attempt_id = ranked.id
	    )
  LIMIT ?
)`, "refresh attempts")
}

func (c *Cleaner) pruneOldHealth(ctx context.Context, now time.Time) (int64, int64, int64, error) {
	cutoff := now.Add(-c.options.HealthMaxAge).UnixMilli()
	tx, err := c.database.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("begin health history cleanup: %w", err)
	}
	defer tx.Rollback()
	health, err := tx.ExecContext(ctx, `
DELETE FROM health_records WHERE id IN (
  SELECT record.id FROM health_records record
  WHERE record.observed_at < ?
    AND NOT EXISTS (
      SELECT 1 FROM node_health_states state WHERE state.latest_record_id = record.id
    )
  ORDER BY record.observed_at, record.id
  LIMIT ?
)`, cutoff, c.options.BatchSize)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("prune health records: %w", err)
	}
	control, err := tx.ExecContext(ctx, `
DELETE FROM control_probe_records WHERE id IN (
  SELECT id FROM control_probe_records
  WHERE observed_at < ? ORDER BY observed_at, id LIMIT ?
)`, cutoff, c.options.BatchSize)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("prune control probe records: %w", err)
	}
	guard, err := tx.ExecContext(ctx, `
DELETE FROM health_guard_windows WHERE window_start IN (
  SELECT window_start FROM health_guard_windows
  WHERE window_end < ? ORDER BY window_start LIMIT ?
)`, cutoff, c.options.BatchSize)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("prune health guard windows: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, 0, fmt.Errorf("commit health history cleanup: %w", err)
	}
	healthCount, _ := health.RowsAffected()
	controlCount, _ := control.RowsAffected()
	guardCount, _ := guard.RowsAffected()
	return healthCount, controlCount, guardCount, nil
}

func (c *Cleaner) pruneInactiveHealth(ctx context.Context) (int64, int64, error) {
	tx, err := c.database.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("begin inactive health cleanup: %w", err)
	}
	defer tx.Rollback()
	queues, err := tx.ExecContext(ctx, `
DELETE FROM probe_queue_items
WHERE status IN ('dormant', 'queued')
  AND node_occurrence_id IN (
    SELECT occurrence.id
    FROM node_occurrences occurrence
    JOIN sources source ON source.id = occurrence.source_id
    WHERE occurrence.lifecycle_state <> 'present'
       OR source.lifecycle_state <> 'active'
  )`)
	if err != nil {
		return 0, 0, fmt.Errorf("prune inactive health queues: %w", err)
	}
	states, err := tx.ExecContext(ctx, `
DELETE FROM node_health_states
WHERE node_occurrence_id IN (
  SELECT occurrence.id
  FROM node_occurrences occurrence
  JOIN sources source ON source.id = occurrence.source_id
  WHERE occurrence.lifecycle_state <> 'present'
     OR source.lifecycle_state <> 'active'
)
AND NOT EXISTS (
  SELECT 1 FROM probe_queue_items queue
  WHERE queue.node_occurrence_id = node_health_states.node_occurrence_id
    AND queue.status IN ('leased', 'running')
)`)
	if err != nil {
		return 0, 0, fmt.Errorf("prune inactive health states: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit inactive health cleanup: %w", err)
	}
	queueCount, _ := queues.RowsAffected()
	stateCount, _ := states.RowsAffected()
	return queueCount, stateCount, nil
}

func (c *Cleaner) pruneRanked(ctx context.Context, query, label string) (int64, error) {
	result, err := c.database.ExecContext(ctx, query, c.options.JobHistory, c.options.BatchSize)
	if err != nil {
		return 0, fmt.Errorf("prune %s: %w", label, err)
	}
	count, _ := result.RowsAffected()
	return count, nil
}

func (c *Cleaner) pruneFingerprints(ctx context.Context) (int64, error) {
	result, err := c.database.ExecContext(ctx, `
DELETE FROM fingerprints WHERE id IN (
  SELECT fingerprint.id FROM fingerprints fingerprint
  WHERE NOT EXISTS (SELECT 1 FROM raw_nodes node WHERE node.fingerprint_id = fingerprint.id)
    AND NOT EXISTS (SELECT 1 FROM node_occurrences occurrence WHERE occurrence.current_fingerprint_id = fingerprint.id)
  ORDER BY fingerprint.created_at, fingerprint.id
  LIMIT ?
)`, c.options.BatchSize)
	if err != nil {
		return 0, fmt.Errorf("prune unreferenced fingerprints: %w", err)
	}
	count, _ := result.RowsAffected()
	return count, nil
}
