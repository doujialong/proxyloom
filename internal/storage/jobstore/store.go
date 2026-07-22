package jobstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrNotFound = errors.New("job not found")
	ErrConflict = errors.New("job state conflict")
)

type Status string

const (
	StatusQueued    Status = "queued"
	StatusLeased    Status = "leased"
	StatusRunning   Status = "running"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusDead      Status = "dead"
)

type Job struct {
	ID               string
	SourceID         string
	SourceRevisionID string
	Status           Status
	Priority         int
	DedupeKey        string
	LeaseOwner       string
	LeaseExpiresAt   *time.Time
	Attempt          int
	MaxAttempts      int
	ErrorCode        string
	ErrorDetail      string
	CorrelationID    string
	DueAt            time.Time
	CreatedAt        time.Time
	StartedAt        *time.Time
	FinishedAt       *time.Time
}

type Options struct {
	Now   func() time.Time
	NewID func() string
}

type Store struct {
	database *sql.DB
	now      func() time.Time
	newID    func() string
}

type EnqueueRequest struct {
	SourceID         string
	SourceRevisionID string
	DueAt            time.Time
	Priority         int
	MaxAttempts      int
	CorrelationID    string
	ExpediteExisting bool
}

func New(database *sql.DB, options Options) (*Store, error) {
	if database == nil || options.Now == nil || options.NewID == nil {
		return nil, fmt.Errorf("job store database, clock and ID generator are required")
	}
	return &Store{database: database, now: options.Now, newID: options.NewID}, nil
}

func (s *Store) Enqueue(ctx context.Context, request EnqueueRequest) (Job, error) {
	if !validID(request.SourceID) || !validID(request.SourceRevisionID) {
		return Job{}, ErrNotFound
	}
	if request.DueAt.IsZero() {
		request.DueAt = s.now().UTC()
	}
	if request.MaxAttempts == 0 {
		request.MaxAttempts = 3
	}
	if request.MaxAttempts < 1 || request.MaxAttempts > 20 || strings.TrimSpace(request.CorrelationID) == "" || len(request.CorrelationID) > 200 {
		return Job{}, fmt.Errorf("invalid job retry or correlation settings")
	}
	id := s.newID()
	if !validID(id) {
		return Job{}, fmt.Errorf("job ID generator returned an invalid ID")
	}
	now := s.now().UTC()
	dedupeKey := request.SourceID + ":" + request.SourceRevisionID
	job := Job{
		ID: id, SourceID: request.SourceID, SourceRevisionID: request.SourceRevisionID,
		Status: StatusQueued, Priority: request.Priority, DedupeKey: dedupeKey,
		MaxAttempts: request.MaxAttempts, CorrelationID: request.CorrelationID,
		DueAt: request.DueAt.UTC(), CreatedAt: now,
	}
	_, err := s.database.ExecContext(ctx, `
INSERT INTO jobs(
  id, job_type, source_id, source_revision_id, status, priority, dedupe_key,
  attempt, max_attempts, correlation_id, due_at, created_at
) VALUES (?, 'source_refresh', ?, ?, 'queued', ?, ?, 0, ?, ?, ?, ?)`,
		job.ID, job.SourceID, job.SourceRevisionID, job.Priority, job.DedupeKey,
		job.MaxAttempts, job.CorrelationID, job.DueAt.UnixMilli(), job.CreatedAt.UnixMilli(),
	)
	if err == nil {
		return job, nil
	}
	var existingID string
	lookupErr := s.database.QueryRowContext(ctx, `
SELECT id FROM jobs
WHERE job_type = 'source_refresh' AND dedupe_key = ?
  AND status IN ('queued', 'leased', 'running')`, dedupeKey).Scan(&existingID)
	if lookupErr == nil {
		if request.ExpediteExisting {
			if _, updateErr := s.database.ExecContext(ctx, `
UPDATE jobs
	SET due_at = MIN(due_at, ?), priority = MAX(priority, ?), correlation_id = ?
WHERE id = ? AND status = 'queued'`,
				job.DueAt.UnixMilli(), job.Priority, job.CorrelationID, existingID); updateErr != nil {
				return Job{}, fmt.Errorf("expedite queued source refresh: %w", updateErr)
			}
		}
		return s.Get(ctx, existingID)
	}
	return Job{}, fmt.Errorf("enqueue source refresh: %w", err)
}

func (s *Store) Claim(ctx context.Context, owner string, lease time.Duration) (Job, bool, error) {
	if strings.TrimSpace(owner) == "" || len(owner) > 200 || lease <= 0 {
		return Job{}, false, fmt.Errorf("valid lease owner and duration are required")
	}
	now := s.now().UTC()
	expires := now.Add(lease)
	row := s.database.QueryRowContext(ctx, `
UPDATE jobs
SET status = 'leased', lease_owner = ?, lease_expires_at = ?,
    attempt = attempt + 1, started_at = COALESCE(started_at, ?),
    error_code = NULL, error_detail = NULL
WHERE id = (
  SELECT id FROM jobs
  WHERE status = 'queued' AND due_at <= ?
  ORDER BY priority DESC, due_at, created_at, id
  LIMIT 1
)
RETURNING id, source_id, source_revision_id, status, priority, dedupe_key,
          lease_owner, lease_expires_at, attempt, max_attempts,
          COALESCE(error_code, ''), COALESCE(error_detail, ''), correlation_id,
          due_at, created_at, started_at, finished_at`,
		owner, expires.UnixMilli(), now.UnixMilli(), now.UnixMilli(),
	)
	job, err := scanJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, false, nil
	}
	if err != nil {
		return Job{}, false, fmt.Errorf("claim refresh job: %w", err)
	}
	return job, true, nil
}

func (s *Store) MarkRunning(ctx context.Context, id, owner string) (Job, error) {
	now := s.now().UTC()
	result, err := s.database.ExecContext(ctx, `
UPDATE jobs SET status = 'running'
WHERE id = ? AND status = 'leased' AND lease_owner = ? AND lease_expires_at > ?`,
		id, owner, now.UnixMilli())
	if err != nil {
		return Job{}, fmt.Errorf("start leased job: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return Job{}, ErrConflict
	}
	return s.Get(ctx, id)
}

func (s *Store) Complete(ctx context.Context, id, owner string) (Job, error) {
	return s.finish(ctx, id, owner, StatusSucceeded, "", "")
}

func (s *Store) Fail(ctx context.Context, id, owner, code, detail string) (Job, error) {
	if strings.TrimSpace(code) == "" || len(code) > 128 || len(detail) > 4096 {
		return Job{}, fmt.Errorf("bounded job error code is required")
	}
	return s.finish(ctx, id, owner, StatusFailed, code, detail)
}

func (s *Store) CancelQueuedSuperseded(ctx context.Context, sourceID, currentRevisionID string) (int64, error) {
	if !validID(sourceID) || !validID(currentRevisionID) {
		return 0, ErrNotFound
	}
	now := s.now().UTC()
	result, err := s.database.ExecContext(ctx, `
UPDATE jobs
SET status = 'dead', error_code = 'superseded_revision',
    error_detail = 'queued refresh belongs to a superseded source revision',
    finished_at = ?
WHERE job_type = 'source_refresh' AND source_id = ? AND source_revision_id <> ?
  AND status = 'queued'`, now.UnixMilli(), sourceID, currentRevisionID)
	if err != nil {
		return 0, fmt.Errorf("cancel superseded refresh jobs: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count cancelled superseded refresh jobs: %w", err)
	}
	return count, nil
}

func (s *Store) finish(ctx context.Context, id, owner string, status Status, code, detail string) (Job, error) {
	now := s.now().UTC()
	result, err := s.database.ExecContext(ctx, `
UPDATE jobs
SET status = ?, lease_owner = NULL, lease_expires_at = NULL,
    error_code = ?, error_detail = ?, finished_at = ?
WHERE id = ? AND status = 'running' AND lease_owner = ?`,
		string(status), nullableString(code), nullableString(detail), now.UnixMilli(), id, owner,
	)
	if err != nil {
		return Job{}, fmt.Errorf("finish refresh job: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return Job{}, ErrConflict
	}
	return s.Get(ctx, id)
}

func (s *Store) RecoverExpired(ctx context.Context) (int64, error) {
	now := s.now().UTC().UnixMilli()
	dead, err := s.database.ExecContext(ctx, `
UPDATE jobs
SET status = 'dead', lease_owner = NULL, lease_expires_at = NULL,
    error_code = 'lease_expired', error_detail = 'worker lease expired at process recovery',
    finished_at = ?
WHERE status IN ('leased', 'running') AND lease_expires_at <= ? AND attempt >= max_attempts`, now, now)
	if err != nil {
		return 0, fmt.Errorf("dead-letter expired jobs: %w", err)
	}
	queued, err := s.database.ExecContext(ctx, `
UPDATE jobs
SET status = 'queued', lease_owner = NULL, lease_expires_at = NULL,
    error_code = 'lease_expired', error_detail = 'worker lease expired and job was requeued',
    due_at = ?
WHERE status IN ('leased', 'running') AND lease_expires_at <= ? AND attempt < max_attempts`, now, now)
	if err != nil {
		return 0, fmt.Errorf("requeue expired jobs: %w", err)
	}
	deadCount, _ := dead.RowsAffected()
	queuedCount, _ := queued.RowsAffected()
	return deadCount + queuedCount, nil
}

func (s *Store) Get(ctx context.Context, id string) (Job, error) {
	if !validID(id) {
		return Job{}, ErrNotFound
	}
	job, err := scanJob(s.database.QueryRowContext(ctx, `
SELECT id, source_id, source_revision_id, status, priority, dedupe_key,
       COALESCE(lease_owner, ''), lease_expires_at, attempt, max_attempts,
       COALESCE(error_code, ''), COALESCE(error_detail, ''), correlation_id,
       due_at, created_at, started_at, finished_at
FROM jobs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	if err != nil {
		return Job{}, fmt.Errorf("read refresh job: %w", err)
	}
	return job, nil
}

func (s *Store) ActiveForSource(ctx context.Context, sourceID, revisionID string) (Job, bool, error) {
	if !validID(sourceID) || !validID(revisionID) {
		return Job{}, false, ErrNotFound
	}
	job, err := scanJob(s.database.QueryRowContext(ctx, `
SELECT id, source_id, source_revision_id, status, priority, dedupe_key,
       COALESCE(lease_owner, ''), lease_expires_at, attempt, max_attempts,
       COALESCE(error_code, ''), COALESCE(error_detail, ''), correlation_id,
       due_at, created_at, started_at, finished_at
FROM jobs
WHERE source_id = ? AND source_revision_id = ?
  AND status IN ('queued', 'leased', 'running')
ORDER BY due_at, created_at, id LIMIT 1`, sourceID, revisionID))
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, false, nil
	}
	if err != nil {
		return Job{}, false, fmt.Errorf("read active source refresh job: %w", err)
	}
	return job, true, nil
}

type scanner interface {
	Scan(dest ...interface{}) error
}

func scanJob(row scanner) (Job, error) {
	var job Job
	var status string
	var leaseExpires, started, finished sql.NullInt64
	var dueAt, createdAt int64
	if err := row.Scan(
		&job.ID, &job.SourceID, &job.SourceRevisionID, &status, &job.Priority, &job.DedupeKey,
		&job.LeaseOwner, &leaseExpires, &job.Attempt, &job.MaxAttempts,
		&job.ErrorCode, &job.ErrorDetail, &job.CorrelationID,
		&dueAt, &createdAt, &started, &finished,
	); err != nil {
		return Job{}, err
	}
	job.Status = Status(status)
	job.DueAt = time.UnixMilli(dueAt).UTC()
	job.CreatedAt = time.UnixMilli(createdAt).UTC()
	job.LeaseExpiresAt = timeFromNull(leaseExpires)
	job.StartedAt = timeFromNull(started)
	job.FinishedAt = timeFromNull(finished)
	return job, nil
}

func timeFromNull(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	result := time.UnixMilli(value.Int64).UTC()
	return &result
}

func nullableString(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}

func validID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}
