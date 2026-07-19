package outputjobstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrNotFound = errors.New("managed output build job not found")
	ErrConflict = errors.New("managed output build job state conflict")
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
	ID              string
	OutputID        string
	TriggerKind     string
	TriggerSourceID string
	Status          Status
	Priority        int
	DedupeKey       string
	LeaseOwner      string
	LeaseExpiresAt  *time.Time
	Attempt         int
	MaxAttempts     int
	ErrorCode       string
	ErrorDetail     string
	CorrelationID   string
	DueAt           time.Time
	CreatedAt       time.Time
	StartedAt       *time.Time
	FinishedAt      *time.Time
}

type EnqueueRequest struct {
	OutputID        string
	TriggerKind     string
	TriggerSourceID string
	Priority        int
	MaxAttempts     int
	CorrelationID   string
	DueAt           time.Time
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

func New(database *sql.DB, options Options) (*Store, error) {
	if database == nil || options.Now == nil || options.NewID == nil {
		return nil, fmt.Errorf("managed output job store dependencies are required")
	}
	return &Store{database: database, now: options.Now, newID: options.NewID}, nil
}

func (s *Store) Enqueue(ctx context.Context, request EnqueueRequest) (Job, error) {
	if !validID(request.OutputID) || request.TriggerSourceID != "" && !validID(request.TriggerSourceID) ||
		request.TriggerKind != "manual" && request.TriggerKind != "source_refresh" &&
			request.TriggerKind != "health_boundary" && request.TriggerKind != "collection_update" {
		return Job{}, fmt.Errorf("invalid managed output build trigger")
	}
	if request.MaxAttempts == 0 {
		request.MaxAttempts = 3
	}
	if request.MaxAttempts < 1 || request.MaxAttempts > 20 || strings.TrimSpace(request.CorrelationID) == "" || len(request.CorrelationID) > 200 {
		return Job{}, fmt.Errorf("invalid managed output build retry or correlation settings")
	}
	if request.DueAt.IsZero() {
		request.DueAt = s.now().UTC()
	}
	id := s.newID()
	if !validID(id) {
		return Job{}, fmt.Errorf("managed output build job ID generator returned an invalid ID")
	}
	now := s.now().UTC()
	_, err := s.database.ExecContext(ctx, `
INSERT INTO managed_output_build_jobs(
  id, output_id, trigger_kind, trigger_source_id, status, priority, dedupe_key,
  attempt, max_attempts, correlation_id, due_at, created_at
)
SELECT ?, id, ?, ?, 'queued', ?, ?, 0, ?, ?, ?, ?
FROM managed_outputs WHERE id = ? AND lifecycle_state = 'active'`,
		id, request.TriggerKind, nullableString(request.TriggerSourceID), request.Priority, request.OutputID,
		request.MaxAttempts, request.CorrelationID, request.DueAt.UTC().UnixMilli(), now.UnixMilli(), request.OutputID)
	if err == nil {
		return s.Get(ctx, id)
	}
	var existingID string
	if lookupErr := s.database.QueryRowContext(ctx, `
SELECT id FROM managed_output_build_jobs
WHERE dedupe_key = ? AND status IN ('queued', 'leased', 'running')`, request.OutputID).Scan(&existingID); lookupErr == nil {
		return s.Get(ctx, existingID)
	}
	return Job{}, fmt.Errorf("enqueue managed output build: %w", err)
}

func (s *Store) Claim(ctx context.Context, owner string, lease time.Duration) (Job, bool, error) {
	if strings.TrimSpace(owner) == "" || len(owner) > 200 || lease <= 0 {
		return Job{}, false, fmt.Errorf("valid managed output build lease is required")
	}
	now := s.now().UTC()
	job, err := scanJob(s.database.QueryRowContext(ctx, `
UPDATE managed_output_build_jobs
SET status = 'leased', lease_owner = ?, lease_expires_at = ?, attempt = attempt + 1,
    started_at = COALESCE(started_at, ?), error_code = NULL, error_detail = NULL
WHERE id = (
  SELECT id FROM managed_output_build_jobs
  WHERE status = 'queued' AND due_at <= ?
  ORDER BY priority DESC, due_at, created_at, id LIMIT 1
)
RETURNING id, output_id, trigger_kind, COALESCE(trigger_source_id, ''), status, priority,
          dedupe_key, COALESCE(lease_owner, ''), lease_expires_at, attempt, max_attempts,
          COALESCE(error_code, ''), COALESCE(error_detail, ''), correlation_id,
          due_at, created_at, started_at, finished_at`,
		owner, now.Add(lease).UnixMilli(), now.UnixMilli(), now.UnixMilli()))
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, false, nil
	}
	if err != nil {
		return Job{}, false, fmt.Errorf("claim managed output build: %w", err)
	}
	return job, true, nil
}

func (s *Store) MarkRunning(ctx context.Context, id, owner string) (Job, error) {
	result, err := s.database.ExecContext(ctx, `
UPDATE managed_output_build_jobs SET status = 'running'
WHERE id = ? AND status = 'leased' AND lease_owner = ? AND lease_expires_at > ?`,
		id, owner, s.now().UTC().UnixMilli())
	if err != nil {
		return Job{}, fmt.Errorf("start managed output build: %w", err)
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
		return Job{}, fmt.Errorf("bounded managed output build error is required")
	}
	return s.finish(ctx, id, owner, StatusFailed, code, detail)
}

func (s *Store) finish(ctx context.Context, id, owner string, status Status, code, detail string) (Job, error) {
	now := s.now().UTC()
	result, err := s.database.ExecContext(ctx, `
UPDATE managed_output_build_jobs
SET status = ?, lease_owner = NULL, lease_expires_at = NULL,
    error_code = ?, error_detail = ?, finished_at = ?
WHERE id = ? AND status = 'running' AND lease_owner = ?`,
		status, nullableString(code), nullableString(detail), now.UnixMilli(), id, owner)
	if err != nil {
		return Job{}, fmt.Errorf("finish managed output build: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return Job{}, ErrConflict
	}
	return s.Get(ctx, id)
}

func (s *Store) RecoverExpired(ctx context.Context) (int64, error) {
	now := s.now().UTC().UnixMilli()
	dead, err := s.database.ExecContext(ctx, `
UPDATE managed_output_build_jobs
SET status = 'dead', lease_owner = NULL, lease_expires_at = NULL,
    error_code = 'lease_expired', error_detail = 'build lease expired at process recovery', finished_at = ?
WHERE status IN ('leased', 'running') AND lease_expires_at <= ? AND attempt >= max_attempts`, now, now)
	if err != nil {
		return 0, fmt.Errorf("dead-letter expired managed output builds: %w", err)
	}
	queued, err := s.database.ExecContext(ctx, `
UPDATE managed_output_build_jobs
SET status = 'queued', lease_owner = NULL, lease_expires_at = NULL,
    error_code = 'lease_expired', error_detail = 'build lease expired and was requeued', due_at = ?
WHERE status IN ('leased', 'running') AND lease_expires_at <= ? AND attempt < max_attempts`, now, now)
	if err != nil {
		return 0, fmt.Errorf("requeue expired managed output builds: %w", err)
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
SELECT id, output_id, trigger_kind, COALESCE(trigger_source_id, ''), status, priority,
       dedupe_key, COALESCE(lease_owner, ''), lease_expires_at, attempt, max_attempts,
       COALESCE(error_code, ''), COALESCE(error_detail, ''), correlation_id,
       due_at, created_at, started_at, finished_at
FROM managed_output_build_jobs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	if err != nil {
		return Job{}, fmt.Errorf("read managed output build job: %w", err)
	}
	return job, nil
}

func scanJob(row interface{ Scan(...interface{}) error }) (Job, error) {
	var job Job
	var status string
	var lease, started, finished sql.NullInt64
	var due, created int64
	if err := row.Scan(
		&job.ID, &job.OutputID, &job.TriggerKind, &job.TriggerSourceID, &status, &job.Priority,
		&job.DedupeKey, &job.LeaseOwner, &lease, &job.Attempt, &job.MaxAttempts,
		&job.ErrorCode, &job.ErrorDetail, &job.CorrelationID, &due, &created, &started, &finished,
	); err != nil {
		return Job{}, err
	}
	job.Status = Status(status)
	job.DueAt, job.CreatedAt = time.UnixMilli(due).UTC(), time.UnixMilli(created).UTC()
	job.LeaseExpiresAt, job.StartedAt, job.FinishedAt = nullTime(lease), nullTime(started), nullTime(finished)
	return job, nil
}

func nullTime(value sql.NullInt64) *time.Time {
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
