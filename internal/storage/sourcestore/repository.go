package sourcestore

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/doujialong/proxyloom/internal/identity"
	"github.com/doujialong/proxyloom/internal/occurrence"
)

var (
	ErrNotFound          = errors.New("source store record not found")
	ErrConflict          = errors.New("source store state conflict")
	ErrNoCurrentSnapshot = errors.New("source has no current snapshot")
)

type SourceType string

const (
	SourceRemote SourceType = "remote"
	SourceInline SourceType = "inline"
	SourceUpload SourceType = "upload"
)

type ImportPurpose string

const (
	PurposeNodes            ImportPurpose = "node_source"
	PurposeTemplate         ImportPurpose = "template"
	PurposeTemplateAndNodes ImportPurpose = "template_and_nodes"
	PurposeRawPassthrough   ImportPurpose = "raw_passthrough"
)

type TriggerKind string

const (
	TriggerManual   TriggerKind = "manual"
	TriggerSchedule TriggerKind = "schedule"
	TriggerRetry    TriggerKind = "retry"
	TriggerImport   TriggerKind = "import"
)

type AttemptStatus string

const (
	AttemptRunning     AttemptStatus = "running"
	AttemptSucceeded   AttemptStatus = "succeeded"
	AttemptNotModified AttemptStatus = "not_modified"
	AttemptRejected    AttemptStatus = "rejected"
	AttemptFailed      AttemptStatus = "failed"
)

type Options struct {
	Now   func() time.Time
	NewID func() string
}

type Repository struct {
	database *sql.DB
	now      func() time.Time
	newID    func() string
}

type Source struct {
	ID                  string
	DisplayName         string
	LifecycleState      string
	DraftRevisionID     string
	PublishedRevisionID string
	CurrentSnapshotID   string
	Health              string
	HealthReasonCode    string
	RevisionCounter     int
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type RevisionConfig struct {
	SourceType               SourceType
	InputFormatHint          string
	ImportPurpose            ImportPurpose
	RefreshSchedule          string
	ScheduleTimezone         string
	PrivateNetworkAuthorized bool
	ConfigBlobID             string
	ConfigSchemaVersion      int
	CreatedBy                string
}

type Revision struct {
	ID          string
	SourceID    string
	Number      int
	State       string
	Config      RevisionConfig
	CreatedAt   time.Time
	PublishedAt *time.Time
}

type CreateRequest struct {
	DisplayName string
	Config      RevisionConfig
}

type PublishResult struct {
	Source    Source
	Published Revision
	Draft     Revision
}

type ReplaceDraftResult struct {
	Source Source
	Draft  Revision
}

type ReplaceDraftRequest struct {
	SourceID          string
	ExpectedDraftID   string
	ExpectedUpdatedAt time.Time
	DisplayName       string
	Config            RevisionConfig
}

type Attempt struct {
	ID                 string
	SourceID           string
	SourceRevisionID   string
	Trigger            TriggerKind
	Status             AttemptStatus
	HTTPStatus         *int
	TotalMS            *int
	ResponseBytes      *int
	NodeCount          *int
	WarningCount       int
	ErrorCode          string
	ErrorDetail        string
	AcceptedSnapshotID string
	CorrelationID      string
	StartedAt          time.Time
	FinishedAt         *time.Time
}

type StartAttemptRequest struct {
	SourceID         string
	SourceRevisionID string
	Trigger          TriggerKind
	CorrelationID    string
}

type AttemptMetrics struct {
	HTTPStatus    *int
	TotalMS       *int
	ResponseBytes *int
}

type FailureRequest struct {
	AttemptID    string
	Status       AttemptStatus
	Metrics      AttemptMetrics
	NodeCount    *int
	WarningCount int
	ErrorCode    string
	ErrorDetail  string
}

type AcceptRequest struct {
	AttemptID                  string
	RawBlobID                  string
	DetectedFormat             string
	FormatAdapterVersion       string
	MediaType                  string
	Charset                    string
	ParseLimitsVersion         int
	NodeCount                  int
	LogicalOutboundCount       int
	WarningCount               int
	OccurrenceAlgorithmVersion string
	StaleAfter                 time.Duration
	RetainFor                  time.Duration
	Metrics                    AttemptMetrics
	Nodes                      []AcceptedNode
	Occurrences                []occurrence.Occurrence
}

type AcceptedNode struct {
	Ordinal               int
	ExtractionPath        string
	RawKind               string
	FormatID              string
	FormatAdapterVersion  string
	ProtocolID            string
	ParseStatus           string
	WarningCount          int
	RawBlobID             string
	OriginalNameBlobID    string
	Fingerprint           identity.Fingerprint
	OccurrenceID          string
	MatchMethod           occurrence.MatchMethod
	CanonicalBlobID       string
	CanonicalVersion      string
	CanonicalCompleteness string
	CanonicalFeatureFlags string
}

type RawDocument struct {
	ID                   string
	SourceID             string
	BlobID               string
	DetectedFormat       string
	FormatAdapterVersion string
	MediaType            string
	Charset              string
	ParseLimitsVersion   int
	CreatedAt            time.Time
}

type Snapshot struct {
	ID                         string
	SourceID                   string
	SourceRevisionID           string
	RawDocumentID              string
	RefreshAttemptID           string
	NodeCount                  int
	LogicalOutboundCount       int
	WarningCount               int
	OccurrenceAlgorithmVersion string
	AcceptedAt                 time.Time
	StaleAfter                 time.Time
	RetainUntil                time.Time
}

type StoredOccurrence struct {
	Occurrence occurrence.Occurrence
	NameBlobID string
}

type SourceListOptions struct {
	Limit           int
	BeforeUpdatedAt *time.Time
	BeforeID        string
	Health          string
	Query           string
	IncludeArchived bool
}

func New(database *sql.DB, options Options) (*Repository, error) {
	if database == nil {
		return nil, fmt.Errorf("database is required")
	}
	if options.Now == nil || options.NewID == nil {
		return nil, fmt.Errorf("source store clock and ID generator are required")
	}
	return &Repository{database: database, now: options.Now, newID: options.NewID}, nil
}

func (r *Repository) Create(ctx context.Context, request CreateRequest) (Source, Revision, error) {
	if err := validateCreateRequest(request); err != nil {
		return Source{}, Revision{}, err
	}
	now, err := r.currentTime()
	if err != nil {
		return Source{}, Revision{}, err
	}
	sourceID, err := r.nextID("source")
	if err != nil {
		return Source{}, Revision{}, err
	}
	revisionID, err := r.nextID("source revision")
	if err != nil {
		return Source{}, Revision{}, err
	}
	config := withRevisionDefaults(request.Config)

	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return Source{}, Revision{}, fmt.Errorf("begin source creation: %w", err)
	}
	defer tx.Rollback()
	if err := requireBlobKind(ctx, tx, config.ConfigBlobID, "source_config"); err != nil {
		return Source{}, Revision{}, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO sources(
  id, display_name, lifecycle_state, source_health,
  revision_counter, created_at, updated_at
) VALUES (?, ?, 'active', 'unknown', 0, ?, ?)`,
		sourceID, request.DisplayName, now.UnixMilli(), now.UnixMilli(),
	); err != nil {
		return Source{}, Revision{}, fmt.Errorf("insert source: %w", err)
	}
	if err := insertRevision(ctx, tx, revisionID, sourceID, 1, "draft", config, now, nil); err != nil {
		return Source{}, Revision{}, err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE sources SET draft_revision_id = ?, revision_counter = 1 WHERE id = ?`, revisionID, sourceID); err != nil {
		return Source{}, Revision{}, fmt.Errorf("set source draft revision: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Source{}, Revision{}, fmt.Errorf("commit source creation: %w", err)
	}
	return Source{
			ID: sourceID, DisplayName: request.DisplayName, LifecycleState: "active",
			DraftRevisionID: revisionID, Health: "unknown", RevisionCounter: 1,
			CreatedAt: now, UpdatedAt: now,
		}, Revision{
			ID: revisionID, SourceID: sourceID, Number: 1, State: "draft",
			Config: config, CreatedAt: now,
		}, nil
}

func (r *Repository) Publish(ctx context.Context, sourceID, revisionID string) (PublishResult, error) {
	if !validID(sourceID) || !validID(revisionID) {
		return PublishResult{}, ErrNotFound
	}
	now, err := r.currentTime()
	if err != nil {
		return PublishResult{}, err
	}
	newDraftID, err := r.nextID("source revision")
	if err != nil {
		return PublishResult{}, err
	}
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return PublishResult{}, fmt.Errorf("begin source publication: %w", err)
	}
	defer tx.Rollback()

	var source Source
	var draftID string
	var publishedID sql.NullString
	if err := tx.QueryRowContext(ctx, `
SELECT id, display_name, lifecycle_state, draft_revision_id, published_revision_id,
       current_snapshot_id, source_health, health_reason_code,
       revision_counter, created_at, updated_at
FROM sources WHERE id = ?`, sourceID).Scan(
		&source.ID, &source.DisplayName, &source.LifecycleState, &draftID, &publishedID,
		nullStringScanner(&source.CurrentSnapshotID), &source.Health, nullStringScanner(&source.HealthReasonCode),
		&source.RevisionCounter, timeScanner(&source.CreatedAt), timeScanner(&source.UpdatedAt),
	); errors.Is(err, sql.ErrNoRows) {
		return PublishResult{}, ErrNotFound
	} else if err != nil {
		return PublishResult{}, fmt.Errorf("read source for publication: %w", err)
	}
	if source.LifecycleState != "active" || draftID != revisionID {
		return PublishResult{}, ErrConflict
	}
	published, err := readRevision(ctx, tx, revisionID, sourceID)
	if err != nil {
		return PublishResult{}, err
	}
	if published.State != "draft" {
		return PublishResult{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE sources SET draft_revision_id = NULL, published_revision_id = NULL WHERE id = ?`, sourceID); err != nil {
		return PublishResult{}, fmt.Errorf("clear source revision pointers for publication: %w", err)
	}
	if publishedID.Valid {
		if _, err := tx.ExecContext(ctx, `
UPDATE source_revisions SET state = 'superseded' WHERE id = ? AND source_id = ? AND state = 'published'`,
			publishedID.String, sourceID,
		); err != nil {
			return PublishResult{}, fmt.Errorf("supersede source revision: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE source_revisions SET state = 'published', published_at = ?
WHERE id = ? AND source_id = ? AND state = 'draft'`, now.UnixMilli(), revisionID, sourceID); err != nil {
		return PublishResult{}, fmt.Errorf("publish source revision: %w", err)
	}
	newDraftNumber := source.RevisionCounter + 1
	if err := insertRevision(ctx, tx, newDraftID, sourceID, newDraftNumber, "draft", published.Config, now, nil); err != nil {
		return PublishResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE sources
SET published_revision_id = ?, draft_revision_id = ?, revision_counter = ?, updated_at = ?
WHERE id = ?`, revisionID, newDraftID, newDraftNumber, now.UnixMilli(), sourceID); err != nil {
		return PublishResult{}, fmt.Errorf("switch source revision pointers: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return PublishResult{}, fmt.Errorf("commit source publication: %w", err)
	}
	published.State = "published"
	publishedAt := now
	published.PublishedAt = &publishedAt
	newDraft := Revision{
		ID: newDraftID, SourceID: sourceID, Number: newDraftNumber,
		State: "draft", Config: published.Config, CreatedAt: now,
	}
	source.DraftRevisionID = newDraftID
	source.PublishedRevisionID = revisionID
	source.RevisionCounter = newDraftNumber
	source.UpdatedAt = now
	return PublishResult{Source: source, Published: published, Draft: newDraft}, nil
}

func (r *Repository) ReplaceDraft(ctx context.Context, sourceID, expectedDraftID string, config RevisionConfig) (ReplaceDraftResult, error) {
	return r.ReplaceDraftWithMetadata(ctx, ReplaceDraftRequest{
		SourceID: sourceID, ExpectedDraftID: expectedDraftID, Config: config,
	})
}

func (r *Repository) ReplaceDraftWithMetadata(ctx context.Context, request ReplaceDraftRequest) (ReplaceDraftResult, error) {
	if !validID(request.SourceID) || !validID(request.ExpectedDraftID) {
		return ReplaceDraftResult{}, ErrNotFound
	}
	config := withRevisionDefaults(request.Config)
	if err := validateRevisionConfig(config); err != nil {
		return ReplaceDraftResult{}, err
	}
	if request.DisplayName != "" && (!utf8.ValidString(request.DisplayName) || len(request.DisplayName) > 200) {
		return ReplaceDraftResult{}, fmt.Errorf("display name must be valid UTF-8 and between 1 and 200 bytes")
	}
	now, err := r.currentTime()
	if err != nil {
		return ReplaceDraftResult{}, err
	}
	newDraftID, err := r.nextID("source revision")
	if err != nil {
		return ReplaceDraftResult{}, err
	}
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return ReplaceDraftResult{}, fmt.Errorf("begin source draft replacement: %w", err)
	}
	defer tx.Rollback()
	var source Source
	var draftID string
	var publishedID, snapshotID, reason sql.NullString
	var createdAt, updatedAt int64
	if err := tx.QueryRowContext(ctx, `
SELECT id, display_name, lifecycle_state, draft_revision_id, published_revision_id,
       current_snapshot_id, source_health, health_reason_code,
       revision_counter, created_at, updated_at
FROM sources WHERE id = ?`, request.SourceID).Scan(
		&source.ID, &source.DisplayName, &source.LifecycleState, &draftID, &publishedID,
		&snapshotID, &source.Health, &reason, &source.RevisionCounter, &createdAt, &updatedAt,
	); errors.Is(err, sql.ErrNoRows) {
		return ReplaceDraftResult{}, ErrNotFound
	} else if err != nil {
		return ReplaceDraftResult{}, fmt.Errorf("read source for draft replacement: %w", err)
	}
	if source.LifecycleState != "active" || draftID != request.ExpectedDraftID ||
		(!request.ExpectedUpdatedAt.IsZero() && updatedAt != request.ExpectedUpdatedAt.UTC().UnixMilli()) {
		return ReplaceDraftResult{}, ErrConflict
	}
	if request.DisplayName != "" {
		source.DisplayName = request.DisplayName
	}
	if err := requireBlobKind(ctx, tx, config.ConfigBlobID, "source_config"); err != nil {
		return ReplaceDraftResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sources SET draft_revision_id = NULL WHERE id = ?`, request.SourceID); err != nil {
		return ReplaceDraftResult{}, fmt.Errorf("clear source draft pointer: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE source_revisions SET state = 'archived'
	WHERE id = ? AND source_id = ? AND state = 'draft'`, request.ExpectedDraftID, request.SourceID); err != nil {
		return ReplaceDraftResult{}, fmt.Errorf("archive replaced source draft: %w", err)
	}
	newNumber := source.RevisionCounter + 1
	if err := insertRevision(ctx, tx, newDraftID, request.SourceID, newNumber, "draft", config, now, nil); err != nil {
		return ReplaceDraftResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE sources
SET display_name = ?, draft_revision_id = ?, revision_counter = ?, updated_at = ?
WHERE id = ?`, source.DisplayName, newDraftID, newNumber, now.UnixMilli(), request.SourceID); err != nil {
		return ReplaceDraftResult{}, fmt.Errorf("switch replacement source draft: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ReplaceDraftResult{}, fmt.Errorf("commit source draft replacement: %w", err)
	}
	source.DraftRevisionID = newDraftID
	source.PublishedRevisionID = publishedID.String
	source.CurrentSnapshotID = snapshotID.String
	source.HealthReasonCode = reason.String
	source.RevisionCounter = newNumber
	source.CreatedAt = fromMillis(createdAt)
	source.UpdatedAt = now
	return ReplaceDraftResult{
		Source: source,
		Draft: Revision{
			ID: newDraftID, SourceID: request.SourceID, Number: newNumber,
			State: "draft", Config: config, CreatedAt: now,
		},
	}, nil
}

func (r *Repository) StartAttempt(ctx context.Context, request StartAttemptRequest) (Attempt, error) {
	if !validID(request.SourceID) || !validID(request.SourceRevisionID) {
		return Attempt{}, ErrNotFound
	}
	if !validTrigger(request.Trigger) {
		return Attempt{}, fmt.Errorf("invalid refresh trigger %q", request.Trigger)
	}
	if strings.TrimSpace(request.CorrelationID) == "" || len(request.CorrelationID) > 200 {
		return Attempt{}, fmt.Errorf("correlation ID is required and must not exceed 200 bytes")
	}
	now, err := r.currentTime()
	if err != nil {
		return Attempt{}, err
	}
	id, err := r.nextID("refresh attempt")
	if err != nil {
		return Attempt{}, err
	}
	result, err := r.database.ExecContext(ctx, `
INSERT INTO refresh_attempts(
  id, source_id, source_revision_id, trigger_kind, status,
  correlation_id, started_at
) VALUES (?, ?, ?, ?, 'running', ?, ?)`,
		id, request.SourceID, request.SourceRevisionID, string(request.Trigger), request.CorrelationID, now.UnixMilli(),
	)
	if err != nil {
		return Attempt{}, fmt.Errorf("start refresh attempt: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return Attempt{}, ErrConflict
	}
	return Attempt{
		ID: id, SourceID: request.SourceID, SourceRevisionID: request.SourceRevisionID,
		Trigger: request.Trigger, Status: AttemptRunning,
		CorrelationID: request.CorrelationID, StartedAt: now,
	}, nil
}

func (r *Repository) RecoverRunningAttempts(ctx context.Context) (int64, error) {
	now, err := r.currentTime()
	if err != nil {
		return 0, err
	}
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin running refresh attempt recovery: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
UPDATE sources
SET source_health = 'degraded', health_reason_code = 'service_interrupted', updated_at = ?
WHERE id IN (SELECT source_id FROM refresh_attempts WHERE status = 'running')`, now.UnixMilli()); err != nil {
		return 0, fmt.Errorf("mark interrupted refresh sources degraded: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE refresh_attempts
SET status = 'failed', error_code = 'service_interrupted',
    error_detail = 'refresh was interrupted before process recovery', finished_at = ?
WHERE status = 'running'`, now.UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("recover interrupted refresh attempts: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count recovered refresh attempts: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit running refresh attempt recovery: %w", err)
	}
	return count, nil
}

func (r *Repository) CompleteFailure(ctx context.Context, request FailureRequest) (Attempt, error) {
	if !validID(request.AttemptID) {
		return Attempt{}, ErrNotFound
	}
	if request.Status != AttemptRejected && request.Status != AttemptFailed {
		return Attempt{}, fmt.Errorf("failure status must be rejected or failed")
	}
	if strings.TrimSpace(request.ErrorCode) == "" || len(request.ErrorCode) > 128 {
		return Attempt{}, fmt.Errorf("failure error code is required and must not exceed 128 bytes")
	}
	if len(request.ErrorDetail) > 4096 {
		return Attempt{}, fmt.Errorf("failure error detail must not exceed 4096 bytes")
	}
	if request.WarningCount < 0 || invalidOptionalNonNegative(request.NodeCount) || invalidMetrics(request.Metrics) {
		return Attempt{}, fmt.Errorf("failure metrics must be non-negative")
	}
	now, err := r.currentTime()
	if err != nil {
		return Attempt{}, err
	}
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return Attempt{}, fmt.Errorf("begin refresh failure: %w", err)
	}
	defer tx.Rollback()
	attempt, err := readAttempt(ctx, tx, request.AttemptID)
	if err != nil {
		return Attempt{}, err
	}
	if attempt.Status != AttemptRunning {
		return Attempt{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE refresh_attempts
SET status = ?, http_status = ?, total_ms = ?, response_bytes = ?, node_count = ?,
    warning_count = ?, error_code = ?, error_detail = ?, finished_at = ?
WHERE id = ? AND status = 'running'`,
		string(request.Status), nullableInt(request.Metrics.HTTPStatus), nullableInt(request.Metrics.TotalMS),
		nullableInt(request.Metrics.ResponseBytes), nullableInt(request.NodeCount), request.WarningCount,
		request.ErrorCode, nullableString(request.ErrorDetail), now.UnixMilli(), request.AttemptID,
	); err != nil {
		return Attempt{}, fmt.Errorf("finish failed refresh attempt: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE sources SET source_health = 'degraded', health_reason_code = ?, updated_at = ? WHERE id = ?`,
		request.ErrorCode, now.UnixMilli(), attempt.SourceID,
	); err != nil {
		return Attempt{}, fmt.Errorf("mark source degraded: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Attempt{}, fmt.Errorf("commit refresh failure: %w", err)
	}
	attempt.Status = request.Status
	attempt.HTTPStatus = cloneInt(request.Metrics.HTTPStatus)
	attempt.TotalMS = cloneInt(request.Metrics.TotalMS)
	attempt.ResponseBytes = cloneInt(request.Metrics.ResponseBytes)
	attempt.NodeCount = cloneInt(request.NodeCount)
	attempt.WarningCount = request.WarningCount
	attempt.ErrorCode = request.ErrorCode
	attempt.ErrorDetail = request.ErrorDetail
	attempt.FinishedAt = timePointer(now)
	return attempt, nil
}

func (r *Repository) AcceptSnapshot(ctx context.Context, request AcceptRequest) (Snapshot, RawDocument, error) {
	if err := validateAcceptRequest(request); err != nil {
		return Snapshot{}, RawDocument{}, err
	}
	now, err := r.currentTime()
	if err != nil {
		return Snapshot{}, RawDocument{}, err
	}
	documentID, err := r.nextID("raw document")
	if err != nil {
		return Snapshot{}, RawDocument{}, err
	}
	snapshotID, err := r.nextID("snapshot")
	if err != nil {
		return Snapshot{}, RawDocument{}, err
	}
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, RawDocument{}, fmt.Errorf("begin snapshot acceptance: %w", err)
	}
	defer tx.Rollback()
	attempt, err := readAttempt(ctx, tx, request.AttemptID)
	if err != nil {
		return Snapshot{}, RawDocument{}, err
	}
	if attempt.Status != AttemptRunning {
		return Snapshot{}, RawDocument{}, ErrConflict
	}
	if err := requireBlobKind(ctx, tx, request.RawBlobID, "raw_document"); err != nil {
		return Snapshot{}, RawDocument{}, err
	}
	parseLimitsVersion := request.ParseLimitsVersion
	if parseLimitsVersion == 0 {
		parseLimitsVersion = 1
	}
	result, err := tx.ExecContext(ctx, `
INSERT INTO raw_documents(
  id, source_id, blob_id, detected_format, format_adapter_version,
  content_hmac, media_type, charset, parse_limits_version, created_at
)
SELECT ?, ?, b.id, ?, ?, b.content_hmac, ?, ?, ?, ?
FROM encrypted_blobs b WHERE b.id = ?`,
		documentID, attempt.SourceID, request.DetectedFormat, request.FormatAdapterVersion,
		nullableString(request.MediaType), nullableString(request.Charset), parseLimitsVersion,
		now.UnixMilli(), request.RawBlobID,
	)
	if err != nil {
		return Snapshot{}, RawDocument{}, fmt.Errorf("insert raw document: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return Snapshot{}, RawDocument{}, ErrNotFound
	}
	staleAfter := now.Add(request.StaleAfter)
	retainUntil := now.Add(request.RetainFor)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO snapshots(
  id, source_id, source_revision_id, raw_document_id, refresh_attempt_id,
  node_count, logical_outbound_count, warning_count, content_hmac,
  occurrence_algorithm_version, accepted_at, stale_after, retain_until
)
SELECT ?, ?, ?, ?, ?, ?, ?, ?, d.content_hmac, ?, ?, ?, ?
FROM raw_documents d WHERE d.id = ? AND d.source_id = ?`,
		snapshotID, attempt.SourceID, attempt.SourceRevisionID, documentID, attempt.ID,
		request.NodeCount, request.LogicalOutboundCount, request.WarningCount,
		request.OccurrenceAlgorithmVersion, now.UnixMilli(), staleAfter.UnixMilli(), retainUntil.UnixMilli(),
		documentID, attempt.SourceID,
	); err != nil {
		return Snapshot{}, RawDocument{}, fmt.Errorf("insert accepted snapshot: %w", err)
	}
	if err := r.persistSnapshotDetails(ctx, tx, snapshotID, attempt.SourceID, request.OccurrenceAlgorithmVersion, request.Nodes, request.Occurrences, now); err != nil {
		return Snapshot{}, RawDocument{}, err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE refresh_attempts
SET status = 'succeeded', http_status = ?, total_ms = ?, response_bytes = ?,
    node_count = ?, warning_count = ?, accepted_snapshot_id = ?, finished_at = ?
WHERE id = ? AND status = 'running'`,
		nullableInt(request.Metrics.HTTPStatus), nullableInt(request.Metrics.TotalMS),
		nullableInt(request.Metrics.ResponseBytes), request.NodeCount, request.WarningCount,
		snapshotID, now.UnixMilli(), attempt.ID,
	); err != nil {
		return Snapshot{}, RawDocument{}, fmt.Errorf("finish accepted refresh attempt: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE sources
SET current_snapshot_id = ?, source_health = 'healthy', health_reason_code = NULL, updated_at = ?
WHERE id = ?`, snapshotID, now.UnixMilli(), attempt.SourceID); err != nil {
		return Snapshot{}, RawDocument{}, fmt.Errorf("switch current source snapshot: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Snapshot{}, RawDocument{}, fmt.Errorf("commit snapshot acceptance: %w", err)
	}
	return Snapshot{
			ID: snapshotID, SourceID: attempt.SourceID, SourceRevisionID: attempt.SourceRevisionID,
			RawDocumentID: documentID, RefreshAttemptID: attempt.ID,
			NodeCount: request.NodeCount, LogicalOutboundCount: request.LogicalOutboundCount,
			WarningCount: request.WarningCount, OccurrenceAlgorithmVersion: request.OccurrenceAlgorithmVersion,
			AcceptedAt: now, StaleAfter: staleAfter, RetainUntil: retainUntil,
		}, RawDocument{
			ID: documentID, SourceID: attempt.SourceID, BlobID: request.RawBlobID,
			DetectedFormat: request.DetectedFormat, FormatAdapterVersion: request.FormatAdapterVersion,
			MediaType: request.MediaType, Charset: request.Charset,
			ParseLimitsVersion: parseLimitsVersion, CreatedAt: now,
		}, nil
}

func (r *Repository) CompleteNotModified(ctx context.Context, attemptID string, metrics AttemptMetrics) (Snapshot, Attempt, error) {
	if !validID(attemptID) {
		return Snapshot{}, Attempt{}, ErrNotFound
	}
	if invalidMetrics(metrics) {
		return Snapshot{}, Attempt{}, fmt.Errorf("refresh metrics must be non-negative")
	}
	if metrics.HTTPStatus == nil || *metrics.HTTPStatus != 304 {
		return Snapshot{}, Attempt{}, fmt.Errorf("not-modified refresh requires HTTP status 304")
	}
	now, err := r.currentTime()
	if err != nil {
		return Snapshot{}, Attempt{}, err
	}
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, Attempt{}, fmt.Errorf("begin not-modified refresh: %w", err)
	}
	defer tx.Rollback()
	attempt, err := readAttempt(ctx, tx, attemptID)
	if err != nil {
		return Snapshot{}, Attempt{}, err
	}
	if attempt.Status != AttemptRunning {
		return Snapshot{}, Attempt{}, ErrConflict
	}
	var snapshotID sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT current_snapshot_id FROM sources WHERE id = ?`, attempt.SourceID).Scan(&snapshotID); err != nil {
		return Snapshot{}, Attempt{}, fmt.Errorf("read current snapshot for not-modified refresh: %w", err)
	}
	if !snapshotID.Valid {
		return Snapshot{}, Attempt{}, ErrNoCurrentSnapshot
	}
	snapshot, err := readSnapshot(ctx, tx, snapshotID.String, attempt.SourceID)
	if err != nil {
		return Snapshot{}, Attempt{}, err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE refresh_attempts
SET status = 'not_modified', http_status = ?, total_ms = ?, response_bytes = ?,
    node_count = ?, warning_count = ?, accepted_snapshot_id = ?, finished_at = ?
WHERE id = ? AND status = 'running'`,
		nullableInt(metrics.HTTPStatus), nullableInt(metrics.TotalMS), nullableInt(metrics.ResponseBytes),
		snapshot.NodeCount, snapshot.WarningCount, snapshot.ID, now.UnixMilli(), attempt.ID,
	); err != nil {
		return Snapshot{}, Attempt{}, fmt.Errorf("finish not-modified refresh attempt: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE sources SET source_health = 'healthy', health_reason_code = NULL, updated_at = ? WHERE id = ?`,
		now.UnixMilli(), attempt.SourceID,
	); err != nil {
		return Snapshot{}, Attempt{}, fmt.Errorf("mark not-modified source healthy: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Snapshot{}, Attempt{}, fmt.Errorf("commit not-modified refresh: %w", err)
	}
	attempt.Status = AttemptNotModified
	attempt.HTTPStatus = cloneInt(metrics.HTTPStatus)
	attempt.TotalMS = cloneInt(metrics.TotalMS)
	attempt.ResponseBytes = cloneInt(metrics.ResponseBytes)
	attempt.NodeCount = intPointer(snapshot.NodeCount)
	attempt.WarningCount = snapshot.WarningCount
	attempt.AcceptedSnapshotID = snapshot.ID
	attempt.FinishedAt = timePointer(now)
	return snapshot, attempt, nil
}

func (r *Repository) GetSource(ctx context.Context, id string) (Source, error) {
	if !validID(id) {
		return Source{}, ErrNotFound
	}
	var source Source
	var draft, published, snapshot, reason sql.NullString
	var createdAt, updatedAt int64
	err := r.database.QueryRowContext(ctx, `
SELECT id, display_name, lifecycle_state, draft_revision_id, published_revision_id,
       current_snapshot_id, source_health, health_reason_code,
       revision_counter, created_at, updated_at
FROM sources WHERE id = ?`, id).Scan(
		&source.ID, &source.DisplayName, &source.LifecycleState, &draft, &published,
		&snapshot, &source.Health, &reason, &source.RevisionCounter, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Source{}, ErrNotFound
	}
	if err != nil {
		return Source{}, fmt.Errorf("read source: %w", err)
	}
	source.DraftRevisionID = draft.String
	source.PublishedRevisionID = published.String
	source.CurrentSnapshotID = snapshot.String
	source.HealthReasonCode = reason.String
	source.CreatedAt = fromMillis(createdAt)
	source.UpdatedAt = fromMillis(updatedAt)
	return source, nil
}

func (r *Repository) ListSources(ctx context.Context, options SourceListOptions) ([]Source, bool, error) {
	if options.Limit <= 0 || options.Limit > 200 {
		return nil, false, fmt.Errorf("source list limit must be between 1 and 200")
	}
	if options.BeforeUpdatedAt != nil && !validID(options.BeforeID) {
		return nil, false, fmt.Errorf("source list cursor is invalid")
	}
	if options.Health != "" && options.Health != "unknown" && options.Health != "healthy" &&
		options.Health != "degraded" && options.Health != "unhealthy" && options.Health != "disabled" {
		return nil, false, fmt.Errorf("source health filter is invalid")
	}
	query := `
SELECT id, display_name, lifecycle_state, draft_revision_id, published_revision_id,
       current_snapshot_id, source_health, health_reason_code,
       revision_counter, created_at, updated_at
FROM sources WHERE 1 = 1`
	arguments := make([]interface{}, 0, 8)
	if !options.IncludeArchived {
		query += ` AND lifecycle_state = 'active'`
	}
	if options.Health != "" {
		query += ` AND source_health = ?`
		arguments = append(arguments, options.Health)
	}
	if strings.TrimSpace(options.Query) != "" {
		query += ` AND display_name LIKE ? ESCAPE '\' COLLATE NOCASE`
		arguments = append(arguments, "%"+escapeLike(strings.TrimSpace(options.Query))+"%")
	}
	if options.BeforeUpdatedAt != nil {
		query += ` AND (updated_at < ? OR (updated_at = ? AND id < ?))`
		millis := options.BeforeUpdatedAt.UTC().UnixMilli()
		arguments = append(arguments, millis, millis, options.BeforeID)
	}
	query += ` ORDER BY updated_at DESC, id DESC LIMIT ?`
	arguments = append(arguments, options.Limit+1)
	rows, err := r.database.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, false, fmt.Errorf("list sources: %w", err)
	}
	defer rows.Close()
	result := make([]Source, 0, options.Limit+1)
	for rows.Next() {
		source, err := scanSource(rows)
		if err != nil {
			return nil, false, fmt.Errorf("scan source list: %w", err)
		}
		result = append(result, source)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate source list: %w", err)
	}
	hasMore := len(result) > options.Limit
	if hasMore {
		result = result[:options.Limit]
	}
	return result, hasMore, nil
}

func (r *Repository) ListRevisions(ctx context.Context, sourceID string, limit int) ([]Revision, error) {
	if !validID(sourceID) {
		return nil, ErrNotFound
	}
	if limit <= 0 || limit > 200 {
		return nil, fmt.Errorf("revision list limit must be between 1 and 200")
	}
	rows, err := r.database.QueryContext(ctx, `
SELECT id FROM source_revisions WHERE source_id = ?
ORDER BY revision_number DESC LIMIT ?`, sourceID, limit)
	if err != nil {
		return nil, fmt.Errorf("list source revisions: %w", err)
	}
	defer rows.Close()
	ids := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan source revision ID: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate source revisions: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close source revisions: %w", err)
	}
	if len(ids) == 0 {
		if _, err := r.GetSource(ctx, sourceID); err != nil {
			return nil, err
		}
	}
	result := make([]Revision, len(ids))
	for index, id := range ids {
		revision, err := r.GetRevision(ctx, sourceID, id)
		if err != nil {
			return nil, err
		}
		result[index] = revision
	}
	return result, nil
}

func (r *Repository) ListAttempts(ctx context.Context, sourceID string, limit int) ([]Attempt, error) {
	if !validID(sourceID) {
		return nil, ErrNotFound
	}
	if limit <= 0 || limit > 200 {
		return nil, fmt.Errorf("attempt list limit must be between 1 and 200")
	}
	rows, err := r.database.QueryContext(ctx, `
SELECT id FROM refresh_attempts WHERE source_id = ?
ORDER BY started_at DESC, id DESC LIMIT ?`, sourceID, limit)
	if err != nil {
		return nil, fmt.Errorf("list refresh attempts: %w", err)
	}
	defer rows.Close()
	ids := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan refresh attempt ID: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate refresh attempts: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close refresh attempts: %w", err)
	}
	if len(ids) == 0 {
		if _, err := r.GetSource(ctx, sourceID); err != nil {
			return nil, err
		}
	}
	result := make([]Attempt, len(ids))
	for index, id := range ids {
		attempt, err := r.GetAttempt(ctx, id)
		if err != nil {
			return nil, err
		}
		result[index] = attempt
	}
	return result, nil
}

func (r *Repository) ListSnapshots(ctx context.Context, sourceID string, limit int) ([]Snapshot, error) {
	if !validID(sourceID) {
		return nil, ErrNotFound
	}
	if limit <= 0 || limit > 200 {
		return nil, fmt.Errorf("snapshot list limit must be between 1 and 200")
	}
	rows, err := r.database.QueryContext(ctx, `
SELECT id FROM snapshots WHERE source_id = ?
ORDER BY accepted_at DESC, id DESC LIMIT ?`, sourceID, limit)
	if err != nil {
		return nil, fmt.Errorf("list snapshots: %w", err)
	}
	defer rows.Close()
	ids := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan snapshot ID: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate snapshots: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close snapshots: %w", err)
	}
	if len(ids) == 0 {
		if _, err := r.GetSource(ctx, sourceID); err != nil {
			return nil, err
		}
	}
	result := make([]Snapshot, len(ids))
	for index, id := range ids {
		snapshot, err := readSnapshot(ctx, r.database, id, sourceID)
		if err != nil {
			return nil, err
		}
		result[index] = snapshot
	}
	return result, nil
}

func (r *Repository) Archive(ctx context.Context, sourceID string, expectedUpdatedAt time.Time) (Source, error) {
	if !validID(sourceID) {
		return Source{}, ErrNotFound
	}
	now, err := r.currentTime()
	if err != nil {
		return Source{}, err
	}
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return Source{}, fmt.Errorf("begin source archive: %w", err)
	}
	defer tx.Rollback()
	var state string
	var updatedAt int64
	if err := tx.QueryRowContext(ctx, `SELECT lifecycle_state, updated_at FROM sources WHERE id = ?`, sourceID).Scan(&state, &updatedAt); errors.Is(err, sql.ErrNoRows) {
		return Source{}, ErrNotFound
	} else if err != nil {
		return Source{}, fmt.Errorf("read source for archive: %w", err)
	}
	if state != "active" || expectedUpdatedAt.IsZero() || updatedAt != expectedUpdatedAt.UTC().UnixMilli() {
		return Source{}, ErrConflict
	}
	var running int
	if err := tx.QueryRowContext(ctx, `
SELECT (SELECT count(*) FROM refresh_attempts WHERE source_id = ? AND status = 'running') +
       (SELECT count(*) FROM jobs WHERE source_id = ? AND status IN ('leased', 'running'))`, sourceID, sourceID).Scan(&running); err != nil {
		return Source{}, fmt.Errorf("inspect active source work: %w", err)
	}
	if running != 0 {
		return Source{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE jobs SET status = 'cancelled', error_code = 'source_archived',
    error_detail = 'source archived before refresh started', finished_at = ?
WHERE source_id = ? AND status = 'queued'`, now.UnixMilli(), sourceID); err != nil {
		return Source{}, fmt.Errorf("cancel queued source work: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE sources SET lifecycle_state = 'archived', source_health = 'disabled',
    health_reason_code = 'source_archived', archived_at = ?, updated_at = ?
WHERE id = ? AND lifecycle_state = 'active' AND updated_at = ?`,
		now.UnixMilli(), now.UnixMilli(), sourceID, expectedUpdatedAt.UTC().UnixMilli())
	if err != nil {
		return Source{}, fmt.Errorf("archive source: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return Source{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return Source{}, fmt.Errorf("commit source archive: %w", err)
	}
	return r.GetSource(ctx, sourceID)
}

func (r *Repository) GetRevision(ctx context.Context, sourceID, revisionID string) (Revision, error) {
	if !validID(sourceID) || !validID(revisionID) {
		return Revision{}, ErrNotFound
	}
	return readRevision(ctx, r.database, revisionID, sourceID)
}

func (r *Repository) ListOccurrences(ctx context.Context, sourceID string) ([]StoredOccurrence, error) {
	if !validID(sourceID) {
		return nil, ErrNotFound
	}
	rows, err := r.database.QueryContext(ctx, `
SELECT o.id, f.kind, f.algorithm, f.projection_version, f.key_id, f.digest,
       COALESCE(rn.extraction_path, ''), f.protocol_id, COALESCE(rn.original_name_blob_id, ''),
       o.lifecycle_state, o.duplicate_slot, o.first_seen_at, o.last_seen_at,
       o.absent_since, o.retain_until, o.association_version
FROM node_occurrences o
JOIN fingerprints f ON f.id = o.current_fingerprint_id
LEFT JOIN raw_nodes rn ON rn.id = (
  SELECT so.raw_node_id
  FROM snapshot_occurrences so
  JOIN snapshots recent ON recent.id = so.snapshot_id
  WHERE so.node_occurrence_id = o.id
  ORDER BY recent.accepted_at DESC, so.rowid DESC
  LIMIT 1
)
WHERE o.source_id = ?
ORDER BY o.created_at, o.id`, sourceID)
	if err != nil {
		return nil, fmt.Errorf("list source occurrences: %w", err)
	}
	defer rows.Close()
	result := make([]StoredOccurrence, 0)
	for rows.Next() {
		var stored StoredOccurrence
		var kind, algorithm, projectionVersion, keyID, protocolID, state, associationVersion string
		var digest []byte
		var firstSeen, lastSeen int64
		var absentSince, retainUntil sql.NullInt64
		if err := rows.Scan(
			&stored.Occurrence.ID, &kind, &algorithm, &projectionVersion, &keyID, &digest,
			&stored.Occurrence.ExtractionPath, &protocolID, &stored.NameBlobID,
			&state, &stored.Occurrence.DuplicateSlot, &firstSeen, &lastSeen,
			&absentSince, &retainUntil, &associationVersion,
		); err != nil {
			return nil, fmt.Errorf("scan source occurrence: %w", err)
		}
		if len(digest) != 32 {
			return nil, fmt.Errorf("source occurrence %s has an invalid fingerprint digest", stored.Occurrence.ID)
		}
		stored.Occurrence.Fingerprint = identity.Fingerprint{
			Kind: identity.Kind(kind), Algorithm: algorithm, ProjectionVersion: projectionVersion,
			KeyID: keyID, Digest: base64.RawURLEncoding.EncodeToString(digest),
		}
		stored.Occurrence.ProtocolID = protocolID
		stored.Occurrence.State = occurrence.State(state)
		stored.Occurrence.CreatedAt = fromMillis(firstSeen)
		stored.Occurrence.LastSeenAt = fromMillis(lastSeen)
		stored.Occurrence.AlgorithmVersion = associationVersion
		if absentSince.Valid {
			value := fromMillis(absentSince.Int64)
			stored.Occurrence.AbsentSince = &value
		}
		if retainUntil.Valid {
			value := fromMillis(retainUntil.Int64)
			stored.Occurrence.RetainUntil = &value
		}
		result = append(result, stored)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate source occurrences: %w", err)
	}
	return result, nil
}

func (r *Repository) CurrentSnapshot(ctx context.Context, sourceID string) (Snapshot, error) {
	if !validID(sourceID) {
		return Snapshot{}, ErrNotFound
	}
	var snapshotID sql.NullString
	if err := r.database.QueryRowContext(ctx, `SELECT current_snapshot_id FROM sources WHERE id = ?`, sourceID).Scan(&snapshotID); errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, ErrNotFound
	} else if err != nil {
		return Snapshot{}, fmt.Errorf("read current source snapshot: %w", err)
	}
	if !snapshotID.Valid {
		return Snapshot{}, ErrNoCurrentSnapshot
	}
	return readSnapshot(ctx, r.database, snapshotID.String, sourceID)
}

func (r *Repository) GetAttempt(ctx context.Context, id string) (Attempt, error) {
	if !validID(id) {
		return Attempt{}, ErrNotFound
	}
	return readAttempt(ctx, r.database, id)
}

type queryer interface {
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

type rowScanner interface {
	Scan(...interface{}) error
}

func scanSource(row rowScanner) (Source, error) {
	var source Source
	var draft, published, snapshot, reason sql.NullString
	var createdAt, updatedAt int64
	if err := row.Scan(
		&source.ID, &source.DisplayName, &source.LifecycleState, &draft, &published,
		&snapshot, &source.Health, &reason, &source.RevisionCounter, &createdAt, &updatedAt,
	); err != nil {
		return Source{}, err
	}
	source.DraftRevisionID = draft.String
	source.PublishedRevisionID = published.String
	source.CurrentSnapshotID = snapshot.String
	source.HealthReasonCode = reason.String
	source.CreatedAt = fromMillis(createdAt)
	source.UpdatedAt = fromMillis(updatedAt)
	return source, nil
}

func readRevision(ctx context.Context, query queryer, id, sourceID string) (Revision, error) {
	var revision Revision
	var hint, schedule, createdBy sql.NullString
	var privateNetwork int
	var createdAt int64
	var publishedAt sql.NullInt64
	err := query.QueryRowContext(ctx, `
SELECT id, source_id, revision_number, state, source_type, input_format_hint,
       import_purpose, refresh_schedule, schedule_timezone,
       private_network_authorized, config_blob_id, config_schema_version,
       created_by, created_at, published_at
FROM source_revisions WHERE id = ? AND source_id = ?`, id, sourceID).Scan(
		&revision.ID, &revision.SourceID, &revision.Number, &revision.State,
		&revision.Config.SourceType, &hint, &revision.Config.ImportPurpose, &schedule,
		&revision.Config.ScheduleTimezone, &privateNetwork, &revision.Config.ConfigBlobID,
		&revision.Config.ConfigSchemaVersion, &createdBy, &createdAt, &publishedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Revision{}, ErrNotFound
	}
	if err != nil {
		return Revision{}, fmt.Errorf("read source revision: %w", err)
	}
	revision.Config.InputFormatHint = hint.String
	revision.Config.RefreshSchedule = schedule.String
	revision.Config.PrivateNetworkAuthorized = privateNetwork == 1
	revision.Config.CreatedBy = createdBy.String
	revision.CreatedAt = fromMillis(createdAt)
	if publishedAt.Valid {
		value := fromMillis(publishedAt.Int64)
		revision.PublishedAt = &value
	}
	return revision, nil
}

func readAttempt(ctx context.Context, query queryer, id string) (Attempt, error) {
	var attempt Attempt
	var httpStatus, totalMS, responseBytes, nodeCount sql.NullInt64
	var errorCode, errorDetail, snapshotID sql.NullString
	var startedAt int64
	var finishedAt sql.NullInt64
	err := query.QueryRowContext(ctx, `
SELECT id, source_id, source_revision_id, trigger_kind, status,
       http_status, total_ms, response_bytes, node_count, warning_count,
       error_code, error_detail, accepted_snapshot_id, correlation_id,
       started_at, finished_at
FROM refresh_attempts WHERE id = ?`, id).Scan(
		&attempt.ID, &attempt.SourceID, &attempt.SourceRevisionID, &attempt.Trigger, &attempt.Status,
		&httpStatus, &totalMS, &responseBytes, &nodeCount, &attempt.WarningCount,
		&errorCode, &errorDetail, &snapshotID, &attempt.CorrelationID, &startedAt, &finishedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Attempt{}, ErrNotFound
	}
	if err != nil {
		return Attempt{}, fmt.Errorf("read refresh attempt: %w", err)
	}
	attempt.HTTPStatus = nullIntPointer(httpStatus)
	attempt.TotalMS = nullIntPointer(totalMS)
	attempt.ResponseBytes = nullIntPointer(responseBytes)
	attempt.NodeCount = nullIntPointer(nodeCount)
	attempt.ErrorCode = errorCode.String
	attempt.ErrorDetail = errorDetail.String
	attempt.AcceptedSnapshotID = snapshotID.String
	attempt.StartedAt = fromMillis(startedAt)
	if finishedAt.Valid {
		value := fromMillis(finishedAt.Int64)
		attempt.FinishedAt = &value
	}
	return attempt, nil
}

func readSnapshot(ctx context.Context, query queryer, id, sourceID string) (Snapshot, error) {
	var snapshot Snapshot
	var acceptedAt, staleAfter, retainUntil int64
	err := query.QueryRowContext(ctx, `
SELECT id, source_id, source_revision_id, raw_document_id, refresh_attempt_id,
       node_count, logical_outbound_count, warning_count,
       occurrence_algorithm_version, accepted_at, stale_after, retain_until
FROM snapshots WHERE id = ? AND source_id = ?`, id, sourceID).Scan(
		&snapshot.ID, &snapshot.SourceID, &snapshot.SourceRevisionID,
		&snapshot.RawDocumentID, &snapshot.RefreshAttemptID, &snapshot.NodeCount,
		&snapshot.LogicalOutboundCount, &snapshot.WarningCount,
		&snapshot.OccurrenceAlgorithmVersion, &acceptedAt, &staleAfter, &retainUntil,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, ErrNotFound
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("read snapshot: %w", err)
	}
	snapshot.AcceptedAt = fromMillis(acceptedAt)
	snapshot.StaleAfter = fromMillis(staleAfter)
	snapshot.RetainUntil = fromMillis(retainUntil)
	return snapshot, nil
}

func insertRevision(ctx context.Context, tx *sql.Tx, id, sourceID string, number int, state string, config RevisionConfig, createdAt time.Time, publishedAt *time.Time) error {
	var published interface{}
	if publishedAt != nil {
		published = publishedAt.UnixMilli()
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO source_revisions(
  id, source_id, revision_number, state, source_type, input_format_hint,
  import_purpose, refresh_schedule, schedule_timezone,
  private_network_authorized, config_blob_id, config_schema_version,
  created_by, created_at, published_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, sourceID, number, state, string(config.SourceType), nullableString(config.InputFormatHint),
		string(config.ImportPurpose), nullableString(config.RefreshSchedule), config.ScheduleTimezone,
		boolInt(config.PrivateNetworkAuthorized), config.ConfigBlobID, config.ConfigSchemaVersion,
		nullableString(config.CreatedBy), createdAt.UnixMilli(), published,
	)
	if err != nil {
		return fmt.Errorf("insert source revision: %w", err)
	}
	return nil
}

func requireBlobKind(ctx context.Context, query queryer, id, want string) error {
	if !validID(id) {
		return ErrNotFound
	}
	var kind string
	if err := query.QueryRowContext(ctx, `SELECT kind FROM encrypted_blobs WHERE id = ?`, id).Scan(&kind); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("read encrypted blob kind: %w", err)
	}
	if kind != want {
		return fmt.Errorf("%w: encrypted blob kind is %q, want %q", ErrConflict, kind, want)
	}
	return nil
}

func validateCreateRequest(request CreateRequest) error {
	if !utf8.ValidString(request.DisplayName) || strings.TrimSpace(request.DisplayName) == "" || utf8.RuneCountInString(request.DisplayName) > 200 {
		return fmt.Errorf("source display name is required and must not exceed 200 characters")
	}
	config := withRevisionDefaults(request.Config)
	return validateRevisionConfig(config)
}

func validateRevisionConfig(config RevisionConfig) error {
	if !validSourceType(config.SourceType) {
		return fmt.Errorf("invalid source type %q", config.SourceType)
	}
	if !validImportPurpose(config.ImportPurpose) {
		return fmt.Errorf("invalid import purpose %q", config.ImportPurpose)
	}
	if !validID(config.ConfigBlobID) {
		return fmt.Errorf("valid source config blob ID is required")
	}
	if config.ConfigSchemaVersion <= 0 {
		return fmt.Errorf("source config schema version must be positive")
	}
	if config.ScheduleTimezone == "" || len(config.ScheduleTimezone) > 64 {
		return fmt.Errorf("source schedule timezone is required and must not exceed 64 bytes")
	}
	if len(config.InputFormatHint) > 128 || len(config.RefreshSchedule) > 256 {
		return fmt.Errorf("source format hint or refresh schedule exceeds its limit")
	}
	if config.CreatedBy != "" && !validID(config.CreatedBy) {
		return fmt.Errorf("source revision creator must be a valid ID")
	}
	return nil
}

func validateAcceptRequest(request AcceptRequest) error {
	if !validID(request.AttemptID) || !validID(request.RawBlobID) {
		return ErrNotFound
	}
	if request.DetectedFormat == "" || len(request.DetectedFormat) > 128 ||
		request.FormatAdapterVersion == "" || len(request.FormatAdapterVersion) > 128 {
		return fmt.Errorf("detected format and adapter version are required and bounded")
	}
	if len(request.MediaType) > 128 || len(request.Charset) > 128 {
		return fmt.Errorf("raw document media type or charset exceeds its limit")
	}
	if request.ParseLimitsVersion < 0 || request.NodeCount < 0 || request.LogicalOutboundCount < 0 ||
		request.WarningCount < 0 || invalidMetrics(request.Metrics) {
		return fmt.Errorf("snapshot counts and metrics must be non-negative")
	}
	if len(request.Nodes) != request.NodeCount {
		return fmt.Errorf("snapshot node count does not match persisted node details")
	}
	if request.NodeCount > 0 && len(request.Occurrences) == 0 {
		return fmt.Errorf("snapshot occurrences are required when nodes are present")
	}
	if request.OccurrenceAlgorithmVersion == "" || len(request.OccurrenceAlgorithmVersion) > 128 {
		return fmt.Errorf("occurrence algorithm version is required and bounded")
	}
	if request.OccurrenceAlgorithmVersion != occurrence.AlgorithmVersion {
		return fmt.Errorf("unsupported occurrence algorithm version %q", request.OccurrenceAlgorithmVersion)
	}
	if request.StaleAfter <= 0 || request.RetainFor < request.StaleAfter {
		return fmt.Errorf("snapshot retention must be at least its positive stale duration")
	}
	return nil
}

func (r *Repository) persistSnapshotDetails(ctx context.Context, tx *sql.Tx, snapshotID, sourceID, associationVersion string, nodes []AcceptedNode, occurrences []occurrence.Occurrence, now time.Time) error {
	fingerprintIDs := make(map[string]string)
	occurrencesByID := make(map[string]occurrence.Occurrence, len(occurrences))
	for _, item := range occurrences {
		if _, duplicate := occurrencesByID[item.ID]; duplicate {
			return fmt.Errorf("duplicate persisted occurrence %q", item.ID)
		}
		if item.AlgorithmVersion != associationVersion {
			return fmt.Errorf("occurrence %q uses a different association version", item.ID)
		}
		fingerprintID, err := r.ensureFingerprint(ctx, tx, item.ProtocolID, item.Fingerprint, now)
		if err != nil {
			return err
		}
		fingerprintIDs[item.Fingerprint.MatchKey()] = fingerprintID
		occurrencesByID[item.ID] = item
		if err := persistOccurrence(ctx, tx, sourceID, fingerprintID, item, now); err != nil {
			return err
		}
	}
	seenOrdinals := make(map[int]struct{}, len(nodes))
	seenOccurrences := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		if err := validateAcceptedNode(node); err != nil {
			return err
		}
		if _, duplicate := seenOrdinals[node.Ordinal]; duplicate {
			return fmt.Errorf("duplicate accepted node ordinal %d", node.Ordinal)
		}
		seenOrdinals[node.Ordinal] = struct{}{}
		if _, duplicate := seenOccurrences[node.OccurrenceID]; duplicate {
			return fmt.Errorf("duplicate accepted node occurrence %q", node.OccurrenceID)
		}
		seenOccurrences[node.OccurrenceID] = struct{}{}
		linkedOccurrence, exists := occurrencesByID[node.OccurrenceID]
		if !exists || linkedOccurrence.State != occurrence.StatePresent {
			return fmt.Errorf("accepted node ordinal %d has no present occurrence", node.Ordinal)
		}
		if linkedOccurrence.ProtocolID != node.ProtocolID || linkedOccurrence.Fingerprint.MatchKey() != node.Fingerprint.MatchKey() {
			return fmt.Errorf("accepted node ordinal %d differs from its occurrence identity", node.Ordinal)
		}
		fingerprintID, exists := fingerprintIDs[node.Fingerprint.MatchKey()]
		if !exists {
			return fmt.Errorf("accepted node ordinal %d has no persisted occurrence fingerprint", node.Ordinal)
		}
		if err := requireBlobKind(ctx, tx, node.RawBlobID, "raw_node"); err != nil {
			return err
		}
		var nameHMAC interface{}
		if node.OriginalNameBlobID != "" {
			digest, err := requireBlobKindAndHMAC(ctx, tx, node.OriginalNameBlobID, "node_name")
			if err != nil {
				return err
			}
			nameHMAC = digest
		}
		rawNodeID, err := r.nextID("raw node")
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO raw_nodes(
  id, snapshot_id, raw_blob_id, original_name_blob_id, original_name_hmac,
  source_ordinal, extraction_path, raw_kind, format_id, format_adapter_version,
  protocol_id, fingerprint_id, parse_status, warning_count, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			rawNodeID, snapshotID, node.RawBlobID, nullableString(node.OriginalNameBlobID), nameHMAC,
			node.Ordinal, node.ExtractionPath, node.RawKind, node.FormatID, node.FormatAdapterVersion,
			node.ProtocolID, fingerprintID, node.ParseStatus, node.WarningCount, now.UnixMilli(),
		); err != nil {
			return fmt.Errorf("insert raw node ordinal %d: %w", node.Ordinal, err)
		}
		if node.CanonicalBlobID != "" {
			if err := requireBlobKind(ctx, tx, node.CanonicalBlobID, "canonical_node"); err != nil {
				return err
			}
			flags := node.CanonicalFeatureFlags
			if flags == "" {
				flags = "[]"
			}
			if _, err := tx.ExecContext(ctx, `
INSERT INTO canonical_nodes(
  raw_node_id, protocol_adapter_version, completeness,
  canonical_blob_id, feature_flags, generated_at
) VALUES (?, ?, ?, ?, ?, ?)`,
				rawNodeID, node.CanonicalVersion, node.CanonicalCompleteness,
				node.CanonicalBlobID, flags, now.UnixMilli(),
			); err != nil {
				return fmt.Errorf("insert canonical node ordinal %d: %w", node.Ordinal, err)
			}
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO snapshot_occurrences(
  snapshot_id, raw_node_id, node_occurrence_id, occurrence_ordinal,
  match_method, association_version, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			snapshotID, rawNodeID, node.OccurrenceID, node.Ordinal,
			string(node.MatchMethod), occurrence.AlgorithmVersion, now.UnixMilli(),
		); err != nil {
			return fmt.Errorf("link snapshot node ordinal %d: %w", node.Ordinal, err)
		}
	}
	for _, item := range occurrences {
		if item.State == occurrence.StatePresent {
			if _, linked := seenOccurrences[item.ID]; !linked {
				return fmt.Errorf("present occurrence %q has no accepted node", item.ID)
			}
		}
	}
	for ordinal := 0; ordinal < len(nodes); ordinal++ {
		if _, exists := seenOrdinals[ordinal]; !exists {
			return fmt.Errorf("accepted node ordinals must be contiguous from zero")
		}
	}
	return nil
}

func (r *Repository) ensureFingerprint(ctx context.Context, tx *sql.Tx, protocolID string, fingerprint identity.Fingerprint, now time.Time) (string, error) {
	if protocolID == "" || len(protocolID) > 128 || fingerprint.Algorithm != identity.Algorithm ||
		(fingerprint.Kind != identity.KindSemantic && fingerprint.Kind != identity.KindOpaqueStructural) ||
		fingerprint.ProjectionVersion == "" || !validID(fingerprint.KeyID) {
		return "", fmt.Errorf("invalid persisted fingerprint metadata")
	}
	digest, err := base64.RawURLEncoding.DecodeString(fingerprint.Digest)
	if err != nil || len(digest) != 32 {
		return "", fmt.Errorf("invalid persisted fingerprint digest")
	}
	var keyPurpose string
	if err := tx.QueryRowContext(ctx, `SELECT purpose FROM data_keys WHERE id = ?`, fingerprint.KeyID).Scan(&keyPurpose); errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	} else if err != nil {
		return "", fmt.Errorf("read fingerprint key purpose: %w", err)
	} else if keyPurpose != "fingerprint_hmac" {
		return "", fmt.Errorf("%w: fingerprint uses a key with purpose %q", ErrConflict, keyPurpose)
	}
	var existingID, existingProtocol, existingKind, existingAlgorithm string
	err = tx.QueryRowContext(ctx, `
SELECT id, protocol_id, kind, algorithm FROM fingerprints
WHERE key_id = ? AND projection_version = ? AND digest = ?`,
		fingerprint.KeyID, fingerprint.ProjectionVersion, digest,
	).Scan(&existingID, &existingProtocol, &existingKind, &existingAlgorithm)
	if err == nil {
		if existingProtocol != protocolID || existingKind != string(fingerprint.Kind) || existingAlgorithm != fingerprint.Algorithm {
			return "", fmt.Errorf("%w: fingerprint metadata differs for an existing digest", ErrConflict)
		}
		return existingID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("read persisted fingerprint: %w", err)
	}
	id, err := r.nextID("fingerprint")
	if err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO fingerprints(
  id, protocol_id, kind, algorithm, projection_version,
  key_id, digest, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, protocolID, string(fingerprint.Kind), fingerprint.Algorithm,
		fingerprint.ProjectionVersion, fingerprint.KeyID, digest, now.UnixMilli(),
	); err != nil {
		return "", fmt.Errorf("insert fingerprint: %w", err)
	}
	return id, nil
}

func persistOccurrence(ctx context.Context, tx *sql.Tx, sourceID, fingerprintID string, item occurrence.Occurrence, now time.Time) error {
	if !validID(item.ID) || item.ProtocolID == "" || len(item.ProtocolID) > 128 || item.DuplicateSlot < 1 ||
		item.CreatedAt.IsZero() || item.LastSeenAt.IsZero() || item.LastSeenAt.Before(item.CreatedAt) || item.LastSeenAt.After(now) ||
		item.AlgorithmVersion == "" || len(item.AlgorithmVersion) > 128 {
		return fmt.Errorf("invalid persisted occurrence %q", item.ID)
	}
	if item.State != occurrence.StatePresent && item.State != occurrence.StateAbsent && item.State != occurrence.StateRetired {
		return fmt.Errorf("invalid persisted occurrence state %q", item.State)
	}
	if item.State == occurrence.StatePresent && (item.AbsentSince != nil || item.RetainUntil != nil) {
		return fmt.Errorf("present occurrence %q has absence timestamps", item.ID)
	}
	if item.State == occurrence.StateAbsent && (item.AbsentSince == nil || item.RetainUntil == nil || !item.RetainUntil.After(*item.AbsentSince)) {
		return fmt.Errorf("absent occurrence %q has invalid retention timestamps", item.ID)
	}
	var existingSource string
	var existingCreatedAt int64
	err := tx.QueryRowContext(ctx, `SELECT source_id, created_at FROM node_occurrences WHERE id = ?`, item.ID).Scan(&existingSource, &existingCreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx, `
INSERT INTO node_occurrences(
  id, source_id, current_fingerprint_id, lifecycle_state, duplicate_slot,
  first_seen_at, last_seen_at, absent_since, retain_until,
  association_version, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			item.ID, sourceID, fingerprintID, string(item.State), item.DuplicateSlot,
			item.CreatedAt.UTC().UnixMilli(), item.LastSeenAt.UTC().UnixMilli(), nullableTime(item.AbsentSince),
			nullableTime(item.RetainUntil), item.AlgorithmVersion, item.CreatedAt.UTC().UnixMilli(), now.UnixMilli(),
		)
		if err != nil {
			return fmt.Errorf("insert node occurrence %s: %w", item.ID, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read node occurrence %s: %w", item.ID, err)
	}
	if existingSource != sourceID {
		return fmt.Errorf("%w: occurrence belongs to another source", ErrConflict)
	}
	if existingCreatedAt != item.CreatedAt.UTC().UnixMilli() {
		return fmt.Errorf("%w: occurrence creation time is immutable", ErrConflict)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE node_occurrences
SET current_fingerprint_id = ?, lifecycle_state = ?, duplicate_slot = ?,
    last_seen_at = ?, absent_since = ?, retain_until = ?,
    association_version = ?, updated_at = ?
WHERE id = ? AND source_id = ?`,
		fingerprintID, string(item.State), item.DuplicateSlot, item.LastSeenAt.UTC().UnixMilli(),
		nullableTime(item.AbsentSince), nullableTime(item.RetainUntil), item.AlgorithmVersion,
		now.UnixMilli(), item.ID, sourceID,
	); err != nil {
		return fmt.Errorf("update node occurrence %s: %w", item.ID, err)
	}
	return nil
}

func validateAcceptedNode(node AcceptedNode) error {
	if node.Ordinal < 0 || len(node.ExtractionPath) > 1024 ||
		!validID(node.RawBlobID) || !validID(node.OccurrenceID) || node.WarningCount < 0 {
		return fmt.Errorf("invalid accepted node ordinal %d", node.Ordinal)
	}
	if node.RawKind != "json_object" && node.RawKind != "uri" && node.RawKind != "text" {
		return fmt.Errorf("invalid accepted node raw kind %q", node.RawKind)
	}
	if node.ParseStatus != "complete" && node.ParseStatus != "partial" && node.ParseStatus != "opaque" && node.ParseStatus != "invalid" {
		return fmt.Errorf("invalid accepted node parse status %q", node.ParseStatus)
	}
	if node.FormatID == "" || len(node.FormatID) > 128 || node.FormatAdapterVersion == "" || len(node.FormatAdapterVersion) > 128 ||
		node.ProtocolID == "" || len(node.ProtocolID) > 128 {
		return fmt.Errorf("accepted node format and protocol metadata are required")
	}
	if !validMatchMethod(node.MatchMethod) {
		return fmt.Errorf("invalid accepted node match method %q", node.MatchMethod)
	}
	if node.CanonicalBlobID != "" {
		if !validID(node.CanonicalBlobID) || node.CanonicalVersion == "" ||
			(node.CanonicalCompleteness != "complete" && node.CanonicalCompleteness != "partial" && node.CanonicalCompleteness != "opaque") {
			return fmt.Errorf("invalid accepted canonical node ordinal %d", node.Ordinal)
		}
		flags := node.CanonicalFeatureFlags
		if flags == "" {
			flags = "[]"
		}
		var decodedFlags []string
		if len(flags) > 4096 || json.Unmarshal([]byte(flags), &decodedFlags) != nil {
			return fmt.Errorf("invalid canonical feature flags for node ordinal %d", node.Ordinal)
		}
	} else if node.CanonicalVersion != "" || node.CanonicalCompleteness != "" || node.CanonicalFeatureFlags != "" {
		return fmt.Errorf("canonical metadata without a blob for node ordinal %d", node.Ordinal)
	}
	return nil
}

func validMatchMethod(value occurrence.MatchMethod) bool {
	return value == occurrence.MatchFingerprintUnique || value == occurrence.MatchPath ||
		value == occurrence.MatchDuplicateSlot || value == occurrence.MatchAuxiliaryUnique ||
		value == occurrence.MatchNew || value == occurrence.MatchAmbiguousNew
}

func requireBlobKindAndHMAC(ctx context.Context, query queryer, id, want string) ([]byte, error) {
	if !validID(id) {
		return nil, ErrNotFound
	}
	var kind string
	var digest []byte
	if err := query.QueryRowContext(ctx, `SELECT kind, content_hmac FROM encrypted_blobs WHERE id = ?`, id).Scan(&kind, &digest); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, fmt.Errorf("read encrypted blob metadata: %w", err)
	}
	if kind != want || len(digest) != 32 {
		return nil, fmt.Errorf("%w: encrypted blob kind or digest is invalid", ErrConflict)
	}
	return digest, nil
}

func nullableTime(value *time.Time) interface{} {
	if value == nil {
		return nil
	}
	return value.UTC().UnixMilli()
}

func escapeLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	return strings.ReplaceAll(value, `_`, `\_`)
}

func withRevisionDefaults(config RevisionConfig) RevisionConfig {
	if config.ScheduleTimezone == "" {
		config.ScheduleTimezone = "UTC"
	}
	if config.ConfigSchemaVersion == 0 {
		config.ConfigSchemaVersion = 1
	}
	return config
}

func validSourceType(value SourceType) bool {
	return value == SourceRemote || value == SourceInline || value == SourceUpload
}

func validImportPurpose(value ImportPurpose) bool {
	return value == PurposeNodes || value == PurposeTemplate || value == PurposeTemplateAndNodes || value == PurposeRawPassthrough
}

func validTrigger(value TriggerKind) bool {
	return value == TriggerManual || value == TriggerSchedule || value == TriggerRetry || value == TriggerImport
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

func (r *Repository) currentTime() (time.Time, error) {
	if r == nil || r.database == nil || r.now == nil || r.newID == nil {
		return time.Time{}, fmt.Errorf("source store is not initialized")
	}
	now := r.now().UTC()
	if now.IsZero() {
		return time.Time{}, fmt.Errorf("source store clock returned zero time")
	}
	return now, nil
}

func (r *Repository) nextID(kind string) (string, error) {
	id := r.newID()
	if !validID(id) {
		return "", fmt.Errorf("%s ID generator returned an invalid ID", kind)
	}
	return id, nil
}

func invalidMetrics(metrics AttemptMetrics) bool {
	return invalidOptionalNonNegative(metrics.HTTPStatus) || invalidOptionalNonNegative(metrics.TotalMS) ||
		invalidOptionalNonNegative(metrics.ResponseBytes) ||
		(metrics.HTTPStatus != nil && (*metrics.HTTPStatus < 100 || *metrics.HTTPStatus > 599))
}

func invalidOptionalNonNegative(value *int) bool {
	return value != nil && *value < 0
}

func nullableString(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}

func nullableInt(value *int) interface{} {
	if value == nil {
		return nil
	}
	return *value
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func intPointer(value int) *int {
	return &value
}

func timePointer(value time.Time) *time.Time {
	return &value
}

func nullIntPointer(value sql.NullInt64) *int {
	if !value.Valid {
		return nil
	}
	converted := int(value.Int64)
	return &converted
}

func fromMillis(value int64) time.Time {
	return time.UnixMilli(value).UTC()
}

type nullStringTarget struct {
	target *string
}

func (target nullStringTarget) Scan(value interface{}) error {
	var nullable sql.NullString
	if err := nullable.Scan(value); err != nil {
		return err
	}
	if nullable.Valid {
		*target.target = nullable.String
	}
	return nil
}

func nullStringScanner(target *string) sql.Scanner {
	return nullStringTarget{target: target}
}

type timeTarget struct {
	target *time.Time
}

func (target timeTarget) Scan(value interface{}) error {
	var milliseconds int64
	switch typed := value.(type) {
	case int64:
		milliseconds = typed
	case int:
		milliseconds = int64(typed)
	default:
		return fmt.Errorf("unexpected SQLite time type %T", value)
	}
	*target.target = fromMillis(milliseconds)
	return nil
}

func timeScanner(target *time.Time) sql.Scanner {
	return timeTarget{target: target}
}
