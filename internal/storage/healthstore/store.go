package healthstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const (
	DefaultStaleAfter       = time.Hour
	DefaultPeriodicInterval = 30 * time.Minute
	DefaultLease            = 30 * time.Second
	QueueHardLimit          = 100000
)

var (
	ErrNotFound  = errors.New("health record not found")
	ErrConflict  = errors.New("health state conflict")
	ErrQueueFull = errors.New("health queue reached its hard limit")
)

type State string

const (
	StateUnchecked   State = "unchecked"
	StateHealthy     State = "healthy"
	StateDegraded    State = "degraded"
	StateUnhealthy   State = "unhealthy"
	StateUnsupported State = "unsupported"
	StateDisabled    State = "disabled"
)

type ResultClass string

const (
	ResultSuccess          ResultClass = "success"
	ResultDNSFailure       ResultClass = "dns_failure"
	ResultConnectTimeout   ResultClass = "connect_timeout"
	ResultConnectRefused   ResultClass = "connect_refused"
	ResultAuthFailure      ResultClass = "auth_failure"
	ResultTLSFailure       ResultClass = "tls_failure"
	ResultProtocolFailure  ResultClass = "protocol_failure"
	ResultUnexpectedStatus ResultClass = "unexpected_status"
	ResultTargetFailure    ResultClass = "target_failure"
	ResultUnsupported      ResultClass = "executor_unsupported"
	ResultExecutorCrash    ResultClass = "executor_crash"
	ResultResourceLimited  ResultClass = "resource_limited"
	ResultCancelled        ResultClass = "cancelled"
)

type Options struct {
	Now   func() time.Time
	NewID func() string
}

type Store struct {
	database *sql.DB
	now      func() time.Time
	newID    func() string
}

type ProbeItem struct {
	ID               string
	NodeOccurrenceID string
	SourceID         string
	SnapshotID       string
	ProtocolID       string
	FormatID         string
	RawBlobID        string
	CanonicalBlobID  string
	PriorityClass    string
	Attempt          int
	State            State
	RecoveryStep     int
}

type ProbeResult struct {
	Class            ResultClass
	Success          bool
	NodeAttributable bool
	TargetID         string
	HTTPStatus       *int
	Total            time.Duration
	DiagnosticCode   string
	ExecutorID       string
	ExecutorVersion  string
}

type HealthState struct {
	NodeOccurrenceID     string
	LatestRecordID       string
	State                State
	Stale                bool
	ConsecutiveSuccesses int
	ConsecutiveFailures  int
	RecoveryStep         int
	NextCheckAt          *time.Time
	UpdatedAt            time.Time
}

type NodeSummary struct {
	NodeOccurrenceID string
	SourceID         string
	ProtocolID       string
	FingerprintKind  string
	NameBlobID       string
	OccurrenceState  string
	HealthState      State
	Stale            bool
	LastSeenAt       time.Time
	UpdatedAt        time.Time
}

type NodeListOptions struct {
	NodeOccurrenceID string
	SourceID         string
	ProtocolID       string
	State            State
	PresentOnly      bool
	BeforeLastSeenAt *time.Time
	BeforeID         string
	Limit            int
}

type Record struct {
	ID               string
	NodeOccurrenceID string
	SnapshotID       string
	ProtocolID       string
	TargetID         string
	Class            ResultClass
	Success          bool
	NodeAttributable bool
	HTTPStatus       *int
	Total            time.Duration
	DiagnosticCode   string
	ExecutorID       string
	ExecutorVersion  string
	ObservedAt       time.Time
	StaleAfter       time.Time
}

type Capacity struct {
	Total     int
	Queued    int
	Running   int
	Dormant   int
	HardLimit int
}

type TransitionInput struct {
	State                State
	ConsecutiveSuccesses int
	ConsecutiveFailures  int
	RecoveryStep         int
	Result               ProbeResult
	Now                  time.Time
}

type Transition struct {
	State                State
	ConsecutiveSuccesses int
	ConsecutiveFailures  int
	RecoveryStep         int
	NextCheckAt          *time.Time
}

func New(database *sql.DB, options Options) (*Store, error) {
	if database == nil || options.Now == nil || options.NewID == nil {
		return nil, fmt.Errorf("health store dependencies are required")
	}
	return &Store{database: database, now: options.Now, newID: options.NewID}, nil
}

func (s *Store) SynchronizeSnapshot(ctx context.Context, sourceID, snapshotID string) error {
	now := s.now().UTC()
	rows, err := s.database.QueryContext(ctx, `
SELECT so.node_occurrence_id, rn.protocol_id, rn.format_id,
       rn.raw_blob_id, COALESCE(cn.canonical_blob_id, '')
FROM snapshot_occurrences so
JOIN snapshots sn ON sn.id = so.snapshot_id
JOIN raw_nodes rn ON rn.id = so.raw_node_id
LEFT JOIN canonical_nodes cn ON cn.raw_node_id = rn.id
WHERE so.snapshot_id = ? AND sn.source_id = ?
ORDER BY so.occurrence_ordinal`, snapshotID, sourceID)
	if err != nil {
		return fmt.Errorf("list snapshot nodes for health scheduling: %w", err)
	}
	type candidate struct {
		occurrenceID    string
		protocolID      string
		formatID        string
		rawBlobID       string
		canonicalBlobID string
	}
	candidates := make([]candidate, 0)
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.occurrenceID, &item.protocolID, &item.formatID, &item.rawBlobID, &item.canonicalBlobID); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan health scheduling candidate: %w", err)
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate health scheduling candidates: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close health scheduling candidates: %w", err)
	}
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin health snapshot synchronization: %w", err)
	}
	defer tx.Rollback()
	var queueCount int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM probe_queue_items`).Scan(&queueCount); err != nil {
		return fmt.Errorf("count health queue: %w", err)
	}
	for _, item := range candidates {
		supported := probeSupported(item.protocolID) && (item.formatID == "sing-box-json" || item.canonicalBlobID != "")
		state := StateUnsupported
		if supported {
			state = StateUnchecked
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO node_health_states(
  node_occurrence_id, state, stale, consecutive_successes,
  consecutive_failures, recovery_step, next_check_at, updated_at
) VALUES (?, ?, 0, 0, 0, 0, ?, ?)
ON CONFLICT(node_occurrence_id) DO UPDATE SET
  state = CASE
    WHEN node_health_states.state = 'unsupported' AND excluded.state = 'unchecked' THEN 'unchecked'
    WHEN excluded.state = 'unsupported' THEN 'unsupported'
    ELSE node_health_states.state
  END,
  next_check_at = CASE
    WHEN excluded.state = 'unsupported' THEN NULL
    ELSE COALESCE(node_health_states.next_check_at, excluded.next_check_at)
  END,
  updated_at = excluded.updated_at`,
			item.occurrenceID, string(state), nullableTimeIf(supported, now), now.UnixMilli()); err != nil {
			return fmt.Errorf("initialize node health state: %w", err)
		}
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM probe_queue_items WHERE node_occurrence_id = ?`, item.occurrenceID).Scan(&exists); err != nil {
			return fmt.Errorf("inspect health queue candidate: %w", err)
		}
		if exists == 0 {
			if queueCount >= QueueHardLimit {
				return ErrQueueFull
			}
			queueCount++
			id := s.newID()
			status := "dormant"
			var due interface{}
			if supported {
				status, due = "queued", now.UnixMilli()
			}
			if _, err := tx.ExecContext(ctx, `
INSERT INTO probe_queue_items(
  id, node_occurrence_id, priority_class, priority, status,
  due_at, created_at, updated_at
) VALUES (?, ?, 'initial', 300, ?, ?, ?, ?)`,
				id, item.occurrenceID, status, due, now.UnixMilli(), now.UnixMilli()); err != nil {
				return fmt.Errorf("enqueue initial node health check: %w", err)
			}
		} else if supported {
			if _, err := tx.ExecContext(ctx, `
UPDATE probe_queue_items
SET status = CASE WHEN status = 'dormant' THEN 'queued' ELSE status END,
    due_at = CASE WHEN status = 'dormant' OR due_at IS NULL OR due_at > ? THEN ? ELSE due_at END,
    priority_class = CASE WHEN priority < 300 THEN 'initial' ELSE priority_class END,
    priority = CASE WHEN priority < 300 THEN 300 ELSE priority END,
    updated_at = ?
WHERE node_occurrence_id = ?`, now.UnixMilli(), now.UnixMilli(), now.UnixMilli(), item.occurrenceID); err != nil {
				return fmt.Errorf("refresh node health queue: %w", err)
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE probe_queue_items
SET status = 'dormant', due_at = NULL, lease_owner = NULL,
    lease_expires_at = NULL, updated_at = ?
WHERE status IN ('dormant', 'queued')
  AND node_occurrence_id IN (
    SELECT id FROM node_occurrences
    WHERE source_id = ? AND lifecycle_state <> 'present'
  )`, now.UnixMilli(), sourceID); err != nil {
		return fmt.Errorf("deactivate absent node health checks: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit health snapshot synchronization: %w", err)
	}
	return nil
}

// SynchronizeCurrentSnapshots re-evaluates executor support after an application upgrade.
func (s *Store) SynchronizeCurrentSnapshots(ctx context.Context) error {
	rows, err := s.database.QueryContext(ctx, `
SELECT id, current_snapshot_id
FROM sources
WHERE lifecycle_state = 'active' AND current_snapshot_id IS NOT NULL
ORDER BY id`)
	if err != nil {
		return fmt.Errorf("list current snapshots for health synchronization: %w", err)
	}
	type currentSnapshot struct {
		sourceID   string
		snapshotID string
	}
	items := make([]currentSnapshot, 0)
	for rows.Next() {
		var item currentSnapshot
		if err := rows.Scan(&item.sourceID, &item.snapshotID); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan current snapshot for health synchronization: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate current snapshots for health synchronization: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close current snapshot health synchronization: %w", err)
	}
	for _, item := range items {
		if err := s.SynchronizeSnapshot(ctx, item.sourceID, item.snapshotID); err != nil {
			return fmt.Errorf("synchronize current snapshot %s: %w", item.snapshotID, err)
		}
	}
	return nil
}

func (s *Store) RecoverExpired(ctx context.Context) (int, error) {
	now := s.now().UTC().UnixMilli()
	result, err := s.database.ExecContext(ctx, `
UPDATE probe_queue_items
SET status = 'queued', lease_owner = NULL, lease_expires_at = NULL,
    due_at = ?, attempt = attempt + 1, updated_at = ?
WHERE status IN ('leased', 'running') AND lease_expires_at <= ?`, now, now, now)
	if err != nil {
		return 0, fmt.Errorf("recover expired health leases: %w", err)
	}
	count, _ := result.RowsAffected()
	return int(count), nil
}

func (s *Store) Claim(ctx context.Context, owner string, lease time.Duration) (ProbeItem, bool, error) {
	if owner == "" {
		return ProbeItem{}, false, fmt.Errorf("health lease owner is required")
	}
	if lease <= 0 {
		lease = DefaultLease
	}
	now := s.now().UTC()
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return ProbeItem{}, false, fmt.Errorf("begin health queue claim: %w", err)
	}
	defer tx.Rollback()
	var item ProbeItem
	err = tx.QueryRowContext(ctx, `
SELECT q.id, q.node_occurrence_id, q.priority_class, q.attempt,
       hs.state, hs.recovery_step,
       o.source_id, s.current_snapshot_id, rn.protocol_id, rn.format_id,
       rn.raw_blob_id, COALESCE(cn.canonical_blob_id, '')
FROM probe_queue_items q
JOIN node_occurrences o ON o.id = q.node_occurrence_id AND o.lifecycle_state = 'present'
JOIN node_health_states hs ON hs.node_occurrence_id = q.node_occurrence_id
JOIN sources s ON s.id = o.source_id AND s.lifecycle_state = 'active'
JOIN snapshot_occurrences so ON so.snapshot_id = s.current_snapshot_id
  AND so.node_occurrence_id = q.node_occurrence_id
JOIN raw_nodes rn ON rn.id = so.raw_node_id
LEFT JOIN canonical_nodes cn ON cn.raw_node_id = rn.id
WHERE q.status = 'queued' AND q.due_at <= ?
ORDER BY q.priority DESC, q.due_at, q.created_at, q.id
LIMIT 1`, now.UnixMilli()).Scan(
		&item.ID, &item.NodeOccurrenceID, &item.PriorityClass, &item.Attempt,
		&item.State, &item.RecoveryStep,
		&item.SourceID, &item.SnapshotID, &item.ProtocolID, &item.FormatID,
		&item.RawBlobID, &item.CanonicalBlobID)
	if errors.Is(err, sql.ErrNoRows) {
		return ProbeItem{}, false, nil
	}
	if err != nil {
		return ProbeItem{}, false, fmt.Errorf("select health queue item: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE probe_queue_items
SET status = 'running', lease_owner = ?, lease_expires_at = ?, updated_at = ?
WHERE id = ? AND status = 'queued'`, owner, now.Add(lease).UnixMilli(), now.UnixMilli(), item.ID)
	if err != nil {
		return ProbeItem{}, false, fmt.Errorf("claim health queue item: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ProbeItem{}, false, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return ProbeItem{}, false, fmt.Errorf("commit health queue claim: %w", err)
	}
	return item, true, nil
}

func (s *Store) Complete(ctx context.Context, item ProbeItem, owner string, result ProbeResult) (HealthState, error) {
	if !validResult(result) {
		return HealthState{}, fmt.Errorf("invalid node probe result")
	}
	now := s.now().UTC()
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return HealthState{}, fmt.Errorf("begin node probe completion: %w", err)
	}
	defer tx.Rollback()
	var queueOwner, status string
	if err := tx.QueryRowContext(ctx, `SELECT lease_owner, status FROM probe_queue_items WHERE id = ?`, item.ID).Scan(&queueOwner, &status); errors.Is(err, sql.ErrNoRows) {
		return HealthState{}, ErrNotFound
	} else if err != nil {
		return HealthState{}, fmt.Errorf("read running health queue item: %w", err)
	}
	if queueOwner != owner || status != "running" {
		return HealthState{}, ErrConflict
	}
	state, err := readState(ctx, tx, item.NodeOccurrenceID)
	if err != nil {
		return HealthState{}, err
	}
	recordID := s.newID()
	totalMS := int(result.Total.Milliseconds())
	if totalMS < 0 {
		totalMS = 0
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO health_records(
  id, node_occurrence_id, snapshot_id, protocol_id, probe_level,
  target_id, result_class, success, node_attributable, http_status,
  total_ms, executor_id, executor_version, diagnostic_code,
  observed_at, stale_after, created_at
) VALUES (?, ?, ?, ?, 'proxy_http', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		recordID, item.NodeOccurrenceID, item.SnapshotID, item.ProtocolID,
		nullableString(result.TargetID), string(result.Class), boolInt(result.Success), boolInt(result.NodeAttributable), nullableInt(result.HTTPStatus),
		totalMS, result.ExecutorID, result.ExecutorVersion, nullableString(result.DiagnosticCode),
		now.UnixMilli(), now.Add(DefaultStaleAfter).UnixMilli(), now.UnixMilli()); err != nil {
		return HealthState{}, fmt.Errorf("insert node health record: %w", err)
	}
	transition := ApplyTransition(TransitionInput{
		State: state.State, ConsecutiveSuccesses: state.ConsecutiveSuccesses,
		ConsecutiveFailures: state.ConsecutiveFailures, RecoveryStep: state.RecoveryStep,
		Result: result, Now: now,
	})
	if _, err := tx.ExecContext(ctx, `
UPDATE node_health_states
SET latest_record_id = ?, state = ?, stale = 0, consecutive_successes = ?,
    consecutive_failures = ?, recovery_step = ?, next_check_at = ?, updated_at = ?
WHERE node_occurrence_id = ?`,
		recordID, string(transition.State), transition.ConsecutiveSuccesses,
		transition.ConsecutiveFailures, transition.RecoveryStep, nullableTime(transition.NextCheckAt),
		now.UnixMilli(), item.NodeOccurrenceID); err != nil {
		return HealthState{}, fmt.Errorf("update node health state: %w", err)
	}
	priorityClass, priority := priorityFor(transition)
	if _, err := tx.ExecContext(ctx, `
UPDATE probe_queue_items
SET status = ?, priority_class = ?, priority = ?, due_at = ?,
    lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
WHERE id = ?`, queueStatus(transition.NextCheckAt), priorityClass, priority,
		nullableTime(transition.NextCheckAt), now.UnixMilli(), item.ID); err != nil {
		return HealthState{}, fmt.Errorf("reschedule node health check: %w", err)
	}
	if err := updateGuardWindow(ctx, tx, now); err != nil {
		return HealthState{}, err
	}
	if err := tx.Commit(); err != nil {
		return HealthState{}, fmt.Errorf("commit node probe completion: %w", err)
	}
	state.LatestRecordID = recordID
	state.State = transition.State
	state.Stale = false
	state.ConsecutiveSuccesses = transition.ConsecutiveSuccesses
	state.ConsecutiveFailures = transition.ConsecutiveFailures
	state.RecoveryStep = transition.RecoveryStep
	state.NextCheckAt = transition.NextCheckAt
	state.UpdatedAt = now
	return state, nil
}

func (s *Store) ManualEnqueue(ctx context.Context, occurrenceID string) error {
	now := s.now().UTC()
	result, err := s.database.ExecContext(ctx, `
UPDATE probe_queue_items
SET status = 'queued', priority_class = 'manual', priority = 1000,
    due_at = ?, lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
WHERE node_occurrence_id = ? AND status IN ('dormant', 'queued')`, now.UnixMilli(), now.UnixMilli(), occurrenceID)
	if err != nil {
		return fmt.Errorf("enqueue manual node check: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrConflict
	}
	return nil
}

func (s *Store) ListNodes(ctx context.Context, options NodeListOptions) ([]NodeSummary, bool, error) {
	if options.Limit <= 0 || options.Limit > 200 {
		return nil, false, fmt.Errorf("node list limit must be between 1 and 200")
	}
	if options.BeforeLastSeenAt != nil && len(options.BeforeID) != 36 {
		return nil, false, fmt.Errorf("node list cursor is invalid")
	}
	query := `
SELECT o.id, o.source_id, f.protocol_id, f.kind,
       COALESCE((
         SELECT rn.original_name_blob_id
         FROM snapshot_occurrences so
         JOIN snapshots sn ON sn.id = so.snapshot_id
         JOIN raw_nodes rn ON rn.id = so.raw_node_id
         WHERE so.node_occurrence_id = o.id
         ORDER BY sn.accepted_at DESC, rn.source_ordinal DESC LIMIT 1
       ), ''),
       o.lifecycle_state, COALESCE(h.state, 'unchecked'),
       COALESCE(h.stale, 1), o.last_seen_at, COALESCE(h.updated_at, o.updated_at)
FROM node_occurrences o
JOIN fingerprints f ON f.id = o.current_fingerprint_id
LEFT JOIN node_health_states h ON h.node_occurrence_id = o.id
WHERE 1 = 1`
	arguments := make([]interface{}, 0, 4)
	if options.NodeOccurrenceID != "" {
		query += ` AND o.id = ?`
		arguments = append(arguments, options.NodeOccurrenceID)
	}
	if options.SourceID != "" {
		query += ` AND o.source_id = ?`
		arguments = append(arguments, options.SourceID)
	}
	if options.ProtocolID != "" {
		query += ` AND f.protocol_id = ?`
		arguments = append(arguments, options.ProtocolID)
	}
	if options.State != "" {
		query += ` AND COALESCE(h.state, 'unchecked') = ?`
		arguments = append(arguments, string(options.State))
	}
	if options.PresentOnly {
		query += ` AND o.lifecycle_state = 'present'`
	}
	if options.BeforeLastSeenAt != nil {
		query += ` AND (o.last_seen_at < ? OR (o.last_seen_at = ? AND o.id < ?))`
		millis := options.BeforeLastSeenAt.UTC().UnixMilli()
		arguments = append(arguments, millis, millis, options.BeforeID)
	}
	query += ` ORDER BY o.last_seen_at DESC, o.id DESC LIMIT ?`
	arguments = append(arguments, options.Limit+1)
	rows, err := s.database.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, false, fmt.Errorf("list node health summaries: %w", err)
	}
	defer rows.Close()
	result := make([]NodeSummary, 0, options.Limit+1)
	for rows.Next() {
		var item NodeSummary
		var stale int
		var lastSeen, updated int64
		if err := rows.Scan(
			&item.NodeOccurrenceID, &item.SourceID, &item.ProtocolID, &item.FingerprintKind, &item.NameBlobID,
			&item.OccurrenceState, &item.HealthState, &stale, &lastSeen, &updated,
		); err != nil {
			return nil, false, fmt.Errorf("scan node health summary: %w", err)
		}
		item.LastSeenAt = time.UnixMilli(lastSeen).UTC()
		item.UpdatedAt = time.UnixMilli(updated).UTC()
		item.Stale = stale == 1 || s.now().UTC().Sub(item.UpdatedAt) >= DefaultStaleAfter
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate node health summaries: %w", err)
	}
	hasMore := len(result) > options.Limit
	if hasMore {
		result = result[:options.Limit]
	}
	return result, hasMore, nil
}

func (s *Store) Node(ctx context.Context, occurrenceID string) (NodeSummary, error) {
	items, _, err := s.ListNodes(ctx, NodeListOptions{NodeOccurrenceID: occurrenceID, Limit: 1})
	if err != nil {
		return NodeSummary{}, err
	}
	if len(items) == 1 {
		return items[0], nil
	}
	return NodeSummary{}, ErrNotFound
}

func (s *Store) Records(ctx context.Context, occurrenceID string, limit int) ([]Record, error) {
	if limit <= 0 || limit > 200 {
		return nil, fmt.Errorf("health record limit must be between 1 and 200")
	}
	rows, err := s.database.QueryContext(ctx, `
SELECT id, node_occurrence_id, snapshot_id, protocol_id, target_id,
       result_class, success, node_attributable, http_status, total_ms,
       diagnostic_code, executor_id, executor_version, observed_at, stale_after
FROM health_records WHERE node_occurrence_id = ?
ORDER BY observed_at DESC, id DESC LIMIT ?`, occurrenceID, limit)
	if err != nil {
		return nil, fmt.Errorf("list node health records: %w", err)
	}
	defer rows.Close()
	result := make([]Record, 0, limit)
	for rows.Next() {
		var record Record
		var target, diagnostic sql.NullString
		var status sql.NullInt64
		var success, attributable int
		var totalMS, observed, stale int64
		if err := rows.Scan(
			&record.ID, &record.NodeOccurrenceID, &record.SnapshotID, &record.ProtocolID,
			&target, &record.Class, &success, &attributable, &status, &totalMS,
			&diagnostic, &record.ExecutorID, &record.ExecutorVersion, &observed, &stale,
		); err != nil {
			return nil, fmt.Errorf("scan node health record: %w", err)
		}
		record.TargetID, record.DiagnosticCode = target.String, diagnostic.String
		record.Success, record.NodeAttributable = success == 1, attributable == 1
		if status.Valid {
			value := int(status.Int64)
			record.HTTPStatus = &value
		}
		record.Total = time.Duration(totalMS) * time.Millisecond
		record.ObservedAt = time.UnixMilli(observed).UTC()
		record.StaleAfter = time.UnixMilli(stale).UTC()
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node health records: %w", err)
	}
	if len(result) == 0 {
		if _, err := s.Node(ctx, occurrenceID); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (s *Store) Capacity(ctx context.Context) (Capacity, error) {
	var capacity Capacity
	err := s.database.QueryRowContext(ctx, `
SELECT count(*),
       COALESCE(sum(CASE WHEN status = 'queued' THEN 1 ELSE 0 END), 0),
       COALESCE(sum(CASE WHEN status IN ('leased', 'running') THEN 1 ELSE 0 END), 0),
       COALESCE(sum(CASE WHEN status = 'dormant' THEN 1 ELSE 0 END), 0)
FROM probe_queue_items queue
JOIN node_occurrences occurrence ON occurrence.id = queue.node_occurrence_id
WHERE occurrence.lifecycle_state = 'present'`).Scan(&capacity.Total, &capacity.Queued, &capacity.Running, &capacity.Dormant)
	if err != nil {
		return Capacity{}, fmt.Errorf("read health queue capacity: %w", err)
	}
	capacity.HardLimit = QueueHardLimit
	return capacity, nil
}

func (s *Store) State(ctx context.Context, occurrenceID string) (HealthState, error) {
	return readState(ctx, s.database, occurrenceID)
}

func (s *Store) States(ctx context.Context, occurrenceIDs []string) (map[string]HealthState, error) {
	result := make(map[string]HealthState, len(occurrenceIDs))
	for _, occurrenceID := range occurrenceIDs {
		if _, duplicate := result[occurrenceID]; duplicate {
			continue
		}
		state, err := s.State(ctx, occurrenceID)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		result[occurrenceID] = state
	}
	return result, nil
}

func (s *Store) RecordControl(ctx context.Context, targetID string, result ProbeResult) error {
	if targetID == "" || !validResult(result) {
		return fmt.Errorf("invalid control probe result")
	}
	now := s.now().UTC()
	_, err := s.database.ExecContext(ctx, `
INSERT INTO control_probe_records(
  id, target_id, success, http_status, result_class, total_ms,
  observed_at, valid_until
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		s.newID(), targetID, boolInt(result.Success), nullableInt(result.HTTPStatus), string(result.Class),
		maxInt(0, int(result.Total.Milliseconds())), now.UnixMilli(), now.Add(5*time.Minute).UnixMilli())
	if err != nil {
		return fmt.Errorf("record direct control probe: %w", err)
	}
	return nil
}

func (s *Store) ControlsAvailable(ctx context.Context) (bool, bool, error) {
	now := s.now().UTC().UnixMilli()
	var total, successful int
	if err := s.database.QueryRowContext(ctx, `
SELECT count(*), COALESCE(sum(success), 0) FROM (
  SELECT target_id, success FROM control_probe_records r
  WHERE valid_until > ? AND observed_at = (
    SELECT max(newer.observed_at) FROM control_probe_records newer
    WHERE newer.target_id = r.target_id AND newer.valid_until > ?
  )
)`, now, now).Scan(&total, &successful); err != nil {
		return false, false, fmt.Errorf("read direct control probes: %w", err)
	}
	return total >= 2, successful > 0, nil
}

func (s *Store) GuardSuppressed(ctx context.Context) (bool, string, error) {
	var conclusion string
	err := s.database.QueryRowContext(ctx, `
SELECT conclusion FROM health_guard_windows
WHERE window_end >= ? ORDER BY window_start DESC LIMIT 1`, s.now().UTC().Add(-10*time.Minute).UnixMilli()).Scan(&conclusion)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "normal", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("read health guard state: %w", err)
	}
	return conclusion == "mass_failure_suppressed" || conclusion == "control_failure_suppressed", conclusion, nil
}

func ApplyTransition(input TransitionInput) Transition {
	now := input.Now.UTC()
	result := Transition{
		State: input.State, ConsecutiveSuccesses: input.ConsecutiveSuccesses,
		ConsecutiveFailures: input.ConsecutiveFailures, RecoveryStep: input.RecoveryStep,
	}
	if input.Result.Class == ResultUnsupported {
		result.State = StateUnsupported
		result.ConsecutiveSuccesses, result.ConsecutiveFailures, result.RecoveryStep = 0, 0, 0
		return result
	}
	if input.Result.Success {
		result.ConsecutiveFailures = 0
		result.ConsecutiveSuccesses++
		if input.State == StateUnhealthy {
			result.State, result.RecoveryStep, result.ConsecutiveSuccesses = StateDegraded, 1, 1
			result.NextCheckAt = timePointer(now.Add(2 * time.Minute))
			return result
		}
		if input.State == StateDegraded && input.RecoveryStep == 1 {
			result.State, result.RecoveryStep = StateHealthy, 0
			result.NextCheckAt = timePointer(now.Add(DefaultPeriodicInterval))
			return result
		}
		result.State, result.RecoveryStep = StateHealthy, 0
		result.NextCheckAt = timePointer(now.Add(DefaultPeriodicInterval))
		return result
	}
	if !input.Result.NodeAttributable {
		result.NextCheckAt = timePointer(now.Add(5 * time.Minute))
		return result
	}
	result.ConsecutiveSuccesses = 0
	result.ConsecutiveFailures++
	result.RecoveryStep = 0
	switch result.ConsecutiveFailures {
	case 1:
		result.State = StateDegraded
		result.NextCheckAt = timePointer(now.Add(time.Minute))
	case 2:
		result.State = StateDegraded
		result.NextCheckAt = timePointer(now.Add(5 * time.Minute))
	case 3:
		result.State = StateUnhealthy
		result.NextCheckAt = timePointer(now.Add(10 * time.Minute))
	case 4:
		result.State = StateUnhealthy
		result.NextCheckAt = timePointer(now.Add(20 * time.Minute))
	case 5:
		result.State = StateUnhealthy
		result.NextCheckAt = timePointer(now.Add(30 * time.Minute))
	default:
		result.State = StateUnhealthy
		result.NextCheckAt = timePointer(now.Add(time.Hour))
	}
	return result
}

func probeSupported(protocolID string) bool {
	switch protocolID {
	case "shadowsocks", "vmess", "vless", "trojan", "hysteria2", "tuic", "anytls":
		return true
	default:
		return false
	}
}

func validResult(result ProbeResult) bool {
	if result.ExecutorID == "" || result.ExecutorVersion == "" || result.Total < 0 {
		return false
	}
	if result.Success {
		return result.Class == ResultSuccess && !result.NodeAttributable
	}
	return result.Class != "" && result.Class != ResultSuccess
}

func priorityFor(transition Transition) (string, int) {
	if transition.NextCheckAt == nil {
		return "periodic", 0
	}
	if transition.State == StateUnhealthy || transition.RecoveryStep > 0 {
		return "unhealthy_recovery", 800
	}
	if transition.State == StateDegraded {
		return "failure_recheck", 600
	}
	return "periodic", 100
}

func queueStatus(next *time.Time) string {
	if next == nil {
		return "dormant"
	}
	return "queued"
}

type queryer interface {
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

func readState(ctx context.Context, query queryer, occurrenceID string) (HealthState, error) {
	var state HealthState
	var latest sql.NullString
	var stale int
	var next sql.NullInt64
	var updated int64
	err := query.QueryRowContext(ctx, `
SELECT node_occurrence_id, latest_record_id, state, stale,
       consecutive_successes, consecutive_failures, recovery_step,
       next_check_at, updated_at
FROM node_health_states WHERE node_occurrence_id = ?`, occurrenceID).Scan(
		&state.NodeOccurrenceID, &latest, &state.State, &stale,
		&state.ConsecutiveSuccesses, &state.ConsecutiveFailures, &state.RecoveryStep,
		&next, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return HealthState{}, ErrNotFound
	}
	if err != nil {
		return HealthState{}, fmt.Errorf("read node health state: %w", err)
	}
	state.LatestRecordID = latest.String
	state.Stale = stale == 1
	state.UpdatedAt = time.UnixMilli(updated).UTC()
	if next.Valid {
		value := time.UnixMilli(next.Int64).UTC()
		state.NextCheckAt = &value
	}
	return state, nil
}

func updateGuardWindow(ctx context.Context, tx *sql.Tx, now time.Time) error {
	windowStart := now.Truncate(5 * time.Minute)
	windowEnd := windowStart.Add(5 * time.Minute)
	var controlTotal, controlFailed int
	if err := tx.QueryRowContext(ctx, `
SELECT count(*), COALESCE(sum(CASE WHEN success = 0 THEN 1 ELSE 0 END), 0)
FROM (
  SELECT target_id, success FROM control_probe_records r
  WHERE observed_at >= ? AND observed_at < ? AND observed_at = (
    SELECT max(newer.observed_at) FROM control_probe_records newer
    WHERE newer.target_id = r.target_id AND newer.observed_at >= ? AND newer.observed_at < ?
  )
)`, windowStart.UnixMilli(), windowEnd.UnixMilli(), windowStart.UnixMilli(), windowEnd.UnixMilli()).Scan(&controlTotal, &controlFailed); err != nil {
		return fmt.Errorf("calculate control health window: %w", err)
	}
	var eligible, failed int
	if err := tx.QueryRowContext(ctx, `
SELECT count(*), COALESCE(sum(CASE WHEN success = 0 THEN 1 ELSE 0 END), 0)
FROM (
  SELECT node_occurrence_id, success FROM health_records r
  WHERE observed_at >= ? AND observed_at < ?
    AND (success = 1 OR node_attributable = 1)
    AND observed_at = (
      SELECT max(newer.observed_at) FROM health_records newer
      WHERE newer.node_occurrence_id = r.node_occurrence_id
        AND newer.observed_at >= ? AND newer.observed_at < ?
        AND (newer.success = 1 OR newer.node_attributable = 1)
    )
)`, windowStart.UnixMilli(), windowEnd.UnixMilli(), windowStart.UnixMilli(), windowEnd.UnixMilli()).Scan(&eligible, &failed); err != nil {
		return fmt.Errorf("calculate node health window: %w", err)
	}
	conclusion := "normal"
	if controlTotal >= 2 && controlFailed == controlTotal {
		conclusion = "control_failure_suppressed"
	} else if eligible < 10 {
		conclusion = "insufficient_sample"
	} else if failed*2 >= eligible {
		conclusion = "mass_failure_suppressed"
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO health_guard_windows(
  window_start, window_end, conclusion, control_total, control_failed,
  eligible_unique, node_failure_unique, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(window_start) DO UPDATE SET
  conclusion = excluded.conclusion, control_total = excluded.control_total,
  control_failed = excluded.control_failed, eligible_unique = excluded.eligible_unique,
  node_failure_unique = excluded.node_failure_unique`,
		windowStart.UnixMilli(), windowEnd.UnixMilli(), conclusion, controlTotal, controlFailed,
		eligible, failed, now.UnixMilli()); err != nil {
		return fmt.Errorf("update node health guard window: %w", err)
	}
	return nil
}

func nullableTimeIf(condition bool, value time.Time) interface{} {
	if !condition {
		return nil
	}
	return value.UnixMilli()
}

func nullableTime(value *time.Time) interface{} {
	if value == nil {
		return nil
	}
	return value.UTC().UnixMilli()
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

func timePointer(value time.Time) *time.Time { return &value }

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}
