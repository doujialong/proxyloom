package healthstore

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	storagesqlite "github.com/doujialong/proxyloom/internal/storage/sqlite"
)

func TestApplyTransitionFailureAndRecoverySchedule(t *testing.T) {
	now := time.Date(2026, 7, 18, 8, 0, 0, 0, time.UTC)
	state := Transition{State: StateUnchecked}
	failure := ProbeResult{
		Class: ResultConnectTimeout, NodeAttributable: true,
		ExecutorID: "sing-box", ExecutorVersion: "1.12.25", Total: time.Second,
	}
	wantDelays := []time.Duration{time.Minute, 5 * time.Minute, 10 * time.Minute, 20 * time.Minute, 30 * time.Minute, time.Hour}
	for index, delay := range wantDelays {
		state = ApplyTransition(TransitionInput{
			State: state.State, ConsecutiveSuccesses: state.ConsecutiveSuccesses,
			ConsecutiveFailures: state.ConsecutiveFailures, RecoveryStep: state.RecoveryStep,
			Result: failure, Now: now,
		})
		if state.NextCheckAt == nil || !state.NextCheckAt.Equal(now.Add(delay)) {
			t.Fatalf("failure %d next = %v, want %v", index+1, state.NextCheckAt, now.Add(delay))
		}
		if index < 2 && state.State != StateDegraded || index >= 2 && state.State != StateUnhealthy {
			t.Fatalf("failure %d state = %s", index+1, state.State)
		}
	}
	success := ProbeResult{
		Class: ResultSuccess, Success: true,
		ExecutorID: "sing-box", ExecutorVersion: "1.12.25", Total: time.Second,
	}
	state = ApplyTransition(TransitionInput{
		State: state.State, ConsecutiveFailures: state.ConsecutiveFailures,
		Result: success, Now: now,
	})
	if state.State != StateDegraded || state.RecoveryStep != 1 || state.NextCheckAt == nil || !state.NextCheckAt.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("first recovery = %+v", state)
	}
	state = ApplyTransition(TransitionInput{
		State: state.State, ConsecutiveSuccesses: state.ConsecutiveSuccesses,
		RecoveryStep: state.RecoveryStep, Result: success, Now: now.Add(2 * time.Minute),
	})
	if state.State != StateHealthy || state.RecoveryStep != 0 || state.NextCheckAt == nil || !state.NextCheckAt.Equal(now.Add(32*time.Minute)) {
		t.Fatalf("confirmed recovery = %+v", state)
	}
}

func TestApplyTransitionInfrastructureAndUnsupported(t *testing.T) {
	now := time.Date(2026, 7, 18, 8, 0, 0, 0, time.UTC)
	infrastructure := ApplyTransition(TransitionInput{
		State: StateHealthy, ConsecutiveSuccesses: 4,
		Result: ProbeResult{
			Class: ResultExecutorCrash, ExecutorID: "sing-box",
			ExecutorVersion: "1.12.25", Total: time.Second,
		},
		Now: now,
	})
	if infrastructure.State != StateHealthy || infrastructure.ConsecutiveFailures != 0 || infrastructure.NextCheckAt == nil || !infrastructure.NextCheckAt.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("infrastructure transition = %+v", infrastructure)
	}
	unsupported := ApplyTransition(TransitionInput{
		State: StateUnchecked,
		Result: ProbeResult{
			Class: ResultUnsupported, ExecutorID: "sing-box",
			ExecutorVersion: "1.12.25", Total: 0,
		},
		Now: now,
	})
	if unsupported.State != StateUnsupported || unsupported.NextCheckAt != nil {
		t.Fatalf("unsupported transition = %+v", unsupported)
	}
}

func TestNodeOverviewAndCapacityExcludeInactiveOccurrences(t *testing.T) {
	database, err := sql.Open(storagesqlite.DriverName, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	if _, err := database.Exec(`
CREATE TABLE fingerprints(id TEXT PRIMARY KEY, protocol_id TEXT, kind TEXT);
CREATE TABLE sources(id TEXT PRIMARY KEY, lifecycle_state TEXT NOT NULL);
CREATE TABLE node_occurrences(
  id TEXT PRIMARY KEY, source_id TEXT, current_fingerprint_id TEXT,
  lifecycle_state TEXT, last_seen_at INTEGER, updated_at INTEGER
);
CREATE TABLE node_health_states(
  node_occurrence_id TEXT PRIMARY KEY, state TEXT, stale INTEGER, updated_at INTEGER
);
CREATE TABLE probe_queue_items(
  node_occurrence_id TEXT PRIMARY KEY, status TEXT,
  priority_class TEXT, priority INTEGER, due_at INTEGER,
  lease_owner TEXT, lease_expires_at INTEGER, updated_at INTEGER
);
CREATE TABLE snapshot_occurrences(snapshot_id TEXT, raw_node_id TEXT, node_occurrence_id TEXT);
CREATE TABLE snapshots(id TEXT PRIMARY KEY, accepted_at INTEGER);
CREATE TABLE raw_nodes(id TEXT PRIMARY KEY, original_name_blob_id TEXT, source_ordinal INTEGER);
`); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	if _, err := database.Exec(`
INSERT INTO fingerprints VALUES ('fingerprint', 'vless', 'semantic');
INSERT INTO sources VALUES ('active-source', 'active'), ('archived-source', 'archived');
INSERT INTO node_occurrences VALUES ('present', 'active-source', 'fingerprint', 'present', ?, ?);
INSERT INTO node_occurrences VALUES ('absent', 'active-source', 'fingerprint', 'absent', ?, ?);
INSERT INTO node_occurrences VALUES ('archived', 'archived-source', 'fingerprint', 'present', ?, ?);
INSERT INTO node_health_states VALUES ('present', 'unhealthy', 0, ?);
INSERT INTO node_health_states VALUES ('absent', 'unhealthy', 0, ?);
INSERT INTO node_health_states VALUES ('archived', 'unhealthy', 0, ?);
INSERT INTO probe_queue_items VALUES ('present', 'queued', 'periodic', 100, 0, NULL, NULL, 0);
INSERT INTO probe_queue_items VALUES ('absent', 'queued', 'periodic', 100, 0, NULL, NULL, 0);
INSERT INTO probe_queue_items VALUES ('archived', 'queued', 'periodic', 100, 0, NULL, NULL, 0);
`, now.UnixMilli(), now.UnixMilli(), now.Add(-time.Hour).UnixMilli(), now.UnixMilli(), now.Add(-2*time.Hour).UnixMilli(), now.UnixMilli(), now.UnixMilli(), now.UnixMilli(), now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	store, err := New(database, Options{Now: func() time.Time { return now }, NewID: func() string { return "id" }})
	if err != nil {
		t.Fatal(err)
	}
	items, _, err := store.ListNodes(context.Background(), NodeListOptions{PresentOnly: true, Limit: 10})
	if err != nil || len(items) != 1 || items[0].NodeOccurrenceID != "present" {
		t.Fatalf("present ListNodes() = %+v, %v", items, err)
	}
	all, _, err := store.ListNodes(context.Background(), NodeListOptions{Limit: 10})
	if err != nil || len(all) != 2 {
		t.Fatalf("active-source ListNodes() = %+v, %v", all, err)
	}
	capacity, err := store.Capacity(context.Background())
	if err != nil || capacity.Total != 1 || capacity.Queued != 1 {
		t.Fatalf("Capacity() = %+v, %v", capacity, err)
	}
	if err := store.ManualEnqueue(context.Background(), "present"); err != nil {
		t.Fatalf("active ManualEnqueue() error = %v", err)
	}
	if err := store.ManualEnqueue(context.Background(), "archived"); !errors.Is(err, ErrConflict) {
		t.Fatalf("archived ManualEnqueue() error = %v, want conflict", err)
	}
}
