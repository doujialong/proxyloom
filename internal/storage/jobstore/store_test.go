package jobstore

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

const (
	testSourceID   = "00000000-0000-4000-8000-000000000101"
	testRevisionID = "00000000-0000-4000-8000-000000000102"
	nextRevisionID = "00000000-0000-4000-8000-000000000103"
)

func TestEnqueueDeduplicatesSameSourceRevision(t *testing.T) {
	store, database := newTestStore(t)
	defer database.Close()

	first, err := store.Enqueue(context.Background(), EnqueueRequest{
		SourceID: testSourceID, SourceRevisionID: testRevisionID, CorrelationID: "first",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Enqueue(context.Background(), EnqueueRequest{
		SourceID: testSourceID, SourceRevisionID: testRevisionID, CorrelationID: "second",
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatalf("same revision created duplicate jobs: %s and %s", first.ID, second.ID)
	}
	expectedKey := testSourceID + ":" + testRevisionID
	if first.DedupeKey != expectedKey {
		t.Fatalf("dedupe key = %q, want %q", first.DedupeKey, expectedKey)
	}
}

func TestEnqueueCanExpediteExistingQueuedJob(t *testing.T) {
	store, database := newTestStore(t)
	defer database.Close()

	now := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	first, err := store.Enqueue(context.Background(), EnqueueRequest{
		SourceID: testSourceID, SourceRevisionID: testRevisionID,
		DueAt: now.Add(time.Hour), Priority: 1, CorrelationID: "scheduled",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Enqueue(context.Background(), EnqueueRequest{
		SourceID: testSourceID, SourceRevisionID: testRevisionID,
		DueAt: now, Priority: 10, CorrelationID: "manual", ExpediteExisting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatalf("expedite created duplicate job: %s and %s", first.ID, second.ID)
	}
	if !second.DueAt.Equal(now) || second.Priority != 10 || second.CorrelationID != "manual" {
		t.Fatalf("expedited job due/priority/correlation = %s/%d/%s, want %s/10/manual", second.DueAt, second.Priority, second.CorrelationID, now)
	}
}

func TestEnqueueCreatesJobForNewSourceRevision(t *testing.T) {
	store, database := newTestStore(t)
	defer database.Close()

	first, err := store.Enqueue(context.Background(), EnqueueRequest{
		SourceID: testSourceID, SourceRevisionID: testRevisionID, CorrelationID: "first",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Enqueue(context.Background(), EnqueueRequest{
		SourceID: testSourceID, SourceRevisionID: nextRevisionID, CorrelationID: "second",
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == first.ID {
		t.Fatalf("new revision reused active job %s", first.ID)
	}
	if second.SourceRevisionID != nextRevisionID {
		t.Fatalf("new job revision = %q, want %q", second.SourceRevisionID, nextRevisionID)
	}
}

func TestActiveForSourceReturnsPersistedSchedule(t *testing.T) {
	store, database := newTestStore(t)
	defer database.Close()
	due := time.Date(2026, 7, 22, 12, 30, 0, 0, time.UTC)
	created, err := store.Enqueue(context.Background(), EnqueueRequest{
		SourceID: testSourceID, SourceRevisionID: testRevisionID,
		DueAt: due, CorrelationID: "retry-1-" + testSourceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	active, exists, err := store.ActiveForSource(context.Background(), testSourceID, testRevisionID)
	if err != nil || !exists || active.ID != created.ID || !active.DueAt.Equal(due) {
		t.Fatalf("ActiveForSource() = %+v, %v, %v", active, exists, err)
	}
	if _, err := store.CancelQueuedSuperseded(context.Background(), testSourceID, nextRevisionID); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := store.ActiveForSource(context.Background(), testSourceID, testRevisionID); err != nil || exists {
		t.Fatalf("terminal ActiveForSource() exists=%v err=%v", exists, err)
	}
}

func TestCancelQueuedSupersededKeepsCurrentRevision(t *testing.T) {
	store, database := newTestStore(t)
	defer database.Close()

	oldJob, err := store.Enqueue(context.Background(), EnqueueRequest{
		SourceID: testSourceID, SourceRevisionID: testRevisionID, CorrelationID: "old",
	})
	if err != nil {
		t.Fatal(err)
	}
	currentJob, err := store.Enqueue(context.Background(), EnqueueRequest{
		SourceID: testSourceID, SourceRevisionID: nextRevisionID, CorrelationID: "current",
	})
	if err != nil {
		t.Fatal(err)
	}
	cancelled, err := store.CancelQueuedSuperseded(context.Background(), testSourceID, nextRevisionID)
	if err != nil || cancelled != 1 {
		t.Fatalf("CancelQueuedSuperseded() = %d, %v", cancelled, err)
	}
	oldJob, err = store.Get(context.Background(), oldJob.ID)
	if err != nil || oldJob.Status != StatusDead || oldJob.ErrorCode != "superseded_revision" {
		t.Fatalf("superseded job = %+v, %v", oldJob, err)
	}
	currentJob, err = store.Get(context.Background(), currentJob.ID)
	if err != nil || currentJob.Status != StatusQueued {
		t.Fatalf("current job = %+v, %v", currentJob, err)
	}
}

func newTestStore(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	if _, err := database.Exec(`
CREATE TABLE jobs (
  id TEXT PRIMARY KEY,
  job_type TEXT NOT NULL,
  source_id TEXT NOT NULL,
  source_revision_id TEXT NOT NULL,
  status TEXT NOT NULL,
  priority INTEGER NOT NULL,
  dedupe_key TEXT NOT NULL,
  lease_owner TEXT,
  lease_expires_at INTEGER,
  attempt INTEGER NOT NULL,
  max_attempts INTEGER NOT NULL,
  error_code TEXT,
  error_detail TEXT,
  correlation_id TEXT NOT NULL,
  due_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  started_at INTEGER,
  finished_at INTEGER
);
CREATE UNIQUE INDEX jobs_one_active_refresh
  ON jobs(job_type, dedupe_key)
  WHERE status IN ('queued', 'leased', 'running');`); err != nil {
		database.Close()
		t.Fatal(err)
	}
	ids := []string{
		"00000000-0000-4000-8000-000000000201",
		"00000000-0000-4000-8000-000000000202",
		"00000000-0000-4000-8000-000000000203",
	}
	index := 0
	store, err := New(database, Options{
		Now: func() time.Time { return time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC) },
		NewID: func() string {
			id := ids[index]
			index++
			return id
		},
	})
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	return store, database
}
