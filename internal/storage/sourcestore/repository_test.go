package sourcestore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/doujialong/proxyloom/internal/crypto/keyring"
	"github.com/doujialong/proxyloom/internal/crypto/masterkey"
	"github.com/doujialong/proxyloom/internal/identity"
	"github.com/doujialong/proxyloom/internal/occurrence"
	"github.com/doujialong/proxyloom/internal/storage/blobstore"
	storagesqlite "github.com/doujialong/proxyloom/internal/storage/sqlite"
)

func TestSourceSnapshotLifecycleKeepsLastValidSnapshot(t *testing.T) {
	environment := newTestEnvironment(t)
	defer environment.close()

	source, initialDraft := environment.createSource(t, "Primary")
	published, err := environment.repository.Publish(context.Background(), source.ID, initialDraft.ID)
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if published.Published.State != "published" || published.Draft.State != "draft" ||
		published.Published.ID == published.Draft.ID || published.Source.RevisionCounter != 2 {
		t.Fatalf("publication = %+v", published)
	}

	attempt := environment.startAttempt(t, source.ID, published.Published.ID, TriggerImport)
	rawContent := []byte("vless://fixture@example.test:443#Node")
	rawBlob := environment.putBlob(t, "raw_document", rawContent)
	nodes, occurrences := environment.acceptedDetails(t, rawContent)
	httpOK := 200
	totalMS := 42
	responseBytes := 39
	snapshot, document, err := environment.repository.AcceptSnapshot(context.Background(), AcceptRequest{
		AttemptID: attempt.ID, RawBlobID: rawBlob.ID,
		DetectedFormat: "uri-list", FormatAdapterVersion: "uri-list-v1",
		MediaType: "text/plain", Charset: "utf-8", ParseLimitsVersion: 1,
		NodeCount: 1, WarningCount: 0,
		OccurrenceAlgorithmVersion: occurrence.AlgorithmVersion,
		StaleAfter:                 72 * time.Hour, RetainFor: 30 * 24 * time.Hour,
		Metrics: AttemptMetrics{HTTPStatus: &httpOK, TotalMS: &totalMS, ResponseBytes: &responseBytes},
		Nodes:   nodes, Occurrences: occurrences,
	})
	if err != nil {
		t.Fatalf("AcceptSnapshot() error = %v", err)
	}
	if snapshot.RawDocumentID != document.ID || snapshot.SourceID != source.ID || snapshot.NodeCount != 1 {
		t.Fatalf("snapshot = %+v, document = %+v", snapshot, document)
	}
	storedOccurrences, err := environment.repository.ListOccurrences(context.Background(), source.ID)
	if err != nil || len(storedOccurrences) != 1 || storedOccurrences[0].Occurrence.ID != occurrences[0].ID {
		t.Fatalf("ListOccurrences() = %+v, %v", storedOccurrences, err)
	}
	storedName, record, err := environment.blobs.Get(context.Background(), storedOccurrences[0].NameBlobID)
	if err != nil || record.Kind != "node_name" || string(storedName) != "Node" {
		t.Fatalf("stored occurrence name = %q, %+v, %v", storedName, record, err)
	}
	current, err := environment.repository.CurrentSnapshot(context.Background(), source.ID)
	if err != nil || current.ID != snapshot.ID {
		t.Fatalf("CurrentSnapshot() = %+v, %v", current, err)
	}

	environment.advance(time.Hour)
	failedAttempt := environment.startAttempt(t, source.ID, published.Published.ID, TriggerSchedule)
	failure, err := environment.repository.CompleteFailure(context.Background(), FailureRequest{
		AttemptID: failedAttempt.ID, Status: AttemptRejected,
		ErrorCode: "minimum_nodes", ErrorDetail: "content did not meet the configured threshold",
	})
	if err != nil || failure.Status != AttemptRejected {
		t.Fatalf("CompleteFailure() = %+v, %v", failure, err)
	}
	current, err = environment.repository.CurrentSnapshot(context.Background(), source.ID)
	if err != nil || current.ID != snapshot.ID {
		t.Fatalf("current snapshot changed after failure: %+v, %v", current, err)
	}
	afterFailure, err := environment.repository.GetSource(context.Background(), source.ID)
	if err != nil || afterFailure.CurrentSnapshotID != snapshot.ID || afterFailure.Health != "degraded" {
		t.Fatalf("source after failure = %+v, %v", afterFailure, err)
	}
	failureState, err := environment.repository.RefreshFailures(context.Background(), source.ID, published.Published.ID, 10)
	if err != nil || failureState.ConsecutiveFailures != 1 || failureState.RetryAttempts != 0 || failureState.LastErrorCode != "minimum_nodes" {
		t.Fatalf("refresh failures after rejection = %+v, %v", failureState, err)
	}

	environment.advance(time.Hour)
	notModifiedAttempt := environment.startAttempt(t, source.ID, published.Published.ID, TriggerSchedule)
	httpNotModified := 304
	reused, completed, err := environment.repository.CompleteNotModified(context.Background(), notModifiedAttempt.ID, AttemptMetrics{
		HTTPStatus: &httpNotModified,
	})
	if err != nil || reused.ID != snapshot.ID || completed.AcceptedSnapshotID != snapshot.ID {
		t.Fatalf("CompleteNotModified() = %+v, %+v, %v", reused, completed, err)
	}
	failureState, err = environment.repository.RefreshFailures(context.Background(), source.ID, published.Published.ID, 10)
	if err != nil || failureState.ConsecutiveFailures != 0 || failureState.LastErrorCode != "" {
		t.Fatalf("refresh failures after success = %+v, %v", failureState, err)
	}
	var snapshots, documents int
	if err := environment.database.QueryRow("SELECT count(*) FROM snapshots WHERE source_id = ?", source.ID).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if err := environment.database.QueryRow("SELECT count(*) FROM raw_documents WHERE source_id = ?", source.ID).Scan(&documents); err != nil {
		t.Fatal(err)
	}
	if snapshots != 1 || documents != 1 {
		t.Fatalf("304 created history rows: snapshots=%d documents=%d", snapshots, documents)
	}

	environment.advance(time.Hour)
	unchangedAttempt := environment.startAttempt(t, source.ID, published.Published.ID, TriggerSchedule)
	reused, completed, err = environment.repository.CompleteUnchanged(context.Background(), unchangedAttempt.ID, snapshot.ID, AttemptMetrics{
		HTTPStatus: &httpOK, ResponseBytes: &responseBytes,
	})
	if err != nil || reused.ID != snapshot.ID || completed.Status != AttemptSucceeded || completed.AcceptedSnapshotID != snapshot.ID {
		t.Fatalf("CompleteUnchanged() = %+v, %+v, %v", reused, completed, err)
	}
	if err := environment.database.QueryRow("SELECT count(*) FROM snapshots WHERE source_id = ?", source.ID).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if err := environment.database.QueryRow("SELECT count(*) FROM raw_documents WHERE source_id = ?", source.ID).Scan(&documents); err != nil {
		t.Fatal(err)
	}
	if snapshots != 1 || documents != 1 {
		t.Fatalf("unchanged 200 created history rows: snapshots=%d documents=%d", snapshots, documents)
	}

	environment.advance(time.Hour)
	newAttempt := environment.startAttempt(t, source.ID, published.Published.ID, TriggerSchedule)
	newRawContent := []byte("vless://fixture@new.example.test:443#Node")
	newRawBlob := environment.putBlob(t, "raw_document", newRawContent)
	newNodes, newOccurrences := environment.acceptedDetails(t, newRawContent)
	newSnapshot, _, err := environment.repository.AcceptSnapshot(context.Background(), AcceptRequest{
		AttemptID: newAttempt.ID, RawBlobID: newRawBlob.ID,
		DetectedFormat: "uri-list", FormatAdapterVersion: "uri-list-v1",
		NodeCount: 1, OccurrenceAlgorithmVersion: occurrence.AlgorithmVersion,
		StaleAfter: 72 * time.Hour, RetainFor: 30 * 24 * time.Hour,
		Nodes: newNodes, Occurrences: newOccurrences,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := environment.database.Exec(
		"UPDATE sources SET current_snapshot_id = ? WHERE id = ?", snapshot.ID, source.ID,
	); err == nil {
		t.Fatal("database allowed current snapshot to move backward")
	}
	current, err = environment.repository.CurrentSnapshot(context.Background(), source.ID)
	if err != nil || current.ID != newSnapshot.ID {
		t.Fatalf("current snapshot after rollback attempt = %+v, %v", current, err)
	}
}

func TestRefreshFailuresTracksCurrentRetryWindow(t *testing.T) {
	environment := newTestEnvironment(t)
	defer environment.close()
	source, draft := environment.createSource(t, "Retry window")
	published, err := environment.repository.Publish(context.Background(), source.ID, draft.ID)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		attempt := environment.startAttempt(t, source.ID, published.Published.ID, TriggerRetry)
		if _, err := environment.repository.CompleteFailure(context.Background(), FailureRequest{
			AttemptID: attempt.ID, Status: AttemptFailed, ErrorCode: "temporary", ErrorDetail: "temporary failure",
		}); err != nil {
			t.Fatal(err)
		}
	}
	state, err := environment.repository.RefreshFailures(context.Background(), source.ID, published.Published.ID, 10)
	if err != nil || state.ConsecutiveFailures != 3 || state.RetryAttempts != 3 {
		t.Fatalf("retry window state = %+v, %v", state, err)
	}
	periodic := environment.startAttempt(t, source.ID, published.Published.ID, TriggerSchedule)
	if _, err := environment.repository.CompleteFailure(context.Background(), FailureRequest{
		AttemptID: periodic.ID, Status: AttemptFailed, ErrorCode: "temporary", ErrorDetail: "new periodic failure",
	}); err != nil {
		t.Fatal(err)
	}
	state, err = environment.repository.RefreshFailures(context.Background(), source.ID, published.Published.ID, 10)
	if err != nil || state.ConsecutiveFailures != 4 || state.RetryAttempts != 0 {
		t.Fatalf("new retry window state = %+v, %v", state, err)
	}
}

func TestSourceRevisionOwnershipAndTerminalAttemptConstraints(t *testing.T) {
	environment := newTestEnvironment(t)
	defer environment.close()

	firstSource, firstDraft := environment.createSource(t, "First")
	firstPublished, err := environment.repository.Publish(context.Background(), firstSource.ID, firstDraft.ID)
	if err != nil {
		t.Fatal(err)
	}
	replacementConfig := environment.putBlob(t, "source_config", []byte(`{"kind":"inline","version":2}`))
	environment.advance(time.Minute)
	replacement, err := environment.repository.ReplaceDraft(
		context.Background(), firstSource.ID, firstPublished.Draft.ID,
		RevisionConfig{SourceType: SourceInline, ImportPurpose: PurposeNodes, ConfigBlobID: replacementConfig.ID},
	)
	if err != nil {
		t.Fatalf("ReplaceDraft() error = %v", err)
	}
	if replacement.Draft.Number != 3 || replacement.Draft.Config.ConfigBlobID != replacementConfig.ID ||
		replacement.Source.PublishedRevisionID != firstPublished.Published.ID {
		t.Fatalf("replacement = %+v", replacement)
	}
	if _, err := environment.repository.ReplaceDraft(
		context.Background(), firstSource.ID, firstPublished.Draft.ID, replacement.Draft.Config,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("ReplaceDraft(stale expected draft) error = %v", err)
	}
	secondSource, secondDraft := environment.createSource(t, "Second")
	secondPublished, err := environment.repository.Publish(context.Background(), secondSource.ID, secondDraft.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := environment.repository.StartAttempt(context.Background(), StartAttemptRequest{
		SourceID: firstSource.ID, SourceRevisionID: secondPublished.Published.ID,
		Trigger: TriggerManual, CorrelationID: "cross-source",
	}); err == nil {
		t.Fatal("StartAttempt() accepted another source's revision")
	}

	attempt := environment.startAttempt(t, firstSource.ID, firstPublished.Published.ID, TriggerManual)
	if _, err := environment.repository.StartAttempt(context.Background(), StartAttemptRequest{
		SourceID: firstSource.ID, SourceRevisionID: firstPublished.Published.ID,
		Trigger: TriggerRetry, CorrelationID: "overlapping",
	}); err == nil {
		t.Fatal("StartAttempt() allowed overlapping refreshes for one source")
	}
	if _, err := environment.repository.CompleteFailure(context.Background(), FailureRequest{
		AttemptID: attempt.ID, Status: AttemptFailed, ErrorCode: "network_timeout",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := environment.database.Exec(
		"UPDATE refresh_attempts SET error_detail = 'changed' WHERE id = ?", attempt.ID,
	); err == nil {
		t.Fatal("database allowed a terminal refresh attempt mutation")
	}
	if _, err := environment.repository.CompleteFailure(context.Background(), FailureRequest{
		AttemptID: attempt.ID, Status: AttemptFailed, ErrorCode: "again",
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("second CompleteFailure() error = %v", err)
	}

	secondPublication, err := environment.repository.Publish(context.Background(), firstSource.ID, replacement.Draft.ID)
	if err != nil {
		t.Fatalf("second Publish() error = %v", err)
	}
	if secondPublication.Published.ID != replacement.Draft.ID {
		t.Fatalf("second publication = %+v", secondPublication)
	}
	if _, err := environment.repository.StartAttempt(context.Background(), StartAttemptRequest{
		SourceID: firstSource.ID, SourceRevisionID: firstPublished.Published.ID,
		Trigger: TriggerManual, CorrelationID: "stale-revision",
	}); err == nil {
		t.Fatal("StartAttempt() accepted a superseded source revision")
	}
}

func TestRecoverRunningAttemptsClosesInterruptedRefresh(t *testing.T) {
	environment := newTestEnvironment(t)
	defer environment.close()
	source, draft := environment.createSource(t, "Interrupted")
	published, err := environment.repository.Publish(context.Background(), source.ID, draft.ID)
	if err != nil {
		t.Fatal(err)
	}
	attempt := environment.startAttempt(t, source.ID, published.Published.ID, TriggerSchedule)
	environment.advance(time.Minute)
	recovered, err := environment.repository.RecoverRunningAttempts(context.Background())
	if err != nil || recovered != 1 {
		t.Fatalf("RecoverRunningAttempts() = %d, %v", recovered, err)
	}
	stored, err := environment.repository.GetAttempt(context.Background(), attempt.ID)
	if err != nil || stored.Status != AttemptFailed || stored.ErrorCode != "service_interrupted" || stored.FinishedAt == nil {
		t.Fatalf("recovered attempt = %+v, %v", stored, err)
	}
	if recovered, err := environment.repository.RecoverRunningAttempts(context.Background()); err != nil || recovered != 0 {
		t.Fatalf("second RecoverRunningAttempts() = %d, %v", recovered, err)
	}
}

func TestSnapshotAcceptanceRollsBackAsOneTransaction(t *testing.T) {
	environment := newTestEnvironment(t)
	defer environment.close()

	source, draft := environment.createSource(t, "Atomic")
	published, err := environment.repository.Publish(context.Background(), source.ID, draft.ID)
	if err != nil {
		t.Fatal(err)
	}
	attempt := environment.startAttempt(t, source.ID, published.Published.ID, TriggerImport)
	rawContent := []byte("trojan://secret@example.test:443#Node")
	rawBlob := environment.putBlob(t, "raw_document", rawContent)
	nodes, occurrences := environment.acceptedDetails(t, rawContent)
	if _, err := environment.database.Exec(`
CREATE TRIGGER reject_snapshot_switch
BEFORE UPDATE OF current_snapshot_id ON sources
BEGIN
  SELECT RAISE(ABORT, 'forced snapshot switch failure');
END`); err != nil {
		t.Fatal(err)
	}
	_, _, err = environment.repository.AcceptSnapshot(context.Background(), AcceptRequest{
		AttemptID: attempt.ID, RawBlobID: rawBlob.ID,
		DetectedFormat: "uri-list", FormatAdapterVersion: "uri-list-v1",
		NodeCount: 1, OccurrenceAlgorithmVersion: occurrence.AlgorithmVersion,
		StaleAfter: time.Hour, RetainFor: 24 * time.Hour,
		Nodes: nodes, Occurrences: occurrences,
	})
	if err == nil {
		t.Fatal("AcceptSnapshot() succeeded despite a forced pointer failure")
	}
	for _, table := range []string{
		"raw_documents", "snapshots", "fingerprints", "raw_nodes",
		"canonical_nodes", "node_occurrences", "snapshot_occurrences",
	} {
		var count int
		if err := environment.database.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s count = %d, %v", table, count, err)
		}
	}
	storedAttempt, err := environment.repository.GetAttempt(context.Background(), attempt.ID)
	if err != nil || storedAttempt.Status != AttemptRunning {
		t.Fatalf("attempt after rollback = %+v, %v", storedAttempt, err)
	}
	if _, err := environment.repository.CurrentSnapshot(context.Background(), source.ID); !errors.Is(err, ErrNoCurrentSnapshot) {
		t.Fatalf("CurrentSnapshot() error = %v", err)
	}
}

func TestNotModifiedRequiresAnExistingSnapshot(t *testing.T) {
	environment := newTestEnvironment(t)
	defer environment.close()

	source, draft := environment.createSource(t, "Empty")
	published, err := environment.repository.Publish(context.Background(), source.ID, draft.ID)
	if err != nil {
		t.Fatal(err)
	}
	attempt := environment.startAttempt(t, source.ID, published.Published.ID, TriggerManual)
	httpOK := 200
	if _, _, err := environment.repository.CompleteNotModified(context.Background(), attempt.ID, AttemptMetrics{HTTPStatus: &httpOK}); err == nil {
		t.Fatal("CompleteNotModified() accepted a non-304 status")
	}
	httpNotModified := 304
	if _, _, err := environment.repository.CompleteNotModified(context.Background(), attempt.ID, AttemptMetrics{HTTPStatus: &httpNotModified}); !errors.Is(err, ErrNoCurrentSnapshot) {
		t.Fatalf("CompleteNotModified() error = %v", err)
	}
	stored, err := environment.repository.GetAttempt(context.Background(), attempt.ID)
	if err != nil || stored.Status != AttemptRunning {
		t.Fatalf("attempt after rejected 304 = %+v, %v", stored, err)
	}
}

type testEnvironment struct {
	database       *sql.DB
	sqliteStore    *storagesqlite.Store
	keyring        *keyring.Ring
	blobs          *blobstore.Store
	repository     *Repository
	now            time.Time
	nextOccurrence int
}

func newTestEnvironment(t *testing.T) *testEnvironment {
	t.Helper()
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	sqliteStore, err := storagesqlite.Open(context.Background(), filepath.Join(t.TempDir(), "proxyloom.db"), storagesqlite.OpenOptions{
		Migrate: storagesqlite.MigrateOptions{Now: func() time.Time { return now }},
	})
	if err != nil {
		t.Fatal(err)
	}
	master := masterkey.Key{ID: "00000000-0000-4000-8000-000000000001"}
	for index := range master.Material {
		master.Material[index] = 0x44
	}
	ring, err := storagesqlite.BootstrapKeys(context.Background(), sqliteStore.DB(), master, storagesqlite.KeyBootstrapOptions{
		Now: now, Random: incrementingReader(4096), NewID: fixtureIDGenerator(1),
	})
	if err != nil {
		sqliteStore.Close()
		t.Fatal(err)
	}
	blobs, err := blobstore.New(sqliteStore.DB(), ring, blobstore.Options{
		Root: filepath.Join(t.TempDir(), "blobs"), InlineThreshold: 1024, MaxPlaintext: 1 << 20,
		Random: incrementingReader(1 << 20), Now: func() time.Time { return now }, NewID: fixtureIDGenerator(1000),
	})
	if err != nil {
		ring.Close()
		sqliteStore.Close()
		t.Fatal(err)
	}
	environment := &testEnvironment{
		sqliteStore: sqliteStore, keyring: ring, blobs: blobs, now: now,
		nextOccurrence: 800,
	}
	environment.database = sqliteStore.DB()
	repository, err := New(sqliteStore.DB(), Options{
		Now: func() time.Time { return environment.now }, NewID: fixtureIDGenerator(100),
	})
	if err != nil {
		environment.close()
		t.Fatal(err)
	}
	environment.repository = repository
	return environment
}

func (environment *testEnvironment) close() {
	if environment.keyring != nil {
		environment.keyring.Close()
	}
	if environment.sqliteStore != nil {
		_ = environment.sqliteStore.Close()
	}
}

func (environment *testEnvironment) advance(duration time.Duration) {
	environment.now = environment.now.Add(duration)
}

func (environment *testEnvironment) putBlob(t *testing.T, kind string, plaintext []byte) blobstore.Record {
	t.Helper()
	record, err := environment.blobs.Put(context.Background(), blobstore.PutRequest{Kind: kind, Plaintext: plaintext})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func (environment *testEnvironment) acceptedDetails(t *testing.T, raw []byte) ([]AcceptedNode, []occurrence.Occurrence) {
	t.Helper()
	fingerprintKey, err := environment.keyring.Active(keyring.PurposeFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	fingerprinter, err := identity.NewFingerprinter(fingerprintKey.Material[:], fingerprintKey.ID)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := fingerprinter.SumBytes(identity.ByteProjection{
		Value: raw, Kind: identity.KindOpaqueStructural, Version: identity.OpaqueURIProjection,
	})
	if err != nil {
		t.Fatal(err)
	}
	rawNode := environment.putBlob(t, "raw_node", raw)
	name := environment.putBlob(t, "node_name", []byte("Node"))
	occurrenceID := fmt.Sprintf("00000000-0000-7000-8000-%012d", environment.nextOccurrence)
	environment.nextOccurrence++
	item := occurrence.Occurrence{
		ID: occurrenceID, Fingerprint: fingerprint, ExtractionPath: "/0", ProtocolID: "vless",
		OriginalName: "Node", State: occurrence.StatePresent, DuplicateSlot: 1,
		CreatedAt: environment.now, LastSeenAt: environment.now,
		AlgorithmVersion: occurrence.AlgorithmVersion,
	}
	node := AcceptedNode{
		Ordinal: 0, ExtractionPath: "/0", RawKind: "uri",
		FormatID: "uri-list", FormatAdapterVersion: "uri-list-v1", ProtocolID: "vless",
		ParseStatus: "opaque", RawBlobID: rawNode.ID, OriginalNameBlobID: name.ID,
		Fingerprint: fingerprint, OccurrenceID: occurrenceID, MatchMethod: occurrence.MatchNew,
	}
	return []AcceptedNode{node}, []occurrence.Occurrence{item}
}

func (environment *testEnvironment) createSource(t *testing.T, displayName string) (Source, Revision) {
	t.Helper()
	config := environment.putBlob(t, "source_config", []byte(`{"kind":"inline"}`))
	source, revision, err := environment.repository.Create(context.Background(), CreateRequest{
		DisplayName: displayName,
		Config: RevisionConfig{
			SourceType: SourceInline, ImportPurpose: PurposeNodes, ConfigBlobID: config.ID,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return source, revision
}

func (environment *testEnvironment) startAttempt(t *testing.T, sourceID, revisionID string, trigger TriggerKind) Attempt {
	t.Helper()
	attempt, err := environment.repository.StartAttempt(context.Background(), StartAttemptRequest{
		SourceID: sourceID, SourceRevisionID: revisionID, Trigger: trigger,
		CorrelationID: fmt.Sprintf("correlation-%s", trigger),
	})
	if err != nil {
		t.Fatal(err)
	}
	return attempt
}

func fixtureIDGenerator(start int) func() string {
	next := start
	return func() string {
		id := fmt.Sprintf("00000000-0000-7000-8000-%012d", next)
		next++
		return id
	}
}

func incrementingReader(size int) *bytes.Reader {
	content := make([]byte, size)
	for index := range content {
		content[index] = byte(index)
	}
	return bytes.NewReader(content)
}
