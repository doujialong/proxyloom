package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	proxybuild "github.com/doujialong/proxyloom/internal/build"
	"github.com/doujialong/proxyloom/internal/convert"
	"github.com/doujialong/proxyloom/internal/crypto/keyring"
	"github.com/doujialong/proxyloom/internal/fetcher"
	"github.com/doujialong/proxyloom/internal/format/clienttext"
	"github.com/doujialong/proxyloom/internal/format/mihomo"
	"github.com/doujialong/proxyloom/internal/format/singbox"
	"github.com/doujialong/proxyloom/internal/format/urilist"
	"github.com/doujialong/proxyloom/internal/identity"
	"github.com/doujialong/proxyloom/internal/ingest"
	"github.com/doujialong/proxyloom/internal/jsonlossless"
	"github.com/doujialong/proxyloom/internal/occurrence"
	"github.com/doujialong/proxyloom/internal/protocol"
	"github.com/doujialong/proxyloom/internal/storage/artifactstore"
	"github.com/doujialong/proxyloom/internal/storage/blobstore"
	"github.com/doujialong/proxyloom/internal/storage/healthstore"
	"github.com/doujialong/proxyloom/internal/storage/jobstore"
	"github.com/doujialong/proxyloom/internal/storage/sourcestore"
)

const SourceConfigVersion = 4

type SourceConfig struct {
	Type                     sourcestore.SourceType `json:"type"`
	InlineContent            string                 `json:"inline_content,omitempty"`
	URL                      string                 `json:"url,omitempty"`
	RequestHeaders           map[string]string      `json:"request_headers,omitempty"`
	ProxyURL                 string                 `json:"proxy_url,omitempty"`
	TimeoutSeconds           int                    `json:"timeout_seconds,omitempty"`
	InputFormat              string                 `json:"input_format"`
	OutputFormat             string                 `json:"output_format"`
	MinimumNodes             int                    `json:"minimum_nodes"`
	MaximumDropRatio         float64                `json:"maximum_drop_ratio"`
	RefreshIntervalSeconds   int                    `json:"refresh_interval_seconds"`
	PrivateNetworkAuthorized bool                   `json:"private_network_authorized"`
	MaxResponseBytes         int                    `json:"max_response_bytes"`
	HealthFilterEnabled      bool                   `json:"health_filter_enabled"`
}

type ManagerOptions struct {
	Now             func() time.Time
	NewID           func() string
	HealthScheduler interface {
		SynchronizeSnapshot(context.Context, string, string) error
	}
	HealthReader interface {
		States(context.Context, []string) (map[string]healthstore.HealthState, error)
		GuardSuppressed(context.Context) (bool, string, error)
	}
	HealthCatalog interface {
		ListNodes(context.Context, healthstore.NodeListOptions) ([]healthstore.NodeSummary, bool, error)
		Node(context.Context, string) (healthstore.NodeSummary, error)
		Records(context.Context, string, int) ([]healthstore.Record, error)
		ManualEnqueue(context.Context, string) error
		Capacity(context.Context) (healthstore.Capacity, error)
	}
}

type Manager struct {
	keys            *keyring.Ring
	blobs           *blobstore.Store
	sources         *sourcestore.Repository
	jobs            *jobstore.Store
	artifacts       *artifactstore.Store
	registry        *protocol.Registry
	now             func() time.Time
	newID           func() string
	healthScheduler interface {
		SynchronizeSnapshot(context.Context, string, string) error
	}
	healthReader interface {
		States(context.Context, []string) (map[string]healthstore.HealthState, error)
		GuardSuppressed(context.Context) (bool, string, error)
	}
	healthCatalog interface {
		ListNodes(context.Context, healthstore.NodeListOptions) ([]healthstore.NodeSummary, bool, error)
		Node(context.Context, string) (healthstore.NodeSummary, error)
		Records(context.Context, string, int) ([]healthstore.Record, error)
		ManualEnqueue(context.Context, string) error
		Capacity(context.Context) (healthstore.Capacity, error)
	}
}

type CreateResult struct {
	Source     sourcestore.Source
	Revision   sourcestore.Revision
	Job        jobstore.Job
	Credential artifactstore.Credential
}

type UpdateResult struct {
	Source   sourcestore.Source
	Revision sourcestore.Revision
	Job      jobstore.Job
}

type RefreshResult struct {
	Snapshot            sourcestore.Snapshot
	Artifact            artifactstore.Artifact
	DetectedFormat      string
	NodeCount           int
	NextRefreshAt       *time.Time
	HealthScheduleError error
}

type SourceDetail struct {
	Source         sourcestore.Source
	Draft          sourcestore.Revision
	Published      *sourcestore.Revision
	Config         SourceConfig
	MaskedLocation string
	MaskedProxy    string
	Stale          bool
}

type NodeDetail struct {
	Summary      healthstore.NodeSummary
	OriginalName string
}

type OperationError struct {
	Code string
	Err  error
}

func (e *OperationError) Error() string { return e.Code + ": " + e.Err.Error() }
func (e *OperationError) Unwrap() error { return e.Err }

func NewManager(keys *keyring.Ring, blobs *blobstore.Store, sources *sourcestore.Repository, jobs *jobstore.Store, artifacts *artifactstore.Store, options ManagerOptions) (*Manager, error) {
	if keys == nil || blobs == nil || sources == nil || jobs == nil || artifacts == nil || options.Now == nil || options.NewID == nil {
		return nil, fmt.Errorf("manager dependencies are required")
	}
	return &Manager{
		keys: keys, blobs: blobs, sources: sources, jobs: jobs, artifacts: artifacts,
		registry: protocol.NewRegistry(), now: options.Now, newID: options.NewID,
		healthScheduler: options.HealthScheduler,
		healthReader:    options.HealthReader,
		healthCatalog:   options.HealthCatalog,
	}, nil
}

func (m *Manager) CreateSource(ctx context.Context, displayName string, config SourceConfig) (CreateResult, error) {
	config = normalizeConfig(config)
	if err := validateConfig(config); err != nil {
		return CreateResult{}, err
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return CreateResult{}, fmt.Errorf("encode source config: %w", err)
	}
	configBlob, err := m.blobs.Put(ctx, blobstore.PutRequest{Kind: "source_config", Plaintext: encoded})
	if err != nil {
		return CreateResult{}, err
	}
	source, draft, err := m.sources.Create(ctx, sourcestore.CreateRequest{
		DisplayName: displayName,
		Config: sourcestore.RevisionConfig{
			SourceType: config.Type, InputFormatHint: config.InputFormat,
			ImportPurpose:            sourcestore.PurposeNodes,
			RefreshSchedule:          refreshSchedule(config.RefreshIntervalSeconds),
			PrivateNetworkAuthorized: config.PrivateNetworkAuthorized,
			ConfigBlobID:             configBlob.ID, ConfigSchemaVersion: SourceConfigVersion,
		},
	})
	if err != nil {
		return CreateResult{}, err
	}
	published, err := m.sources.Publish(ctx, source.ID, draft.ID)
	if err != nil {
		return CreateResult{}, err
	}
	credential, err := m.artifacts.CreateCredential(ctx, source.ID)
	if err != nil {
		return CreateResult{}, err
	}
	job, err := m.jobs.Enqueue(ctx, jobstore.EnqueueRequest{
		SourceID: source.ID, SourceRevisionID: published.Published.ID,
		DueAt: m.now().UTC(), CorrelationID: "create-" + source.ID,
	})
	if err != nil {
		return CreateResult{}, err
	}
	return CreateResult{
		Source: published.Source, Revision: published.Published,
		Job: job, Credential: credential,
	}, nil
}

func (m *Manager) UpdateSource(ctx context.Context, sourceID string, config SourceConfig) (UpdateResult, error) {
	source, err := m.sources.GetSource(ctx, sourceID)
	if err != nil {
		return UpdateResult{}, err
	}
	return m.UpdateSourceAt(ctx, sourceID, source.DisplayName, time.Time{}, config)
}

func (m *Manager) UpdateSourceAt(ctx context.Context, sourceID, displayName string, expectedUpdatedAt time.Time, config SourceConfig) (UpdateResult, error) {
	config = normalizeConfig(config)
	if err := validateConfig(config); err != nil {
		return UpdateResult{}, err
	}
	if strings.TrimSpace(displayName) == "" || len(displayName) > 200 || !utf8.ValidString(displayName) {
		return UpdateResult{}, fmt.Errorf("display name must be valid UTF-8 and between 1 and 200 bytes")
	}
	source, err := m.sources.GetSource(ctx, sourceID)
	if err != nil {
		return UpdateResult{}, err
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return UpdateResult{}, fmt.Errorf("encode source config: %w", err)
	}
	configBlob, err := m.blobs.Put(ctx, blobstore.PutRequest{Kind: "source_config", Plaintext: encoded})
	if err != nil {
		return UpdateResult{}, err
	}
	replaced, err := m.sources.ReplaceDraftWithMetadata(ctx, sourcestore.ReplaceDraftRequest{
		SourceID: source.ID, ExpectedDraftID: source.DraftRevisionID,
		ExpectedUpdatedAt: expectedUpdatedAt, DisplayName: displayName,
		Config: sourcestore.RevisionConfig{
			SourceType: config.Type, InputFormatHint: config.InputFormat,
			ImportPurpose:            sourcestore.PurposeNodes,
			RefreshSchedule:          refreshSchedule(config.RefreshIntervalSeconds),
			PrivateNetworkAuthorized: config.PrivateNetworkAuthorized,
			ConfigBlobID:             configBlob.ID, ConfigSchemaVersion: SourceConfigVersion,
		},
	})
	if err != nil {
		return UpdateResult{}, err
	}
	published, err := m.sources.Publish(ctx, source.ID, replaced.Draft.ID)
	if err != nil {
		return UpdateResult{}, err
	}
	job, err := m.jobs.Enqueue(ctx, jobstore.EnqueueRequest{
		SourceID: source.ID, SourceRevisionID: published.Published.ID,
		DueAt: m.now().UTC(), CorrelationID: "update-" + source.ID,
	})
	if err != nil {
		return UpdateResult{}, err
	}
	return UpdateResult{Source: published.Source, Revision: published.Published, Job: job}, nil
}

func (m *Manager) CurrentSourceConfig(ctx context.Context, sourceID string) (SourceDetail, SourceConfig, error) {
	detail, err := m.GetSource(ctx, sourceID)
	if err != nil {
		return SourceDetail{}, SourceConfig{}, err
	}
	config, err := m.loadConfig(ctx, detail.Draft)
	if err != nil {
		return SourceDetail{}, SourceConfig{}, err
	}
	return detail, config, nil
}

func (m *Manager) EnqueueRefresh(ctx context.Context, sourceID, correlationID string) (jobstore.Job, error) {
	source, err := m.sources.GetSource(ctx, sourceID)
	if err != nil {
		return jobstore.Job{}, err
	}
	if source.PublishedRevisionID == "" {
		return jobstore.Job{}, sourcestore.ErrConflict
	}
	return m.jobs.Enqueue(ctx, jobstore.EnqueueRequest{
		SourceID: source.ID, SourceRevisionID: source.PublishedRevisionID,
		DueAt: m.now().UTC(), CorrelationID: correlationID,
	})
}

func (m *Manager) NextRefreshAfterFailure(ctx context.Context, sourceID, revisionID string) (*time.Time, error) {
	revision, err := m.sources.GetRevision(ctx, sourceID, revisionID)
	if err != nil {
		return nil, err
	}
	config, err := m.loadConfig(ctx, revision)
	if err != nil {
		return nil, err
	}
	if config.RefreshIntervalSeconds <= 0 {
		return nil, nil
	}
	next := m.now().UTC().Add(time.Duration(config.RefreshIntervalSeconds) * time.Second)
	return &next, nil
}

func (m *Manager) EnqueueHealthRebuild(ctx context.Context, sourceID string) error {
	source, err := m.sources.GetSource(ctx, sourceID)
	if err != nil {
		return err
	}
	if source.PublishedRevisionID == "" || source.LifecycleState != "active" {
		return nil
	}
	revision, err := m.sources.GetRevision(ctx, sourceID, source.PublishedRevisionID)
	if err != nil {
		return err
	}
	config, err := m.loadConfig(ctx, revision)
	if err != nil {
		return err
	}
	if !config.HealthFilterEnabled {
		return nil
	}
	_, err = m.EnqueueRefresh(ctx, sourceID, "health-boundary-"+sourceID)
	return err
}

func (m *Manager) CreatePublicationCredential(ctx context.Context, sourceID string) (artifactstore.Credential, error) {
	return m.artifacts.CreateCredential(ctx, sourceID)
}

func (m *Manager) GetSource(ctx context.Context, sourceID string) (SourceDetail, error) {
	source, err := m.sources.GetSource(ctx, sourceID)
	if err != nil {
		return SourceDetail{}, err
	}
	return m.sourceDetail(ctx, source)
}

func (m *Manager) ListSources(ctx context.Context, options sourcestore.SourceListOptions) ([]SourceDetail, bool, error) {
	sources, hasMore, err := m.sources.ListSources(ctx, options)
	if err != nil {
		return nil, false, err
	}
	result := make([]SourceDetail, len(sources))
	for index, source := range sources {
		detail, err := m.sourceDetail(ctx, source)
		if err != nil {
			return nil, false, err
		}
		result[index] = detail
	}
	return result, hasMore, nil
}

func (m *Manager) ArchiveSource(ctx context.Context, sourceID string, expectedUpdatedAt time.Time) (SourceDetail, error) {
	source, err := m.sources.Archive(ctx, sourceID, expectedUpdatedAt)
	if err != nil {
		return SourceDetail{}, err
	}
	return m.sourceDetail(ctx, source)
}

func (m *Manager) ListSourceRevisions(ctx context.Context, sourceID string, limit int) ([]sourcestore.Revision, error) {
	return m.sources.ListRevisions(ctx, sourceID, limit)
}

func (m *Manager) ListRefreshAttempts(ctx context.Context, sourceID string, limit int) ([]sourcestore.Attempt, error) {
	return m.sources.ListAttempts(ctx, sourceID, limit)
}

func (m *Manager) ListSnapshots(ctx context.Context, sourceID string, limit int) ([]sourcestore.Snapshot, error) {
	return m.sources.ListSnapshots(ctx, sourceID, limit)
}

func (m *Manager) ListNodes(ctx context.Context, options healthstore.NodeListOptions) ([]NodeDetail, bool, error) {
	if m.healthCatalog == nil {
		return nil, false, fmt.Errorf("node health catalog is unavailable")
	}
	summaries, hasMore, err := m.healthCatalog.ListNodes(ctx, options)
	if err != nil {
		return nil, false, err
	}
	result := make([]NodeDetail, len(summaries))
	for index, summary := range summaries {
		detail, err := m.nodeDetail(ctx, summary)
		if err != nil {
			return nil, false, err
		}
		result[index] = detail
	}
	return result, hasMore, nil
}

func (m *Manager) GetNode(ctx context.Context, occurrenceID string) (NodeDetail, error) {
	if m.healthCatalog == nil {
		return NodeDetail{}, fmt.Errorf("node health catalog is unavailable")
	}
	summary, err := m.healthCatalog.Node(ctx, occurrenceID)
	if err != nil {
		return NodeDetail{}, err
	}
	return m.nodeDetail(ctx, summary)
}

func (m *Manager) NodeHealthRecords(ctx context.Context, occurrenceID string, limit int) ([]healthstore.Record, error) {
	if m.healthCatalog == nil {
		return nil, fmt.Errorf("node health catalog is unavailable")
	}
	return m.healthCatalog.Records(ctx, occurrenceID, limit)
}

func (m *Manager) EnqueueNodeCheck(ctx context.Context, occurrenceID string) error {
	if m.healthCatalog == nil {
		return fmt.Errorf("node health catalog is unavailable")
	}
	return m.healthCatalog.ManualEnqueue(ctx, occurrenceID)
}

func (m *Manager) HealthCapacity(ctx context.Context) (healthstore.Capacity, error) {
	if m.healthCatalog == nil {
		return healthstore.Capacity{}, fmt.Errorf("node health catalog is unavailable")
	}
	return m.healthCatalog.Capacity(ctx)
}

func (m *Manager) HealthGuard(ctx context.Context) (bool, string, error) {
	if m.healthReader == nil {
		return false, "", fmt.Errorf("node health guard is unavailable")
	}
	return m.healthReader.GuardSuppressed(ctx)
}

func (m *Manager) nodeDetail(ctx context.Context, summary healthstore.NodeSummary) (NodeDetail, error) {
	detail := NodeDetail{Summary: summary, OriginalName: summary.ProtocolID}
	if summary.NameBlobID == "" {
		return detail, nil
	}
	name, record, err := m.blobs.Get(ctx, summary.NameBlobID)
	if err != nil {
		return NodeDetail{}, err
	}
	if record.Kind != "node_name" || !utf8.Valid(name) {
		return NodeDetail{}, fmt.Errorf("node occurrence %s has invalid name data", summary.NodeOccurrenceID)
	}
	detail.OriginalName = string(name)
	return detail, nil
}

func (m *Manager) sourceDetail(ctx context.Context, source sourcestore.Source) (SourceDetail, error) {
	draft, err := m.sources.GetRevision(ctx, source.ID, source.DraftRevisionID)
	if err != nil {
		return SourceDetail{}, err
	}
	config, err := m.loadConfig(ctx, draft)
	if err != nil {
		return SourceDetail{}, err
	}
	detail := SourceDetail{
		Source: source, Draft: draft, Config: config,
		MaskedLocation: maskSourceLocation(config), MaskedProxy: maskProxyLocation(config.ProxyURL),
	}
	if source.PublishedRevisionID != "" {
		published, err := m.sources.GetRevision(ctx, source.ID, source.PublishedRevisionID)
		if err != nil {
			return SourceDetail{}, err
		}
		detail.Published = &published
	}
	if source.CurrentSnapshotID != "" {
		snapshot, err := m.sources.CurrentSnapshot(ctx, source.ID)
		if err != nil {
			return SourceDetail{}, err
		}
		detail.Stale = !m.now().UTC().Before(snapshot.StaleAfter)
	}
	return detail, nil
}

func maskSourceLocation(config SourceConfig) string {
	if config.Type == sourcestore.SourceInline {
		return "inline"
	}
	if config.Type == sourcestore.SourceUpload {
		return "upload"
	}
	parsed, err := url.Parse(config.URL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "remote"
	}
	return parsed.Scheme + "://" + parsed.Host + "/..."
}

func maskProxyLocation(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

func (m *Manager) Refresh(ctx context.Context, sourceID, revisionID, correlationID string) (RefreshResult, error) {
	attempt, err := m.sources.StartAttempt(ctx, sourcestore.StartAttemptRequest{
		SourceID: sourceID, SourceRevisionID: revisionID,
		Trigger: sourcestore.TriggerSchedule, CorrelationID: correlationID,
	})
	if err != nil {
		return RefreshResult{}, operationError("attempt_start_failed", err)
	}
	started := time.Now().UTC()
	revision, err := m.sources.GetRevision(ctx, sourceID, revisionID)
	if err != nil {
		return RefreshResult{}, m.failAttempt(ctx, attempt.ID, "config_unavailable", err, sourcestore.AttemptMetrics{})
	}
	config, err := m.loadConfig(ctx, revision)
	if err != nil {
		return RefreshResult{}, m.failAttempt(ctx, attempt.ID, "config_invalid", err, sourcestore.AttemptMetrics{})
	}
	content, mediaType, httpStatus, err := m.obtainContent(ctx, config)
	if err != nil {
		return RefreshResult{}, m.failAttempt(ctx, attempt.ID, "fetch_failed", err, metricsSince(started, 0, httpStatus))
	}
	existing, err := m.loadOccurrences(ctx, sourceID)
	if err != nil {
		return RefreshResult{}, m.failAttempt(ctx, attempt.ID, "occurrence_load_failed", err, metricsSince(started, len(content), httpStatus))
	}
	fingerprintKey, err := m.keys.Active(keyring.PurposeFingerprint)
	if err != nil {
		return RefreshResult{}, m.failAttempt(ctx, attempt.ID, "fingerprint_key_unavailable", err, metricsSince(started, len(content), httpStatus))
	}
	fingerprinter, err := identity.NewFingerprinter(fingerprintKey.Material[:], fingerprintKey.ID)
	if err != nil {
		return RefreshResult{}, m.failAttempt(ctx, attempt.ID, "fingerprint_init_failed", err, metricsSince(started, len(content), httpStatus))
	}
	processed, err := m.process(ctx, sourceID, config, content, existing, fingerprinter)
	if err != nil {
		return RefreshResult{}, m.rejectAttempt(ctx, attempt.ID, "parse_failed", err, nil, metricsSince(started, len(content), httpStatus))
	}
	if processed.outputFormat == "sing-box" {
		if _, err := singbox.Parse(processed.artifact, m.registry, singbox.DefaultLimits()); err != nil {
			return RefreshResult{}, m.rejectAttempt(ctx, attempt.ID, "structural_validation_failed", err, nil, metricsSince(started, len(content), httpStatus))
		}
	}
	if processed.includedCount < config.MinimumNodes {
		return RefreshResult{}, m.rejectAttempt(ctx, attempt.ID, "health_filter_gate_rejected",
			fmt.Errorf("health filtering retained %d nodes, below minimum %d", processed.includedCount, config.MinimumNodes),
			nil, metricsSince(started, len(content), httpStatus))
	}
	previousCount := 0
	if previous, previousErr := m.sources.CurrentSnapshot(ctx, sourceID); previousErr == nil {
		previousCount = previous.NodeCount
	} else if !errors.Is(previousErr, sourcestore.ErrNoCurrentSnapshot) {
		return RefreshResult{}, m.failAttempt(ctx, attempt.ID, "snapshot_read_failed", previousErr, metricsSince(started, len(content), httpStatus))
	}
	if err := checkContentGates(processed.nodeCount, previousCount, config); err != nil {
		count := processed.nodeCount
		return RefreshResult{}, m.rejectAttempt(ctx, attempt.ID, "content_gate_rejected", err, &count, metricsSince(started, len(content), httpStatus))
	}
	rawDocument, err := m.blobs.Put(ctx, blobstore.PutRequest{Kind: "raw_document", Plaintext: content})
	if err != nil {
		return RefreshResult{}, m.failAttempt(ctx, attempt.ID, "raw_document_store_failed", err, metricsSince(started, len(content), httpStatus))
	}
	acceptedNodes, err := processed.persist(ctx, m.blobs)
	if err != nil {
		return RefreshResult{}, m.failAttempt(ctx, attempt.ID, "node_store_failed", err, metricsSince(started, len(content), httpStatus))
	}
	metrics := metricsSince(started, len(content), httpStatus)
	artifactBlob, err := m.blobs.Put(ctx, blobstore.PutRequest{Kind: "artifact", Plaintext: processed.artifact, Public: true})
	if err != nil {
		return RefreshResult{}, m.failAttempt(ctx, attempt.ID, "artifact_store_failed", err, metrics)
	}
	snapshot, _, err := m.sources.AcceptSnapshot(ctx, sourcestore.AcceptRequest{
		AttemptID: attempt.ID, RawBlobID: rawDocument.ID,
		DetectedFormat: processed.detectedFormat, FormatAdapterVersion: processed.adapterVersion,
		MediaType: mediaType, Charset: "utf-8", ParseLimitsVersion: 1,
		NodeCount: processed.nodeCount, LogicalOutboundCount: processed.logicalCount,
		WarningCount: processed.warningCount, OccurrenceAlgorithmVersion: occurrence.AlgorithmVersion,
		StaleAfter: staleDuration(config.RefreshIntervalSeconds), RetainFor: 30 * 24 * time.Hour,
		Metrics: metrics, Nodes: acceptedNodes, Occurrences: processed.occurrences,
	})
	if err != nil {
		return RefreshResult{}, m.failAttempt(ctx, attempt.ID, "snapshot_accept_failed", err, metrics)
	}
	artifact, err := m.artifacts.Publish(ctx, artifactstore.PublishRequest{
		SourceID: sourceID, SnapshotID: snapshot.ID, ContentBlobID: artifactBlob.ID,
		ContentType: processed.contentType, NodeCount: processed.includedCount,
		WarningCount: processed.warningCount, OutputFormat: processed.outputFormat,
		BuilderVersion: processed.builderVersion,
	})
	if err != nil {
		return RefreshResult{}, operationError("artifact_publish_failed", err)
	}
	result := RefreshResult{
		Snapshot: snapshot, Artifact: artifact, DetectedFormat: processed.detectedFormat,
		NodeCount: processed.includedCount,
	}
	if config.RefreshIntervalSeconds > 0 {
		next := m.now().UTC().Add(time.Duration(config.RefreshIntervalSeconds) * time.Second)
		result.NextRefreshAt = &next
	}
	if m.healthScheduler != nil {
		result.HealthScheduleError = m.healthScheduler.SynchronizeSnapshot(ctx, sourceID, snapshot.ID)
	}
	return result, nil
}

type processedSnapshot struct {
	detectedFormat string
	outputFormat   string
	adapterVersion string
	builderVersion string
	contentType    string
	nodeCount      int
	includedCount  int
	logicalCount   int
	warningCount   int
	artifact       []byte
	occurrences    []occurrence.Occurrence
	persist        func(context.Context, *blobstore.Store) ([]sourcestore.AcceptedNode, error)
}

func (m *Manager) process(ctx context.Context, sourceID string, config SourceConfig, content []byte, existing []occurrence.Occurrence, fingerprinter *identity.Fingerprinter) (processedSnapshot, error) {
	format := config.InputFormat
	if format == "auto" {
		candidates := []string{"uri-list", "mihomo", "client-text"}
		if json.Valid(content) {
			candidates = []string{"sing-box", "mihomo"}
		}
		errorsByFormat := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			explicit := config
			explicit.InputFormat = candidate
			processed, err := m.process(ctx, sourceID, explicit, content, existing, fingerprinter)
			if err == nil {
				return processed, nil
			}
			errorsByFormat = append(errorsByFormat, candidate+": "+err.Error())
		}
		return processedSnapshot{}, fmt.Errorf("unrecognized subscription format (%s)", strings.Join(errorsByFormat, "; "))
	}
	options := ingest.Options{
		SourceID: sourceID, Now: m.now().UTC(), OccurrenceRetention: occurrence.DefaultRetention,
		NewOccurrenceID: m.newID,
	}
	switch format {
	case "sing-box":
		processor, err := ingest.NewProcessor(m.registry, fingerprinter, singbox.DefaultLimits())
		if err != nil {
			return processedSnapshot{}, err
		}
		snapshot, err := processor.Process(content, existing, options)
		if err != nil {
			return processedSnapshot{}, err
		}
		excluded, err := m.healthExclusions(ctx, config, singBoxOccurrenceIDs(snapshot.Nodes))
		if err != nil {
			return processedSnapshot{}, err
		}
		candidates := make([]proxybuild.Candidate, len(snapshot.Nodes))
		for index, node := range snapshot.Nodes {
			candidates[index] = proxybuild.Candidate{
				OccurrenceID: node.OccurrenceID, StableKey: node.NamingKey,
				Node: node.Raw, CandidateOrdinal: node.Raw.Ordinal,
				Excluded: excluded[node.OccurrenceID],
			}
		}
		reservedNames := make([]string, 0, len(snapshot.Document.NonNodes))
		for _, node := range snapshot.Document.NonNodes {
			if node.DisplayName != "" {
				reservedNames = append(reservedNames, node.DisplayName)
			}
		}
		built, err := proxybuild.Outbounds(candidates, proxybuild.Options{
			Now: options.Now, NameRetention: occurrence.DefaultRetention, ReservedNames: reservedNames,
		})
		if err != nil {
			return processedSnapshot{}, err
		}
		artifact := built.Artifact
		if len(built.Changes) == 0 && len(excluded) == 0 {
			artifact = append([]byte(nil), content...)
		} else {
			artifact, err = proxybuild.RenderSingBoxDocument(snapshot.Document, built.AllocationSnapshot)
			if err != nil {
				return processedSnapshot{}, err
			}
		}
		return processedSnapshot{
			detectedFormat: "sing-box", adapterVersion: singbox.AdapterVersion,
			outputFormat:   "sing-box",
			builderVersion: proxybuild.BuilderVersion, contentType: "application/json",
			nodeCount: len(snapshot.Nodes), includedCount: len(snapshot.Nodes) - len(excluded),
			logicalCount: len(snapshot.Document.NonNodes),
			warningCount: len(snapshot.Document.Issues), artifact: artifact,
			occurrences: snapshot.Occurrences,
			persist: func(ctx context.Context, blobs *blobstore.Store) ([]sourcestore.AcceptedNode, error) {
				return persistSingBoxNodes(ctx, blobs, snapshot)
			},
		}, nil
	case "uri-list":
		processor, err := ingest.NewURIProcessor(m.registry, fingerprinter, urilist.DefaultLimits())
		if err != nil {
			return processedSnapshot{}, err
		}
		snapshot, err := processor.Process(content, existing, options)
		if err != nil {
			return processedSnapshot{}, err
		}
		excluded, err := m.healthExclusions(ctx, config, uriOccurrenceIDs(snapshot.Nodes))
		if err != nil {
			return processedSnapshot{}, err
		}
		candidates := make([]proxybuild.URICandidate, len(snapshot.Nodes))
		for index, node := range snapshot.Nodes {
			candidates[index] = proxybuild.URICandidate{
				OccurrenceID: node.OccurrenceID, StableKey: node.NamingKey,
				Node: node.Raw, CandidateOrdinal: node.Raw.Ordinal,
				Excluded: excluded[node.OccurrenceID],
			}
		}
		built, err := proxybuild.URIList(candidates, proxybuild.URIOptions{
			Now: options.Now, NameRetention: occurrence.DefaultRetention,
		})
		if err != nil {
			return processedSnapshot{}, err
		}
		artifact := built.Artifact
		if !built.Changed {
			artifact = append([]byte(nil), content...)
		} else {
			switch snapshot.Document.Encoding {
			case urilist.EncodingBase64Standard:
				artifact = []byte(base64.StdEncoding.EncodeToString(artifact) + "\n")
			case urilist.EncodingBase64URL:
				artifact = []byte(base64.RawURLEncoding.EncodeToString(artifact) + "\n")
			}
		}
		contentType := "text/plain; charset=utf-8"
		builderVersion := proxybuild.URIBuilderVersion
		outputFormat := "uri-list"
		if config.OutputFormat == "sing-box" {
			artifact, err = convert.URIToSingBox(filterURINodes(snapshot.Document.Nodes, snapshot.Nodes, excluded), built.Names)
			if err != nil {
				return processedSnapshot{}, err
			}
			contentType = "application/json"
			builderVersion = convert.SingBoxRendererVersion
			outputFormat = "sing-box"
		}
		warnings := 0
		for _, node := range snapshot.Nodes {
			warnings += len(node.Raw.Warnings)
		}
		return processedSnapshot{
			detectedFormat: "uri-list", adapterVersion: urilist.AdapterVersion,
			outputFormat: outputFormat, builderVersion: builderVersion, contentType: contentType,
			nodeCount: len(snapshot.Nodes), includedCount: len(snapshot.Nodes) - len(excluded),
			warningCount: warnings, artifact: artifact,
			occurrences: snapshot.Occurrences,
			persist: func(ctx context.Context, blobs *blobstore.Store) ([]sourcestore.AcceptedNode, error) {
				return persistURINodes(ctx, blobs, snapshot, built.Names)
			},
		}, nil
	case "mihomo":
		processor, err := ingest.NewMihomoProcessor(m.registry, fingerprinter, mihomo.DefaultLimits())
		if err != nil {
			return processedSnapshot{}, err
		}
		snapshot, err := processor.Process(content, existing, options)
		if err != nil {
			return processedSnapshot{}, err
		}
		excluded, err := m.healthExclusions(ctx, config, mihomoOccurrenceIDs(snapshot.Nodes))
		if err != nil {
			return processedSnapshot{}, err
		}
		candidates := make([]proxybuild.MihomoCandidate, len(snapshot.Nodes))
		for index, node := range snapshot.Nodes {
			candidates[index] = proxybuild.MihomoCandidate{
				OccurrenceID: node.OccurrenceID, StableKey: node.NamingKey,
				Node: node.Raw, CandidateOrdinal: node.Raw.Ordinal,
				Excluded: excluded[node.OccurrenceID],
			}
		}
		built, err := proxybuild.Mihomo(candidates, snapshot.Document, proxybuild.MihomoOptions{
			Now: options.Now, NameRetention: occurrence.DefaultRetention,
		})
		if err != nil {
			return processedSnapshot{}, err
		}
		artifact := built.Artifact
		contentType := "application/yaml; charset=utf-8"
		builderVersion := proxybuild.MihomoBuilderVersion
		outputFormat := "mihomo"
		if config.OutputFormat == "sing-box" {
			artifact, err = convert.MihomoToSingBox(filterMihomoNodes(snapshot.Document.Nodes, snapshot.Nodes, excluded), built.Names)
			if err != nil {
				return processedSnapshot{}, err
			}
			contentType = "application/json"
			builderVersion = convert.SingBoxRendererVersion
			outputFormat = "sing-box"
		}
		warnings := 0
		for _, node := range snapshot.Nodes {
			warnings += len(node.Raw.Warnings)
		}
		return processedSnapshot{
			detectedFormat: "mihomo", adapterVersion: mihomo.AdapterVersion,
			outputFormat: outputFormat, builderVersion: builderVersion, contentType: contentType,
			nodeCount: len(snapshot.Nodes), includedCount: len(snapshot.Nodes) - len(excluded),
			logicalCount: len(snapshot.Document.NonNodes),
			warningCount: warnings, artifact: artifact,
			occurrences: snapshot.Occurrences,
			persist: func(ctx context.Context, blobs *blobstore.Store) ([]sourcestore.AcceptedNode, error) {
				return persistMihomoNodes(ctx, blobs, snapshot, built.Names)
			},
		}, nil
	case "client-text":
		processor, err := ingest.NewClientTextProcessor(m.registry, fingerprinter, clienttext.DefaultLimits())
		if err != nil {
			return processedSnapshot{}, err
		}
		snapshot, err := processor.Process(content, existing, options)
		if err != nil {
			return processedSnapshot{}, err
		}
		excluded, err := m.healthExclusions(ctx, config, clientOccurrenceIDs(snapshot.Nodes))
		if err != nil {
			return processedSnapshot{}, err
		}
		candidates := make([]proxybuild.ClientTextCandidate, len(snapshot.Nodes))
		for index, node := range snapshot.Nodes {
			candidates[index] = proxybuild.ClientTextCandidate{
				OccurrenceID: node.OccurrenceID, StableKey: node.NamingKey,
				Node: node.Raw, CandidateOrdinal: node.Raw.Ordinal,
				Excluded: excluded[node.OccurrenceID],
			}
		}
		built, err := proxybuild.ClientText(candidates, snapshot.Document, proxybuild.ClientTextOptions{
			Now: options.Now, NameRetention: occurrence.DefaultRetention,
		})
		if err != nil {
			return processedSnapshot{}, err
		}
		artifact := built.Artifact
		contentType := "text/plain; charset=utf-8"
		builderVersion := proxybuild.ClientTextBuilderVersion
		outputFormat := "client-text"
		if config.OutputFormat == "sing-box" {
			artifact, err = convert.ClientTextToSingBox(filterClientNodes(snapshot.Document.Nodes, snapshot.Nodes, excluded), built.Names)
			if err != nil {
				return processedSnapshot{}, err
			}
			contentType = "application/json"
			builderVersion = convert.SingBoxRendererVersion
			outputFormat = "sing-box"
		}
		warnings := 0
		for _, node := range snapshot.Nodes {
			warnings += len(node.Raw.Warnings)
		}
		return processedSnapshot{
			detectedFormat: "client-text", adapterVersion: clienttext.AdapterVersion,
			outputFormat: outputFormat, builderVersion: builderVersion, contentType: contentType,
			nodeCount: len(snapshot.Nodes), includedCount: len(snapshot.Nodes) - len(excluded),
			warningCount: warnings, artifact: artifact,
			occurrences: snapshot.Occurrences,
			persist: func(ctx context.Context, blobs *blobstore.Store) ([]sourcestore.AcceptedNode, error) {
				return persistClientTextNodes(ctx, blobs, snapshot, built.Names)
			},
		}, nil
	default:
		return processedSnapshot{}, fmt.Errorf("unsupported input format %q", format)
	}
}

func persistSingBoxNodes(ctx context.Context, blobs *blobstore.Store, snapshot *ingest.Snapshot) ([]sourcestore.AcceptedNode, error) {
	result := make([]sourcestore.AcceptedNode, len(snapshot.Nodes))
	for index, node := range snapshot.Nodes {
		raw, err := jsonlossless.MarshalCompact(node.Raw.Raw)
		if err != nil {
			return nil, err
		}
		rawBlob, err := blobs.Put(ctx, blobstore.PutRequest{Kind: "raw_node", Plaintext: raw})
		if err != nil {
			return nil, err
		}
		nameBlobID := ""
		if node.Raw.DisplayName != "" {
			nameBlob, err := blobs.Put(ctx, blobstore.PutRequest{Kind: "node_name", Plaintext: []byte(node.Raw.DisplayName)})
			if err != nil {
				return nil, err
			}
			nameBlobID = nameBlob.ID
		}
		canonical, err := json.Marshal(node.Raw.Canonical)
		if err != nil {
			return nil, err
		}
		canonicalBlob, err := blobs.Put(ctx, blobstore.PutRequest{Kind: "canonical_node", Plaintext: canonical})
		if err != nil {
			return nil, err
		}
		result[index] = sourcestore.AcceptedNode{
			Ordinal: index, ExtractionPath: node.Raw.ExtractionPath, RawKind: "json_object",
			FormatID: node.Raw.FormatID, FormatAdapterVersion: node.Raw.AdapterVersion,
			ProtocolID: node.Raw.ProtocolID, ParseStatus: string(node.Raw.ParseStatus),
			WarningCount: len(node.Raw.Canonical.Issues), RawBlobID: rawBlob.ID,
			OriginalNameBlobID: nameBlobID, Fingerprint: node.Fingerprint,
			OccurrenceID: node.OccurrenceID, MatchMethod: node.MatchMethod,
			CanonicalBlobID: canonicalBlob.ID, CanonicalVersion: node.Raw.Canonical.AdapterVersion,
			CanonicalCompleteness: string(node.Raw.Canonical.Completeness), CanonicalFeatureFlags: "[]",
		}
	}
	return result, nil
}

func persistURINodes(ctx context.Context, blobs *blobstore.Store, snapshot *ingest.URISnapshot, names map[int]string) ([]sourcestore.AcceptedNode, error) {
	result := make([]sourcestore.AcceptedNode, len(snapshot.Nodes))
	for index, node := range snapshot.Nodes {
		rawBlob, err := blobs.Put(ctx, blobstore.PutRequest{Kind: "raw_node", Plaintext: node.Raw.Raw})
		if err != nil {
			return nil, err
		}
		nameBlobID := ""
		if node.Raw.DisplayName != "" {
			nameBlob, err := blobs.Put(ctx, blobstore.PutRequest{Kind: "node_name", Plaintext: []byte(node.Raw.DisplayName)})
			if err != nil {
				return nil, err
			}
			nameBlobID = nameBlob.ID
		}
		result[index] = sourcestore.AcceptedNode{
			Ordinal: node.Raw.Ordinal, ExtractionPath: node.Raw.ExtractionPath, RawKind: "uri",
			FormatID: urilist.FormatID, FormatAdapterVersion: urilist.AdapterVersion,
			ProtocolID: node.Raw.ProtocolID, ParseStatus: "opaque", WarningCount: len(node.Raw.Warnings),
			RawBlobID: rawBlob.ID, OriginalNameBlobID: nameBlobID,
			Fingerprint: node.Fingerprint, OccurrenceID: node.OccurrenceID, MatchMethod: node.MatchMethod,
		}
		if outbounds, convertErr := convert.URIOutbounds([]urilist.RawNode{node.Raw}, map[int]string{node.Raw.Ordinal: names[node.Raw.Ordinal]}); convertErr == nil {
			if err := persistConvertedCanonical(ctx, blobs, &result[index], outbounds); err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}

func persistMihomoNodes(ctx context.Context, blobs *blobstore.Store, snapshot *ingest.MihomoSnapshot, names map[int]string) ([]sourcestore.AcceptedNode, error) {
	result := make([]sourcestore.AcceptedNode, len(snapshot.Nodes))
	for index, node := range snapshot.Nodes {
		rawBlob, err := blobs.Put(ctx, blobstore.PutRequest{Kind: "raw_node", Plaintext: node.Raw.RawBytes})
		if err != nil {
			return nil, err
		}
		nameBlob, err := blobs.Put(ctx, blobstore.PutRequest{Kind: "node_name", Plaintext: []byte(node.Raw.DisplayName)})
		if err != nil {
			return nil, err
		}
		result[index] = sourcestore.AcceptedNode{
			Ordinal: node.Raw.Ordinal, ExtractionPath: node.Raw.ExtractionPath, RawKind: "text",
			FormatID: mihomo.FormatID, FormatAdapterVersion: mihomo.AdapterVersion,
			ProtocolID: node.Raw.ProtocolID, ParseStatus: "opaque", WarningCount: len(node.Raw.Warnings),
			RawBlobID: rawBlob.ID, OriginalNameBlobID: nameBlob.ID,
			Fingerprint: node.Fingerprint, OccurrenceID: node.OccurrenceID, MatchMethod: node.MatchMethod,
		}
		if outbounds, convertErr := convert.MihomoOutbounds([]mihomo.RawNode{node.Raw}, map[int]string{node.Raw.Ordinal: names[node.Raw.Ordinal]}); convertErr == nil {
			if err := persistConvertedCanonical(ctx, blobs, &result[index], outbounds); err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}

func persistClientTextNodes(ctx context.Context, blobs *blobstore.Store, snapshot *ingest.ClientTextSnapshot, names map[int]string) ([]sourcestore.AcceptedNode, error) {
	result := make([]sourcestore.AcceptedNode, len(snapshot.Nodes))
	for index, node := range snapshot.Nodes {
		rawBlob, err := blobs.Put(ctx, blobstore.PutRequest{Kind: "raw_node", Plaintext: node.Raw.Raw})
		if err != nil {
			return nil, err
		}
		nameBlob, err := blobs.Put(ctx, blobstore.PutRequest{Kind: "node_name", Plaintext: []byte(node.Raw.DisplayName)})
		if err != nil {
			return nil, err
		}
		result[index] = sourcestore.AcceptedNode{
			Ordinal: node.Raw.Ordinal, ExtractionPath: node.Raw.ExtractionPath, RawKind: "text",
			FormatID: clienttext.FormatID, FormatAdapterVersion: clienttext.AdapterVersion,
			ProtocolID: node.Raw.ProtocolID, ParseStatus: "opaque", WarningCount: len(node.Raw.Warnings),
			RawBlobID: rawBlob.ID, OriginalNameBlobID: nameBlob.ID,
			Fingerprint: node.Fingerprint, OccurrenceID: node.OccurrenceID, MatchMethod: node.MatchMethod,
		}
		if outbounds, convertErr := convert.ClientTextOutbounds([]clienttext.RawNode{node.Raw}, map[int]string{node.Raw.Ordinal: names[node.Raw.Ordinal]}); convertErr == nil {
			if err := persistConvertedCanonical(ctx, blobs, &result[index], outbounds); err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}

func persistConvertedCanonical(ctx context.Context, blobs *blobstore.Store, node *sourcestore.AcceptedNode, outbounds []convert.Outbound) error {
	canonical, err := json.Marshal(outbounds)
	if err != nil {
		return fmt.Errorf("encode converted canonical node: %w", err)
	}
	canonicalBlob, err := blobs.Put(ctx, blobstore.PutRequest{Kind: "canonical_node", Plaintext: canonical})
	if err != nil {
		return err
	}
	node.ParseStatus = "complete"
	node.CanonicalBlobID = canonicalBlob.ID
	node.CanonicalVersion = convert.SingBoxRendererVersion
	node.CanonicalCompleteness = "complete"
	node.CanonicalFeatureFlags = "[]"
	return nil
}

func (m *Manager) healthExclusions(ctx context.Context, config SourceConfig, occurrenceIDs []string) (map[string]bool, error) {
	excluded := make(map[string]bool)
	if !config.HealthFilterEnabled || m.healthReader == nil || len(occurrenceIDs) == 0 {
		return excluded, nil
	}
	suppressed, _, err := m.healthReader.GuardSuppressed(ctx)
	if err != nil {
		return nil, fmt.Errorf("read health failure guard: %w", err)
	}
	if suppressed {
		return excluded, nil
	}
	states, err := m.healthReader.States(ctx, occurrenceIDs)
	if err != nil {
		return nil, fmt.Errorf("read node health states: %w", err)
	}
	now := m.now().UTC()
	for occurrenceID, state := range states {
		if now.Sub(state.UpdatedAt) >= healthstore.DefaultStaleAfter {
			continue
		}
		if state.State == healthstore.StateUnhealthy || state.RecoveryStep == 1 {
			excluded[occurrenceID] = true
		}
	}
	return excluded, nil
}

func singBoxOccurrenceIDs(nodes []ingest.Node) []string {
	result := make([]string, len(nodes))
	for index, node := range nodes {
		result[index] = node.OccurrenceID
	}
	return result
}

func uriOccurrenceIDs(nodes []ingest.URINode) []string {
	result := make([]string, len(nodes))
	for index, node := range nodes {
		result[index] = node.OccurrenceID
	}
	return result
}

func mihomoOccurrenceIDs(nodes []ingest.MihomoNode) []string {
	result := make([]string, len(nodes))
	for index, node := range nodes {
		result[index] = node.OccurrenceID
	}
	return result
}

func clientOccurrenceIDs(nodes []ingest.ClientTextNode) []string {
	result := make([]string, len(nodes))
	for index, node := range nodes {
		result[index] = node.OccurrenceID
	}
	return result
}

func filterURINodes(raw []urilist.RawNode, processed []ingest.URINode, excluded map[string]bool) []urilist.RawNode {
	result := make([]urilist.RawNode, 0, len(raw))
	for index, node := range raw {
		if index < len(processed) && !excluded[processed[index].OccurrenceID] {
			result = append(result, node)
		}
	}
	return result
}

func filterMihomoNodes(raw []mihomo.RawNode, processed []ingest.MihomoNode, excluded map[string]bool) []mihomo.RawNode {
	result := make([]mihomo.RawNode, 0, len(raw))
	for index, node := range raw {
		if index < len(processed) && !excluded[processed[index].OccurrenceID] {
			result = append(result, node)
		}
	}
	return result
}

func filterClientNodes(raw []clienttext.RawNode, processed []ingest.ClientTextNode, excluded map[string]bool) []clienttext.RawNode {
	result := make([]clienttext.RawNode, 0, len(raw))
	for index, node := range raw {
		if index < len(processed) && !excluded[processed[index].OccurrenceID] {
			result = append(result, node)
		}
	}
	return result
}

func (m *Manager) loadOccurrences(ctx context.Context, sourceID string) ([]occurrence.Occurrence, error) {
	stored, err := m.sources.ListOccurrences(ctx, sourceID)
	if err != nil {
		return nil, err
	}
	result := make([]occurrence.Occurrence, len(stored))
	for index, item := range stored {
		result[index] = item.Occurrence
		if item.NameBlobID == "" {
			continue
		}
		name, record, err := m.blobs.Get(ctx, item.NameBlobID)
		if err != nil {
			return nil, err
		}
		if record.Kind != "node_name" || !utf8.Valid(name) {
			return nil, fmt.Errorf("occurrence %s has invalid name data", item.Occurrence.ID)
		}
		result[index].OriginalName = string(name)
	}
	return result, nil
}

func (m *Manager) loadConfig(ctx context.Context, revision sourcestore.Revision) (SourceConfig, error) {
	content, record, err := m.blobs.Get(ctx, revision.Config.ConfigBlobID)
	if err != nil {
		return SourceConfig{}, err
	}
	if record.Kind != "source_config" {
		return SourceConfig{}, fmt.Errorf("source revision references a non-config blob")
	}
	var config SourceConfig
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return SourceConfig{}, fmt.Errorf("decode source config: %w", err)
	}
	config = normalizeConfig(config)
	if err := validateConfig(config); err != nil {
		return SourceConfig{}, err
	}
	if config.Type != revision.Config.SourceType || config.PrivateNetworkAuthorized != revision.Config.PrivateNetworkAuthorized {
		return SourceConfig{}, fmt.Errorf("source config differs from immutable revision metadata")
	}
	return config, nil
}

func (m *Manager) obtainContent(ctx context.Context, config SourceConfig) ([]byte, string, int, error) {
	if config.Type == sourcestore.SourceInline {
		return []byte(config.InlineContent), "text/plain", 0, nil
	}
	result, err := fetcher.Fetch(ctx, config.URL, fetcher.Options{
		Timeout: time.Duration(config.TimeoutSeconds) * time.Second, MaxBytes: config.MaxResponseBytes,
		PrivateNetworkAuthorized: config.PrivateNetworkAuthorized, Headers: config.RequestHeaders,
		ProxyURL: config.ProxyURL,
	})
	if err != nil {
		return nil, "", result.StatusCode, err
	}
	return result.Content, result.ContentType, result.StatusCode, nil
}

func (m *Manager) failAttempt(ctx context.Context, attemptID, code string, cause error, metrics sourcestore.AttemptMetrics) error {
	_, completeErr := m.sources.CompleteFailure(ctx, sourcestore.FailureRequest{
		AttemptID: attemptID, Status: sourcestore.AttemptFailed,
		Metrics: metrics, ErrorCode: code, ErrorDetail: boundedDetail(cause),
	})
	if completeErr != nil {
		return operationError(code, fmt.Errorf("%v; record failure: %w", cause, completeErr))
	}
	return operationError(code, cause)
}

func (m *Manager) rejectAttempt(ctx context.Context, attemptID, code string, cause error, nodeCount *int, metrics sourcestore.AttemptMetrics) error {
	_, completeErr := m.sources.CompleteFailure(ctx, sourcestore.FailureRequest{
		AttemptID: attemptID, Status: sourcestore.AttemptRejected, Metrics: metrics,
		NodeCount: nodeCount, ErrorCode: code, ErrorDetail: boundedDetail(cause),
	})
	if completeErr != nil {
		return operationError(code, fmt.Errorf("%v; record rejection: %w", cause, completeErr))
	}
	return operationError(code, cause)
}

func normalizeConfig(config SourceConfig) SourceConfig {
	if config.InputFormat == "" {
		config.InputFormat = "auto"
	}
	if config.OutputFormat == "" {
		config.OutputFormat = "same"
	}
	if config.MinimumNodes == 0 {
		config.MinimumNodes = 1
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = fetcher.DefaultMaxBytes
	}
	if config.Type == sourcestore.SourceRemote && config.TimeoutSeconds == 0 {
		config.TimeoutSeconds = int(fetcher.DefaultTimeout / time.Second)
	}
	return config
}

func validateConfig(config SourceConfig) error {
	if config.Type != sourcestore.SourceInline && config.Type != sourcestore.SourceRemote {
		return fmt.Errorf("source type must be inline or remote")
	}
	if config.Type == sourcestore.SourceInline && (config.InlineContent == "" || len(config.InlineContent) > fetcher.HardMaxBytes || config.URL != "" || len(config.RequestHeaders) != 0 || config.ProxyURL != "" || config.TimeoutSeconds != 0) {
		return fmt.Errorf("inline source requires bounded content and no remote request settings")
	}
	if config.Type == sourcestore.SourceRemote && (config.URL == "" || config.InlineContent != "") {
		return fmt.Errorf("remote source requires a URL and no inline content")
	}
	if err := fetcher.ValidateHeaders(config.RequestHeaders); err != nil {
		return err
	}
	if err := fetcher.ValidateProxyURL(config.ProxyURL); err != nil {
		return err
	}
	if config.Type == sourcestore.SourceRemote && (config.TimeoutSeconds < 1 || config.TimeoutSeconds > 120) {
		return fmt.Errorf("remote source timeout must be between 1 and 120 seconds")
	}
	if config.InputFormat != "auto" && config.InputFormat != "sing-box" && config.InputFormat != "uri-list" && config.InputFormat != "mihomo" && config.InputFormat != "client-text" {
		return fmt.Errorf("input format must be auto, sing-box, uri-list, mihomo or client-text")
	}
	if config.OutputFormat != "same" && config.OutputFormat != "sing-box" {
		return fmt.Errorf("output format must be same or sing-box")
	}
	if config.MinimumNodes < 1 || config.MinimumNodes > 100000 || config.MaximumDropRatio < 0 || config.MaximumDropRatio > 1 {
		return fmt.Errorf("invalid source content gates")
	}
	if config.RefreshIntervalSeconds != 0 && (config.RefreshIntervalSeconds < 60 || config.RefreshIntervalSeconds > 30*24*60*60) {
		return fmt.Errorf("refresh interval must be zero or between 60 seconds and 30 days")
	}
	if config.MaxResponseBytes < 1024 || config.MaxResponseBytes > fetcher.HardMaxBytes {
		return fmt.Errorf("maximum response bytes must be between 1 KiB and 50 MiB")
	}
	return nil
}

func checkContentGates(current, previous int, config SourceConfig) error {
	if current < config.MinimumNodes {
		return fmt.Errorf("source produced %d nodes, below minimum %d", current, config.MinimumNodes)
	}
	if previous > 0 && current < previous {
		drop := float64(previous-current) / float64(previous)
		if drop > config.MaximumDropRatio {
			return fmt.Errorf("source node count dropped %.2f%%, above %.2f%% limit", drop*100, config.MaximumDropRatio*100)
		}
	}
	return nil
}

func metricsSince(started time.Time, responseBytes, status int) sourcestore.AttemptMetrics {
	total := int(time.Since(started).Milliseconds())
	if total < 0 {
		total = 0
	}
	bytesValue := responseBytes
	metrics := sourcestore.AttemptMetrics{TotalMS: &total, ResponseBytes: &bytesValue}
	if status > 0 {
		statusValue := status
		metrics.HTTPStatus = &statusValue
	}
	return metrics
}

func staleDuration(intervalSeconds int) time.Duration {
	if intervalSeconds <= 0 {
		return 72 * time.Hour
	}
	duration := 3 * time.Duration(intervalSeconds) * time.Second
	if duration < time.Hour {
		return time.Hour
	}
	return duration
}

func refreshSchedule(intervalSeconds int) string {
	if intervalSeconds <= 0 {
		return ""
	}
	return fmt.Sprintf("every:%ds", intervalSeconds)
}

func boundedDetail(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	if len(value) > 1000 {
		value = value[:1000]
	}
	return value
}

func operationError(code string, err error) error {
	return &OperationError{Code: code, Err: err}
}
