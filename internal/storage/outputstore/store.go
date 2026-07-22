package outputstore

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/doujialong/proxyloom/internal/crypto/keyring"
	"github.com/doujialong/proxyloom/internal/storage/blobstore"
)

var (
	ErrNotFound     = errors.New("managed output resource not found")
	ErrConflict     = errors.New("managed output resource conflict")
	ErrUnauthorized = errors.New("invalid managed output publication token")
)

type Options struct {
	Now    func() time.Time
	NewID  func() string
	Random io.Reader
}

type Store struct {
	database *sql.DB
	keys     *keyring.Ring
	blobs    *blobstore.Store
	now      func() time.Time
	newID    func() string
	random   io.Reader
}

type Member struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

type CollectionConfig struct {
	Members []Member `json:"members"`
}

type Operation struct {
	Type          string                 `json:"type"`
	SchemaVersion int                    `json:"schema_version"`
	Config        map[string]interface{} `json:"config"`
}

type PipelineConfig struct {
	Operations []Operation `json:"operations"`
}

type RemoteTemplateConfig struct {
	SourceType               string            `json:"source_type"`
	TargetFormat             string            `json:"target_format"`
	URL                      string            `json:"url"`
	Headers                  map[string]string `json:"headers,omitempty"`
	PrivateNetworkAuthorized bool              `json:"private_network_authorized,omitempty"`
	RefreshIntervalSeconds   int               `json:"refresh_interval_seconds"`
	Content                  json.RawMessage   `json:"content"`
	ContentSHA256            string            `json:"content_sha256"`
	FetchedAt                time.Time         `json:"fetched_at"`
}

type Resource struct {
	ID             string
	Type           string
	DisplayName    string
	ConfigBlobID   string
	RevisionNumber int
	LifecycleState string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type OutputCreate struct {
	DisplayName         string
	CollectionID        string
	PipelineID          string
	TemplateID          string
	TargetProfile       string
	OutputShape         string
	HealthFilterEnabled bool
	MinimumNodes        int
	MaximumDropRatio    *float64
}

type OutputPolicyUpdate struct {
	HealthFilterEnabled bool
	MinimumNodes        int
	MaximumDropRatio    float64
}

const (
	TargetSingBox11225 = "sing-box-1.12.25"
	TargetMomo121      = "momo-1.2.1-sing-box-1.12.25"
	TargetSingBox11314 = "sing-box-1.13.14"
)

func SupportedTargetProfile(profile string) bool {
	switch profile {
	case TargetSingBox11225, TargetMomo121, TargetSingBox11314:
		return true
	default:
		return false
	}
}

type Output struct {
	ID                  string
	DisplayName         string
	CollectionID        string
	PipelineID          string
	TemplateID          string
	TargetProfile       string
	OutputShape         string
	HealthFilterEnabled bool
	MinimumNodes        int
	MaximumDropRatio    float64
	AllocationBlobID    string
	CurrentArtifactID   string
	NextBuildSequence   int
	LifecycleState      string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type Credential struct {
	ID       string
	OutputID string
	Token    string
}

type NodeInput struct {
	SourceID         string
	OccurrenceID     string
	SourceOrdinal    int
	FormatID         string
	ProtocolID       string
	RawBlobID        string
	NameBlobID       string
	CanonicalBlobID  string
	CanonicalVersion string
	HealthState      string
	HealthStale      bool
	RecoveryStep     int
}

type PublishRequest struct {
	OutputID         string
	ContentBlobID    string
	ManifestBlobID   string
	AllocationBlobID string
	ContentType      string
	NodeCount        int
	ExcludedCount    int
	WarningCount     int
	TargetProfile    string
	ValidatorVersion string
}

type Artifact struct {
	ID               string
	OutputID         string
	BuildSequence    int
	ContentBlobID    string
	ManifestBlobID   string
	ContentType      string
	ContentLength    int
	PublicSHA256     string
	NodeCount        int
	ExcludedCount    int
	WarningCount     int
	TargetProfile    string
	ValidatorVersion string
	CreatedAt        time.Time
}

func New(database *sql.DB, keys *keyring.Ring, blobs *blobstore.Store, options Options) (*Store, error) {
	if database == nil || keys == nil || blobs == nil || options.Now == nil || options.NewID == nil || options.Random == nil {
		return nil, fmt.Errorf("managed output store dependencies are required")
	}
	return &Store{database: database, keys: keys, blobs: blobs, now: options.Now, newID: options.NewID, random: options.Random}, nil
}

func (s *Store) CreateCollection(ctx context.Context, displayName string, config CollectionConfig) (Resource, error) {
	if err := s.validateCollection(ctx, config); err != nil {
		return Resource{}, err
	}
	return s.createJSONResource(ctx, "collection", displayName, "collection_config", config)
}

func (s *Store) validateCollection(ctx context.Context, config CollectionConfig) error {
	if len(config.Members) == 0 || len(config.Members) > 1000 {
		return fmt.Errorf("collection requires 1 to 1000 members")
	}
	seen := make(map[string]struct{}, len(config.Members))
	for index := range config.Members {
		member := &config.Members[index]
		if member.Kind != "source" && member.Kind != "node_occurrence" || !validID(member.ID) {
			return fmt.Errorf("invalid collection member at index %d", index)
		}
		identity := member.Kind + "/" + member.ID
		if _, duplicate := seen[identity]; duplicate {
			return fmt.Errorf("duplicate collection member at index %d", index)
		}
		seen[identity] = struct{}{}
		table := "sources"
		if member.Kind == "node_occurrence" {
			table = "node_occurrences"
		}
		var exists int
		if err := s.database.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE id = ?", member.ID).Scan(&exists); err != nil || exists != 1 {
			return ErrNotFound
		}
	}
	return nil
}

func (s *Store) UpdateCollection(ctx context.Context, id, displayName string, expectedRevision int, config CollectionConfig) (Resource, error) {
	if !validID(id) || expectedRevision < 1 || !validDisplayName(displayName) {
		return Resource{}, fmt.Errorf("invalid collection update")
	}
	current, err := s.Resource(ctx, id, "collection")
	if err != nil {
		return Resource{}, err
	}
	if current.LifecycleState != "active" || current.RevisionNumber != expectedRevision {
		return Resource{}, ErrConflict
	}
	if err := s.validateCollection(ctx, config); err != nil {
		return Resource{}, err
	}
	content, err := json.Marshal(config)
	if err != nil {
		return Resource{}, fmt.Errorf("encode collection config: %w", err)
	}
	blob, err := s.blobs.Put(ctx, blobstore.PutRequest{Kind: "collection_config", Plaintext: content})
	if err != nil {
		return Resource{}, err
	}
	keepBlob := false
	defer func() {
		if !keepBlob {
			_, _ = s.blobs.DeleteUnreferenced(context.Background(), blob.ID)
		}
	}()
	now := s.now().UTC()
	result, err := s.database.ExecContext(ctx, `
UPDATE managed_resources
SET display_name = ?, config_blob_id = ?, revision_number = revision_number + 1, updated_at = ?
WHERE id = ? AND resource_type = 'collection' AND lifecycle_state = 'active' AND revision_number = ?`,
		displayName, blob.ID, now.UnixMilli(), id, expectedRevision)
	if err != nil {
		return Resource{}, fmt.Errorf("update managed collection: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return Resource{}, ErrConflict
	}
	keepBlob = true
	updated, err := s.Resource(ctx, id, "collection")
	if err == nil {
		_, _ = s.blobs.DeleteUnreferenced(context.Background(), current.ConfigBlobID)
	}
	return updated, err
}

func (s *Store) CreatePipeline(ctx context.Context, displayName string, config PipelineConfig) (Resource, error) {
	if err := validatePipelineConfig(config); err != nil {
		return Resource{}, err
	}
	return s.createJSONResource(ctx, "pipeline", displayName, "pipeline_config", config)
}

func validatePipelineConfig(config PipelineConfig) error {
	if len(config.Operations) > 100 {
		return fmt.Errorf("pipeline cannot contain more than 100 operations")
	}
	for index, operation := range config.Operations {
		if operation.SchemaVersion != 1 || operation.Type != "filter" && operation.Type != "rename" && operation.Type != "sort" {
			return fmt.Errorf("unsupported pipeline operation at index %d", index)
		}
	}
	return nil
}

func (s *Store) UpdatePipeline(ctx context.Context, id, displayName string, expectedRevision int, config PipelineConfig) (Resource, error) {
	if !validID(id) || expectedRevision < 1 || !validDisplayName(displayName) {
		return Resource{}, fmt.Errorf("invalid pipeline update")
	}
	if err := validatePipelineConfig(config); err != nil {
		return Resource{}, err
	}
	current, err := s.Resource(ctx, id, "pipeline")
	if err != nil {
		return Resource{}, err
	}
	if current.LifecycleState != "active" || current.RevisionNumber != expectedRevision {
		return Resource{}, ErrConflict
	}
	content, err := json.Marshal(config)
	if err != nil {
		return Resource{}, fmt.Errorf("encode pipeline config: %w", err)
	}
	blob, err := s.blobs.Put(ctx, blobstore.PutRequest{Kind: "pipeline_config", Plaintext: content})
	if err != nil {
		return Resource{}, err
	}
	keepBlob := false
	defer func() {
		if !keepBlob {
			_, _ = s.blobs.DeleteUnreferenced(context.Background(), blob.ID)
		}
	}()
	now := s.now().UTC()
	result, err := s.database.ExecContext(ctx, `
UPDATE managed_resources
SET display_name = ?, config_blob_id = ?, revision_number = revision_number + 1, updated_at = ?
WHERE id = ? AND resource_type = 'pipeline' AND lifecycle_state = 'active' AND revision_number = ?`,
		displayName, blob.ID, now.UnixMilli(), id, expectedRevision)
	if err != nil {
		return Resource{}, fmt.Errorf("update managed pipeline: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return Resource{}, ErrConflict
	}
	keepBlob = true
	updated, err := s.Resource(ctx, id, "pipeline")
	if err == nil {
		_, _ = s.blobs.DeleteUnreferenced(context.Background(), current.ConfigBlobID)
	}
	return updated, err
}

func (s *Store) CreateTemplate(ctx context.Context, displayName string, content []byte) (Resource, error) {
	if len(content) == 0 || len(content) > 50<<20 || !utf8.Valid(content) {
		return Resource{}, fmt.Errorf("template content must be bounded UTF-8")
	}
	blob, err := s.blobs.Put(ctx, blobstore.PutRequest{Kind: "template_config", Plaintext: content})
	if err != nil {
		return Resource{}, err
	}
	resource, err := s.insertResource(ctx, "template", displayName, blob.ID)
	if err != nil {
		_, _ = s.blobs.DeleteUnreferenced(context.Background(), blob.ID)
	}
	return resource, err
}

func (s *Store) CreateRemoteTemplate(ctx context.Context, displayName string, config RemoteTemplateConfig) (Resource, error) {
	var err error
	config, err = normalizeRemoteTemplateConfig(config)
	if err != nil {
		return Resource{}, err
	}
	if err := validateRemoteTemplateConfig(config); err != nil {
		return Resource{}, err
	}
	return s.createJSONResource(ctx, "template", displayName, "template_remote_config", config)
}

func (s *Store) UpdateRemoteTemplate(ctx context.Context, id string, expectedRevision int, config RemoteTemplateConfig) (Resource, error) {
	if !validID(id) || expectedRevision < 1 {
		return Resource{}, fmt.Errorf("invalid remote template update")
	}
	var err error
	config, err = normalizeRemoteTemplateConfig(config)
	if err != nil {
		return Resource{}, err
	}
	if err := validateRemoteTemplateConfig(config); err != nil {
		return Resource{}, err
	}
	current, err := s.Resource(ctx, id, "template")
	if err != nil {
		return Resource{}, err
	}
	if current.LifecycleState != "active" || current.RevisionNumber != expectedRevision {
		return Resource{}, ErrConflict
	}
	if _, remote, err := s.RemoteTemplateConfig(ctx, current); err != nil {
		return Resource{}, err
	} else if !remote {
		return Resource{}, ErrConflict
	}
	content, err := json.Marshal(config)
	if err != nil {
		return Resource{}, fmt.Errorf("encode remote template config: %w", err)
	}
	blob, err := s.blobs.Put(ctx, blobstore.PutRequest{Kind: "template_remote_config", Plaintext: content})
	if err != nil {
		return Resource{}, err
	}
	keepBlob := false
	defer func() {
		if !keepBlob {
			_, _ = s.blobs.DeleteUnreferenced(context.Background(), blob.ID)
		}
	}()
	now := s.now().UTC()
	result, err := s.database.ExecContext(ctx, `
UPDATE managed_resources
SET config_blob_id = ?, revision_number = revision_number + 1, updated_at = ?
WHERE id = ? AND resource_type = 'template' AND lifecycle_state = 'active' AND revision_number = ?`,
		blob.ID, now.UnixMilli(), id, expectedRevision)
	if err != nil {
		return Resource{}, fmt.Errorf("update managed remote template: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return Resource{}, ErrConflict
	}
	keepBlob = true
	updated, err := s.Resource(ctx, id, "template")
	if err == nil {
		_, _ = s.blobs.DeleteUnreferenced(context.Background(), current.ConfigBlobID)
	}
	return updated, err
}

func (s *Store) createJSONResource(ctx context.Context, resourceType, displayName, blobKind string, config interface{}) (Resource, error) {
	content, err := json.Marshal(config)
	if err != nil {
		return Resource{}, fmt.Errorf("encode %s config: %w", resourceType, err)
	}
	blob, err := s.blobs.Put(ctx, blobstore.PutRequest{Kind: blobKind, Plaintext: content})
	if err != nil {
		return Resource{}, err
	}
	resource, err := s.insertResource(ctx, resourceType, displayName, blob.ID)
	if err != nil {
		_, _ = s.blobs.DeleteUnreferenced(context.Background(), blob.ID)
	}
	return resource, err
}

func (s *Store) insertResource(ctx context.Context, resourceType, displayName, blobID string) (Resource, error) {
	if !validDisplayName(displayName) {
		return Resource{}, fmt.Errorf("resource display name must contain 1 to 200 UTF-8 bytes")
	}
	id := s.newID()
	if !validID(id) {
		return Resource{}, fmt.Errorf("resource ID generator returned an invalid ID")
	}
	now := s.now().UTC()
	if _, err := s.database.ExecContext(ctx, `
INSERT INTO managed_resources(
  id, resource_type, display_name, config_blob_id, revision_number,
  lifecycle_state, created_at, updated_at
) VALUES (?, ?, ?, ?, 1, 'active', ?, ?)`, id, resourceType, displayName, blobID, now.UnixMilli(), now.UnixMilli()); err != nil {
		return Resource{}, fmt.Errorf("insert managed %s: %w", resourceType, err)
	}
	return Resource{ID: id, Type: resourceType, DisplayName: displayName, ConfigBlobID: blobID, RevisionNumber: 1, LifecycleState: "active", CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Store) Resource(ctx context.Context, id, resourceType string) (Resource, error) {
	resource, err := scanResource(s.database.QueryRowContext(ctx, `
SELECT id, resource_type, display_name, config_blob_id, revision_number,
       lifecycle_state, created_at, updated_at
FROM managed_resources WHERE id = ? AND resource_type = ?`, id, resourceType))
	if errors.Is(err, sql.ErrNoRows) {
		return Resource{}, ErrNotFound
	}
	return resource, err
}

func (s *Store) Resources(ctx context.Context, resourceType string) ([]Resource, error) {
	rows, err := s.database.QueryContext(ctx, `
SELECT id, resource_type, display_name, config_blob_id, revision_number,
       lifecycle_state, created_at, updated_at
FROM managed_resources WHERE resource_type = ? AND lifecycle_state = 'active'
ORDER BY updated_at DESC, id DESC`, resourceType)
	if err != nil {
		return nil, fmt.Errorf("list managed resources: %w", err)
	}
	defer rows.Close()
	result := make([]Resource, 0)
	for rows.Next() {
		resource, err := scanResource(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, resource)
	}
	return result, rows.Err()
}

func (s *Store) CollectionConfig(ctx context.Context, resource Resource) (CollectionConfig, error) {
	var config CollectionConfig
	if resource.Type != "collection" {
		return config, ErrConflict
	}
	return config, s.decodeResourceConfig(ctx, resource, "collection_config", &config)
}

func (s *Store) PipelineConfig(ctx context.Context, resource Resource) (PipelineConfig, error) {
	var config PipelineConfig
	if resource.Type != "pipeline" {
		return config, ErrConflict
	}
	return config, s.decodeResourceConfig(ctx, resource, "pipeline_config", &config)
}

func (s *Store) TemplateContent(ctx context.Context, resource Resource) ([]byte, error) {
	if resource.Type != "template" {
		return nil, ErrConflict
	}
	content, record, err := s.blobs.Get(ctx, resource.ConfigBlobID)
	if err != nil {
		return nil, err
	}
	if record.Kind == "template_config" {
		return content, nil
	}
	if record.Kind != "template_remote_config" {
		return nil, ErrConflict
	}
	config, err := decodeRemoteTemplateConfig(content)
	if err != nil {
		return nil, ErrConflict
	}
	return append([]byte(nil), config.Content...), nil
}

func (s *Store) RemoteTemplateConfig(ctx context.Context, resource Resource) (RemoteTemplateConfig, bool, error) {
	var config RemoteTemplateConfig
	if resource.Type != "template" {
		return config, false, ErrConflict
	}
	content, record, err := s.blobs.Get(ctx, resource.ConfigBlobID)
	if err != nil {
		return config, false, err
	}
	if record.Kind == "template_config" {
		return config, false, nil
	}
	if record.Kind != "template_remote_config" {
		return config, false, ErrConflict
	}
	config, err = decodeRemoteTemplateConfig(content)
	if err != nil {
		return config, false, ErrConflict
	}
	return config, true, nil
}

func validateRemoteTemplateConfig(config RemoteTemplateConfig) error {
	if config.SourceType != "remote" || config.TargetFormat != "sing-box" || strings.TrimSpace(config.URL) == "" || len(config.URL) > 8192 {
		return fmt.Errorf("remote template source configuration is invalid")
	}
	if config.RefreshIntervalSeconds < 60 || config.RefreshIntervalSeconds > 7*24*60*60 {
		return fmt.Errorf("remote template refresh interval must be between 60 seconds and 7 days")
	}
	if len(config.Headers) > 32 {
		return fmt.Errorf("remote template has too many request headers")
	}
	contentDigest := sha256.Sum256(config.Content)
	if len(config.Content) == 0 || len(config.Content) > 49<<20 || !json.Valid(config.Content) ||
		config.ContentSHA256 != fmt.Sprintf("%x", contentDigest) || config.FetchedAt.IsZero() {
		return fmt.Errorf("remote template content metadata is invalid")
	}
	return nil
}

func NormalizeRemoteTemplateContent(content []byte) (json.RawMessage, string, error) {
	if len(content) == 0 || len(content) > 49<<20 || !json.Valid(content) {
		return nil, "", fmt.Errorf("remote template content must be bounded JSON")
	}
	normalized, err := json.Marshal(json.RawMessage(content))
	if err != nil {
		return nil, "", fmt.Errorf("normalize remote template content: %w", err)
	}
	digest := sha256.Sum256(normalized)
	return json.RawMessage(normalized), fmt.Sprintf("%x", digest), nil
}

func normalizeRemoteTemplateConfig(config RemoteTemplateConfig) (RemoteTemplateConfig, error) {
	content, digest, err := NormalizeRemoteTemplateContent(config.Content)
	if err != nil {
		return RemoteTemplateConfig{}, err
	}
	config.Content = content
	config.ContentSHA256 = digest
	return config, nil
}

func decodeRemoteTemplateConfig(content []byte) (RemoteTemplateConfig, error) {
	var config RemoteTemplateConfig
	if err := json.Unmarshal(content, &config); err != nil {
		return RemoteTemplateConfig{}, err
	}
	config, err := normalizeRemoteTemplateConfig(config)
	if err != nil {
		return RemoteTemplateConfig{}, err
	}
	if err := validateRemoteTemplateConfig(config); err != nil {
		return RemoteTemplateConfig{}, err
	}
	return config, nil
}

func (s *Store) decodeResourceConfig(ctx context.Context, resource Resource, kind string, target interface{}) error {
	content, record, err := s.blobs.Get(ctx, resource.ConfigBlobID)
	if err != nil {
		return err
	}
	if record.Kind != kind || json.Unmarshal(content, target) != nil {
		return ErrConflict
	}
	return nil
}

func (s *Store) CreateOutput(ctx context.Context, request OutputCreate) (Output, Credential, error) {
	if !validDisplayName(request.DisplayName) || !validID(request.CollectionID) || request.PipelineID != "" && !validID(request.PipelineID) || request.TemplateID != "" && !validID(request.TemplateID) {
		return Output{}, Credential{}, fmt.Errorf("invalid managed output identity")
	}
	if !SupportedTargetProfile(request.TargetProfile) {
		return Output{}, Credential{}, fmt.Errorf("unsupported target profile")
	}
	if request.OutputShape != "outbounds_object" && request.OutputShape != "full_config" || request.OutputShape == "full_config" && request.TemplateID == "" {
		return Output{}, Credential{}, fmt.Errorf("invalid managed output shape or template")
	}
	if request.MinimumNodes == 0 {
		request.MinimumNodes = 1
	}
	maximumDropRatio := 0.5
	if request.MaximumDropRatio != nil {
		maximumDropRatio = *request.MaximumDropRatio
	}
	if request.MinimumNodes < 1 || request.MinimumNodes > 100000 || maximumDropRatio < 0 || maximumDropRatio > 1 {
		return Output{}, Credential{}, fmt.Errorf("invalid managed output content gates")
	}
	id := s.newID()
	if !validID(id) {
		return Output{}, Credential{}, fmt.Errorf("output ID generator returned an invalid ID")
	}
	now := s.now().UTC()
	_, err := s.database.ExecContext(ctx, `
INSERT INTO managed_outputs(
  id, display_name, collection_id, pipeline_id, template_id, target_profile,
  output_shape, health_filter_enabled, minimum_nodes, maximum_drop_ratio,
  lifecycle_state, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`,
		id, request.DisplayName, request.CollectionID, nullableString(request.PipelineID), nullableString(request.TemplateID),
		request.TargetProfile, request.OutputShape, boolInt(request.HealthFilterEnabled), request.MinimumNodes,
		maximumDropRatio, now.UnixMilli(), now.UnixMilli())
	if err != nil {
		return Output{}, Credential{}, fmt.Errorf("insert managed output: %w", err)
	}
	output, err := s.Output(ctx, id)
	if err != nil {
		return Output{}, Credential{}, err
	}
	credential, err := s.CreateCredential(ctx, id)
	if err != nil {
		_, _ = s.database.ExecContext(ctx, `DELETE FROM managed_outputs WHERE id = ? AND current_artifact_id IS NULL`, id)
		return Output{}, Credential{}, err
	}
	return output, credential, nil
}

func (s *Store) Output(ctx context.Context, id string) (Output, error) {
	output, err := scanOutput(s.database.QueryRowContext(ctx, outputSelect+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Output{}, ErrNotFound
	}
	return output, err
}

func (s *Store) UpdateOutputPolicy(ctx context.Context, id string, update OutputPolicyUpdate) (Output, error) {
	if !validID(id) || update.MinimumNodes < 1 || update.MinimumNodes > 100000 ||
		update.MaximumDropRatio < 0 || update.MaximumDropRatio > 1 {
		return Output{}, fmt.Errorf("invalid managed output policy")
	}
	now := s.now().UTC()
	result, err := s.database.ExecContext(ctx, `
UPDATE managed_outputs
SET health_filter_enabled = ?, minimum_nodes = ?, maximum_drop_ratio = ?, updated_at = ?
WHERE id = ? AND lifecycle_state = 'active'`, boolInt(update.HealthFilterEnabled),
		update.MinimumNodes, update.MaximumDropRatio, now.UnixMilli(), id)
	if err != nil {
		return Output{}, fmt.Errorf("update managed output policy: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil {
		return Output{}, fmt.Errorf("count managed output policy update: %w", err)
	} else if affected != 1 {
		return Output{}, ErrNotFound
	}
	return s.Output(ctx, id)
}

func (s *Store) Outputs(ctx context.Context) ([]Output, error) {
	rows, err := s.database.QueryContext(ctx, outputSelect+` WHERE lifecycle_state = 'active' ORDER BY updated_at DESC, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list managed outputs: %w", err)
	}
	defer rows.Close()
	result := make([]Output, 0)
	for rows.Next() {
		output, err := scanOutput(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, output)
	}
	return result, rows.Err()
}

func (s *Store) OutputIDsForCollection(ctx context.Context, collectionID string) ([]string, error) {
	if !validID(collectionID) {
		return nil, ErrNotFound
	}
	rows, err := s.database.QueryContext(ctx, `
SELECT id FROM managed_outputs
WHERE collection_id = ? AND lifecycle_state = 'active'
ORDER BY id`, collectionID)
	if err != nil {
		return nil, fmt.Errorf("list managed outputs for collection: %w", err)
	}
	defer rows.Close()
	result := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, rows.Err()
}

func (s *Store) OutputIDsForTemplate(ctx context.Context, templateID string) ([]string, error) {
	if !validID(templateID) {
		return nil, ErrNotFound
	}
	rows, err := s.database.QueryContext(ctx, `
SELECT id FROM managed_outputs
WHERE template_id = ? AND lifecycle_state = 'active'
ORDER BY id`, templateID)
	if err != nil {
		return nil, fmt.Errorf("list managed outputs for template: %w", err)
	}
	defer rows.Close()
	result := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, rows.Err()
}

func (s *Store) OutputIDsForPipeline(ctx context.Context, pipelineID string) ([]string, error) {
	if !validID(pipelineID) {
		return nil, ErrNotFound
	}
	rows, err := s.database.QueryContext(ctx, `
SELECT id FROM managed_outputs
WHERE pipeline_id = ? AND lifecycle_state = 'active'
ORDER BY id`, pipelineID)
	if err != nil {
		return nil, fmt.Errorf("list managed outputs for pipeline: %w", err)
	}
	defer rows.Close()
	result := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, rows.Err()
}

func (s *Store) OutputIDsForSource(ctx context.Context, sourceID string) ([]string, error) {
	return s.outputIDsForSource(ctx, sourceID, false)
}

func (s *Store) HealthFilteredOutputIDsForSource(ctx context.Context, sourceID string) ([]string, error) {
	return s.outputIDsForSource(ctx, sourceID, true)
}

func (s *Store) outputIDsForSource(ctx context.Context, sourceID string, healthFilterOnly bool) ([]string, error) {
	if !validID(sourceID) {
		return nil, ErrNotFound
	}
	outputs, err := s.Outputs(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0)
	for _, output := range outputs {
		if healthFilterOnly && !output.HealthFilterEnabled {
			continue
		}
		resource, err := s.Resource(ctx, output.CollectionID, "collection")
		if err != nil {
			return nil, err
		}
		config, err := s.CollectionConfig(ctx, resource)
		if err != nil {
			return nil, err
		}
		matched := false
		for _, member := range config.Members {
			if !member.Enabled {
				continue
			}
			if member.Kind == "source" && member.ID == sourceID {
				matched = true
				break
			}
			if member.Kind == "node_occurrence" {
				var memberSourceID string
				if err := s.database.QueryRowContext(ctx, `SELECT source_id FROM node_occurrences WHERE id = ?`, member.ID).Scan(&memberSourceID); err != nil {
					return nil, fmt.Errorf("resolve collection node source: %w", err)
				}
				if memberSourceID == sourceID {
					matched = true
					break
				}
			}
		}
		if matched {
			result = append(result, output.ID)
		}
	}
	return result, nil
}

func (s *Store) Nodes(ctx context.Context, config CollectionConfig) ([]NodeInput, error) {
	result := make([]NodeInput, 0)
	seen := make(map[string]struct{})
	for _, member := range config.Members {
		if !member.Enabled {
			continue
		}
		items, err := s.memberNodes(ctx, member)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			if _, duplicate := seen[item.OccurrenceID]; duplicate {
				continue
			}
			seen[item.OccurrenceID] = struct{}{}
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *Store) memberNodes(ctx context.Context, member Member) ([]NodeInput, error) {
	query := `
SELECT s.id, so.node_occurrence_id, rn.source_ordinal, rn.format_id, rn.protocol_id,
       rn.raw_blob_id, COALESCE(rn.original_name_blob_id, ''),
       COALESCE(cn.canonical_blob_id, ''), COALESCE(cn.protocol_adapter_version, ''),
       COALESCE(h.state, 'unchecked'), COALESCE(h.stale, 1), COALESCE(h.recovery_step, 0)
FROM sources s
JOIN snapshots sn ON sn.id = s.current_snapshot_id
JOIN snapshot_occurrences so ON so.snapshot_id = sn.id
JOIN raw_nodes rn ON rn.id = so.raw_node_id
LEFT JOIN canonical_nodes cn ON cn.raw_node_id = rn.id
LEFT JOIN node_health_states h ON h.node_occurrence_id = so.node_occurrence_id
WHERE s.lifecycle_state = 'active' AND `
	argument := member.ID
	if member.Kind == "source" {
		query += `s.id = ?`
	} else {
		query += `so.node_occurrence_id = ?`
	}
	query += ` ORDER BY rn.source_ordinal`
	rows, err := s.database.QueryContext(ctx, query, argument)
	if err != nil {
		return nil, fmt.Errorf("read collection nodes: %w", err)
	}
	defer rows.Close()
	result := make([]NodeInput, 0)
	for rows.Next() {
		var item NodeInput
		var stale int
		if err := rows.Scan(
			&item.SourceID, &item.OccurrenceID, &item.SourceOrdinal, &item.FormatID, &item.ProtocolID,
			&item.RawBlobID, &item.NameBlobID, &item.CanonicalBlobID, &item.CanonicalVersion,
			&item.HealthState, &stale, &item.RecoveryStep,
		); err != nil {
			return nil, fmt.Errorf("scan collection node: %w", err)
		}
		item.HealthStale = stale == 1
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate collection nodes: %w", err)
	}
	if len(result) == 0 {
		return nil, ErrNotFound
	}
	return result, nil
}

func (s *Store) Blob(ctx context.Context, id string) ([]byte, blobstore.Record, error) {
	return s.blobs.Get(ctx, id)
}

func (s *Store) PutBlob(ctx context.Context, kind string, content []byte, public bool) (blobstore.Record, error) {
	return s.blobs.Put(ctx, blobstore.PutRequest{Kind: kind, Plaintext: content, Public: public})
}

func (s *Store) DiscardBlob(ctx context.Context, id string) error {
	_, err := s.blobs.DeleteUnreferenced(ctx, id)
	return err
}

func (s *Store) Publish(ctx context.Context, request PublishRequest) (Artifact, error) {
	if !validID(request.OutputID) || !validID(request.ContentBlobID) || !validID(request.ManifestBlobID) || !validID(request.AllocationBlobID) ||
		request.NodeCount < 0 || request.ExcludedCount < 0 || request.WarningCount < 0 || request.ContentType == "" || request.ValidatorVersion == "" {
		return Artifact{}, fmt.Errorf("invalid managed output publication")
	}
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return Artifact{}, fmt.Errorf("begin managed output publication: %w", err)
	}
	defer tx.Rollback()
	var sequence, minimum, previousCount int
	var maximum float64
	var previousAllocationBlobID string
	if err := tx.QueryRowContext(ctx, `
SELECT next_build_sequence, minimum_nodes, maximum_drop_ratio,
       COALESCE((SELECT node_count FROM managed_output_artifacts a WHERE a.id = o.current_artifact_id), 0),
       COALESCE(allocation_blob_id, '')
FROM managed_outputs o WHERE id = ? AND lifecycle_state = 'active'`, request.OutputID).Scan(
		&sequence, &minimum, &maximum, &previousCount, &previousAllocationBlobID,
	); errors.Is(err, sql.ErrNoRows) {
		return Artifact{}, ErrNotFound
	} else if err != nil {
		return Artifact{}, fmt.Errorf("read managed output publication state: %w", err)
	}
	if request.NodeCount < minimum || previousCount > 0 && request.NodeCount < previousCount && float64(previousCount-request.NodeCount)/float64(previousCount) > maximum {
		return Artifact{}, fmt.Errorf("%w: managed output content gate rejected %d nodes", ErrConflict, request.NodeCount)
	}
	var contentSize int
	var digest sql.NullString
	checks := []struct{ id, kind string }{{request.ContentBlobID, "output_artifact"}, {request.ManifestBlobID, "build_manifest"}, {request.AllocationBlobID, "allocation_state"}}
	for _, check := range checks {
		var kind string
		var size int
		var public sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT kind, plaintext_size, public_sha256 FROM encrypted_blobs WHERE id = ?`, check.id).Scan(&kind, &size, &public); err != nil || kind != check.kind {
			return Artifact{}, ErrConflict
		}
		if check.id == request.ContentBlobID {
			contentSize, digest = size, public
		}
	}
	if !digest.Valid || len(digest.String) != 64 {
		return Artifact{}, ErrConflict
	}
	id := s.newID()
	if !validID(id) {
		return Artifact{}, fmt.Errorf("managed output artifact ID generator returned an invalid ID")
	}
	now := s.now().UTC()
	artifact := Artifact{
		ID: id, OutputID: request.OutputID, BuildSequence: sequence,
		ContentBlobID: request.ContentBlobID, ManifestBlobID: request.ManifestBlobID,
		ContentType: request.ContentType, ContentLength: contentSize, PublicSHA256: digest.String,
		NodeCount: request.NodeCount, ExcludedCount: request.ExcludedCount, WarningCount: request.WarningCount,
		TargetProfile: request.TargetProfile, ValidatorVersion: request.ValidatorVersion, CreatedAt: now,
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO managed_output_artifacts(
  id, output_id, build_sequence, content_blob_id, manifest_blob_id,
  content_type, content_length, public_sha256, node_count, excluded_count,
  warning_count, target_profile, validator_version, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		artifact.ID, artifact.OutputID, artifact.BuildSequence, artifact.ContentBlobID, artifact.ManifestBlobID,
		artifact.ContentType, artifact.ContentLength, artifact.PublicSHA256, artifact.NodeCount,
		artifact.ExcludedCount, artifact.WarningCount, artifact.TargetProfile, artifact.ValidatorVersion,
		artifact.CreatedAt.UnixMilli()); err != nil {
		return Artifact{}, fmt.Errorf("insert managed output artifact: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE managed_outputs
SET current_artifact_id = ?, allocation_blob_id = ?, next_build_sequence = ?, updated_at = ?
WHERE id = ? AND next_build_sequence = ?`, artifact.ID, request.AllocationBlobID,
		sequence+1, now.UnixMilli(), request.OutputID, sequence)
	if err != nil {
		return Artifact{}, fmt.Errorf("publish managed output artifact: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return Artifact{}, fmt.Errorf("%w: managed output publication was superseded", ErrConflict)
	}
	if err := tx.Commit(); err != nil {
		return Artifact{}, fmt.Errorf("commit managed output publication: %w", err)
	}
	if previousAllocationBlobID != "" && previousAllocationBlobID != request.AllocationBlobID {
		_, _ = s.blobs.DeleteUnreferenced(context.Background(), previousAllocationBlobID)
	}
	return artifact, nil
}

func (s *Store) UpdateAllocation(ctx context.Context, outputID, currentArtifactID, expectedAllocationBlobID, allocationBlobID string) error {
	if !validID(outputID) || !validID(currentArtifactID) || !validID(allocationBlobID) || expectedAllocationBlobID != "" && !validID(expectedAllocationBlobID) {
		return fmt.Errorf("invalid managed output allocation update")
	}
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin managed output allocation update: %w", err)
	}
	defer tx.Rollback()
	var kind string
	if err := tx.QueryRowContext(ctx, `SELECT kind FROM encrypted_blobs WHERE id = ?`, allocationBlobID).Scan(&kind); err != nil || kind != "allocation_state" {
		return ErrConflict
	}
	now := s.now().UTC()
	result, err := tx.ExecContext(ctx, `
UPDATE managed_outputs
SET allocation_blob_id = ?, updated_at = ?
WHERE id = ? AND lifecycle_state = 'active' AND current_artifact_id = ?
  AND COALESCE(allocation_blob_id, '') = ?`, allocationBlobID, now.UnixMilli(), outputID, currentArtifactID, expectedAllocationBlobID)
	if err != nil {
		return fmt.Errorf("update managed output allocation: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit managed output allocation update: %w", err)
	}
	if expectedAllocationBlobID != "" && expectedAllocationBlobID != allocationBlobID {
		_, _ = s.blobs.DeleteUnreferenced(context.Background(), expectedAllocationBlobID)
	}
	return nil
}

func (s *Store) CreateCredential(ctx context.Context, outputID string) (Credential, error) {
	return s.createCredential(ctx, outputID, false)
}

func (s *Store) RotateCredential(ctx context.Context, outputID string, revokeExisting bool) (Credential, error) {
	return s.createCredential(ctx, outputID, revokeExisting)
}

func (s *Store) createCredential(ctx context.Context, outputID string, revokeExisting bool) (Credential, error) {
	if !validID(outputID) {
		return Credential{}, ErrNotFound
	}
	id := s.newID()
	secret := make([]byte, 32)
	if !validID(id) {
		return Credential{}, fmt.Errorf("managed output token ID generator returned an invalid ID")
	}
	if _, err := io.ReadFull(s.random, secret); err != nil {
		return Credential{}, fmt.Errorf("generate managed output token: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(secret)
	wipe(secret)
	key, err := s.keys.Active(keyring.PurposeToken)
	if err != nil {
		return Credential{}, err
	}
	digest := tokenDigest(key, id, encoded)
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return Credential{}, fmt.Errorf("begin managed output token creation: %w", err)
	}
	defer tx.Rollback()
	now := s.now().UTC().UnixMilli()
	if revokeExisting {
		if _, err := tx.ExecContext(ctx, `
UPDATE managed_output_tokens SET revoked_at = ?
WHERE output_id = ? AND revoked_at IS NULL`, now, outputID); err != nil {
			return Credential{}, fmt.Errorf("revoke prior managed output tokens: %w", err)
		}
	}
	result, err := tx.ExecContext(ctx, `
INSERT INTO managed_output_tokens(id, output_id, key_id, token_hmac, created_at)
SELECT ?, id, ?, ?, ? FROM managed_outputs WHERE id = ? AND lifecycle_state = 'active'`,
		id, key.ID, digest, now, outputID)
	if err != nil {
		return Credential{}, fmt.Errorf("store managed output token: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return Credential{}, ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return Credential{}, fmt.Errorf("commit managed output token creation: %w", err)
	}
	return Credential{ID: id, OutputID: outputID, Token: "out1." + id + "." + encoded}, nil
}

func (s *Store) Resolve(ctx context.Context, token string) (Artifact, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "out1" || !validID(parts[1]) || len(parts[2]) != 43 {
		return Artifact{}, ErrUnauthorized
	}
	var outputID, keyID string
	var stored []byte
	var revoked sql.NullInt64
	if err := s.database.QueryRowContext(ctx, `
SELECT output_id, key_id, token_hmac, revoked_at FROM managed_output_tokens WHERE id = ?`, parts[1]).Scan(&outputID, &keyID, &stored, &revoked); err != nil {
		return Artifact{}, ErrUnauthorized
	}
	key, err := s.keys.ByID(keyID)
	if err != nil || revoked.Valid || subtle.ConstantTimeCompare(stored, tokenDigest(key, parts[1], parts[2])) != 1 {
		return Artifact{}, ErrUnauthorized
	}
	_, _ = s.database.ExecContext(ctx, `
UPDATE managed_output_tokens SET last_used_at = ?
WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)`,
		s.now().UTC().UnixMilli(), parts[1], s.now().UTC().Add(-5*time.Minute).UnixMilli())
	artifact, err := scanArtifact(s.database.QueryRowContext(ctx, `
SELECT a.id, a.output_id, a.build_sequence, a.content_blob_id, a.manifest_blob_id,
       a.content_type, a.content_length, a.public_sha256, a.node_count,
       a.excluded_count, a.warning_count, a.target_profile, a.validator_version, a.created_at
FROM managed_outputs o JOIN managed_output_artifacts a ON a.id = o.current_artifact_id
WHERE o.id = ? AND o.lifecycle_state = 'active'`, outputID))
	if errors.Is(err, sql.ErrNoRows) {
		return Artifact{}, ErrNotFound
	}
	return artifact, err
}

func (s *Store) Artifact(ctx context.Context, id string) (Artifact, error) {
	if !validID(id) {
		return Artifact{}, ErrNotFound
	}
	artifact, err := scanArtifact(s.database.QueryRowContext(ctx, `
SELECT id, output_id, build_sequence, content_blob_id, manifest_blob_id,
       content_type, content_length, public_sha256, node_count,
       excluded_count, warning_count, target_profile, validator_version, created_at
FROM managed_output_artifacts WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Artifact{}, ErrNotFound
	}
	return artifact, err
}

func (s *Store) Content(ctx context.Context, artifact Artifact) ([]byte, error) {
	content, record, err := s.blobs.Get(ctx, artifact.ContentBlobID)
	if err != nil {
		return nil, err
	}
	if record.Kind != "output_artifact" || record.PublicSHA256 != artifact.PublicSHA256 || len(content) != artifact.ContentLength {
		return nil, ErrConflict
	}
	return content, nil
}

const outputSelect = `
SELECT id, display_name, collection_id, COALESCE(pipeline_id, ''), COALESCE(template_id, ''),
       target_profile, output_shape, health_filter_enabled, minimum_nodes, maximum_drop_ratio,
       COALESCE(allocation_blob_id, ''), COALESCE(current_artifact_id, ''), next_build_sequence,
       lifecycle_state, created_at, updated_at
FROM managed_outputs`

func scanResource(row interface{ Scan(...interface{}) error }) (Resource, error) {
	var resource Resource
	var created, updated int64
	if err := row.Scan(&resource.ID, &resource.Type, &resource.DisplayName, &resource.ConfigBlobID,
		&resource.RevisionNumber, &resource.LifecycleState, &created, &updated); err != nil {
		return Resource{}, err
	}
	resource.CreatedAt, resource.UpdatedAt = time.UnixMilli(created).UTC(), time.UnixMilli(updated).UTC()
	return resource, nil
}

func scanOutput(row interface{ Scan(...interface{}) error }) (Output, error) {
	var output Output
	var health int
	var created, updated int64
	if err := row.Scan(
		&output.ID, &output.DisplayName, &output.CollectionID, &output.PipelineID, &output.TemplateID,
		&output.TargetProfile, &output.OutputShape, &health, &output.MinimumNodes, &output.MaximumDropRatio,
		&output.AllocationBlobID, &output.CurrentArtifactID, &output.NextBuildSequence,
		&output.LifecycleState, &created, &updated,
	); err != nil {
		return Output{}, err
	}
	output.HealthFilterEnabled = health == 1
	output.CreatedAt, output.UpdatedAt = time.UnixMilli(created).UTC(), time.UnixMilli(updated).UTC()
	return output, nil
}

func scanArtifact(row interface{ Scan(...interface{}) error }) (Artifact, error) {
	var artifact Artifact
	var created int64
	if err := row.Scan(
		&artifact.ID, &artifact.OutputID, &artifact.BuildSequence, &artifact.ContentBlobID, &artifact.ManifestBlobID,
		&artifact.ContentType, &artifact.ContentLength, &artifact.PublicSHA256, &artifact.NodeCount,
		&artifact.ExcludedCount, &artifact.WarningCount, &artifact.TargetProfile, &artifact.ValidatorVersion, &created,
	); err != nil {
		return Artifact{}, err
	}
	artifact.CreatedAt = time.UnixMilli(created).UTC()
	return artifact, nil
}

func tokenDigest(key keyring.DataKey, id, secret string) []byte {
	mac := hmac.New(sha256.New, key.Material[:])
	mac.Write([]byte("proxyloom-managed-output-token-v1\x00"))
	mac.Write([]byte(id))
	mac.Write([]byte{0})
	mac.Write([]byte(secret))
	return mac.Sum(nil)
}

func validDisplayName(value string) bool {
	return value != "" && len(value) <= 200 && utf8.ValidString(value)
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

func nullableString(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
