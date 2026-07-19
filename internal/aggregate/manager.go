package aggregate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/doujialong/proxyloom/internal/convert"
	"github.com/doujialong/proxyloom/internal/fetcher"
	"github.com/doujialong/proxyloom/internal/format/singbox"
	"github.com/doujialong/proxyloom/internal/jsonlossless"
	"github.com/doujialong/proxyloom/internal/naming"
	"github.com/doujialong/proxyloom/internal/occurrence"
	"github.com/doujialong/proxyloom/internal/patch"
	"github.com/doujialong/proxyloom/internal/protocol"
	"github.com/doujialong/proxyloom/internal/storage/outputjobstore"
	"github.com/doujialong/proxyloom/internal/storage/outputstore"
)

const BuilderVersion = "managed-output-builder-v1"

type Validator interface {
	Check(context.Context, []byte) error
	Version() string
}

type RemoteFetcher func(context.Context, string, fetcher.Options) (fetcher.Result, error)

type Options struct {
	Now         func() time.Time
	Validators  map[string]Validator
	Jobs        *outputjobstore.Store
	FetchRemote RemoteFetcher
}

type Manager struct {
	store       *outputstore.Store
	now         func() time.Time
	validators  map[string]Validator
	registry    *protocol.Registry
	jobs        *outputjobstore.Store
	fetchRemote RemoteFetcher
}

type BuildResult struct {
	Artifact outputstore.Artifact
	Content  []byte
}

type candidate struct {
	input    outputstore.NodeInput
	baseName string
	excluded bool
	ordinal  int
}

type RemoteTemplateCreate struct {
	URL                      string
	Headers                  map[string]string
	PrivateNetworkAuthorized bool
	RefreshIntervalSeconds   int
}

func New(store *outputstore.Store, options Options) (*Manager, error) {
	if store == nil || options.Now == nil || options.Jobs == nil {
		return nil, fmt.Errorf("aggregate manager dependencies are required")
	}
	validators := make(map[string]Validator, len(options.Validators))
	for profile, validator := range options.Validators {
		if !outputstore.SupportedTargetProfile(profile) || validator == nil || validator.Version() == "" {
			return nil, fmt.Errorf("invalid validator for target profile %q", profile)
		}
		validators[profile] = validator
	}
	if options.FetchRemote == nil {
		options.FetchRemote = fetcher.Fetch
	}
	return &Manager{
		store: store, now: options.Now, validators: validators, registry: protocol.NewRegistry(),
		jobs: options.Jobs, fetchRemote: options.FetchRemote,
	}, nil
}

func (m *Manager) Store() *outputstore.Store { return m.store }

func (m *Manager) EnqueueBuild(ctx context.Context, outputID, correlationID string) (outputjobstore.Job, error) {
	if _, err := m.store.Output(ctx, outputID); err != nil {
		return outputjobstore.Job{}, err
	}
	return m.jobs.Enqueue(ctx, outputjobstore.EnqueueRequest{
		OutputID: outputID, TriggerKind: "manual", CorrelationID: correlationID,
	})
}

func (m *Manager) EnqueueForSource(ctx context.Context, sourceID, triggerKind string) error {
	var ids []string
	var err error
	if triggerKind == "health_boundary" {
		ids, err = m.store.HealthFilteredOutputIDsForSource(ctx, sourceID)
	} else {
		ids, err = m.store.OutputIDsForSource(ctx, sourceID)
	}
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := m.jobs.Enqueue(ctx, outputjobstore.EnqueueRequest{
			OutputID: id, TriggerKind: triggerKind, TriggerSourceID: sourceID,
			CorrelationID: triggerKind + "-" + sourceID,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) EnqueueForCollection(ctx context.Context, collectionID string) error {
	ids, err := m.store.OutputIDsForCollection(ctx, collectionID)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := m.jobs.Enqueue(ctx, outputjobstore.EnqueueRequest{
			OutputID: id, TriggerKind: "collection_update",
			CorrelationID: "collection-update-" + collectionID,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) EnqueueForPipeline(ctx context.Context, pipelineID string) error {
	ids, err := m.store.OutputIDsForPipeline(ctx, pipelineID)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := m.jobs.Enqueue(ctx, outputjobstore.EnqueueRequest{
			OutputID: id, TriggerKind: "manual",
			CorrelationID: "pipeline-update-" + pipelineID,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) EnqueueForTemplate(ctx context.Context, templateID string) error {
	template, err := m.store.Resource(ctx, templateID, "template")
	if err != nil {
		return err
	}
	ids, err := m.store.OutputIDsForTemplate(ctx, templateID)
	if err != nil {
		return err
	}
	for _, id := range ids {
		current, err := m.outputUsesTemplateRevision(ctx, id, template.ID, template.RevisionNumber)
		if err != nil {
			return err
		}
		if current {
			continue
		}
		if _, err := m.jobs.Enqueue(ctx, outputjobstore.EnqueueRequest{
			OutputID: id, TriggerKind: "manual",
			CorrelationID: "template-refresh-" + templateID,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) outputUsesTemplateRevision(ctx context.Context, outputID, templateID string, revision int) (bool, error) {
	output, err := m.store.Output(ctx, outputID)
	if err != nil {
		return false, err
	}
	if output.CurrentArtifactID == "" {
		return false, nil
	}
	artifact, err := m.store.Artifact(ctx, output.CurrentArtifactID)
	if err != nil {
		return false, err
	}
	content, record, err := m.store.Blob(ctx, artifact.ManifestBlobID)
	if err != nil {
		return false, err
	}
	if record.Kind != "build_manifest" {
		return false, outputstore.ErrConflict
	}
	var manifest struct {
		TemplateID       string `json:"template_id"`
		TemplateRevision int    `json:"template_revision"`
	}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return false, outputstore.ErrConflict
	}
	return manifest.TemplateID == templateID && manifest.TemplateRevision == revision, nil
}

func (m *Manager) BuildJob(ctx context.Context, id string) (outputjobstore.Job, error) {
	return m.jobs.Get(ctx, id)
}

func (m *Manager) CreateTemplate(ctx context.Context, displayName string, content []byte) (outputstore.Resource, error) {
	if err := m.validateTemplate(content); err != nil {
		return outputstore.Resource{}, err
	}
	return m.store.CreateTemplate(ctx, displayName, content)
}

func (m *Manager) CreateRemoteTemplate(ctx context.Context, displayName string, input RemoteTemplateCreate) (outputstore.Resource, error) {
	config, err := m.fetchRemoteTemplate(ctx, input)
	if err != nil {
		return outputstore.Resource{}, err
	}
	if err := m.validateTemplate(config.Content); err != nil {
		return outputstore.Resource{}, err
	}
	return m.store.CreateRemoteTemplate(ctx, displayName, config)
}

func (m *Manager) RefreshRemoteTemplate(ctx context.Context, id string) (outputstore.Resource, bool, error) {
	resource, err := m.store.Resource(ctx, id, "template")
	if err != nil {
		return outputstore.Resource{}, false, err
	}
	current, remote, err := m.store.RemoteTemplateConfig(ctx, resource)
	if err != nil {
		return outputstore.Resource{}, false, err
	}
	if !remote {
		return outputstore.Resource{}, false, outputstore.ErrConflict
	}
	updated, err := m.fetchRemoteTemplate(ctx, RemoteTemplateCreate{
		URL: current.URL, Headers: current.Headers,
		PrivateNetworkAuthorized: current.PrivateNetworkAuthorized,
		RefreshIntervalSeconds:   current.RefreshIntervalSeconds,
	})
	if err != nil {
		return outputstore.Resource{}, false, err
	}
	if err := m.validateTemplate(updated.Content); err != nil {
		return outputstore.Resource{}, false, err
	}
	if updated.ContentSHA256 == current.ContentSHA256 {
		if err := m.EnqueueForTemplate(ctx, resource.ID); err != nil {
			return resource, false, err
		}
		return resource, false, nil
	}
	resource, err = m.store.UpdateRemoteTemplate(ctx, resource.ID, resource.RevisionNumber, updated)
	if err != nil {
		return outputstore.Resource{}, false, err
	}
	if err := m.EnqueueForTemplate(ctx, resource.ID); err != nil {
		return resource, true, err
	}
	return resource, true, nil
}

func (m *Manager) fetchRemoteTemplate(ctx context.Context, input RemoteTemplateCreate) (outputstore.RemoteTemplateConfig, error) {
	if input.RefreshIntervalSeconds == 0 {
		input.RefreshIntervalSeconds = 3600
	}
	if input.RefreshIntervalSeconds < 60 || input.RefreshIntervalSeconds > 7*24*60*60 {
		return outputstore.RemoteTemplateConfig{}, fmt.Errorf("remote template refresh interval must be between 60 seconds and 7 days")
	}
	parsed, err := url.Parse(input.URL)
	if err != nil || parsed.Host == "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return outputstore.RemoteTemplateConfig{}, fmt.Errorf("remote template URL must be an absolute HTTP or HTTPS URL")
	}
	if err := fetcher.ValidateHeaders(input.Headers); err != nil {
		return outputstore.RemoteTemplateConfig{}, err
	}
	result, err := m.fetchRemote(ctx, input.URL, fetcher.Options{
		Timeout: 15 * time.Second, MaxBytes: 49 << 20,
		PrivateNetworkAuthorized: input.PrivateNetworkAuthorized,
		Headers:                  input.Headers,
	})
	if err != nil {
		return outputstore.RemoteTemplateConfig{}, err
	}
	content, digest, err := outputstore.NormalizeRemoteTemplateContent(result.Content)
	if err != nil {
		return outputstore.RemoteTemplateConfig{}, err
	}
	return outputstore.RemoteTemplateConfig{
		SourceType: "remote", TargetFormat: "sing-box", URL: input.URL,
		Headers: input.Headers, PrivateNetworkAuthorized: input.PrivateNetworkAuthorized,
		RefreshIntervalSeconds: input.RefreshIntervalSeconds,
		Content:                content,
		ContentSHA256:          digest, FetchedAt: m.now().UTC(),
	}, nil
}

func (m *Manager) validateTemplate(content []byte) error {
	document, err := singbox.Parse(content, m.registry, singbox.DefaultLimits())
	if err != nil || document.Shape != singbox.ShapeFullConfig {
		return fmt.Errorf("template must be a sing-box full config: %w", err)
	}
	if len(document.Nodes) != 0 {
		return fmt.Errorf("template must not contain proxy nodes; import them as a source")
	}
	if !containsTemplateMarker(document.Root) {
		return fmt.Errorf("template must contain a ProxyLoom node marker in a logical outbound")
	}
	allTags := map[string]struct{}{"__proxyloom_template_validation_node": {}}
	for _, outbound := range document.NonNodes {
		if outbound.DisplayName != "" {
			allTags[outbound.DisplayName] = struct{}{}
		}
	}
	if err := expandTemplateReferences(document.Root.Clone(), []string{"__proxyloom_template_validation_node"}, allTags); err != nil {
		return fmt.Errorf("validate template references: %w", err)
	}
	return nil
}

func (m *Manager) CreatePipeline(ctx context.Context, displayName string, config outputstore.PipelineConfig) (outputstore.Resource, error) {
	if err := validatePipeline(config); err != nil {
		return outputstore.Resource{}, err
	}
	return m.store.CreatePipeline(ctx, displayName, config)
}

func (m *Manager) Build(ctx context.Context, outputID string) (BuildResult, error) {
	output, err := m.store.Output(ctx, outputID)
	if err != nil {
		return BuildResult{}, err
	}
	collection, err := m.store.Resource(ctx, output.CollectionID, "collection")
	if err != nil {
		return BuildResult{}, err
	}
	collectionConfig, err := m.store.CollectionConfig(ctx, collection)
	if err != nil {
		return BuildResult{}, err
	}
	inputs, err := m.store.Nodes(ctx, collectionConfig)
	if err != nil {
		return BuildResult{}, err
	}
	candidates, err := m.prepareCandidates(ctx, output, inputs)
	if err != nil {
		return BuildResult{}, err
	}
	if output.PipelineID != "" {
		resource, err := m.store.Resource(ctx, output.PipelineID, "pipeline")
		if err != nil {
			return BuildResult{}, err
		}
		pipeline, err := m.store.PipelineConfig(ctx, resource)
		if err != nil {
			return BuildResult{}, err
		}
		if err := validatePipeline(pipeline); err != nil {
			return BuildResult{}, err
		}
		if err := applyPipeline(candidates, pipeline); err != nil {
			return BuildResult{}, err
		}
	}
	for index := range candidates {
		candidates[index].ordinal = index
	}
	existing, err := m.loadAllocations(ctx, output)
	if err != nil {
		return BuildResult{}, err
	}
	reservedNames, err := m.templateReservedNames(ctx, output)
	if err != nil {
		return BuildResult{}, err
	}
	baseByOccurrence := make(map[string]string, len(candidates))
	nameCandidates := make([]naming.Candidate, len(candidates))
	for index, item := range candidates {
		baseByOccurrence[item.input.OccurrenceID] = item.baseName
		nameCandidates[index] = naming.Candidate{
			OccurrenceID: item.input.OccurrenceID, BaseName: item.baseName,
			StableKey:        item.input.SourceID + "/" + item.input.OccurrenceID,
			CandidateOrdinal: item.ordinal,
		}
	}
	stableExisting := existing[:0]
	for _, allocation := range existing {
		if base, present := baseByOccurrence[allocation.OccurrenceID]; !present || allocation.BaseName == base {
			stableExisting = append(stableExisting, allocation)
		}
	}
	allocated, err := naming.Allocate(stableExisting, nameCandidates, naming.Options{
		Now: m.now().UTC(), Retention: occurrence.DefaultRetention, ReservedNames: reservedNames,
	})
	if err != nil {
		return BuildResult{}, err
	}
	nameByOccurrence := make(map[string]string, len(allocated.Snapshot))
	for _, item := range allocated.Snapshot {
		nameByOccurrence[item.OccurrenceID] = item.FinalName
	}
	outbounds := make([]*jsonlossless.Node, 0, len(candidates))
	includedIDs := make([]string, 0, len(candidates))
	excluded := 0
	for _, item := range candidates {
		if item.excluded {
			excluded++
			continue
		}
		nodes, err := m.renderCandidate(ctx, item, nameByOccurrence[item.input.OccurrenceID])
		if err != nil {
			return BuildResult{}, fmt.Errorf("render occurrence %s: %w", item.input.OccurrenceID, err)
		}
		outbounds = append(outbounds, nodes...)
		includedIDs = append(includedIDs, item.input.OccurrenceID)
	}
	if len(outbounds) == 0 {
		return BuildResult{}, fmt.Errorf("managed output contains no included nodes")
	}
	root := jsonlossless.NewObject(jsonlossless.Member{Key: "outbounds", KeyRaw: `"outbounds"`, Value: jsonlossless.NewArray(outbounds...)})
	templateRevision := 0
	if output.OutputShape == "full_config" {
		root, templateRevision, err = m.renderTemplate(ctx, output, outbounds)
		if err != nil {
			return BuildResult{}, err
		}
	}
	content, err := jsonlossless.MarshalIndent(root, "", "  ")
	if err != nil {
		return BuildResult{}, err
	}
	content = append(content, '\n')
	if _, err := singbox.Parse(content, m.registry, singbox.DefaultLimits()); err != nil {
		return BuildResult{}, fmt.Errorf("generated sing-box config failed internal validation: %w", err)
	}
	validator, available := m.validators[output.TargetProfile]
	if !available {
		return BuildResult{}, fmt.Errorf("target validator for profile %s is unavailable", output.TargetProfile)
	}
	if err := validator.Check(ctx, content); err != nil {
		return BuildResult{}, fmt.Errorf("generated config failed target validation for %s: %w", output.TargetProfile, err)
	}
	validatorVersion := "sing-box-" + validator.Version() + "-check"
	allocationContent, err := json.Marshal(allocated.Allocations)
	if err != nil {
		return BuildResult{}, err
	}
	manifestContent, err := json.Marshal(map[string]interface{}{
		"version": BuilderVersion, "output_id": output.ID, "target_profile": output.TargetProfile,
		"validator_version": validatorVersion,
		"collection_id":     output.CollectionID, "pipeline_id": output.PipelineID,
		"template_id": output.TemplateID, "template_revision": templateRevision,
		"included_occurrence_ids": includedIDs,
		"excluded_count":          excluded, "built_at": m.now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return BuildResult{}, err
	}
	contentBlob, err := m.store.PutBlob(ctx, "output_artifact", content, true)
	if err != nil {
		return BuildResult{}, err
	}
	pendingBlobIDs := []string{contentBlob.ID}
	published := false
	defer func() {
		if published {
			return
		}
		for _, id := range pendingBlobIDs {
			_ = m.store.DiscardBlob(context.Background(), id)
		}
	}()
	manifestBlob, err := m.store.PutBlob(ctx, "build_manifest", manifestContent, false)
	if err != nil {
		return BuildResult{}, err
	}
	pendingBlobIDs = append(pendingBlobIDs, manifestBlob.ID)
	allocationBlob, err := m.store.PutBlob(ctx, "allocation_state", allocationContent, false)
	if err != nil {
		return BuildResult{}, err
	}
	pendingBlobIDs = append(pendingBlobIDs, allocationBlob.ID)
	artifact, err := m.store.Publish(ctx, outputstore.PublishRequest{
		OutputID: output.ID, ContentBlobID: contentBlob.ID, ManifestBlobID: manifestBlob.ID,
		AllocationBlobID: allocationBlob.ID, ContentType: "application/json",
		NodeCount: len(outbounds), ExcludedCount: excluded, TargetProfile: output.TargetProfile,
		ValidatorVersion: validatorVersion,
	})
	if err != nil {
		return BuildResult{}, err
	}
	published = true
	return BuildResult{Artifact: artifact, Content: content}, nil
}

func (m *Manager) templateReservedNames(ctx context.Context, output outputstore.Output) ([]string, error) {
	if output.OutputShape != "full_config" {
		return nil, nil
	}
	resource, err := m.store.Resource(ctx, output.TemplateID, "template")
	if err != nil {
		return nil, err
	}
	content, err := m.store.TemplateContent(ctx, resource)
	if err != nil {
		return nil, err
	}
	document, err := singbox.Parse(content, m.registry, singbox.DefaultLimits())
	if err != nil || document.Shape != singbox.ShapeFullConfig {
		return nil, fmt.Errorf("parse managed output template for reserved names: %w", err)
	}
	result := make([]string, 0, len(document.NonNodes))
	for _, outbound := range document.NonNodes {
		if outbound.DisplayName != "" {
			result = append(result, outbound.DisplayName)
		}
	}
	return result, nil
}

func validatePipeline(pipeline outputstore.PipelineConfig) error {
	for index, operation := range pipeline.Operations {
		if operation.SchemaVersion != 1 {
			return fmt.Errorf("pipeline operation %d has an unsupported schema version", index)
		}
		switch operation.Type {
		case "filter":
			if err := validateFilterConfig(operation.Config); err != nil {
				return fmt.Errorf("pipeline filter %d: %w", index, err)
			}
		case "rename":
			if err := allowConfigKeys(operation.Config, "prefix", "suffix", "pattern", "replacement"); err != nil {
				return fmt.Errorf("pipeline rename %d: %w", index, err)
			}
			configured := false
			for _, key := range []string{"prefix", "suffix", "pattern", "replacement"} {
				if value, exists := operation.Config[key]; exists {
					text, ok := value.(string)
					if !ok || len(text) > 512 {
						return fmt.Errorf("pipeline rename %d property %q is invalid", index, key)
					}
					configured = configured || text != ""
				}
			}
			if !configured {
				return fmt.Errorf("pipeline rename %d has no effect", index)
			}
			if pattern, _ := operation.Config["pattern"].(string); pattern != "" {
				if _, err := regexp.Compile(pattern); err != nil {
					return fmt.Errorf("pipeline rename %d regex: %w", index, err)
				}
			}
		case "sort":
			if err := allowConfigKeys(operation.Config, "by", "descending"); err != nil {
				return fmt.Errorf("pipeline sort %d: %w", index, err)
			}
			if field, exists := operation.Config["by"]; exists {
				text, ok := field.(string)
				if !ok || !validPipelineField(text) {
					return fmt.Errorf("pipeline sort %d has an invalid field", index)
				}
			}
			if descending, exists := operation.Config["descending"]; exists {
				if _, ok := descending.(bool); !ok {
					return fmt.Errorf("pipeline sort %d descending must be boolean", index)
				}
			}
		default:
			return fmt.Errorf("pipeline operation %d has unsupported type %q", index, operation.Type)
		}
	}
	return nil
}

func validateFilterConfig(config map[string]interface{}) error {
	groupName, groupValue, grouped := filterGroup(config)
	if grouped {
		if len(config) != 1 {
			return fmt.Errorf("filter group %q cannot contain sibling properties", groupName)
		}
		conditions, ok := filterConditions(groupValue)
		if !ok || len(conditions) < 1 || len(conditions) > 16 {
			return fmt.Errorf("filter group %q requires 1 to 16 conditions", groupName)
		}
		for index, condition := range conditions {
			if _, _, nested := filterGroup(condition); nested {
				return fmt.Errorf("filter group %q condition %d must be a leaf", groupName, index)
			}
			if err := validateFilterLeaf(condition); err != nil {
				return fmt.Errorf("filter group %q condition %d: %w", groupName, index, err)
			}
		}
		return nil
	}
	return validateFilterLeaf(config)
}

func validateFilterLeaf(config map[string]interface{}) error {
	if err := allowConfigKeys(config, "field", "operator", "value"); err != nil {
		return err
	}
	field, fieldOK := config["field"].(string)
	operator, operatorOK := config["operator"].(string)
	value, valueOK := config["value"].(string)
	if !fieldOK || !operatorOK || !valueOK || !validPipelineField(field) ||
		operator != "equals" && operator != "contains" && operator != "regex" {
		return fmt.Errorf("invalid field, operator, or value")
	}
	if len(value) > 512 {
		return fmt.Errorf("expression is too long")
	}
	if operator == "regex" {
		if _, err := regexp.Compile(value); err != nil {
			return fmt.Errorf("regex: %w", err)
		}
	}
	return nil
}

func filterGroup(config map[string]interface{}) (string, interface{}, bool) {
	if value, exists := config["all"]; exists {
		return "all", value, true
	}
	if value, exists := config["any"]; exists {
		return "any", value, true
	}
	return "", nil, false
}

func filterConditions(value interface{}) ([]map[string]interface{}, bool) {
	if typed, ok := value.([]map[string]interface{}); ok {
		return typed, true
	}
	items, ok := value.([]interface{})
	if !ok {
		return nil, false
	}
	result := make([]map[string]interface{}, len(items))
	for index, item := range items {
		condition, ok := item.(map[string]interface{})
		if !ok {
			return nil, false
		}
		result[index] = condition
	}
	return result, true
}

func allowConfigKeys(config map[string]interface{}, allowed ...string) error {
	set := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		set[key] = struct{}{}
	}
	for key := range config {
		if _, exists := set[key]; !exists {
			return fmt.Errorf("unknown property %q", key)
		}
	}
	return nil
}

func validPipelineField(field string) bool {
	return field == "name" || field == "protocol" || field == "source_id" || field == "health"
}

func (m *Manager) prepareCandidates(ctx context.Context, output outputstore.Output, inputs []outputstore.NodeInput) ([]candidate, error) {
	result := make([]candidate, len(inputs))
	for index, input := range inputs {
		baseName := input.ProtocolID
		if input.NameBlobID != "" {
			name, record, err := m.store.Blob(ctx, input.NameBlobID)
			if err != nil {
				return nil, err
			}
			if record.Kind != "node_name" || !utf8.Valid(name) {
				return nil, fmt.Errorf("occurrence %s has invalid original name", input.OccurrenceID)
			}
			if strings.TrimSpace(string(name)) != "" {
				baseName = string(name)
			}
		}
		excluded := output.HealthFilterEnabled && !input.HealthStale &&
			(input.HealthState == "unhealthy" || input.RecoveryStep == 1)
		result[index] = candidate{input: input, baseName: baseName, excluded: excluded, ordinal: index}
	}
	return result, nil
}

func (m *Manager) loadAllocations(ctx context.Context, output outputstore.Output) ([]naming.Allocation, error) {
	if output.AllocationBlobID == "" {
		return nil, nil
	}
	content, record, err := m.store.Blob(ctx, output.AllocationBlobID)
	if err != nil {
		return nil, err
	}
	if record.Kind != "allocation_state" {
		return nil, fmt.Errorf("managed output allocation state has an invalid blob kind")
	}
	var allocations []naming.Allocation
	if err := json.Unmarshal(content, &allocations); err != nil {
		return nil, fmt.Errorf("decode managed output allocation state: %w", err)
	}
	return allocations, nil
}

func (m *Manager) renderCandidate(ctx context.Context, item candidate, finalName string) ([]*jsonlossless.Node, error) {
	if item.input.FormatID == singbox.FormatID {
		raw, record, err := m.store.Blob(ctx, item.input.RawBlobID)
		if err != nil {
			return nil, err
		}
		if record.Kind != "raw_node" {
			return nil, fmt.Errorf("sing-box raw node blob has invalid kind")
		}
		document, err := singbox.Parse(raw, m.registry, singbox.DefaultLimits())
		if err != nil || len(document.Nodes) != 1 {
			return nil, fmt.Errorf("parse preserved sing-box node: %w", err)
		}
		patched, _, err := patch.ApplyTag(document.Nodes[0].Raw, finalName, "managed-output-name")
		if err != nil {
			return nil, err
		}
		return []*jsonlossless.Node{patched}, nil
	}
	if item.input.CanonicalBlobID == "" || item.input.CanonicalVersion != convert.SingBoxRendererVersion {
		return nil, fmt.Errorf("protocol %s from format %s has no lossless-enough sing-box conversion", item.input.ProtocolID, item.input.FormatID)
	}
	content, record, err := m.store.Blob(ctx, item.input.CanonicalBlobID)
	if err != nil {
		return nil, err
	}
	if record.Kind != "canonical_node" {
		return nil, fmt.Errorf("converted canonical blob has invalid kind")
	}
	var converted []convert.Outbound
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.UseNumber()
	if err := decoder.Decode(&converted); err != nil || len(converted) == 0 {
		return nil, fmt.Errorf("decode converted canonical node: %w", err)
	}
	oldToNew := make(map[string]string, len(converted))
	for index, outbound := range converted {
		old, _ := outbound["tag"].(string)
		name := finalName
		if index < len(converted)-1 {
			name = fmt.Sprintf("__proxyloom_%s_%d", strings.ReplaceAll(item.input.OccurrenceID[:8], "-", ""), index+1)
		}
		oldToNew[old] = name
		outbound["tag"] = name
	}
	for _, outbound := range converted {
		rewriteStringReferences(outbound, oldToNew)
	}
	result := make([]*jsonlossless.Node, 0, len(converted))
	for _, outbound := range converted {
		encoded, err := json.Marshal(outbound)
		if err != nil {
			return nil, err
		}
		node, err := jsonlossless.Parse(encoded, jsonlossless.DefaultLimits())
		if err != nil {
			return nil, err
		}
		result = append(result, node)
	}
	return result, nil
}

func (m *Manager) renderTemplate(ctx context.Context, output outputstore.Output, nodes []*jsonlossless.Node) (*jsonlossless.Node, int, error) {
	resource, err := m.store.Resource(ctx, output.TemplateID, "template")
	if err != nil {
		return nil, 0, err
	}
	content, err := m.store.TemplateContent(ctx, resource)
	if err != nil {
		return nil, 0, err
	}
	document, err := singbox.Parse(content, m.registry, singbox.DefaultLimits())
	if err != nil || document.Shape != singbox.ShapeFullConfig {
		return nil, 0, fmt.Errorf("parse managed output template: %w", err)
	}
	root := document.Root.Clone()
	outboundArray, _ := root.Member("outbounds")
	logical := make([]*jsonlossless.Node, 0, len(document.NonNodes))
	for _, node := range document.NonNodes {
		logical = append(logical, node.Raw.Clone())
	}
	outboundArray.Elements = append(append(make([]*jsonlossless.Node, 0, len(nodes)+len(logical)), nodes...), logical...)
	tags := make([]string, 0, len(nodes))
	allTags := make(map[string]struct{}, len(outboundArray.Elements))
	for index, outbound := range outboundArray.Elements {
		tagNode, exists := outbound.Member("tag")
		tag, valid := tagNode.StringValue()
		if !exists || !valid || tag == "" {
			return nil, 0, fmt.Errorf("template outbound %d has no tag", index)
		}
		if _, duplicate := allTags[tag]; duplicate {
			return nil, 0, fmt.Errorf("template and nodes contain duplicate outbound tag %q", tag)
		}
		allTags[tag] = struct{}{}
		if index < len(nodes) {
			tags = append(tags, tag)
		}
	}
	if err := expandTemplateReferences(root, tags, allTags); err != nil {
		return nil, 0, err
	}
	return root, resource.RevisionNumber, nil
}

func applyPipeline(candidates []candidate, pipeline outputstore.PipelineConfig) error {
	for _, operation := range pipeline.Operations {
		switch operation.Type {
		case "filter":
			for index := range candidates {
				matched, err := matchesFilter(candidates[index], operation.Config)
				if err != nil {
					return err
				}
				if matched {
					candidates[index].excluded = true
				}
			}
		case "rename":
			prefix, _ := operation.Config["prefix"].(string)
			suffix, _ := operation.Config["suffix"].(string)
			pattern, _ := operation.Config["pattern"].(string)
			replacement, _ := operation.Config["replacement"].(string)
			var expression *regexp.Regexp
			var err error
			if pattern != "" {
				if len(pattern) > 512 {
					return fmt.Errorf("pipeline rename pattern is too long")
				}
				expression, err = regexp.Compile(pattern)
				if err != nil {
					return fmt.Errorf("compile pipeline rename pattern: %w", err)
				}
			}
			for index := range candidates {
				name := candidates[index].baseName
				if expression != nil {
					name = expression.ReplaceAllString(name, replacement)
				}
				name = prefix + name + suffix
				if strings.TrimSpace(name) == "" || len(name) > 512 {
					return fmt.Errorf("pipeline rename produced an invalid node name")
				}
				candidates[index].baseName = name
			}
		case "sort":
			by, _ := operation.Config["by"].(string)
			descending, _ := operation.Config["descending"].(bool)
			if by == "" {
				by = "name"
			}
			sort.SliceStable(candidates, func(i, j int) bool {
				left, right := sortValue(candidates[i], by), sortValue(candidates[j], by)
				if descending {
					return left > right
				}
				return left < right
			})
		}
	}
	return nil
}

func matchesFilter(item candidate, config map[string]interface{}) (bool, error) {
	groupName, groupValue, grouped := filterGroup(config)
	if grouped {
		conditions, ok := filterConditions(groupValue)
		if !ok || len(conditions) == 0 {
			return false, fmt.Errorf("filter group %q is invalid", groupName)
		}
		for _, condition := range conditions {
			matched, err := matchesFilter(item, condition)
			if err != nil {
				return false, err
			}
			if groupName == "all" && !matched {
				return false, nil
			}
			if groupName == "any" && matched {
				return true, nil
			}
		}
		return groupName == "all", nil
	}
	field, _ := config["field"].(string)
	operator, _ := config["operator"].(string)
	value, _ := config["value"].(string)
	actual := sortValue(item, field)
	switch operator {
	case "equals":
		return actual == value, nil
	case "contains":
		return strings.Contains(strings.ToLower(actual), strings.ToLower(value)), nil
	case "regex":
		if len(value) > 512 {
			return false, fmt.Errorf("pipeline filter expression is too long")
		}
		expression, err := regexp.Compile(value)
		if err != nil {
			return false, fmt.Errorf("compile pipeline filter: %w", err)
		}
		return expression.MatchString(actual), nil
	default:
		return false, fmt.Errorf("unsupported pipeline filter operator %q", operator)
	}
}

func sortValue(item candidate, field string) string {
	switch field {
	case "name":
		return item.baseName
	case "protocol":
		return item.input.ProtocolID
	case "source_id":
		return item.input.SourceID
	case "health":
		return item.input.HealthState
	default:
		return ""
	}
}

func rewriteStringReferences(value interface{}, replacements map[string]string) {
	switch typed := value.(type) {
	case convert.Outbound:
		for key, child := range typed {
			if text, ok := child.(string); ok {
				if replacement, exists := replacements[text]; exists && (key == "detour" || key == "tag") {
					typed[key] = replacement
				}
				continue
			}
			rewriteStringReferences(child, replacements)
		}
	case map[string]interface{}:
		for key, child := range typed {
			if text, ok := child.(string); ok {
				if replacement, exists := replacements[text]; exists && (key == "detour" || key == "tag") {
					typed[key] = replacement
				}
				continue
			}
			rewriteStringReferences(child, replacements)
		}
	case []interface{}:
		for _, child := range typed {
			rewriteStringReferences(child, replacements)
		}
	}
}

func expandTemplateReferences(node *jsonlossless.Node, nodeTags []string, allTags map[string]struct{}) error {
	if node == nil {
		return nil
	}
	if node.Kind == jsonlossless.KindObject {
		for _, member := range node.Members {
			if member.Key == "outbounds" && member.Value.Kind == jsonlossless.KindArray && stringArray(member.Value) {
				expanded := make([]*jsonlossless.Node, 0, len(member.Value.Elements)+len(nodeTags))
				for _, element := range member.Value.Elements {
					value, _ := element.StringValue()
					selected, marker, err := selectTemplateNodeTags(value, nodeTags)
					if err != nil {
						return err
					}
					if marker {
						for _, tag := range selected {
							expanded = append(expanded, jsonlossless.NewString(tag))
						}
						continue
					}
					if _, exists := allTags[value]; !exists {
						return fmt.Errorf("template references missing outbound %q", value)
					}
					expanded = append(expanded, element)
				}
				member.Value.Elements = expanded
			}
			if err := expandTemplateReferences(member.Value, nodeTags, allTags); err != nil {
				return err
			}
		}
	}
	if node.Kind == jsonlossless.KindArray {
		for _, element := range node.Elements {
			if err := expandTemplateReferences(element, nodeTags, allTags); err != nil {
				return err
			}
		}
	}
	return nil
}

func selectTemplateNodeTags(value string, nodeTags []string) ([]string, bool, error) {
	if value == "${PROXYLOOM_NODES}" {
		return nodeTags, true, nil
	}
	const (
		prefix              = "${PROXYLOOM_NODES_REGEX:"
		fallbackPrefix      = "${PROXYLOOM_NODES_REGEX_OR_ALL:"
		fallbackFirstPrefix = "${PROXYLOOM_NODES_REGEX_OR_FIRST_8:"
	)
	selectedPrefix := prefix
	fallbackLimit := 0
	if strings.HasPrefix(value, fallbackFirstPrefix) {
		selectedPrefix, fallbackLimit = fallbackFirstPrefix, 8
	} else if strings.HasPrefix(value, fallbackPrefix) {
		selectedPrefix, fallbackLimit = fallbackPrefix, -1
	} else if !strings.HasPrefix(value, prefix) {
		return nil, false, nil
	}
	if !strings.HasSuffix(value, "}") {
		return nil, false, nil
	}
	pattern := strings.TrimSuffix(strings.TrimPrefix(value, selectedPrefix), "}")
	if pattern == "" || len(pattern) > 512 {
		return nil, false, fmt.Errorf("template node-selection regex is empty or too long")
	}
	expression, err := regexp.Compile(pattern)
	if err != nil {
		return nil, false, fmt.Errorf("compile template node-selection regex: %w", err)
	}
	selected := make([]string, 0)
	for _, tag := range nodeTags {
		if expression.MatchString(tag) {
			selected = append(selected, tag)
		}
	}
	if fallbackLimit != 0 && len(selected) == 0 {
		if fallbackLimit > 0 && len(nodeTags) > fallbackLimit {
			return nodeTags[:fallbackLimit], true, nil
		}
		return nodeTags, true, nil
	}
	return selected, true, nil
}

func containsTemplateMarker(node *jsonlossless.Node) bool {
	if node == nil {
		return false
	}
	if value, ok := node.StringValue(); ok {
		return value == "${PROXYLOOM_NODES}" || strings.HasPrefix(value, "${PROXYLOOM_NODES_REGEX:") && strings.HasSuffix(value, "}")
	}
	for _, member := range node.Members {
		if containsTemplateMarker(member.Value) {
			return true
		}
	}
	for _, element := range node.Elements {
		if containsTemplateMarker(element) {
			return true
		}
	}
	return false
}

func stringArray(node *jsonlossless.Node) bool {
	for _, element := range node.Elements {
		if _, ok := element.StringValue(); !ok {
			return false
		}
	}
	return true
}
