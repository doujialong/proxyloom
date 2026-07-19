package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/doujialong/proxyloom/internal/aggregate"
	"github.com/doujialong/proxyloom/internal/storage/outputjobstore"
	"github.com/doujialong/proxyloom/internal/storage/outputstore"
)

type collectionRequest struct {
	DisplayName string `json:"display_name"`
	Members     []struct {
		Kind    string `json:"kind"`
		ID      string `json:"id"`
		Enabled *bool  `json:"enabled,omitempty"`
	} `json:"members"`
}

func (s *Server) collections(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		s.listManagedResources(response, request, "collection")
		return
	}
	if request.Method != http.MethodPost {
		methodNotAllowed(response)
		return
	}
	var input collectionRequest
	if err := decodeJSON(response, request, &input, 1<<20); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	members := make([]outputstore.Member, len(input.Members))
	for index, member := range input.Members {
		enabled := true
		if member.Enabled != nil {
			enabled = *member.Enabled
		}
		members[index] = outputstore.Member{Kind: member.Kind, ID: member.ID, Enabled: enabled}
	}
	resource, err := s.aggregate.Store().CreateCollection(request.Context(), input.DisplayName, outputstore.CollectionConfig{Members: members})
	if err != nil {
		s.writeManagedError(response, "collection_create_failed", err)
		return
	}
	writeJSON(response, http.StatusCreated, managedResourceView(resource, outputstore.CollectionConfig{Members: members}))
}

func (s *Server) collectionAction(response http.ResponseWriter, request *http.Request) {
	id := strings.Trim(strings.TrimPrefix(request.URL.Path, "/api/v1/collections/"), "/")
	if id == "" || strings.Contains(id, "/") {
		writeError(response, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	resource, err := s.aggregate.Store().Resource(request.Context(), id, "collection")
	if err != nil {
		s.writeManagedError(response, "collection_read_failed", err)
		return
	}
	etag := managedResourceETag(resource)
	if request.Method == http.MethodGet {
		config, err := s.aggregate.Store().CollectionConfig(request.Context(), resource)
		if err != nil {
			s.writeManagedError(response, "collection_read_failed", err)
			return
		}
		response.Header().Set("ETag", etag)
		writeJSON(response, http.StatusOK, managedResourceView(resource, config))
		return
	}
	if request.Method != http.MethodPut {
		methodNotAllowed(response)
		return
	}
	if request.Header.Get("If-Match") != etag {
		response.Header().Set("ETag", etag)
		writeError(response, http.StatusPreconditionFailed, "precondition_failed", "If-Match does not match the current collection revision")
		return
	}
	var input collectionRequest
	if err := decodeJSON(response, request, &input, 1<<20); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	members := make([]outputstore.Member, len(input.Members))
	for index, member := range input.Members {
		enabled := true
		if member.Enabled != nil {
			enabled = *member.Enabled
		}
		members[index] = outputstore.Member{Kind: member.Kind, ID: member.ID, Enabled: enabled}
	}
	config := outputstore.CollectionConfig{Members: members}
	updated, err := s.aggregate.Store().UpdateCollection(request.Context(), id, input.DisplayName, resource.RevisionNumber, config)
	if err != nil {
		s.writeManagedError(response, "collection_update_failed", err)
		return
	}
	if err := s.aggregate.EnqueueForCollection(request.Context(), id); err != nil {
		s.writeManagedError(response, "collection_rebuild_enqueue_failed", err)
		return
	}
	response.Header().Set("ETag", managedResourceETag(updated))
	writeJSON(response, http.StatusOK, managedResourceView(updated, config))
}

type pipelineRequest struct {
	DisplayName string                  `json:"display_name"`
	Operations  []outputstore.Operation `json:"operations"`
}

func (s *Server) pipelines(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		s.listManagedResources(response, request, "pipeline")
		return
	}
	if request.Method != http.MethodPost {
		methodNotAllowed(response)
		return
	}
	var input pipelineRequest
	if err := decodeJSON(response, request, &input, 1<<20); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	config := outputstore.PipelineConfig{Operations: input.Operations}
	resource, err := s.aggregate.CreatePipeline(request.Context(), input.DisplayName, config)
	if err != nil {
		s.writeManagedError(response, "pipeline_create_failed", err)
		return
	}
	writeJSON(response, http.StatusCreated, managedResourceView(resource, config))
}

func (s *Server) pipelineAction(response http.ResponseWriter, request *http.Request) {
	id := strings.Trim(strings.TrimPrefix(request.URL.Path, "/api/v1/pipelines/"), "/")
	if id == "" || strings.Contains(id, "/") {
		writeError(response, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	resource, err := s.aggregate.Store().Resource(request.Context(), id, "pipeline")
	if err != nil {
		s.writeManagedError(response, "pipeline_read_failed", err)
		return
	}
	config, err := s.aggregate.Store().PipelineConfig(request.Context(), resource)
	if err != nil {
		s.writeManagedError(response, "pipeline_read_failed", err)
		return
	}
	etag := managedResourceETag(resource)
	if request.Method == http.MethodGet {
		response.Header().Set("ETag", etag)
		writeJSON(response, http.StatusOK, managedResourceView(resource, config))
		return
	}
	if request.Method != http.MethodPut {
		methodNotAllowed(response)
		return
	}
	if request.Header.Get("If-Match") != etag {
		response.Header().Set("ETag", etag)
		writeError(response, http.StatusPreconditionFailed, "precondition_failed", "If-Match does not match the current pipeline revision")
		return
	}
	var input pipelineRequest
	if err := decodeJSON(response, request, &input, 1<<20); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	config = outputstore.PipelineConfig{Operations: input.Operations}
	updated, err := s.aggregate.Store().UpdatePipeline(request.Context(), id, input.DisplayName, resource.RevisionNumber, config)
	if err != nil {
		s.writeManagedError(response, "pipeline_update_failed", err)
		return
	}
	if err := s.aggregate.EnqueueForPipeline(request.Context(), id); err != nil {
		s.writeManagedError(response, "pipeline_rebuild_enqueue_failed", err)
		return
	}
	response.Header().Set("ETag", managedResourceETag(updated))
	writeJSON(response, http.StatusOK, managedResourceView(updated, config))
}

type templateRequest struct {
	DisplayName              string            `json:"display_name"`
	SourceType               string            `json:"source_type,omitempty"`
	TargetFormat             string            `json:"target_format,omitempty"`
	Content                  string            `json:"content"`
	URL                      string            `json:"url,omitempty"`
	Headers                  map[string]string `json:"headers,omitempty"`
	PrivateNetworkAuthorized bool              `json:"private_network_authorized,omitempty"`
	RefreshIntervalSeconds   int               `json:"refresh_interval_seconds,omitempty"`
}

func (s *Server) templates(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		s.listManagedResources(response, request, "template")
		return
	}
	if request.Method != http.MethodPost {
		methodNotAllowed(response)
		return
	}
	var input templateRequest
	if err := decodeJSON(response, request, &input, (50<<20)+4096); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if input.SourceType == "" {
		input.SourceType = "inline"
	}
	if input.TargetFormat == "" {
		input.TargetFormat = "sing-box"
	}
	if input.TargetFormat != "sing-box" || input.SourceType != "inline" && input.SourceType != "remote" {
		writeError(response, http.StatusUnprocessableEntity, "template_create_failed", "template source type or target format is unsupported")
		return
	}
	var resource outputstore.Resource
	var err error
	if input.SourceType == "remote" {
		resource, err = s.aggregate.CreateRemoteTemplate(request.Context(), input.DisplayName, aggregate.RemoteTemplateCreate{
			URL: input.URL, Headers: input.Headers,
			PrivateNetworkAuthorized: input.PrivateNetworkAuthorized,
			RefreshIntervalSeconds:   input.RefreshIntervalSeconds,
		})
	} else {
		if input.URL != "" || len(input.Headers) != 0 || input.RefreshIntervalSeconds != 0 || input.PrivateNetworkAuthorized {
			writeError(response, http.StatusUnprocessableEntity, "template_create_failed", "inline template cannot contain remote source settings")
			return
		}
		resource, err = s.aggregate.CreateTemplate(request.Context(), input.DisplayName, []byte(input.Content))
	}
	if err != nil {
		s.writeManagedError(response, "template_create_failed", err)
		return
	}
	configuration, err := s.templateConfiguration(request.Context(), resource)
	if err != nil {
		s.writeManagedError(response, "template_read_failed", err)
		return
	}
	writeJSON(response, http.StatusCreated, managedResourceView(resource, configuration))
}

func (s *Server) templateAction(response http.ResponseWriter, request *http.Request) {
	path := strings.Trim(strings.TrimPrefix(request.URL.Path, "/api/v1/templates/"), "/")
	parts := strings.Split(path, "/")
	if len(parts) == 1 && parts[0] != "" && request.Method == http.MethodGet {
		resource, err := s.aggregate.Store().Resource(request.Context(), parts[0], "template")
		if err != nil {
			s.writeManagedError(response, "template_read_failed", err)
			return
		}
		configuration, err := s.templateConfiguration(request.Context(), resource)
		if err != nil {
			s.writeManagedError(response, "template_read_failed", err)
			return
		}
		response.Header().Set("ETag", managedResourceETag(resource))
		writeJSON(response, http.StatusOK, managedResourceView(resource, configuration))
		return
	}
	if len(parts) != 2 || parts[0] == "" || parts[1] != "refresh" || request.Method != http.MethodPost {
		if request.Method != http.MethodPost && len(parts) == 2 {
			methodNotAllowed(response)
		} else {
			writeError(response, http.StatusNotFound, "not_found", "resource not found")
		}
		return
	}
	resource, changed, err := s.aggregate.RefreshRemoteTemplate(request.Context(), parts[0])
	if err != nil {
		s.writeManagedError(response, "template_refresh_failed", err)
		return
	}
	configuration, err := s.templateConfiguration(request.Context(), resource)
	if err != nil {
		s.writeManagedError(response, "template_read_failed", err)
		return
	}
	view := managedResourceView(resource, configuration)
	view["changed"] = changed
	writeJSON(response, http.StatusOK, view)
}

func (s *Server) templateConfiguration(ctx context.Context, resource outputstore.Resource) (map[string]interface{}, error) {
	config, remote, err := s.aggregate.Store().RemoteTemplateConfig(ctx, resource)
	if err != nil {
		return nil, err
	}
	if !remote {
		return map[string]interface{}{"source_type": "inline", "target_format": "sing-box"}, nil
	}
	return map[string]interface{}{
		"source_type": "remote", "target_format": "sing-box",
		"masked_location":            maskTemplateURL(config.URL),
		"refresh_interval_seconds":   config.RefreshIntervalSeconds,
		"private_network_authorized": config.PrivateNetworkAuthorized,
		"fetched_at":                 config.FetchedAt.UTC().Format(time.RFC3339Nano),
		"content_sha256":             config.ContentSHA256,
	}, nil
}

func maskTemplateURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "remote"
	}
	return parsed.Scheme + "://" + parsed.Host + "/..."
}

func (s *Server) listManagedResources(response http.ResponseWriter, request *http.Request, resourceType string) {
	items, err := s.aggregate.Store().Resources(request.Context(), resourceType)
	if err != nil {
		s.writeManagedError(response, resourceType+"_list_failed", err)
		return
	}
	views := make([]map[string]interface{}, 0, len(items))
	for _, resource := range items {
		var configuration interface{}
		switch resourceType {
		case "collection":
			configuration, err = s.aggregate.Store().CollectionConfig(request.Context(), resource)
		case "pipeline":
			configuration, err = s.aggregate.Store().PipelineConfig(request.Context(), resource)
		case "template":
			configuration, err = s.templateConfiguration(request.Context(), resource)
		}
		if err != nil {
			s.writeManagedError(response, resourceType+"_list_failed", err)
			return
		}
		views = append(views, managedResourceView(resource, configuration))
	}
	writeJSON(response, http.StatusOK, map[string]interface{}{
		"items": views, "page": map[string]interface{}{"has_more": false, "next_cursor": nil},
	})
}

type outputRequest struct {
	DisplayName         string   `json:"display_name"`
	CollectionID        string   `json:"collection_id"`
	PipelineID          string   `json:"pipeline_id,omitempty"`
	TemplateID          string   `json:"template_id,omitempty"`
	TargetProfile       string   `json:"target_profile,omitempty"`
	OutputShape         string   `json:"output_shape,omitempty"`
	HealthFilterEnabled bool     `json:"health_filter_enabled,omitempty"`
	MinimumNodes        int      `json:"minimum_nodes,omitempty"`
	MaximumDropRatio    *float64 `json:"maximum_drop_ratio,omitempty"`
}

type outputPolicyPatch struct {
	HealthFilterEnabled *bool    `json:"health_filter_enabled,omitempty"`
	MinimumNodes        *int     `json:"minimum_nodes,omitempty"`
	MaximumDropRatio    *float64 `json:"maximum_drop_ratio,omitempty"`
}

func (s *Server) outputs(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		items, err := s.aggregate.Store().Outputs(request.Context())
		if err != nil {
			s.writeManagedError(response, "output_list_failed", err)
			return
		}
		views := make([]map[string]interface{}, len(items))
		for index, item := range items {
			views[index] = managedOutputView(item)
		}
		writeJSON(response, http.StatusOK, map[string]interface{}{
			"items": views, "page": map[string]interface{}{"has_more": false, "next_cursor": nil},
		})
		return
	}
	if request.Method != http.MethodPost {
		methodNotAllowed(response)
		return
	}
	var input outputRequest
	if err := decodeJSON(response, request, &input, 64<<10); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if input.TargetProfile == "" {
		input.TargetProfile = "sing-box-1.12.25"
	}
	if input.OutputShape == "" {
		input.OutputShape = "outbounds_object"
	}
	output, credential, err := s.aggregate.Store().CreateOutput(request.Context(), outputstore.OutputCreate{
		DisplayName: input.DisplayName, CollectionID: input.CollectionID, PipelineID: input.PipelineID,
		TemplateID: input.TemplateID, TargetProfile: input.TargetProfile, OutputShape: input.OutputShape,
		HealthFilterEnabled: input.HealthFilterEnabled, MinimumNodes: input.MinimumNodes,
		MaximumDropRatio: input.MaximumDropRatio,
	})
	if err != nil {
		s.writeManagedError(response, "output_create_failed", err)
		return
	}
	view := managedOutputView(output)
	view["publication_token_id"] = credential.ID
	view["subscription_url"] = "/subscriptions/" + credential.Token
	writeJSON(response, http.StatusCreated, view)
}

func (s *Server) outputAction(response http.ResponseWriter, request *http.Request) {
	path := strings.Trim(strings.TrimPrefix(request.URL.Path, "/api/v1/outputs/"), "/")
	parts := strings.Split(path, "/")
	if len(parts) == 1 && parts[0] != "" && request.Method == http.MethodGet {
		output, err := s.aggregate.Store().Output(request.Context(), parts[0])
		if err != nil {
			s.writeManagedError(response, "output_read_failed", err)
			return
		}
		writeJSON(response, http.StatusOK, managedOutputView(output))
		return
	}
	if len(parts) == 1 && parts[0] != "" && request.Method == http.MethodPatch {
		var input outputPolicyPatch
		if err := decodeJSON(response, request, &input, 16<<10); err != nil {
			writeError(response, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if input.HealthFilterEnabled == nil && input.MinimumNodes == nil && input.MaximumDropRatio == nil {
			writeError(response, http.StatusBadRequest, "invalid_request", "at least one output policy field is required")
			return
		}
		current, err := s.aggregate.Store().Output(request.Context(), parts[0])
		if err != nil {
			s.writeManagedError(response, "output_read_failed", err)
			return
		}
		update := outputstore.OutputPolicyUpdate{
			HealthFilterEnabled: current.HealthFilterEnabled,
			MinimumNodes:        current.MinimumNodes, MaximumDropRatio: current.MaximumDropRatio,
		}
		if input.HealthFilterEnabled != nil {
			update.HealthFilterEnabled = *input.HealthFilterEnabled
		}
		if input.MinimumNodes != nil {
			update.MinimumNodes = *input.MinimumNodes
		}
		if input.MaximumDropRatio != nil {
			update.MaximumDropRatio = *input.MaximumDropRatio
		}
		updated, err := s.aggregate.Store().UpdateOutputPolicy(request.Context(), parts[0], update)
		if err != nil {
			s.writeManagedError(response, "output_policy_update_failed", err)
			return
		}
		job, err := s.aggregate.EnqueueBuild(request.Context(), parts[0], "output-policy-update-"+parts[0])
		if err != nil {
			s.writeManagedError(response, "output_build_failed", err)
			return
		}
		view := managedOutputView(updated)
		view["job_id"] = job.ID
		writeJSON(response, http.StatusAccepted, view)
		return
	}
	if len(parts) != 2 || parts[0] == "" || request.Method != http.MethodPost {
		if request.Method != http.MethodPost && len(parts) == 2 {
			methodNotAllowed(response)
		} else {
			writeError(response, http.StatusNotFound, "not_found", "resource not found")
		}
		return
	}
	switch parts[1] {
	case "build", "builds":
		job, err := s.aggregate.EnqueueBuild(request.Context(), parts[0], "manual-build-"+parts[0])
		if err != nil {
			s.writeManagedError(response, "output_build_failed", err)
			return
		}
		writeJSON(response, http.StatusAccepted, managedBuildJobView(job))
	case "tokens":
		var input struct {
			RevokeExisting *bool `json:"revoke_existing,omitempty"`
		}
		if request.Body != nil && request.ContentLength != 0 {
			if err := decodeJSON(response, request, &input, 8<<10); err != nil {
				writeError(response, http.StatusBadRequest, "invalid_request", err.Error())
				return
			}
		}
		revoke := true
		if input.RevokeExisting != nil {
			revoke = *input.RevokeExisting
		}
		credential, err := s.aggregate.Store().RotateCredential(request.Context(), parts[0], revoke)
		if err != nil {
			s.writeManagedError(response, "publication_token_create_failed", err)
			return
		}
		writeJSON(response, http.StatusCreated, map[string]interface{}{
			"id": credential.ID, "output_id": credential.OutputID,
			"subscription_url": "/subscriptions/" + credential.Token,
		})
	default:
		writeError(response, http.StatusNotFound, "not_found", "resource not found")
	}
}

func managedResourceView(resource outputstore.Resource, configuration interface{}) map[string]interface{} {
	return map[string]interface{}{
		"id": resource.ID, "type": resource.Type, "display_name": resource.DisplayName,
		"revision_number": resource.RevisionNumber, "lifecycle_state": resource.LifecycleState,
		"configuration": configuration,
		"created_at":    resource.CreatedAt.UTC().Format(time.RFC3339Nano),
		"updated_at":    resource.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func managedResourceETag(resource outputstore.Resource) string {
	return fmt.Sprintf(`"managed-resource-%s-%d"`, resource.ID, resource.RevisionNumber)
}

func managedOutputView(output outputstore.Output) map[string]interface{} {
	return map[string]interface{}{
		"id": output.ID, "display_name": output.DisplayName,
		"collection_id": output.CollectionID, "pipeline_id": nullable(output.PipelineID),
		"template_id": nullable(output.TemplateID), "target_profile": output.TargetProfile,
		"output_shape": output.OutputShape, "health_filter_enabled": output.HealthFilterEnabled,
		"minimum_nodes": output.MinimumNodes, "maximum_drop_ratio": output.MaximumDropRatio,
		"current_artifact_id": nullable(output.CurrentArtifactID),
		"next_build_sequence": output.NextBuildSequence, "lifecycle_state": output.LifecycleState,
		"created_at": output.CreatedAt.UTC().Format(time.RFC3339Nano),
		"updated_at": output.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func managedArtifactView(artifact outputstore.Artifact) map[string]interface{} {
	return map[string]interface{}{
		"id": artifact.ID, "output_id": artifact.OutputID, "build_sequence": artifact.BuildSequence,
		"content_type": artifact.ContentType, "content_length": artifact.ContentLength,
		"sha256": artifact.PublicSHA256, "node_count": artifact.NodeCount,
		"excluded_count": artifact.ExcludedCount, "warning_count": artifact.WarningCount,
		"target_profile": artifact.TargetProfile, "validator_version": artifact.ValidatorVersion,
		"created_at": artifact.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func managedBuildJobView(job outputjobstore.Job) map[string]interface{} {
	return map[string]interface{}{
		"id": job.ID, "job_type": "output_build", "output_id": job.OutputID,
		"trigger_kind": job.TriggerKind, "trigger_source_id": nullable(job.TriggerSourceID),
		"status": job.Status, "attempt": job.Attempt, "max_attempts": job.MaxAttempts,
		"error_code": nullable(job.ErrorCode), "error_detail": nullable(job.ErrorDetail),
		"due_at":     job.DueAt.UTC().Format(time.RFC3339Nano),
		"created_at": job.CreatedAt.UTC().Format(time.RFC3339Nano),
		"started_at": nullableTimeValue(job.StartedAt), "finished_at": nullableTimeValue(job.FinishedAt),
	}
}

func (s *Server) writeManagedError(response http.ResponseWriter, code string, err error) {
	status := http.StatusUnprocessableEntity
	if errors.Is(err, outputstore.ErrNotFound) {
		status = http.StatusNotFound
	} else if errors.Is(err, outputstore.ErrConflict) {
		status = http.StatusConflict
	}
	s.log("managed resource operation failed: %v", err)
	writeError(response, status, code, publicMessage(err))
}
