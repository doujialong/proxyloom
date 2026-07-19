package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/doujialong/proxyloom/internal/app"
	"github.com/doujialong/proxyloom/internal/storage/sourcestore"
)

type sourceCursor struct {
	UpdatedAt int64  `json:"updated_at"`
	ID        string `json:"id"`
	Health    string `json:"health,omitempty"`
	Query     string `json:"query,omitempty"`
	Archived  bool   `json:"archived,omitempty"`
	ExpiresAt int64  `json:"expires_at"`
}

func (s *Server) listSources(response http.ResponseWriter, request *http.Request) {
	limit, err := queryLimit(request, 50)
	if err != nil {
		writeError(response, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	health := request.URL.Query().Get("status")
	query := strings.TrimSpace(request.URL.Query().Get("query"))
	includeArchived := request.URL.Query().Get("include_archived") == "true"
	options := sourcestore.SourceListOptions{
		Limit: limit, Health: health, Query: query, IncludeArchived: includeArchived,
	}
	if encoded := request.URL.Query().Get("cursor"); encoded != "" {
		cursor, err := decodeSourceCursor(encoded)
		if err != nil || cursor.Health != health || cursor.Query != query || cursor.Archived != includeArchived || s.now().Unix() >= cursor.ExpiresAt {
			writeError(response, http.StatusBadRequest, "invalid_cursor", "source cursor is invalid, expired, or belongs to different filters")
			return
		}
		before := time.UnixMilli(cursor.UpdatedAt).UTC()
		options.BeforeUpdatedAt = &before
		options.BeforeID = cursor.ID
	}
	items, hasMore, err := s.manager.ListSources(request.Context(), options)
	if err != nil {
		writeError(response, http.StatusBadRequest, "source_list_failed", publicMessage(err))
		return
	}
	views := make([]map[string]interface{}, len(items))
	for index, item := range items {
		views[index] = sourceView(item)
	}
	page := map[string]interface{}{"has_more": hasMore, "next_cursor": nil}
	if hasMore && len(items) > 0 {
		last := items[len(items)-1].Source
		cursor, err := encodeSourceCursor(sourceCursor{
			UpdatedAt: last.UpdatedAt.UnixMilli(), ID: last.ID, Health: health, Query: query,
			Archived: includeArchived, ExpiresAt: s.now().Add(15 * time.Minute).Unix(),
		})
		if err != nil {
			writeError(response, http.StatusInternalServerError, "cursor_create_failed", "source page cursor could not be created")
			return
		}
		page["next_cursor"] = cursor
	}
	writeJSON(response, http.StatusOK, map[string]interface{}{"items": views, "page": page})
}

func (s *Server) getSource(response http.ResponseWriter, request *http.Request, sourceID string) {
	detail, err := s.manager.GetSource(request.Context(), sourceID)
	if err != nil {
		writeSourceReadError(response, err)
		return
	}
	response.Header().Set("ETag", sourceETag(detail.Source))
	writeJSON(response, http.StatusOK, sourceView(detail))
}

func (s *Server) archiveSource(response http.ResponseWriter, request *http.Request, sourceID string) {
	detail, err := s.manager.GetSource(request.Context(), sourceID)
	if err != nil {
		writeSourceReadError(response, err)
		return
	}
	if request.Header.Get("If-Match") != sourceETag(detail.Source) {
		response.Header().Set("ETag", sourceETag(detail.Source))
		writeError(response, http.StatusPreconditionFailed, "precondition_failed", "If-Match does not match the current source revision")
		return
	}
	if _, err := s.manager.ArchiveSource(request.Context(), sourceID, detail.Source.UpdatedAt); err != nil {
		status := http.StatusConflict
		if errors.Is(err, sourcestore.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(response, status, "source_archive_failed", publicMessage(err))
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (s *Server) sourceHistory(response http.ResponseWriter, request *http.Request, sourceID, kind string) {
	limit, err := queryLimit(request, 50)
	if err != nil {
		writeError(response, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	page := map[string]interface{}{"has_more": false, "next_cursor": nil}
	switch kind {
	case "revisions":
		items, err := s.manager.ListSourceRevisions(request.Context(), sourceID, limit)
		if err != nil {
			writeSourceReadError(response, err)
			return
		}
		views := make([]map[string]interface{}, len(items))
		for index, item := range items {
			views[index] = revisionView(item)
		}
		writeJSON(response, http.StatusOK, map[string]interface{}{"items": views, "page": page})
	case "refresh-attempts":
		items, err := s.manager.ListRefreshAttempts(request.Context(), sourceID, limit)
		if err != nil {
			writeSourceReadError(response, err)
			return
		}
		views := make([]map[string]interface{}, len(items))
		for index, item := range items {
			views[index] = attemptView(item)
		}
		writeJSON(response, http.StatusOK, map[string]interface{}{"items": views, "page": page})
	case "snapshots":
		items, err := s.manager.ListSnapshots(request.Context(), sourceID, limit)
		if err != nil {
			writeSourceReadError(response, err)
			return
		}
		views := make([]map[string]interface{}, len(items))
		for index, item := range items {
			views[index] = snapshotView(item, s.now())
		}
		writeJSON(response, http.StatusOK, map[string]interface{}{"items": views, "page": page})
	default:
		writeError(response, http.StatusNotFound, "not_found", "resource not found")
	}
}

func sourceView(detail app.SourceDetail) map[string]interface{} {
	view := map[string]interface{}{
		"id": detail.Source.ID, "display_name": detail.Source.DisplayName,
		"lifecycle_state": detail.Source.LifecycleState, "health": detail.Source.Health,
		"stale": detail.Stale, "draft_revision": revisionView(detail.Draft),
		"published_revision": nil, "current_snapshot_id": nullable(detail.Source.CurrentSnapshotID),
		"masked_location": nullable(detail.MaskedLocation),
		"masked_proxy":    nullable(detail.MaskedProxy),
		"configuration": map[string]interface{}{
			"type": detail.Config.Type, "input_format": detail.Config.InputFormat,
			"output_format": detail.Config.OutputFormat, "minimum_nodes": detail.Config.MinimumNodes,
			"maximum_drop_ratio":         detail.Config.MaximumDropRatio,
			"refresh_interval_seconds":   detail.Config.RefreshIntervalSeconds,
			"timeout_seconds":            detail.Config.TimeoutSeconds,
			"proxy_configured":           detail.Config.ProxyURL != "",
			"private_network_authorized": detail.Config.PrivateNetworkAuthorized,
			"max_response_bytes":         detail.Config.MaxResponseBytes,
			"health_filter_enabled":      detail.Config.HealthFilterEnabled,
		},
		"created_at": detail.Source.CreatedAt.UTC().Format(time.RFC3339Nano),
		"updated_at": detail.Source.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
	if detail.Published != nil {
		view["published_revision"] = revisionView(*detail.Published)
	}
	return view
}

func revisionView(revision sourcestore.Revision) map[string]interface{} {
	return map[string]interface{}{
		"id": revision.ID, "number": revision.Number, "state": revision.State,
		"created_at":   revision.CreatedAt.UTC().Format(time.RFC3339Nano),
		"published_at": nullableTimeValue(revision.PublishedAt),
	}
}

func attemptView(attempt sourcestore.Attempt) map[string]interface{} {
	return map[string]interface{}{
		"id": attempt.ID, "status": attempt.Status, "trigger": attempt.Trigger,
		"http_status": attempt.HTTPStatus, "total_ms": attempt.TotalMS,
		"node_count": attempt.NodeCount, "warning_count": attempt.WarningCount,
		"error_code": nullable(attempt.ErrorCode), "accepted_snapshot_id": nullable(attempt.AcceptedSnapshotID),
		"started_at":  attempt.StartedAt.UTC().Format(time.RFC3339Nano),
		"finished_at": nullableTimeValue(attempt.FinishedAt),
	}
}

func snapshotView(snapshot sourcestore.Snapshot, now time.Time) map[string]interface{} {
	return map[string]interface{}{
		"id": snapshot.ID, "node_count": snapshot.NodeCount,
		"logical_outbound_count": snapshot.LogicalOutboundCount, "warning_count": snapshot.WarningCount,
		"stale":       !now.UTC().Before(snapshot.StaleAfter),
		"accepted_at": snapshot.AcceptedAt.UTC().Format(time.RFC3339Nano),
	}
}

func sourceETag(source sourcestore.Source) string {
	return fmt.Sprintf(`"source-%d-%d"`, source.UpdatedAt.UnixMilli(), source.RevisionCounter)
}

func queryLimit(request *http.Request, defaultValue int) (int, error) {
	value := request.URL.Query().Get("limit")
	if value == "" {
		return defaultValue, nil
	}
	limit, err := strconv.Atoi(value)
	if err != nil || limit < 1 || limit > 200 {
		return 0, fmt.Errorf("limit must be between 1 and 200")
	}
	return limit, nil
}

func encodeSourceCursor(cursor sourceCursor) (string, error) {
	encoded, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeSourceCursor(value string) (sourceCursor, error) {
	if len(value) > 2048 {
		return sourceCursor{}, fmt.Errorf("cursor is too long")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return sourceCursor{}, err
	}
	var cursor sourceCursor
	decoder := json.NewDecoder(strings.NewReader(string(decoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cursor); err != nil || cursor.UpdatedAt <= 0 || len(cursor.ID) != 36 || cursor.ExpiresAt <= 0 {
		return sourceCursor{}, fmt.Errorf("cursor is malformed")
	}
	return cursor, nil
}

func writeSourceReadError(response http.ResponseWriter, err error) {
	if errors.Is(err, sourcestore.ErrNotFound) {
		writeError(response, http.StatusNotFound, "not_found", "source not found")
		return
	}
	writeError(response, http.StatusInternalServerError, "source_read_failed", "source data is temporarily unavailable")
}

func nullableTimeValue(value *time.Time) interface{} {
	if value == nil {
		return nil
	}
	return value.UTC().Format(time.RFC3339Nano)
}
