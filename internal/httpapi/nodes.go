package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/doujialong/proxyloom/internal/app"
	"github.com/doujialong/proxyloom/internal/storage/healthstore"
)

type nodeCursor struct {
	LastSeenAt int64  `json:"last_seen_at"`
	ID         string `json:"id"`
	SourceID   string `json:"source_id,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	Health     string `json:"health,omitempty"`
	ExpiresAt  int64  `json:"expires_at"`
}

func (s *Server) nodes(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(response)
		return
	}
	limit, err := queryLimit(request, 50)
	if err != nil {
		writeError(response, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	sourceID := request.URL.Query().Get("source_id")
	protocolID := request.URL.Query().Get("protocol")
	health := request.URL.Query().Get("health")
	options := healthstore.NodeListOptions{
		SourceID: sourceID, ProtocolID: protocolID, State: healthstore.State(health),
		PresentOnly: true, Limit: limit,
	}
	if encoded := request.URL.Query().Get("cursor"); encoded != "" {
		cursor, err := decodeNodeCursor(encoded)
		if err != nil || cursor.SourceID != sourceID || cursor.Protocol != protocolID || cursor.Health != health || s.now().Unix() >= cursor.ExpiresAt {
			writeError(response, http.StatusBadRequest, "invalid_cursor", "node cursor is invalid, expired, or belongs to different filters")
			return
		}
		before := time.UnixMilli(cursor.LastSeenAt).UTC()
		options.BeforeLastSeenAt = &before
		options.BeforeID = cursor.ID
	}
	items, hasMore, err := s.manager.ListNodes(request.Context(), options)
	if err != nil {
		writeError(response, http.StatusBadRequest, "node_list_failed", publicMessage(err))
		return
	}
	views := make([]map[string]interface{}, len(items))
	for index, item := range items {
		views[index] = nodeView(item)
	}
	page := map[string]interface{}{"has_more": hasMore, "next_cursor": nil}
	if hasMore && len(items) > 0 {
		last := items[len(items)-1].Summary
		cursor, err := encodeNodeCursor(nodeCursor{
			LastSeenAt: last.LastSeenAt.UnixMilli(), ID: last.NodeOccurrenceID, SourceID: sourceID,
			Protocol: protocolID, Health: health, ExpiresAt: s.now().Add(15 * time.Minute).Unix(),
		})
		if err != nil {
			writeError(response, http.StatusInternalServerError, "cursor_create_failed", "node page cursor could not be created")
			return
		}
		page["next_cursor"] = cursor
	}
	writeJSON(response, http.StatusOK, map[string]interface{}{"items": views, "page": page})
}

func encodeNodeCursor(cursor nodeCursor) (string, error) {
	encoded, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeNodeCursor(value string) (nodeCursor, error) {
	if len(value) > 2048 {
		return nodeCursor{}, fmt.Errorf("cursor is too long")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nodeCursor{}, err
	}
	var cursor nodeCursor
	decoder := json.NewDecoder(strings.NewReader(string(decoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cursor); err != nil || cursor.LastSeenAt <= 0 || len(cursor.ID) != 36 || cursor.ExpiresAt <= 0 {
		return nodeCursor{}, fmt.Errorf("cursor is malformed")
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nodeCursor{}, fmt.Errorf("cursor is malformed")
	}
	return cursor, nil
}

func (s *Server) nodeAction(response http.ResponseWriter, request *http.Request) {
	path := strings.TrimPrefix(request.URL.Path, "/api/v1/nodes/")
	parts := strings.Split(path, "/")
	if len(parts) == 1 && parts[0] != "" && request.Method == http.MethodGet {
		item, err := s.manager.GetNode(request.Context(), parts[0])
		if err != nil {
			writeNodeError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, nodeView(item))
		return
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] == "health-records" && request.Method == http.MethodGet {
		limit, err := queryLimit(request, 50)
		if err != nil {
			writeError(response, http.StatusBadRequest, "invalid_pagination", err.Error())
			return
		}
		records, err := s.manager.NodeHealthRecords(request.Context(), parts[0], limit)
		if err != nil {
			writeNodeError(response, err)
			return
		}
		views := make([]map[string]interface{}, len(records))
		for index, record := range records {
			views[index] = healthRecordView(record, s.now())
		}
		writeJSON(response, http.StatusOK, map[string]interface{}{
			"items": views, "page": map[string]interface{}{"has_more": false, "next_cursor": nil},
		})
		return
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] == "checks" && request.Method == http.MethodPost {
		if err := s.manager.EnqueueNodeCheck(request.Context(), parts[0]); err != nil {
			writeNodeError(response, err)
			return
		}
		writeJSON(response, http.StatusAccepted, map[string]interface{}{
			"node_occurrence_id": parts[0], "status": "queued",
		})
		return
	}
	writeError(response, http.StatusNotFound, "not_found", "resource not found")
}

type nodeChecksRequest struct {
	NodeOccurrenceIDs []string `json:"node_occurrence_ids"`
}

func (s *Server) nodeChecks(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(response)
		return
	}
	var input nodeChecksRequest
	if err := decodeJSON(response, request, &input, 64<<10); err != nil || len(input.NodeOccurrenceIDs) == 0 || len(input.NodeOccurrenceIDs) > 200 {
		writeError(response, http.StatusBadRequest, "invalid_request", "node_occurrence_ids must contain 1 to 200 IDs")
		return
	}
	for _, id := range input.NodeOccurrenceIDs {
		if err := s.manager.EnqueueNodeCheck(request.Context(), id); err != nil {
			writeNodeError(response, err)
			return
		}
	}
	writeJSON(response, http.StatusAccepted, map[string]interface{}{
		"accepted": len(input.NodeOccurrenceIDs), "status": "queued",
	})
}

func (s *Server) healthCapacity(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(response)
		return
	}
	capacity, err := s.manager.HealthCapacity(request.Context())
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "health_capacity_unavailable", "health queue capacity is unavailable")
		return
	}
	suppressed, conclusion, err := s.manager.HealthGuard(request.Context())
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "health_guard_unavailable", "health failure guard is unavailable")
		return
	}
	writeJSON(response, http.StatusOK, map[string]interface{}{
		"queue_total": capacity.Total, "queued": capacity.Queued,
		"running": capacity.Running, "dormant": capacity.Dormant,
		"queue_hard_limit":  capacity.HardLimit,
		"filter_suppressed": suppressed, "guard_conclusion": conclusion,
		"executor_concurrency": 4, "configured_concurrency": 16,
	})
}

func nodeView(item app.NodeDetail) map[string]interface{} {
	return map[string]interface{}{
		"id": item.Summary.NodeOccurrenceID, "source_id": item.Summary.SourceID,
		"protocol": item.Summary.ProtocolID, "original_name": item.OriginalName,
		"occurrence_state": item.Summary.OccurrenceState,
		"fingerprint_kind": item.Summary.FingerprintKind,
		"health":           item.Summary.HealthState, "stale": item.Summary.Stale,
		"last_seen_at":      item.Summary.LastSeenAt.UTC().Format(time.RFC3339Nano),
		"health_updated_at": item.Summary.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func healthRecordView(record healthstore.Record, now time.Time) map[string]interface{} {
	return map[string]interface{}{
		"id": record.ID, "node_occurrence_id": record.NodeOccurrenceID,
		"snapshot_id": record.SnapshotID, "protocol": record.ProtocolID,
		"target_id": nullable(record.TargetID), "result_class": record.Class,
		"success": record.Success, "node_attributable": record.NodeAttributable,
		"http_status": record.HTTPStatus, "total_ms": record.Total.Milliseconds(),
		"diagnostic_code": nullable(record.DiagnosticCode),
		"executor_id":     record.ExecutorID, "executor_version": record.ExecutorVersion,
		"observed_at": record.ObservedAt.UTC().Format(time.RFC3339Nano),
		"stale":       !now.UTC().Before(record.StaleAfter),
	}
}

func writeNodeError(response http.ResponseWriter, err error) {
	if errors.Is(err, healthstore.ErrNotFound) {
		writeError(response, http.StatusNotFound, "not_found", "node occurrence not found")
		return
	}
	if errors.Is(err, healthstore.ErrConflict) {
		writeError(response, http.StatusConflict, "node_check_conflict", "node check is already running or unavailable")
		return
	}
	writeError(response, http.StatusBadRequest, "node_operation_failed", publicMessage(err))
}
