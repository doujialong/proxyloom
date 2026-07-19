package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/doujialong/proxyloom/internal/aggregate"
	"github.com/doujialong/proxyloom/internal/app"
	"github.com/doujialong/proxyloom/internal/auth"
	"github.com/doujialong/proxyloom/internal/storage/artifactstore"
	"github.com/doujialong/proxyloom/internal/storage/jobstore"
	"github.com/doujialong/proxyloom/internal/storage/outputstore"
	"github.com/doujialong/proxyloom/internal/storage/sourcestore"
	"github.com/doujialong/proxyloom/internal/webui"
)

type Options struct {
	Log          func(string, ...interface{})
	CookieSecure bool
	Now          func() time.Time
	NewID        func() string
	PublicOrigin string
}

type Server struct {
	manager      *app.Manager
	aggregate    *aggregate.Manager
	jobs         *jobstore.Store
	artifacts    *artifactstore.Store
	admin        *auth.Token
	sessions     *auth.Store
	log          func(string, ...interface{})
	cookieSecure bool
	now          func() time.Time
	newID        func() string
	publicOrigin string
	loginLimiter *rateLimiter
	setupLimiter *rateLimiter
	handler      http.Handler
}

func New(manager *app.Manager, aggregator *aggregate.Manager, jobs *jobstore.Store, artifacts *artifactstore.Store, admin *auth.Token, sessions *auth.Store, options Options) (*Server, error) {
	if manager == nil || aggregator == nil || jobs == nil || artifacts == nil || admin == nil || sessions == nil {
		return nil, fmt.Errorf("HTTP API dependencies are required")
	}
	if options.Log == nil {
		options.Log = func(string, ...interface{}) {}
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.NewID == nil {
		return nil, fmt.Errorf("HTTP API ID generator is required")
	}
	if options.PublicOrigin != "" {
		parsed, err := url.Parse(options.PublicOrigin)
		if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" ||
			parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
			return nil, fmt.Errorf("HTTP API public origin must be an absolute HTTP(S) origin without a path")
		}
		options.PublicOrigin = parsed.Scheme + "://" + parsed.Host
	}
	server := &Server{
		manager: manager, aggregate: aggregator, jobs: jobs, artifacts: artifacts, admin: admin, sessions: sessions,
		log: options.Log, cookieSecure: options.CookieSecure, now: options.Now, newID: options.NewID,
		publicOrigin: options.PublicOrigin,
		loginLimiter: newRateLimiter(5, 5*time.Minute, options.Now),
		setupLimiter: newRateLimiter(10, 5*time.Minute, options.Now),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.health)
	mux.HandleFunc("/readyz", server.ready)
	mux.HandleFunc("/api/v1/setup/status", server.setupStatus)
	mux.HandleFunc("/api/v1/setup/admin", server.setupAdministrator)
	mux.HandleFunc("/api/v1/session", server.session)
	mux.HandleFunc("/api/v1/session/reauthenticate", server.reauthenticate)
	mux.HandleFunc("/api/v1/session/password", server.changePassword)
	mux.HandleFunc("/api/v1/sources", server.requireAdmin(server.sources))
	mux.HandleFunc("/api/v1/sources/", server.requireAdmin(server.sourceAction))
	mux.HandleFunc("/api/v1/jobs/", server.requireAdmin(server.job))
	mux.HandleFunc("/api/v1/nodes", server.requireAdmin(server.nodes))
	mux.HandleFunc("/api/v1/nodes/", server.requireAdmin(server.nodeAction))
	mux.HandleFunc("/api/v1/node-checks", server.requireAdmin(server.nodeChecks))
	mux.HandleFunc("/api/v1/health/capacity", server.requireAdmin(server.healthCapacity))
	mux.HandleFunc("/api/v1/collections", server.requireAdmin(server.collections))
	mux.HandleFunc("/api/v1/collections/", server.requireAdmin(server.collectionAction))
	mux.HandleFunc("/api/v1/pipelines", server.requireAdmin(server.pipelines))
	mux.HandleFunc("/api/v1/pipelines/", server.requireAdmin(server.pipelineAction))
	mux.HandleFunc("/api/v1/templates", server.requireAdmin(server.templates))
	mux.HandleFunc("/api/v1/templates/", server.requireAdmin(server.templateAction))
	mux.HandleFunc("/api/v1/outputs", server.requireAdmin(server.outputs))
	mux.HandleFunc("/api/v1/outputs/", server.requireAdmin(server.outputAction))
	mux.HandleFunc("/subscriptions/", server.subscription)
	mux.HandleFunc("/api/", func(response http.ResponseWriter, _ *http.Request) {
		writeError(response, http.StatusNotFound, "not_found", "resource not found")
	})
	mux.Handle("/", webui.Handler())
	server.handler = server.correlate(securityHeaders(mux))
	return server, nil
}

func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) health(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(response)
		return
	}
	writeJSON(response, http.StatusOK, map[string]interface{}{"status": "ok"})
}

func (s *Server) ready(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(response)
		return
	}
	writeJSON(response, http.StatusOK, map[string]interface{}{"status": "ready"})
}

type createSourceRequest struct {
	DisplayName              string            `json:"display_name"`
	Type                     string            `json:"type"`
	Content                  string            `json:"content,omitempty"`
	URL                      string            `json:"url,omitempty"`
	Headers                  map[string]string `json:"headers,omitempty"`
	ProxyURL                 string            `json:"proxy_url,omitempty"`
	TimeoutSeconds           int               `json:"timeout_seconds,omitempty"`
	InputFormat              string            `json:"input_format,omitempty"`
	OutputFormat             string            `json:"output_format,omitempty"`
	MinimumNodes             int               `json:"minimum_nodes,omitempty"`
	MaximumDropRatio         *float64          `json:"maximum_drop_ratio,omitempty"`
	RefreshIntervalSeconds   int               `json:"refresh_interval_seconds,omitempty"`
	PrivateNetworkAuthorized bool              `json:"private_network_authorized,omitempty"`
	MaxResponseBytes         int               `json:"max_response_bytes,omitempty"`
	HealthFilterEnabled      bool              `json:"health_filter_enabled,omitempty"`
}

func sourceConfigFromRequest(input createSourceRequest) app.SourceConfig {
	maximumDropRatio := 0.5
	if input.MaximumDropRatio != nil {
		maximumDropRatio = *input.MaximumDropRatio
	}
	return app.SourceConfig{
		Type: sourcestore.SourceType(input.Type), InlineContent: input.Content, URL: input.URL,
		RequestHeaders: input.Headers, ProxyURL: input.ProxyURL, TimeoutSeconds: input.TimeoutSeconds,
		InputFormat: input.InputFormat, OutputFormat: input.OutputFormat,
		MinimumNodes: input.MinimumNodes, MaximumDropRatio: maximumDropRatio,
		RefreshIntervalSeconds:   input.RefreshIntervalSeconds,
		PrivateNetworkAuthorized: input.PrivateNetworkAuthorized,
		MaxResponseBytes:         input.MaxResponseBytes,
		HealthFilterEnabled:      input.HealthFilterEnabled,
	}
}

func applySourceMergePatch(body io.Reader, displayName string, config app.SourceConfig) (string, app.SourceConfig, error) {
	decoder := json.NewDecoder(io.LimitReader(body, (50<<20)+1))
	decoder.DisallowUnknownFields()
	var patch map[string]json.RawMessage
	if err := decoder.Decode(&patch); err != nil {
		return "", app.SourceConfig{}, fmt.Errorf("decode source merge patch: %w", err)
	}
	if len(patch) == 0 {
		return "", app.SourceConfig{}, fmt.Errorf("source merge patch must contain at least one property")
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", app.SourceConfig{}, fmt.Errorf("source merge patch must contain one JSON object")
	}
	for name, raw := range patch {
		var err error
		switch name {
		case "display_name":
			displayName, err = patchString(raw, false)
		case "type":
			var value string
			value, err = patchString(raw, false)
			config.Type = sourcestore.SourceType(value)
		case "content":
			config.InlineContent, err = patchString(raw, true)
		case "url":
			config.URL, err = patchString(raw, true)
		case "headers":
			if isJSONNull(raw) {
				config.RequestHeaders = nil
			} else {
				err = json.Unmarshal(raw, &config.RequestHeaders)
			}
		case "proxy_url":
			config.ProxyURL, err = patchString(raw, true)
		case "timeout_seconds":
			err = patchNumber(raw, &config.TimeoutSeconds)
		case "input_format":
			config.InputFormat, err = patchString(raw, true)
		case "output_format":
			config.OutputFormat, err = patchString(raw, true)
		case "minimum_nodes":
			err = patchNumber(raw, &config.MinimumNodes)
		case "maximum_drop_ratio":
			if isJSONNull(raw) {
				config.MaximumDropRatio = 0.5
			} else {
				err = patchNumber(raw, &config.MaximumDropRatio)
			}
		case "refresh_interval_seconds":
			err = patchNumber(raw, &config.RefreshIntervalSeconds)
		case "private_network_authorized":
			err = patchBool(raw, &config.PrivateNetworkAuthorized)
		case "max_response_bytes":
			err = patchNumber(raw, &config.MaxResponseBytes)
		case "health_filter_enabled":
			err = patchBool(raw, &config.HealthFilterEnabled)
		default:
			return "", app.SourceConfig{}, fmt.Errorf("unknown source merge patch property %q", name)
		}
		if err != nil {
			return "", app.SourceConfig{}, fmt.Errorf("invalid source merge patch property %q: %w", name, err)
		}
	}
	return displayName, config, nil
}

func patchString(raw json.RawMessage, nullable bool) (string, error) {
	if isJSONNull(raw) {
		if nullable {
			return "", nil
		}
		return "", fmt.Errorf("null is not allowed")
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	return value, nil
}

func patchNumber(raw json.RawMessage, destination interface{}) error {
	if isJSONNull(raw) {
		switch value := destination.(type) {
		case *int:
			*value = 0
		case *float64:
			*value = 0
		}
		return nil
	}
	return json.Unmarshal(raw, destination)
}

func patchBool(raw json.RawMessage, destination *bool) error {
	if isJSONNull(raw) {
		*destination = false
		return nil
	}
	return json.Unmarshal(raw, destination)
}

func isJSONNull(raw json.RawMessage) bool {
	return strings.TrimSpace(string(raw)) == "null"
}

func (s *Server) sources(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		s.listSources(response, request)
		return
	}
	if request.Method != http.MethodPost {
		methodNotAllowed(response)
		return
	}
	var input createSourceRequest
	if err := decodeJSON(response, request, &input, 50<<20); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, err := s.manager.CreateSource(request.Context(), input.DisplayName, sourceConfigFromRequest(input))
	if err != nil {
		s.log("create source failed: %v", err)
		writeError(response, http.StatusBadRequest, "source_create_failed", publicMessage(err))
		return
	}
	writeJSON(response, http.StatusAccepted, map[string]interface{}{
		"source_id":            result.Source.ID,
		"revision_id":          result.Revision.ID,
		"job_id":               result.Job.ID,
		"publication_token_id": result.Credential.ID,
		"subscription_url":     "/subscriptions/" + result.Credential.Token,
	})
}

func (s *Server) sourceAction(response http.ResponseWriter, request *http.Request) {
	path := strings.TrimPrefix(request.URL.Path, "/api/v1/sources/")
	parts := strings.Split(path, "/")
	if len(parts) == 1 && parts[0] != "" && request.Method == http.MethodGet {
		s.getSource(response, request, parts[0])
		return
	}
	if len(parts) == 1 && parts[0] != "" && request.Method == http.MethodDelete {
		s.archiveSource(response, request, parts[0])
		return
	}
	if len(parts) == 2 && parts[0] != "" && request.Method == http.MethodGet {
		s.sourceHistory(response, request, parts[0], parts[1])
		return
	}
	if (request.Method == http.MethodPut || request.Method == http.MethodPatch) && len(parts) == 1 && parts[0] != "" {
		detail, current, err := s.manager.CurrentSourceConfig(request.Context(), parts[0])
		if err != nil {
			writeSourceReadError(response, err)
			return
		}
		etag := sourceETag(detail.Source)
		if request.Header.Get("If-Match") != etag {
			response.Header().Set("ETag", etag)
			writeError(response, http.StatusPreconditionFailed, "precondition_failed", "If-Match does not match the current source revision")
			return
		}
		displayName := detail.Source.DisplayName
		if request.Method == http.MethodPut {
			var input createSourceRequest
			if err := decodeJSON(response, request, &input, 50<<20); err != nil {
				writeError(response, http.StatusBadRequest, "invalid_request", err.Error())
				return
			}
			if input.DisplayName != "" {
				displayName = input.DisplayName
			}
			current = sourceConfigFromRequest(input)
		} else {
			displayName, current, err = applySourceMergePatch(request.Body, displayName, current)
			if err != nil {
				writeError(response, http.StatusBadRequest, "invalid_request", err.Error())
				return
			}
		}
		result, err := s.manager.UpdateSourceAt(request.Context(), parts[0], displayName, detail.Source.UpdatedAt, current)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, sourcestore.ErrNotFound) {
				status = http.StatusNotFound
			} else if errors.Is(err, sourcestore.ErrConflict) {
				status = http.StatusPreconditionFailed
			}
			writeError(response, status, "source_update_failed", publicMessage(err))
			return
		}
		response.Header().Set("ETag", sourceETag(result.Source))
		writeJSON(response, http.StatusAccepted, map[string]interface{}{
			"source_id": result.Source.ID, "revision_id": result.Revision.ID,
			"job_id": result.Job.ID, "status": result.Job.Status, "display_name": result.Source.DisplayName,
		})
		return
	}
	if request.Method != http.MethodPost || len(parts) != 2 || parts[0] == "" {
		writeError(response, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if parts[1] == "tokens" {
		credential, err := s.manager.CreatePublicationCredential(request.Context(), parts[0])
		if err != nil {
			status := http.StatusConflict
			if errors.Is(err, artifactstore.ErrNotFound) {
				status = http.StatusNotFound
			}
			writeError(response, status, "publication_token_create_failed", publicMessage(err))
			return
		}
		writeJSON(response, http.StatusCreated, map[string]interface{}{
			"source_id":            credential.SourceID,
			"publication_token_id": credential.ID,
			"subscription_url":     "/subscriptions/" + credential.Token,
		})
		return
	}
	if parts[1] != "refresh" {
		writeError(response, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	job, err := s.manager.EnqueueRefresh(request.Context(), parts[0], "api-refresh-"+parts[0])
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, sourcestore.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(response, status, "refresh_enqueue_failed", publicMessage(err))
		return
	}
	writeJSON(response, http.StatusAccepted, map[string]interface{}{"job_id": job.ID, "status": job.Status})
}

func (s *Server) job(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(response)
		return
	}
	id := strings.TrimPrefix(request.URL.Path, "/api/v1/jobs/")
	if id == "" || strings.Contains(id, "/") {
		writeError(response, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	job, err := s.jobs.Get(request.Context(), id)
	if err != nil {
		outputJob, outputErr := s.aggregate.BuildJob(request.Context(), id)
		if outputErr != nil {
			writeError(response, http.StatusNotFound, "not_found", "job not found")
			return
		}
		writeJSON(response, http.StatusOK, managedBuildJobView(outputJob))
		return
	}
	writeJSON(response, http.StatusOK, map[string]interface{}{
		"id": job.ID, "source_id": job.SourceID, "source_revision_id": job.SourceRevisionID,
		"status": job.Status, "attempt": job.Attempt, "max_attempts": job.MaxAttempts,
		"error_code": nullable(job.ErrorCode), "error_detail": nullable(job.ErrorDetail),
		"due_at": job.DueAt, "created_at": job.CreatedAt,
		"started_at": job.StartedAt, "finished_at": job.FinishedAt,
	})
}

func (s *Server) subscription(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		methodNotAllowed(response)
		return
	}
	token := strings.TrimPrefix(request.URL.Path, "/subscriptions/")
	if token == "" || strings.Contains(token, "/") {
		writeError(response, http.StatusNotFound, "not_found", "subscription not found")
		return
	}
	if strings.HasPrefix(token, "out1.") {
		s.managedSubscription(response, request, token)
		return
	}
	artifact, err := s.artifacts.Resolve(request.Context(), token)
	if err != nil {
		if errors.Is(err, artifactstore.ErrNotFound) {
			writeError(response, http.StatusServiceUnavailable, "artifact_unavailable", "no valid artifact has been published")
			return
		}
		writeError(response, http.StatusNotFound, "not_found", "subscription not found")
		return
	}
	etag := `"` + artifact.PublicSHA256 + `"`
	response.Header().Set("ETag", etag)
	response.Header().Set("Last-Modified", artifact.CreatedAt.UTC().Format(http.TimeFormat))
	response.Header().Set("Cache-Control", "private, no-cache")
	response.Header().Set("Referrer-Policy", "no-referrer")
	if request.Header.Get("If-None-Match") == etag {
		response.WriteHeader(http.StatusNotModified)
		return
	}
	content, err := s.artifacts.Content(request.Context(), artifact)
	if err != nil {
		s.log("artifact %s read failed: %v", artifact.ID, err)
		writeError(response, http.StatusServiceUnavailable, "artifact_unavailable", "published artifact is temporarily unavailable")
		return
	}
	response.Header().Set("Content-Type", artifact.ContentType)
	response.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
	response.WriteHeader(http.StatusOK)
	if request.Method == http.MethodGet {
		_, _ = response.Write(content)
	}
}

func (s *Server) managedSubscription(response http.ResponseWriter, request *http.Request, token string) {
	artifact, err := s.aggregate.Store().Resolve(request.Context(), token)
	if err != nil {
		if errors.Is(err, outputstore.ErrNotFound) {
			writeError(response, http.StatusServiceUnavailable, "artifact_unavailable", "no valid artifact has been published")
			return
		}
		writeError(response, http.StatusNotFound, "not_found", "subscription not found")
		return
	}
	etag := `"` + artifact.PublicSHA256 + `"`
	response.Header().Set("ETag", etag)
	response.Header().Set("Last-Modified", artifact.CreatedAt.UTC().Format(http.TimeFormat))
	response.Header().Set("Cache-Control", "private, no-cache")
	response.Header().Set("Referrer-Policy", "no-referrer")
	if request.Header.Get("If-None-Match") == etag {
		response.WriteHeader(http.StatusNotModified)
		return
	}
	content, err := s.aggregate.Store().Content(request.Context(), artifact)
	if err != nil {
		s.log("managed output artifact %s read failed: %v", artifact.ID, err)
		writeError(response, http.StatusServiceUnavailable, "artifact_unavailable", "published artifact is temporarily unavailable")
		return
	}
	response.Header().Set("Content-Type", artifact.ContentType)
	response.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
	response.WriteHeader(http.StatusOK)
	if request.Method == http.MethodGet {
		_, _ = response.Write(content)
	}
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		authorization := request.Header.Get("Authorization")
		if authorization != "" {
			if s.admin.VerifyBearer(authorization) {
				next(response, request)
				return
			}
			response.Header().Set("WWW-Authenticate", `Bearer realm="proxyloom-admin"`)
			writeError(response, http.StatusUnauthorized, "unauthorized", "valid administrator bearer token required")
			return
		}
		session, err := s.authenticateCookie(request)
		if err != nil {
			writeError(response, http.StatusUnauthorized, "unauthorized", "valid administrator session required")
			return
		}
		if isUnsafeMethod(request.Method) {
			if !sameRequestOrigin(request, s.publicOrigin) {
				writeError(response, http.StatusForbidden, "origin_rejected", "request origin does not match the service origin")
				return
			}
			if err := s.sessions.VerifyCSRF(session, request.Header.Get("X-CSRF-Token")); err != nil {
				writeError(response, http.StatusForbidden, "csrf_rejected", "valid CSRF token required")
				return
			}
		}
		next(response, request.WithContext(context.WithValue(request.Context(), sessionContextKey{}, session)))
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(response, request)
	})
}

func decodeJSON(response http.ResponseWriter, request *http.Request, destination interface{}, limit int64) error {
	if request.Body == nil {
		return fmt.Errorf("JSON request body is required")
	}
	request.Body = http.MaxBytesReader(response, request.Body, limit)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON body: %w", err)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("JSON body must contain exactly one value")
	}
	return nil
}

func writeJSON(response http.ResponseWriter, status int, value interface{}) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeError(response http.ResponseWriter, status int, code, message string) {
	writeJSON(response, status, map[string]interface{}{
		"error": map[string]string{"code": code, "message": message},
	})
}

func methodNotAllowed(response http.ResponseWriter) {
	writeError(response, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}

func publicMessage(err error) string {
	if err == nil {
		return "request failed"
	}
	message := err.Error()
	if len(message) > 300 {
		message = message[:300]
	}
	return message
}

func nullable(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}
