package httpapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/doujialong/proxyloom/internal/auth"
)

const sessionCookieName = "proxyloom_session"

type sessionContextKey struct{}
type correlationContextKey struct{}

type setupAdministratorRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Timezone string `json:"timezone,omitempty"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type reauthenticateRequest struct {
	Password string `json:"password"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) setupStatus(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(response)
		return
	}
	required, err := s.sessions.SetupRequired(request.Context())
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "storage_unavailable", "administrator setup state is unavailable")
		return
	}
	writeJSON(response, http.StatusOK, map[string]interface{}{
		"administrator_initialized": !required,
		"master_key":                "valid",
		"database":                  "ready",
	})
}

func (s *Server) setupAdministrator(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(response)
		return
	}
	client := clientAddress(request)
	if !s.setupLimiter.Allow("setup\x00" + client) {
		response.Header().Set("Retry-After", "300")
		writeError(response, http.StatusTooManyRequests, "rate_limited", "too many administrator setup attempts")
		return
	}
	var input setupAdministratorRequest
	if err := decodeJSON(response, request, &input, 8<<10); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	session, err := s.sessions.Bootstrap(
		request.Context(), request.Header.Get("X-ProxyLoom-Setup-Token"), input.Username, input.Password,
		input.Timezone, correlationID(request), client,
	)
	if err != nil {
		status := http.StatusUnprocessableEntity
		code := "administrator_setup_failed"
		if errors.Is(err, auth.ErrSetupAlreadyComplete) {
			status, code = http.StatusConflict, "setup_already_complete"
		} else if errors.Is(err, auth.ErrInvalidSetupToken) {
			status, code = http.StatusUnauthorized, "invalid_setup_token"
		}
		writeError(response, status, code, publicMessage(err))
		return
	}
	s.setupLimiter.Reset("setup\x00" + client)
	s.setSessionCookie(response, session.Token, session.ExpiresAt)
	response.Header().Set("Cache-Control", "no-store")
	writeJSON(response, http.StatusCreated, sessionResponse(session.Administrator, session.CSRFToken, session.ExpiresAt, session.RecentAuthUntil))
}

func (s *Server) session(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodPost:
		client := clientAddress(request)
		var input loginRequest
		if err := decodeJSON(response, request, &input, 8<<10); err != nil {
			writeError(response, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		limitKey := "login\x00" + client + "\x00" + strings.ToLower(strings.TrimSpace(input.Username))
		if !s.loginLimiter.Allow(limitKey) {
			response.Header().Set("Retry-After", "300")
			writeError(response, http.StatusTooManyRequests, "rate_limited", "too many authentication attempts")
			return
		}
		result, err := s.sessions.Login(request.Context(), input.Username, input.Password, correlationID(request), client)
		if err != nil {
			writeError(response, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
			return
		}
		s.loginLimiter.Reset(limitKey)
		s.setSessionCookie(response, result.Token, result.ExpiresAt)
		response.Header().Set("Cache-Control", "no-store")
		writeJSON(response, http.StatusCreated, sessionResponse(result.Administrator, result.CSRFToken, result.ExpiresAt, result.RecentAuthUntil))
	case http.MethodGet:
		session, err := s.authenticateCookie(request)
		if err != nil {
			writeError(response, http.StatusUnauthorized, "unauthorized", "valid administrator session required")
			return
		}
		csrf, err := s.sessions.RotateCSRF(request.Context(), session)
		if err != nil {
			writeError(response, http.StatusServiceUnavailable, "session_update_failed", "administrator session could not be updated")
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		writeJSON(response, http.StatusOK, sessionResponse(
			session.Administrator, csrf, session.ExpiresAt,
			session.RecentAuthAt.Add(auth.RecentAuthenticationTTL),
		))
	case http.MethodDelete:
		session, ok := s.requireCookieMutation(response, request)
		if !ok {
			return
		}
		if err := s.sessions.Revoke(request.Context(), session, correlationID(request), clientAddress(request)); err != nil {
			writeError(response, http.StatusInternalServerError, "session_revoke_failed", "administrator session could not be revoked")
			return
		}
		s.clearSessionCookie(response)
		response.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(response)
	}
}

func (s *Server) reauthenticate(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(response)
		return
	}
	session, ok := s.requireCookieMutation(response, request)
	if !ok {
		return
	}
	var input reauthenticateRequest
	if err := decodeJSON(response, request, &input, 8<<10); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	recentUntil, err := s.sessions.Reauthenticate(
		request.Context(), session, input.Password, correlationID(request), clientAddress(request),
	)
	if err != nil {
		writeError(response, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	writeJSON(response, http.StatusOK, sessionResponse(session.Administrator, request.Header.Get("X-CSRF-Token"), session.ExpiresAt, recentUntil))
}

func (s *Server) changePassword(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(response)
		return
	}
	session, ok := s.requireCookieMutation(response, request)
	if !ok {
		return
	}
	var input changePasswordRequest
	if err := decodeJSON(response, request, &input, 8<<10); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.sessions.ChangePassword(request.Context(), session, input.CurrentPassword, input.NewPassword, correlationID(request), clientAddress(request)); err != nil {
		status := http.StatusUnprocessableEntity
		code := "password_change_failed"
		if errors.Is(err, auth.ErrInvalidCredentials) {
			status, code = http.StatusUnauthorized, "invalid_credentials"
		} else if errors.Is(err, auth.ErrInvalidSession) {
			status, code = http.StatusUnauthorized, "invalid_session"
		}
		writeError(response, status, code, publicMessage(err))
		return
	}
	s.clearSessionCookie(response)
	response.WriteHeader(http.StatusNoContent)
}

func (s *Server) authenticateCookie(request *http.Request) (auth.AuthenticatedSession, error) {
	cookie, err := request.Cookie(sessionCookieName)
	if err != nil {
		return auth.AuthenticatedSession{}, auth.ErrInvalidSession
	}
	return s.sessions.Authenticate(request.Context(), cookie.Value)
}

func (s *Server) requireCookieMutation(response http.ResponseWriter, request *http.Request) (auth.AuthenticatedSession, bool) {
	session, err := s.authenticateCookie(request)
	if err != nil {
		writeError(response, http.StatusUnauthorized, "unauthorized", "valid administrator session required")
		return auth.AuthenticatedSession{}, false
	}
	if !sameRequestOrigin(request, s.publicOrigin) {
		writeError(response, http.StatusForbidden, "origin_rejected", "request origin does not match the service origin")
		return auth.AuthenticatedSession{}, false
	}
	if err := s.sessions.VerifyCSRF(session, request.Header.Get("X-CSRF-Token")); err != nil {
		writeError(response, http.StatusForbidden, "csrf_rejected", "valid CSRF token required")
		return auth.AuthenticatedSession{}, false
	}
	return session, true
}

func (s *Server) setSessionCookie(response http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(response, &http.Cookie{
		Name: sessionCookieName, Value: token, Path: "/", Expires: expires,
		MaxAge: int(expires.Sub(s.now()).Seconds()), HttpOnly: true, Secure: s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(response http.ResponseWriter) {
	http.SetCookie(response, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode,
	})
}

func sessionResponse(administrator auth.Administrator, csrf string, expiresAt, recentUntil time.Time) map[string]interface{} {
	return map[string]interface{}{
		"administrator":     map[string]string{"id": administrator.ID, "username": administrator.Username},
		"csrf_token":        csrf,
		"expires_at":        expiresAt.UTC().Format(time.RFC3339Nano),
		"recent_auth_until": recentUntil.UTC().Format(time.RFC3339Nano),
	}
}

func sameRequestOrigin(request *http.Request, configured string) bool {
	expected := configured
	if expected == "" {
		expectedScheme := "http"
		if request.TLS != nil {
			expectedScheme = "https"
		}
		expected = expectedScheme + "://" + request.Host
	}
	if origin := request.Header.Get("Origin"); origin != "" {
		parsed, err := url.Parse(origin)
		return err == nil && parsed.String() == expected && parsed.Path == ""
	}
	if referer := request.Header.Get("Referer"); referer != "" {
		parsed, err := url.Parse(referer)
		return err == nil && parsed.Scheme+"://"+parsed.Host == expected
	}
	return false
}

func isUnsafeMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func clientAddress(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err == nil {
		return host
	}
	if len(request.RemoteAddr) <= 128 {
		return request.RemoteAddr
	}
	return "unknown"
}

func (s *Server) correlate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		id := request.Header.Get("X-Correlation-ID")
		if len(id) < 1 || len(id) > 200 || strings.ContainsAny(id, "\r\n\x00") {
			id = s.newID()
		}
		response.Header().Set("X-Correlation-ID", id)
		next.ServeHTTP(response, request.WithContext(context.WithValue(request.Context(), correlationContextKey{}, id)))
	})
}

func correlationID(request *http.Request) string {
	value, _ := request.Context().Value(correlationContextKey{}).(string)
	return value
}

type rateEntry struct {
	started time.Time
	count   int
}

type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]rateEntry
	limit   int
	window  time.Duration
	now     func() time.Time
}

func newRateLimiter(limit int, window time.Duration, now func() time.Time) *rateLimiter {
	return &rateLimiter{entries: make(map[string]rateEntry), limit: limit, window: window, now: now}
}

func (r *rateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	entry, exists := r.entries[key]
	if !exists || now.Sub(entry.started) >= r.window {
		r.entries[key] = rateEntry{started: now, count: 1}
		return true
	}
	if entry.count >= r.limit {
		return false
	}
	entry.count++
	r.entries[key] = entry
	return true
}

func (r *rateLimiter) Reset(key string) {
	r.mu.Lock()
	delete(r.entries, key)
	r.mu.Unlock()
}
