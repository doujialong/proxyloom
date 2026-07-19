package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSameRequestOriginUsesExplicitPublicOrigin(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "http://proxyloom:8080/api/v1/sources", nil)
	request.Header.Set("Origin", "https://proxy.example")
	if sameRequestOrigin(request, "") {
		t.Fatal("external HTTPS origin matched the internal HTTP host without configuration")
	}
	if !sameRequestOrigin(request, "https://proxy.example") {
		t.Fatal("configured external origin was rejected")
	}
	request.Header.Set("Origin", "https://proxy.example.attacker.test")
	if sameRequestOrigin(request, "https://proxy.example") {
		t.Fatal("origin prefix attack was accepted")
	}
}

func TestSessionCookieCanBeMarkedSecure(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	server := &Server{cookieSecure: true, now: func() time.Time { return now }}
	response := httptest.NewRecorder()
	server.setSessionCookie(response, "temporary", now.Add(time.Hour))
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("secure session cookie = %+v", cookies)
	}
}
