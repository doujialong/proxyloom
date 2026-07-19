package webui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestHandlerServesSPAAssetsAndSecurityHeaders(t *testing.T) {
	server := httptest.NewServer(Handler())
	defer server.Close()
	response, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	index, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(index), "ProxyLoom") ||
		response.Header.Get("Content-Security-Policy") == "" || response.Header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("index response status=%d headers=%v body=%s", response.StatusCode, response.Header, index)
	}
	match := regexp.MustCompile(`/assets/[^"']+\.js`).Find(index)
	if len(match) == 0 {
		t.Fatalf("built JavaScript asset missing from index: %s", index)
	}
	assetResponse, err := http.Get(server.URL + string(match))
	if err != nil {
		t.Fatal(err)
	}
	assetResponse.Body.Close()
	if assetResponse.StatusCode != http.StatusOK || !strings.Contains(assetResponse.Header.Get("Cache-Control"), "immutable") {
		t.Fatalf("asset status=%d cache=%q", assetResponse.StatusCode, assetResponse.Header.Get("Cache-Control"))
	}
	spaResponse, err := http.Get(server.URL + "/outputs/local-view")
	if err != nil {
		t.Fatal(err)
	}
	spaResponse.Body.Close()
	if spaResponse.StatusCode != http.StatusOK || !strings.HasPrefix(spaResponse.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("SPA fallback status=%d type=%q", spaResponse.StatusCode, spaResponse.Header.Get("Content-Type"))
	}
}

func TestHandlerRejectsUnsafePathsAndMethods(t *testing.T) {
	handler := Handler()
	unsafe := httptest.NewRequest(http.MethodGet, "http://example.test/assets\\secret", nil)
	unsafeResponse := httptest.NewRecorder()
	handler.ServeHTTP(unsafeResponse, unsafe)
	if unsafeResponse.Code != http.StatusNotFound {
		t.Fatalf("unsafe path status = %d", unsafeResponse.Code)
	}
	mutation := httptest.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader("ignored"))
	mutationResponse := httptest.NewRecorder()
	handler.ServeHTTP(mutationResponse, mutation)
	if mutationResponse.Code != http.StatusMethodNotAllowed {
		t.Fatalf("mutation status = %d", mutationResponse.Code)
	}
}
