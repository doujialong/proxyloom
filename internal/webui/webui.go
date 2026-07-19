package webui

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

//go:embed dist
var content embed.FS

const contentSecurityPolicy = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; connect-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'"

func Handler() http.Handler {
	root, err := fs.Sub(content, "dist")
	if err != nil {
		panic(err)
	}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		response.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name, ok := assetName(request.URL.Path)
		if !ok {
			http.NotFound(response, request)
			return
		}
		asset, err := fs.ReadFile(root, name)
		if err != nil && !strings.HasPrefix(name, "assets/") {
			name = "index.html"
			asset, err = fs.ReadFile(root, name)
		}
		if err != nil {
			http.NotFound(response, request)
			return
		}
		digest := sha256.Sum256(asset)
		etag := `"` + hex.EncodeToString(digest[:]) + `"`
		response.Header().Set("ETag", etag)
		if request.Header.Get("If-None-Match") == etag {
			response.WriteHeader(http.StatusNotModified)
			return
		}
		contentType := mime.TypeByExtension(path.Ext(name))
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		response.Header().Set("Content-Type", contentType)
		response.Header().Set("Content-Length", fmt.Sprintf("%d", len(asset)))
		if strings.HasPrefix(name, "assets/") {
			response.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			response.Header().Set("Cache-Control", "no-cache")
		}
		response.WriteHeader(http.StatusOK)
		if request.Method == http.MethodGet {
			_, _ = response.Write(asset)
		}
	})
}

func assetName(requestPath string) (string, bool) {
	if requestPath == "" || requestPath == "/" {
		return "index.html", true
	}
	if strings.Contains(requestPath, "\\") {
		return "", false
	}
	cleaned := path.Clean("/" + requestPath)
	if cleaned != requestPath || strings.Contains(cleaned, "..") {
		return "", false
	}
	return strings.TrimPrefix(cleaned, "/"), true
}
