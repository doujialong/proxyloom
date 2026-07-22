package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/doujialong/proxyloom/internal/aggregate"
	"github.com/doujialong/proxyloom/internal/app"
	"github.com/doujialong/proxyloom/internal/auth"
	"github.com/doujialong/proxyloom/internal/crypto/masterkey"
	"github.com/doujialong/proxyloom/internal/fetcher"
	"github.com/doujialong/proxyloom/internal/storage/healthstore"
)

func TestDeploymentPreviewEndToEndAndRestart(t *testing.T) {
	root := t.TempDir()
	secrets := filepath.Join(root, "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	masterPath := filepath.Join(secrets, "master.key")
	if _, err := masterkey.Generate(masterPath, masterkey.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	adminPath := filepath.Join(secrets, "admin.token")
	if err := auth.Generate(adminPath, auth.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	admin := readAdminBearer(t, adminPath)
	config := Config{
		DataDir: filepath.Join(root, "data"), MasterKeyPath: masterPath,
		AdminTokenPath: adminPath, Listen: "127.0.0.1:0", Development: true,
	}
	service, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service.api.Handler())
	unknownAPI, err := http.Get(server.URL + "/api/v1/does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	unknownType := unknownAPI.Header.Get("Content-Type")
	unknownAPI.Body.Close()
	if unknownAPI.StatusCode != http.StatusNotFound || !strings.HasPrefix(unknownType, "application/json") {
		t.Fatalf("unknown API status=%d type=%q", unknownAPI.StatusCode, unknownType)
	}

	unauthorized, err := http.Post(server.URL+"/api/v1/sources", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized create status = %d", unauthorized.StatusCode)
	}

	uriCreate := postJSON(t, server.URL+"/api/v1/sources", admin, map[string]interface{}{
		"display_name": "URI duplicates", "type": "inline", "input_format": "auto", "output_format": "same",
		"content": "vless://one@example.com:443?encryption=none#Hong%20Kong\n" +
			"vless://two@example.com:443?encryption=none#Hong%20Kong\n",
	})
	worked, err := service.worker.ProcessOne(context.Background())
	if err != nil || !worked {
		t.Fatalf("ProcessOne() = %v, %v", worked, err)
	}
	uriURL := server.URL + requiredString(t, uriCreate, "subscription_url")
	uriResponse, err := http.Get(uriURL)
	if err != nil {
		t.Fatal(err)
	}
	uriArtifact, _ := io.ReadAll(uriResponse.Body)
	uriResponse.Body.Close()
	if uriResponse.StatusCode != http.StatusOK || !bytes.Contains(uriArtifact, []byte("Hong%20Kong%20%232")) {
		t.Fatalf("URI artifact status=%d content=%s", uriResponse.StatusCode, uriArtifact)
	}
	etag := uriResponse.Header.Get("ETag")
	conditional, _ := http.NewRequest(http.MethodGet, uriURL, nil)
	conditional.Header.Set("If-None-Match", etag)
	conditionalResponse, err := http.DefaultClient.Do(conditional)
	if err != nil {
		t.Fatal(err)
	}
	conditionalResponse.Body.Close()
	if conditionalResponse.StatusCode != http.StatusNotModified {
		t.Fatalf("conditional status = %d", conditionalResponse.StatusCode)
	}

	singBoxInput := "{  \"outbounds\" : [ { \"type\":\"selector\", \"tag\":\"Select\", \"outbounds\":[\"Exact\"] }, { \"type\":\"vless\", \"tag\":\"Exact\", \"server\":\"example.com\", \"server_port\":443, \"uuid\":\"00000000-0000-4000-8000-000000000001\", \"future\":{\"n\":1e3} } ], \"future_root\":true }\n"
	singBoxCreate := postJSON(t, server.URL+"/api/v1/sources", admin, map[string]interface{}{
		"display_name": "sing-box exact", "type": "inline", "input_format": "sing-box",
		"output_format": "same", "content": singBoxInput,
	})
	worked, err = service.worker.ProcessOne(context.Background())
	if err != nil || !worked {
		t.Fatalf("second ProcessOne() = %v, %v", worked, err)
	}
	singBoxResponse, err := http.Get(server.URL + requiredString(t, singBoxCreate, "subscription_url"))
	if err != nil {
		t.Fatal(err)
	}
	singBoxArtifact, _ := io.ReadAll(singBoxResponse.Body)
	singBoxResponse.Body.Close()
	if !bytes.Equal(singBoxArtifact, []byte(singBoxInput)) {
		t.Fatalf("sing-box exact pass-through changed\nwant: %s\n got: %s", singBoxInput, singBoxArtifact)
	}
	rotated := postJSONWithStatus(t, server.URL+"/api/v1/sources/"+requiredString(t, singBoxCreate, "source_id")+"/tokens", admin, nil, http.StatusCreated)
	rotatedResponse, err := http.Get(server.URL + requiredString(t, rotated, "subscription_url"))
	if err != nil {
		t.Fatal(err)
	}
	rotatedArtifact, _ := io.ReadAll(rotatedResponse.Body)
	rotatedResponse.Body.Close()
	if rotatedResponse.StatusCode != http.StatusOK || !bytes.Equal(rotatedArtifact, []byte(singBoxInput)) {
		t.Fatalf("rotated publication credential did not resolve the current artifact")
	}

	mihomoInput := "# keep this comment\nproxies:\n  - {name: YAML One, type: ss, server: one.example, port: 443, cipher: aes-128-gcm, password: first}\n  - {name: YAML Two, type: private-future, server: two.example, port: 8443, future: true}\nproxy-groups:\n  - {name: Select, type: select, proxies: [YAML One, YAML Two]}\n"
	mihomoCreate := postJSON(t, server.URL+"/api/v1/sources", admin, map[string]interface{}{
		"display_name": "Mihomo exact", "type": "inline", "input_format": "auto",
		"output_format": "same", "content": mihomoInput,
	})
	worked, err = service.worker.ProcessOne(context.Background())
	if err != nil || !worked {
		t.Fatalf("Mihomo ProcessOne() = %v, %v", worked, err)
	}
	mihomoResponse, err := http.Get(server.URL + requiredString(t, mihomoCreate, "subscription_url"))
	if err != nil {
		t.Fatal(err)
	}
	mihomoArtifact, _ := io.ReadAll(mihomoResponse.Body)
	mihomoResponse.Body.Close()
	if mihomoResponse.StatusCode != http.StatusOK || !bytes.Equal(mihomoArtifact, []byte(mihomoInput)) {
		t.Fatalf("Mihomo exact pass-through status=%d content=%s", mihomoResponse.StatusCode, mihomoArtifact)
	}
	mihomoUpdated := "proxies:\n  - {name: Updated, type: anytls, server: updated.example, port: 443, password: future}\n"
	putJSONWithStatus(t, server.URL+"/api/v1/sources/"+requiredString(t, mihomoCreate, "source_id"), admin, map[string]interface{}{
		"type": "inline", "input_format": "mihomo", "output_format": "same", "content": mihomoUpdated,
	}, http.StatusAccepted)
	worked, err = service.worker.ProcessOne(context.Background())
	if err != nil || !worked {
		t.Fatalf("updated Mihomo ProcessOne() = %v, %v", worked, err)
	}
	updatedResponse, err := http.Get(server.URL + requiredString(t, mihomoCreate, "subscription_url"))
	if err != nil {
		t.Fatal(err)
	}
	updatedArtifact, _ := io.ReadAll(updatedResponse.Body)
	updatedResponse.Body.Close()
	if updatedResponse.StatusCode != http.StatusOK || !bytes.Equal(updatedArtifact, []byte(mihomoUpdated)) {
		t.Fatalf("updated source artifact status=%d content=%s", updatedResponse.StatusCode, updatedArtifact)
	}

	clientInput := "[General]\nloglevel = notify\n[Proxy]\nSame = vmess, one.example, 443, opaque-one\nSame = AnyTLS, two.example, 8443, opaque-two\n[Proxy Group]\nSelect = select, Same\n"
	clientCreate := postJSON(t, server.URL+"/api/v1/sources", admin, map[string]interface{}{
		"display_name": "client text duplicates", "type": "inline", "input_format": "auto",
		"output_format": "same", "content": clientInput,
	})
	worked, err = service.worker.ProcessOne(context.Background())
	if err != nil || !worked {
		t.Fatalf("client text ProcessOne() = %v, %v", worked, err)
	}
	clientJob, err := service.jobs.Get(context.Background(), requiredString(t, clientCreate, "job_id"))
	if err != nil || clientJob.Status != "succeeded" {
		t.Fatalf("client text job status=%s code=%s detail=%s error=%v", clientJob.Status, clientJob.ErrorCode, clientJob.ErrorDetail, err)
	}
	clientResponse, err := http.Get(server.URL + requiredString(t, clientCreate, "subscription_url"))
	if err != nil {
		t.Fatal(err)
	}
	clientArtifact, _ := io.ReadAll(clientResponse.Body)
	clientResponse.Body.Close()
	if clientResponse.StatusCode != http.StatusOK || bytes.Count(clientArtifact, []byte("Same #2 =")) != 1 ||
		!bytes.Contains(clientArtifact, []byte("vmess, one.example")) || !bytes.Contains(clientArtifact, []byte("AnyTLS, two.example")) ||
		!bytes.Contains(clientArtifact, []byte("Select = select, Same")) {
		t.Fatalf("client text artifact status=%d content=%s", clientResponse.StatusCode, clientArtifact)
	}
	clientCrossInput := "[Proxy]\nSame = vmess, one.example, 443, auto, 00000000-0000-4000-8000-000000000001, transport=ws, path=/ws, host=edge.example\nSame = AnyTLS, two.example, 8443, password-two, over-tls=true, sni=edge.example\n"
	putJSONWithStatus(t, server.URL+"/api/v1/sources/"+requiredString(t, clientCreate, "source_id"), admin, map[string]interface{}{
		"type": "inline", "input_format": "client-text", "output_format": "sing-box", "content": clientCrossInput,
	}, http.StatusAccepted)
	worked, err = service.worker.ProcessOne(context.Background())
	if err != nil || !worked {
		t.Fatalf("client text cross-format ProcessOne() = %v, %v", worked, err)
	}
	convertedResponse, err := http.Get(server.URL + requiredString(t, clientCreate, "subscription_url"))
	if err != nil {
		t.Fatal(err)
	}
	convertedArtifact, _ := io.ReadAll(convertedResponse.Body)
	convertedResponse.Body.Close()
	if convertedResponse.StatusCode != http.StatusOK || !json.Valid(convertedArtifact) ||
		convertedResponse.Header.Get("Content-Type") != "application/json" ||
		!bytes.Contains(convertedArtifact, []byte(`"outbounds"`)) || !bytes.Contains(convertedArtifact, []byte(`"tag": "Same #2"`)) {
		t.Fatalf("client text sing-box artifact status=%d type=%q content=%s", convertedResponse.StatusCode, convertedResponse.Header.Get("Content-Type"), convertedArtifact)
	}

	server.Close()
	service.Close()
	reopened, err := Open(context.Background(), config)
	if err != nil {
		t.Fatalf("reopen service: %v", err)
	}
	defer reopened.Close()
	restartedServer := httptest.NewServer(reopened.api.Handler())
	defer restartedServer.Close()
	restartedResponse, err := http.Get(restartedServer.URL + requiredString(t, uriCreate, "subscription_url"))
	if err != nil {
		t.Fatal(err)
	}
	restartedArtifact, _ := io.ReadAll(restartedResponse.Body)
	restartedResponse.Body.Close()
	if restartedResponse.StatusCode != http.StatusOK || !bytes.Equal(restartedArtifact, uriArtifact) {
		t.Fatalf("artifact after restart status=%d content=%s", restartedResponse.StatusCode, restartedArtifact)
	}
}

func TestRemoteSourceFailureKeepsPeriodicScheduleAlive(t *testing.T) {
	root := t.TempDir()
	secrets := filepath.Join(root, "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	masterPath := filepath.Join(secrets, "master.key")
	if _, err := masterkey.Generate(masterPath, masterkey.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	adminPath := filepath.Join(secrets, "admin.token")
	if err := auth.Generate(adminPath, auth.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	service, err := Open(context.Background(), Config{
		DataDir: filepath.Join(root, "data"), MasterKeyPath: masterPath,
		AdminTokenPath: adminPath, Listen: "127.0.0.1:0", Development: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	server := httptest.NewServer(service.api.Handler())
	defer server.Close()
	admin := readAdminBearer(t, adminPath)
	created := postJSON(t, server.URL+"/api/v1/sources", admin, map[string]interface{}{
		"display_name": "periodic remote failure", "type": "remote",
		"url": "https://127.0.0.1/subscription", "input_format": "sing-box",
		"private_network_authorized": true, "timeout_seconds": 1, "refresh_interval_seconds": 60,
	})
	if worked, err := service.worker.ProcessOne(context.Background()); err != nil || !worked {
		t.Fatalf("failed periodic ProcessOne() = %v, %v", worked, err)
	}
	var failed, queued, retryJobs int
	var delayMS int64
	if err := service.sqlite.DB().QueryRow(`
SELECT
  sum(CASE WHEN status = 'failed' THEN 1 ELSE 0 END),
  sum(CASE WHEN status = 'queued' THEN 1 ELSE 0 END),
	  sum(CASE WHEN status = 'queued' AND correlation_id LIKE 'retry-1-%' THEN 1 ELSE 0 END),
  max(CASE WHEN status = 'queued' THEN due_at - created_at ELSE 0 END)
FROM jobs WHERE source_id = ?`, requiredString(t, created, "source_id")).Scan(&failed, &queued, &retryJobs, &delayMS); err != nil {
		t.Fatal(err)
	}
	if failed != 1 || queued != 1 || retryJobs != 1 || delayMS < 48_000 || delayMS > 72_000 {
		t.Fatalf("periodic failure schedule failed=%d queued=%d retry=%d delay_ms=%d", failed, queued, retryJobs, delayMS)
	}
	jobRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/jobs/"+requiredString(t, created, "job_id"), nil)
	jobRequest.Header.Set("Authorization", "Bearer "+admin)
	jobResponse, err := http.DefaultClient.Do(jobRequest)
	if err != nil {
		t.Fatal(err)
	}
	jobView := decodeResponseJSON(t, jobResponse)
	if jobResponse.StatusCode != http.StatusOK || jobView["retry_scheduled"] != true || jobView["next_retry_at"] == nil {
		t.Fatalf("failed job retry view status=%d body=%v", jobResponse.StatusCode, jobView)
	}
	sourceID := requiredString(t, created, "source_id")
	for retryNumber := 1; retryNumber <= app.DefaultSourceRetryCount; retryNumber++ {
		if _, err := service.sqlite.DB().Exec(`UPDATE jobs SET due_at = ? WHERE source_id = ? AND status = 'queued'`, time.Now().Add(-time.Second).UnixMilli(), sourceID); err != nil {
			t.Fatal(err)
		}
		if worked, err := service.worker.ProcessOne(context.Background()); err != nil || !worked {
			t.Fatalf("retry %d ProcessOne() = %v, %v", retryNumber, worked, err)
		}
		var correlation string
		if err := service.sqlite.DB().QueryRow(`SELECT correlation_id FROM jobs WHERE source_id = ? AND status = 'queued'`, sourceID).Scan(&correlation); err != nil {
			t.Fatal(err)
		}
		expectedPrefix := "schedule-after-failure-"
		if retryNumber < app.DefaultSourceRetryCount {
			expectedPrefix = fmt.Sprintf("retry-%d-", retryNumber+1)
		}
		if !strings.HasPrefix(correlation, expectedPrefix) {
			t.Fatalf("retry %d next correlation = %q, want prefix %q", retryNumber, correlation, expectedPrefix)
		}
	}
	if _, err := service.sqlite.DB().Exec(`UPDATE jobs SET due_at = ? WHERE source_id = ? AND status = 'queued'`, time.Now().Add(-time.Second).UnixMilli(), sourceID); err != nil {
		t.Fatal(err)
	}
	if worked, err := service.worker.ProcessOne(context.Background()); err != nil || !worked {
		t.Fatalf("next periodic ProcessOne() = %v, %v", worked, err)
	}
	var restartedCorrelation string
	if err := service.sqlite.DB().QueryRow(`SELECT correlation_id FROM jobs WHERE source_id = ? AND status = 'queued'`, sourceID).Scan(&restartedCorrelation); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(restartedCorrelation, "retry-1-") {
		t.Fatalf("next periodic retry correlation = %q", restartedCorrelation)
	}
}

func TestRefreshScheduleReconciliationRepairsLostChainAndStopsOldRevision(t *testing.T) {
	root := t.TempDir()
	secrets := filepath.Join(root, "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	masterPath := filepath.Join(secrets, "master.key")
	if _, err := masterkey.Generate(masterPath, masterkey.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	adminPath := filepath.Join(secrets, "admin.token")
	if err := auth.Generate(adminPath, auth.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	service, err := Open(context.Background(), Config{
		DataDir: filepath.Join(root, "data"), MasterKeyPath: masterPath,
		AdminTokenPath: adminPath, Listen: "127.0.0.1:0", Development: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	server := httptest.NewServer(service.api.Handler())
	defer server.Close()
	created := postJSON(t, server.URL+"/api/v1/sources", readAdminBearer(t, adminPath), map[string]interface{}{
		"display_name": "reconciled remote", "type": "remote",
		"url": "https://example.test/subscription", "input_format": "sing-box",
		"timeout_seconds": 10, "refresh_interval_seconds": 60,
	})
	sourceID := requiredString(t, created, "source_id")
	oldJob, err := service.jobs.Get(context.Background(), requiredString(t, created, "job_id"))
	if err != nil {
		t.Fatal(err)
	}
	detail, config, err := service.manager.CurrentSourceConfig(context.Background(), sourceID)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := service.manager.UpdateSourceAt(
		context.Background(), sourceID, detail.Source.DisplayName, detail.Source.UpdatedAt, config,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.manager.ReconcileRefreshSchedules(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldJob, err = service.jobs.Get(context.Background(), oldJob.ID)
	if err != nil || oldJob.Status != "dead" || oldJob.ErrorCode != "superseded_revision" {
		t.Fatalf("old revision job = %+v, %v", oldJob, err)
	}
	currentJob, err := service.jobs.Get(context.Background(), updated.Job.ID)
	if err != nil || currentJob.Status != "queued" {
		t.Fatalf("current revision job = %+v, %v", currentJob, err)
	}
	next, err := service.manager.NextRefreshAfterFailure(context.Background(), sourceID, oldJob.SourceRevisionID, errors.New("fixture failure"))
	if err != nil || next.At != nil {
		t.Fatalf("superseded revision next refresh = %v, %v", next, err)
	}
	if _, err := service.sqlite.DB().Exec(`
UPDATE jobs SET status = 'dead', error_code = 'test_chain_loss', finished_at = ? WHERE id = ?`,
		time.Now().UTC().UnixMilli(), currentJob.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.manager.ReconcileRefreshSchedules(context.Background()); err != nil {
		t.Fatal(err)
	}
	var active int
	if err := service.sqlite.DB().QueryRow(`
SELECT count(*) FROM jobs
WHERE source_id = ? AND source_revision_id = ? AND status IN ('queued', 'leased', 'running')`,
		sourceID, updated.Revision.ID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("active current revision jobs = %d, want 1", active)
	}
	manual := postJSON(t, server.URL+"/api/v1/sources", readAdminBearer(t, adminPath), map[string]interface{}{
		"display_name": "manual remote", "type": "remote",
		"url": "https://example.test/manual", "input_format": "sing-box", "timeout_seconds": 10,
	})
	if _, err := service.sqlite.DB().Exec(`
UPDATE jobs SET status = 'dead', error_code = 'test_chain_loss', finished_at = ? WHERE id = ?`,
		time.Now().UTC().UnixMilli(), requiredString(t, manual, "job_id")); err != nil {
		t.Fatal(err)
	}
	if _, err := service.manager.ReconcileRefreshSchedules(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := service.sqlite.DB().QueryRow(`
SELECT count(*) FROM jobs
WHERE source_id = ? AND status IN ('queued', 'leased', 'running')`,
		requiredString(t, manual, "source_id")).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 0 {
		t.Fatalf("manual source active jobs = %d, want 0", active)
	}
}

func TestManagedOutputAggregatesStableNamesTemplateAndRestart(t *testing.T) {
	root := t.TempDir()
	secrets := filepath.Join(root, "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	masterPath := filepath.Join(secrets, "master.key")
	if _, err := masterkey.Generate(masterPath, masterkey.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	adminPath := filepath.Join(secrets, "admin.token")
	if err := auth.Generate(adminPath, auth.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	admin := readAdminBearer(t, adminPath)
	executorPath := filepath.Join(root, "sing-box")
	writeValidator := func(checkExit int) {
		t.Helper()
		script := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = version ]; then echo 'sing-box version 1.12.25'; exit 0; fi\nif [ \"$1\" = check ]; then exit %d; fi\nexit 1\n", checkExit)
		if err := os.WriteFile(executorPath, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeValidator(0)
	config := Config{
		DataDir: filepath.Join(root, "data"), MasterKeyPath: masterPath,
		AdminTokenPath: adminPath, SingBoxPath: executorPath,
		Listen: "127.0.0.1:0", Development: true,
	}
	service, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service.api.Handler())

	first := postJSON(t, server.URL+"/api/v1/sources", admin, map[string]interface{}{
		"display_name": "preserved sing-box", "type": "inline", "input_format": "sing-box",
		"output_format": "same", "content": `{"outbounds":[{"type":"vless","tag":"Shared","server":"one.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001","future":{"number":1e3}}]}`,
	})
	second := postJSON(t, server.URL+"/api/v1/sources", admin, map[string]interface{}{
		"display_name": "converted URI", "type": "inline", "input_format": "uri-list",
		"output_format": "same", "content": "vless://00000000-0000-4000-8000-000000000002@two.example:443?encryption=none#Shared\n",
	})
	for index := 0; index < 2; index++ {
		worked, err := service.worker.ProcessOne(context.Background())
		if err != nil || !worked {
			t.Fatalf("source worker %d = %v, %v", index, worked, err)
		}
	}
	firstID, secondID := requiredString(t, first, "source_id"), requiredString(t, second, "source_id")
	collection := postJSONWithStatus(t, server.URL+"/api/v1/collections", admin, map[string]interface{}{
		"display_name": "all nodes", "members": []map[string]interface{}{
			{"kind": "source", "id": firstID}, {"kind": "source", "id": secondID},
		},
	}, http.StatusCreated)
	postJSONWithStatus(t, server.URL+"/api/v1/templates", admin, map[string]interface{}{
		"display_name": "invalid mixed template", "source_type": "inline", "target_format": "sing-box",
		"content": `{"outbounds":[{"type":"vless","tag":"must-not-disappear","server":"example.test","server_port":443,"uuid":"00000000-0000-4000-8000-000000000003"},{"type":"selector","tag":"Select","outbounds":["${PROXYLOOM_NODES}"]}]}`,
	}, http.StatusUnprocessableEntity)
	template := postJSONWithStatus(t, server.URL+"/api/v1/templates", admin, map[string]interface{}{
		"display_name": "Momo template", "source_type": "inline", "target_format": "sing-box",
		"content": `{"log":{"level":"info"},"outbounds":[{"type":"selector","tag":"Shared","outbounds":["${PROXYLOOM_NODES}"]},{"type":"urltest","tag":"Second only","outbounds":["${PROXYLOOM_NODES_REGEX:#2$}"]},{"type":"direct","tag":"direct"}],"route":{"final":"Shared"}}`,
	}, http.StatusCreated)
	output := postJSONWithStatus(t, server.URL+"/api/v1/outputs", admin, map[string]interface{}{
		"display_name": "Momo full config", "collection_id": requiredString(t, collection, "id"),
		"template_id": requiredString(t, template, "id"), "target_profile": "momo-1.2.1-sing-box-1.12.25",
		"output_shape": "full_config", "maximum_drop_ratio": 1,
	}, http.StatusCreated)
	firstBuild := postJSONWithStatus(t, server.URL+"/api/v1/outputs/"+requiredString(t, output, "id")+"/builds", admin, map[string]interface{}{}, http.StatusAccepted)
	processOutputBuild(t, service, firstBuild, "succeeded")
	firstOutput, err := service.outputs.Output(context.Background(), requiredString(t, output, "id"))
	if err != nil || firstOutput.AllocationBlobID == "" {
		t.Fatalf("first output allocation = %+v, %v", firstOutput, err)
	}
	var artifactsBeforeRepeat, blobsBeforeRepeat int
	if err := service.sqlite.DB().QueryRow(`SELECT count(*) FROM managed_output_artifacts WHERE output_id = ?`, firstOutput.ID).Scan(&artifactsBeforeRepeat); err != nil {
		t.Fatal(err)
	}
	if err := service.sqlite.DB().QueryRow(`SELECT count(*) FROM encrypted_blobs`).Scan(&blobsBeforeRepeat); err != nil {
		t.Fatal(err)
	}
	repeated, err := service.aggregate.Build(context.Background(), firstOutput.ID)
	if err != nil || repeated.Changed || repeated.Artifact.ID != firstOutput.CurrentArtifactID {
		t.Fatalf("unchanged managed build = %+v, %v", repeated, err)
	}
	var artifactsAfterRepeat, blobsAfterRepeat int
	if err := service.sqlite.DB().QueryRow(`SELECT count(*) FROM managed_output_artifacts WHERE output_id = ?`, firstOutput.ID).Scan(&artifactsAfterRepeat); err != nil {
		t.Fatal(err)
	}
	if err := service.sqlite.DB().QueryRow(`SELECT count(*) FROM encrypted_blobs`).Scan(&blobsAfterRepeat); err != nil {
		t.Fatal(err)
	}
	if artifactsAfterRepeat != artifactsBeforeRepeat || blobsAfterRepeat != blobsBeforeRepeat {
		t.Fatalf("unchanged managed build wrote history: artifacts %d->%d blobs %d->%d", artifactsBeforeRepeat, artifactsAfterRepeat, blobsBeforeRepeat, blobsAfterRepeat)
	}
	if err := service.aggregate.EnqueueForTemplate(context.Background(), requiredString(t, template, "id")); err != nil {
		t.Fatal(err)
	}
	var redundantTemplateBuilds int
	if err := service.sqlite.DB().QueryRow(`
SELECT count(*) FROM managed_output_build_jobs
WHERE output_id = ? AND correlation_id = ?`, requiredString(t, output, "id"), "template-refresh-"+requiredString(t, template, "id")).Scan(&redundantTemplateBuilds); err != nil {
		t.Fatal(err)
	}
	if redundantTemplateBuilds != 0 {
		t.Fatalf("current template revision queued %d redundant builds", redundantTemplateBuilds)
	}
	if err := service.aggregate.EnqueueForSource(context.Background(), firstID, "health_boundary"); err != nil {
		t.Fatal(err)
	}
	var disabledHealthBuilds int
	if err := service.sqlite.DB().QueryRow(`
SELECT count(*) FROM managed_output_build_jobs
WHERE output_id = ? AND trigger_kind = 'health_boundary'`, requiredString(t, output, "id")).Scan(&disabledHealthBuilds); err != nil {
		t.Fatal(err)
	}
	if disabledHealthBuilds != 0 {
		t.Fatalf("health boundary queued %d builds for an Output with health filtering disabled", disabledHealthBuilds)
	}
	subscriptionURL := server.URL + requiredString(t, output, "subscription_url")
	beforeContent, beforeNames := readManagedOutput(t, subscriptionURL)
	if beforeNames["one.example"] == beforeNames["two.example"] ||
		!sameStringSet([]string{beforeNames["one.example"], beforeNames["two.example"]}, []string{"Shared #2", "Shared #3"}) {
		t.Fatalf("duplicate names were not allocated with stable numeric suffixes: %v", beforeNames)
	}
	if !bytes.Contains(beforeContent, []byte(`"future": {`)) || !bytes.Contains(beforeContent, []byte(`1e3`)) {
		t.Fatalf("preserved sing-box fields were lost: %s", beforeContent)
	}
	if !bytes.Contains(beforeContent, []byte(`"outbounds": [`)) ||
		!bytes.Contains(beforeContent, []byte(`"Second only"`)) || !bytes.Contains(beforeContent, []byte(`"direct"`)) {
		t.Fatalf("full-config template was not expanded: %s", beforeContent)
	}
	var grouped struct {
		Outbounds []struct {
			Tag       string   `json:"tag"`
			Outbounds []string `json:"outbounds"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(beforeContent, &grouped); err != nil {
		t.Fatal(err)
	}
	regexExpanded := false
	for _, outbound := range grouped.Outbounds {
		if outbound.Tag == "Second only" {
			regexExpanded = len(outbound.Outbounds) == 1 && strings.HasSuffix(outbound.Outbounds[0], "#2")
		}
	}
	if !regexExpanded {
		t.Fatalf("regex template marker did not select the expected stable name: %s", beforeContent)
	}
	automaticRefresh := postJSON(t, server.URL+"/api/v1/sources/"+firstID+"/refresh", admin, map[string]interface{}{})
	var snapshotsBeforeRefresh, sourceArtifactsBeforeRefresh, blobsBeforeRefresh int
	if err := service.sqlite.DB().QueryRow(`SELECT count(*) FROM snapshots WHERE source_id = ?`, firstID).Scan(&snapshotsBeforeRefresh); err != nil {
		t.Fatal(err)
	}
	if err := service.sqlite.DB().QueryRow(`SELECT count(*) FROM artifacts WHERE source_id = ?`, firstID).Scan(&sourceArtifactsBeforeRefresh); err != nil {
		t.Fatal(err)
	}
	if err := service.sqlite.DB().QueryRow(`SELECT count(*) FROM encrypted_blobs`).Scan(&blobsBeforeRefresh); err != nil {
		t.Fatal(err)
	}
	worked, err := service.worker.ProcessOne(context.Background())
	if err != nil || !worked {
		t.Fatalf("automatic output source refresh worker = %v, %v", worked, err)
	}
	sourceJob, err := service.jobs.Get(context.Background(), requiredString(t, automaticRefresh, "job_id"))
	if err != nil || sourceJob.Status != "succeeded" {
		t.Fatalf("automatic output source job = %+v, %v", sourceJob, err)
	}
	var queuedBuilds, snapshotsAfterRefresh, sourceArtifactsAfterRefresh, blobsAfterRefresh int
	if err := service.sqlite.DB().QueryRow(`
SELECT count(*) FROM managed_output_build_jobs
WHERE output_id = ? AND status = 'queued'`, requiredString(t, output, "id")).Scan(&queuedBuilds); err != nil {
		t.Fatal(err)
	}
	if err := service.sqlite.DB().QueryRow(`SELECT count(*) FROM snapshots WHERE source_id = ?`, firstID).Scan(&snapshotsAfterRefresh); err != nil {
		t.Fatal(err)
	}
	if err := service.sqlite.DB().QueryRow(`SELECT count(*) FROM artifacts WHERE source_id = ?`, firstID).Scan(&sourceArtifactsAfterRefresh); err != nil {
		t.Fatal(err)
	}
	if err := service.sqlite.DB().QueryRow(`SELECT count(*) FROM encrypted_blobs`).Scan(&blobsAfterRefresh); err != nil {
		t.Fatal(err)
	}
	if queuedBuilds != 0 || snapshotsAfterRefresh != snapshotsBeforeRefresh || sourceArtifactsAfterRefresh != sourceArtifactsBeforeRefresh || blobsAfterRefresh != blobsBeforeRefresh {
		t.Fatalf("unchanged source refresh wrote history: builds=%d snapshots %d->%d artifacts %d->%d blobs %d->%d",
			queuedBuilds, snapshotsBeforeRefresh, snapshotsAfterRefresh, sourceArtifactsBeforeRefresh, sourceArtifactsAfterRefresh, blobsBeforeRefresh, blobsAfterRefresh)
	}
	if _, _, err := service.outputs.Blob(context.Background(), firstOutput.AllocationBlobID); err != nil {
		t.Fatalf("unchanged build removed active allocation: %v", err)
	}

	collectionURL := server.URL + "/api/v1/collections/" + requiredString(t, collection, "id")
	getCollection, _ := http.NewRequest(http.MethodGet, collectionURL, nil)
	getCollection.Header.Set("Authorization", "Bearer "+admin)
	getResponse, err := http.DefaultClient.Do(getCollection)
	if err != nil {
		t.Fatal(err)
	}
	etag := getResponse.Header.Get("ETag")
	getResponse.Body.Close()
	update := requestJSON(t, http.MethodPut, collectionURL, map[string]interface{}{
		"display_name": "all nodes reversed", "members": []map[string]interface{}{
			{"kind": "source", "id": secondID}, {"kind": "source", "id": firstID},
		},
	})
	update.Header.Set("Authorization", "Bearer "+admin)
	update.Header.Set("If-Match", etag)
	updateResponse, err := http.DefaultClient.Do(update)
	if err != nil {
		t.Fatal(err)
	}
	updateBody, _ := io.ReadAll(updateResponse.Body)
	updateResponse.Body.Close()
	if updateResponse.StatusCode != http.StatusOK {
		t.Fatalf("collection update status=%d body=%s", updateResponse.StatusCode, updateBody)
	}
	reorderedBuild := postJSONWithStatus(t, server.URL+"/api/v1/outputs/"+requiredString(t, output, "id")+"/build", admin, map[string]interface{}{}, http.StatusAccepted)
	processOutputBuild(t, service, reorderedBuild, "succeeded")
	afterContent, afterNames := readManagedOutput(t, subscriptionURL)
	if beforeNames["one.example"] != afterNames["one.example"] || beforeNames["two.example"] != afterNames["two.example"] {
		t.Fatalf("name allocations changed after collection reorder: before=%v after=%v", beforeNames, afterNames)
	}
	var blobsBefore int
	if err := service.sqlite.DB().QueryRow(`SELECT count(*) FROM encrypted_blobs`).Scan(&blobsBefore); err != nil {
		t.Fatal(err)
	}
	rejectedOutput := postJSONWithStatus(t, server.URL+"/api/v1/outputs", admin, map[string]interface{}{
		"display_name": "content gate rejection", "collection_id": requiredString(t, collection, "id"),
		"target_profile": "sing-box-1.12.25", "output_shape": "outbounds_object",
		"minimum_nodes": 3, "maximum_drop_ratio": 0,
	}, http.StatusCreated)
	if ratio, ok := rejectedOutput["maximum_drop_ratio"].(float64); !ok || ratio != 0 {
		t.Fatalf("explicit zero maximum_drop_ratio was not preserved: %v", rejectedOutput["maximum_drop_ratio"])
	}
	rejectedBuild := postJSONWithStatus(t, server.URL+"/api/v1/outputs/"+requiredString(t, rejectedOutput, "id")+"/builds", admin, map[string]interface{}{}, http.StatusAccepted)
	processOutputBuild(t, service, rejectedBuild, "failed")
	var blobsAfter int
	if err := service.sqlite.DB().QueryRow(`SELECT count(*) FROM encrypted_blobs`).Scan(&blobsAfter); err != nil {
		t.Fatal(err)
	}
	if blobsAfter != blobsBefore {
		t.Fatalf("rejected build left encrypted blobs: before=%d after=%d", blobsBefore, blobsAfter)
	}

	writeValidator(1)
	validatorBuild := postJSONWithStatus(t, server.URL+"/api/v1/outputs/"+requiredString(t, output, "id")+"/builds", admin, map[string]interface{}{}, http.StatusAccepted)
	processOutputBuild(t, service, validatorBuild, "failed")
	stillPublished, _ := readManagedOutput(t, subscriptionURL)
	if !bytes.Equal(stillPublished, afterContent) {
		t.Fatal("validator rejection switched the current managed output artifact")
	}
	recoveryJob, err := service.aggregate.EnqueueBuild(context.Background(), requiredString(t, output, "id"), "lease-recovery-test")
	if err != nil {
		t.Fatal(err)
	}
	claimed, exists, err := service.outputJobs.Claim(context.Background(), "crashed-output-worker", time.Minute)
	if err != nil || !exists || claimed.ID != recoveryJob.ID {
		t.Fatalf("claim managed output recovery job = %+v, %v, %v", claimed, exists, err)
	}
	if _, err := service.outputJobs.MarkRunning(context.Background(), claimed.ID, "crashed-output-worker"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.sqlite.DB().Exec(`UPDATE managed_output_build_jobs SET lease_expires_at = 0 WHERE id = ?`, claimed.ID); err != nil {
		t.Fatal(err)
	}
	if recovered, err := service.outputJobs.RecoverExpired(context.Background()); err != nil || recovered != 1 {
		t.Fatalf("recover managed output lease = %d, %v", recovered, err)
	}
	recoveredJob, err := service.outputJobs.Get(context.Background(), claimed.ID)
	if err != nil || recoveredJob.Status != "queued" {
		t.Fatalf("recovered managed output job = %+v, %v", recoveredJob, err)
	}
	writeValidator(0)
	processOutputBuild(t, service, map[string]interface{}{"id": recoveredJob.ID}, "succeeded")

	rotated := postJSONWithStatus(t, server.URL+"/api/v1/outputs/"+requiredString(t, output, "id")+"/tokens", admin, map[string]interface{}{}, http.StatusCreated)
	oldResponse, err := http.Get(subscriptionURL)
	if err != nil {
		t.Fatal(err)
	}
	oldResponse.Body.Close()
	if oldResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("rotated managed output token remained active: %d", oldResponse.StatusCode)
	}
	rotatedPath := requiredString(t, rotated, "subscription_url")
	readManagedOutput(t, server.URL+rotatedPath)
	healthFilteredOutput := postJSONWithStatus(t, server.URL+"/api/v1/outputs", admin, map[string]interface{}{
		"display_name": "health-filtered output", "collection_id": requiredString(t, collection, "id"),
		"target_profile": "sing-box-1.12.25", "output_shape": "outbounds_object",
		"health_filter_enabled": true, "maximum_drop_ratio": 1,
	}, http.StatusCreated)
	if err := service.aggregate.EnqueueForSource(context.Background(), firstID, "health_boundary"); err != nil {
		t.Fatal(err)
	}
	var enabledHealthBuilds int
	if err := service.sqlite.DB().QueryRow(`
SELECT count(*) FROM managed_output_build_jobs
WHERE output_id = ? AND trigger_kind = 'health_boundary' AND status = 'queued'`, requiredString(t, healthFilteredOutput, "id")).Scan(&enabledHealthBuilds); err != nil {
		t.Fatal(err)
	}
	if enabledHealthBuilds != 1 {
		t.Fatalf("health boundary queued %d builds for an Output with health filtering enabled", enabledHealthBuilds)
	}

	server.Close()
	service.Close()
	restarted, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restartedServer := httptest.NewServer(restarted.api.Handler())
	defer restartedServer.Close()
	_, restartedNames := readManagedOutput(t, restartedServer.URL+rotatedPath)
	if afterNames["one.example"] != restartedNames["one.example"] || afterNames["two.example"] != restartedNames["two.example"] {
		t.Fatalf("managed output publication changed after restart: before=%v after=%v", afterNames, restartedNames)
	}
	patchedOutput := patchJSONWithStatus(t, restartedServer.URL+"/api/v1/outputs/"+requiredString(t, output, "id"), admin, map[string]interface{}{
		"health_filter_enabled": true, "minimum_nodes": 2, "maximum_drop_ratio": 0.75,
	}, http.StatusAccepted)
	if enabled, _ := patchedOutput["health_filter_enabled"].(bool); !enabled ||
		patchedOutput["minimum_nodes"] != float64(2) || patchedOutput["maximum_drop_ratio"] != 0.75 ||
		requiredString(t, patchedOutput, "job_id") == "" {
		t.Fatalf("patched output policy = %+v", patchedOutput)
	}
}

func TestRemoteTemplateRefreshKeepsLastValidContentAndQueuesOutputs(t *testing.T) {
	root := t.TempDir()
	secrets := filepath.Join(root, "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	masterPath := filepath.Join(secrets, "master.key")
	if _, err := masterkey.Generate(masterPath, masterkey.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	adminPath := filepath.Join(secrets, "admin.token")
	if err := auth.Generate(adminPath, auth.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	admin := readAdminBearer(t, adminPath)
	firstTemplate := `{"outbounds":[{"type":"selector","tag":"Select","outbounds":["${PROXYLOOM_NODES}"]},{"type":"direct","tag":"direct"}],"route":{"final":"Select"}}`
	secondTemplate := `{"log":{"level":"warn"},"outbounds":[{"type":"selector","tag":"Select","outbounds":["${PROXYLOOM_NODES}"]},{"type":"direct","tag":"direct"}],"route":{"final":"Select"}}`
	thirdTemplate := `{"log":{"level":"error"},"outbounds":[{"type":"selector","tag":"Select","outbounds":["${PROXYLOOM_NODES}"]},{"type":"direct","tag":"direct"}],"route":{"final":"Select"}}`
	var remote struct {
		sync.Mutex
		content  string
		requests int
	}
	remote.content = firstTemplate
	remoteURL := "https://raw.githubusercontent.com/example/private/main/momo.json?token=must-not-leak"
	service, err := Open(context.Background(), Config{
		DataDir: filepath.Join(root, "data"), MasterKeyPath: masterPath,
		AdminTokenPath: adminPath, Listen: "127.0.0.1:0", Development: true,
		RemoteTemplateFetcher: func(_ context.Context, rawURL string, _ fetcher.Options) (fetcher.Result, error) {
			remote.Lock()
			defer remote.Unlock()
			if rawURL != remoteURL {
				return fetcher.Result{}, fmt.Errorf("unexpected remote template URL")
			}
			remote.requests++
			return fetcher.Result{Content: []byte(remote.content), StatusCode: http.StatusOK, ContentType: "application/json"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	apiServer := httptest.NewServer(service.api.Handler())
	defer apiServer.Close()

	createdSource := postJSON(t, apiServer.URL+"/api/v1/sources", admin, map[string]interface{}{
		"display_name": "template test node", "type": "inline", "input_format": "uri-list",
		"output_format": "same", "content": "vless://00000000-0000-4000-8000-000000000001@example.com:443?encryption=none#Node\n",
	})
	if worked, err := service.worker.ProcessOne(context.Background()); err != nil || !worked {
		t.Fatalf("source worker = %v, %v", worked, err)
	}
	collection := postJSONWithStatus(t, apiServer.URL+"/api/v1/collections", admin, map[string]interface{}{
		"display_name": "template test collection",
		"members":      []map[string]interface{}{{"kind": "source", "id": requiredString(t, createdSource, "source_id")}},
	}, http.StatusCreated)
	template := postJSONWithStatus(t, apiServer.URL+"/api/v1/templates", admin, map[string]interface{}{
		"display_name": "GitHub template", "source_type": "remote", "target_format": "sing-box",
		"url":                      remoteURL,
		"refresh_interval_seconds": 60,
	}, http.StatusCreated)
	templateID := requiredString(t, template, "id")
	configuration := template["configuration"].(map[string]interface{})
	if configuration["source_type"] != "remote" || configuration["masked_location"] != "https://raw.githubusercontent.com/..." ||
		strings.Contains(fmt.Sprint(configuration), "must-not-leak") {
		t.Fatalf("remote template configuration was not safely represented: %+v", configuration)
	}
	output := postJSONWithStatus(t, apiServer.URL+"/api/v1/outputs", admin, map[string]interface{}{
		"display_name": "remote template output", "collection_id": requiredString(t, collection, "id"),
		"template_id": templateID, "target_profile": "sing-box-1.12.25", "output_shape": "full_config",
	}, http.StatusCreated)

	unchanged := postJSONWithStatus(t, apiServer.URL+"/api/v1/templates/"+templateID+"/refresh", admin, nil, http.StatusOK)
	if unchanged["changed"] != false || unchanged["revision_number"] != float64(1) {
		t.Fatalf("unchanged remote template created a revision: %+v", unchanged)
	}
	remote.Lock()
	remote.content = secondTemplate
	remote.Unlock()
	changed := postJSONWithStatus(t, apiServer.URL+"/api/v1/templates/"+templateID+"/refresh", admin, nil, http.StatusOK)
	if changed["changed"] != true || changed["revision_number"] != float64(2) {
		t.Fatalf("changed remote template was not revised: %+v", changed)
	}
	var queued int
	if err := service.sqlite.DB().QueryRow(`
SELECT count(*) FROM managed_output_build_jobs
WHERE output_id = ? AND correlation_id = ?`, requiredString(t, output, "id"), "template-refresh-"+templateID).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 1 {
		t.Fatalf("remote template refresh queued %d associated output builds", queued)
	}
	if worked, err := service.outputWorker.ProcessOne(context.Background()); err != nil || !worked {
		t.Fatalf("failed associated output build = %v, %v", worked, err)
	}
	retried := postJSONWithStatus(t, apiServer.URL+"/api/v1/templates/"+templateID+"/refresh", admin, nil, http.StatusOK)
	if retried["changed"] != false {
		t.Fatalf("unchanged recovery refresh reported content change: %+v", retried)
	}
	if err := service.sqlite.DB().QueryRow(`
SELECT count(*) FROM managed_output_build_jobs
WHERE output_id = ? AND correlation_id = ?`, requiredString(t, output, "id"), "template-refresh-"+templateID).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 2 {
		t.Fatalf("unchanged refresh did not retry the failed output build: jobs=%d", queued)
	}

	remote.Lock()
	remote.content = `{"outbounds":[]}`
	remote.Unlock()
	postJSONWithStatus(t, apiServer.URL+"/api/v1/templates/"+templateID+"/refresh", admin, nil, http.StatusUnprocessableEntity)
	resource, err := service.outputs.Resource(context.Background(), templateID, "template")
	if err != nil || resource.RevisionNumber != 2 {
		t.Fatalf("invalid refresh changed resource revision: %+v, %v", resource, err)
	}
	lastValid, err := service.outputs.TemplateContent(context.Background(), resource)
	if err != nil || string(lastValid) != secondTemplate {
		t.Fatalf("invalid refresh replaced last valid template: %s, %v", lastValid, err)
	}

	remote.Lock()
	remote.content = thirdTemplate
	remote.Unlock()
	dueFixtureTime := time.Now().Add(-2 * time.Minute).UnixMilli()
	if _, err := service.sqlite.DB().Exec(`UPDATE managed_resources SET created_at = ?, updated_at = ? WHERE id = ?`, dueFixtureTime, dueFixtureTime, templateID); err != nil {
		t.Fatal(err)
	}
	restartedTemplateWorker, err := aggregate.NewWorker(service.aggregate, service.outputJobs, aggregate.WorkerOptions{Owner: "remote-template-test-worker"})
	if err != nil {
		t.Fatal(err)
	}
	if worked, err := restartedTemplateWorker.ProcessOne(context.Background()); err != nil || !worked {
		t.Fatalf("automatic remote template refresh = %v, %v", worked, err)
	}
	resource, err = service.outputs.Resource(context.Background(), templateID, "template")
	if err != nil || resource.RevisionNumber != 3 {
		t.Fatalf("automatic refresh did not create revision 3: %+v, %v", resource, err)
	}
	lastValid, err = service.outputs.TemplateContent(context.Background(), resource)
	if err != nil || string(lastValid) != thirdTemplate {
		t.Fatalf("automatic refresh stored unexpected content: %s, %v", lastValid, err)
	}

	remote.Lock()
	requestCount := remote.requests
	remote.Unlock()
	postJSONWithStatus(t, apiServer.URL+"/api/v1/templates", admin, map[string]interface{}{
		"display_name": "invalid interval", "source_type": "remote", "url": remoteURL,
		"refresh_interval_seconds": 59,
	}, http.StatusUnprocessableEntity)
	remote.Lock()
	defer remote.Unlock()
	if remote.requests != requestCount {
		t.Fatalf("invalid refresh interval made a network request: before=%d after=%d", requestCount, remote.requests)
	}
}

func TestManagedOutputSelectsExactTargetValidator(t *testing.T) {
	root := t.TempDir()
	secrets := filepath.Join(root, "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	masterPath := filepath.Join(secrets, "master.key")
	if _, err := masterkey.Generate(masterPath, masterkey.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	adminPath := filepath.Join(secrets, "admin.token")
	if err := auth.Generate(adminPath, auth.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	writeValidator := func(path, version string, rejectNaive bool) {
		t.Helper()
		rejection := ""
		if rejectNaive {
			rejection = `if grep -q '"type"[[:space:]]*:[[:space:]]*"naive"' "$3"; then exit 1; fi`
		}
		script := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = version ]; then echo 'sing-box version %s'; exit 0; fi\nif [ \"$1\" = check ]; then %s exit 0; fi\nexit 1\n", version, rejection)
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	validator12Path := filepath.Join(root, "sing-box-1.12")
	validator13Path := filepath.Join(root, "sing-box-1.13")
	writeValidator(validator12Path, "1.12.25", true)
	writeValidator(validator13Path, "1.13.14", false)
	service, err := Open(context.Background(), Config{
		DataDir: filepath.Join(root, "data"), MasterKeyPath: masterPath,
		AdminTokenPath: adminPath, Listen: "127.0.0.1:0", Development: true,
		SingBoxPath: validator12Path, SingBox13Path: validator13Path,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	server := httptest.NewServer(service.api.Handler())
	defer server.Close()
	admin := readAdminBearer(t, adminPath)
	raw := `{"outbounds":[{"type":"naive","tag":"Naive","server":"naive.example","server_port":443,"username":"fixture","password":"fixture"}]}`
	source := postJSON(t, server.URL+"/api/v1/sources", admin, map[string]interface{}{
		"display_name": "sing-box 1.13 raw", "type": "inline", "input_format": "sing-box",
		"output_format": "same", "content": raw,
	})
	worked, err := service.worker.ProcessOne(context.Background())
	if err != nil || !worked {
		t.Fatalf("raw Source refresh = %v, %v", worked, err)
	}
	sourceResponse, err := http.Get(server.URL + requiredString(t, source, "subscription_url"))
	if err != nil {
		t.Fatal(err)
	}
	sourceContent, _ := io.ReadAll(sourceResponse.Body)
	sourceResponse.Body.Close()
	if sourceResponse.StatusCode != http.StatusOK || !bytes.Equal(sourceContent, []byte(raw)) {
		t.Fatalf("raw Source publication status=%d content=%s", sourceResponse.StatusCode, sourceContent)
	}
	collection := postJSONWithStatus(t, server.URL+"/api/v1/collections", admin, map[string]interface{}{
		"display_name": "1.13 nodes", "members": []map[string]interface{}{{
			"kind": "source", "id": requiredString(t, source, "source_id"),
		}},
	}, http.StatusCreated)
	createOutput := func(profile string) map[string]interface{} {
		return postJSONWithStatus(t, server.URL+"/api/v1/outputs", admin, map[string]interface{}{
			"display_name": profile, "collection_id": requiredString(t, collection, "id"),
			"target_profile": profile, "output_shape": "outbounds_object",
		}, http.StatusCreated)
	}
	output12 := createOutput("sing-box-1.12.25")
	build12 := postJSONWithStatus(t, server.URL+"/api/v1/outputs/"+requiredString(t, output12, "id")+"/builds", admin, map[string]interface{}{}, http.StatusAccepted)
	processOutputBuild(t, service, build12, "failed")
	stored12, err := service.outputs.Output(context.Background(), requiredString(t, output12, "id"))
	if err != nil || stored12.CurrentArtifactID != "" {
		t.Fatalf("1.12 rejection published an Artifact: %+v, %v", stored12, err)
	}
	output13 := createOutput("sing-box-1.13.14")
	build13 := postJSONWithStatus(t, server.URL+"/api/v1/outputs/"+requiredString(t, output13, "id")+"/builds", admin, map[string]interface{}{}, http.StatusAccepted)
	processOutputBuild(t, service, build13, "succeeded")
	token := strings.TrimPrefix(requiredString(t, output13, "subscription_url"), "/subscriptions/")
	artifact, err := service.outputs.Resolve(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	content, err := service.outputs.Content(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.TargetProfile != "sing-box-1.13.14" || artifact.ValidatorVersion != "sing-box-1.13.14-check" ||
		artifact.NodeCount != 1 || !bytes.Contains(content, []byte(`"type": "naive"`)) {
		t.Fatalf("1.13 Artifact metadata=%+v content=%s", artifact, content)
	}
}

func readManagedOutput(t *testing.T, url string) ([]byte, map[string]string) {
	t.Helper()
	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	content, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("managed output status=%d body=%s", response.StatusCode, content)
	}
	var document struct {
		Outbounds []struct {
			Type   string `json:"type"`
			Tag    string `json:"tag"`
			Server string `json:"server"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode managed output: %v\n%s", err, content)
	}
	names := make(map[string]string)
	for _, outbound := range document.Outbounds {
		if outbound.Server != "" {
			names[outbound.Server] = outbound.Tag
		}
	}
	return content, names
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, value := range left {
		counts[value]++
	}
	for _, value := range right {
		counts[value]--
		if counts[value] < 0 {
			return false
		}
	}
	return true
}

func processOutputBuild(t *testing.T, service *Service, queued map[string]interface{}, expectedStatus string) {
	t.Helper()
	worked, err := service.outputWorker.ProcessOne(context.Background())
	if err != nil || !worked {
		t.Fatalf("managed output worker = %v, %v", worked, err)
	}
	job, err := service.outputJobs.Get(context.Background(), requiredString(t, queued, "id"))
	if err != nil || string(job.Status) != expectedStatus {
		t.Fatalf("managed output job status=%s code=%s detail=%s error=%v", job.Status, job.ErrorCode, job.ErrorDetail, err)
	}
}

func TestMasterKeyRotationRestartAndFinalize(t *testing.T) {
	root := t.TempDir()
	secrets := filepath.Join(root, "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	masterPath := filepath.Join(secrets, "master.key")
	oldMaster, err := masterkey.Generate(masterPath, masterkey.GenerateOptions{Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	adminPath := filepath.Join(secrets, "admin.token")
	if err := auth.Generate(adminPath, auth.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	config := Config{
		DataDir: filepath.Join(root, "data"), MasterKeyPath: masterPath,
		AdminTokenPath: adminPath, Listen: "127.0.0.1:0", Development: true,
	}

	initial, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	keyIDsBefore := activeDataKeyIDs(t, initial.sqlite.DB())
	initial.Close()

	if err := os.Remove(adminPath); err != nil {
		t.Fatal(err)
	}
	newMasterID, err := RotateMasterKey(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if newMasterID == oldMaster.ID {
		t.Fatal("master key ID did not change")
	}
	activeFile, err := masterkey.Load(masterPath, masterkey.LoadOptions{ExpectedUID: -1, ExpectedGID: -1})
	if err != nil || activeFile.ID != newMasterID {
		t.Fatalf("active master file = %s, %v", activeFile.ID, err)
	}
	previousFile, err := masterkey.Load(masterPath+".previous", masterkey.LoadOptions{ExpectedUID: -1, ExpectedGID: -1})
	if err != nil || previousFile.ID != oldMaster.ID {
		t.Fatalf("previous master file = %s, %v", previousFile.ID, err)
	}
	if err := auth.Generate(adminPath, auth.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}

	restarted, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if keyIDsAfter := activeDataKeyIDs(t, restarted.sqlite.DB()); !equalStringMaps(keyIDsBefore, keyIDsAfter) {
		t.Fatalf("data key IDs changed during master rotation: before=%v after=%v", keyIDsBefore, keyIDsAfter)
	}
	var activeID, previousState string
	if err := restarted.sqlite.DB().QueryRow(`SELECT active_master_key_id FROM instances WHERE singleton = 1`).Scan(&activeID); err != nil {
		t.Fatal(err)
	}
	if err := restarted.sqlite.DB().QueryRow(`SELECT state FROM master_key_slots WHERE id = ?`, oldMaster.ID).Scan(&previousState); err != nil {
		t.Fatal(err)
	}
	if activeID != newMasterID || previousState != "retired" {
		t.Fatalf("rotation activation active=%s previous_state=%s", activeID, previousState)
	}
	restarted.Close()

	if err := FinalizeMasterKeyRotation(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(masterPath + ".previous"); !os.IsNotExist(err) {
		t.Fatalf("previous master key still exists: %v", err)
	}
	verified, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer verified.Close()
	var preparedAudit, startedAudit, finalizedAudit int
	if err := verified.sqlite.DB().QueryRow(`
SELECT
	SUM(CASE WHEN action = 'master_key.rotation_prepared' THEN 1 ELSE 0 END),
	SUM(CASE WHEN action = 'master_key.rotation_finalize_started' THEN 1 ELSE 0 END),
	SUM(CASE WHEN action = 'master_key.rotation_finalized' THEN 1 ELSE 0 END)
FROM audit_events`).Scan(&preparedAudit, &startedAudit, &finalizedAudit); err != nil {
		t.Fatal(err)
	}
	if preparedAudit != 1 || startedAudit != 1 || finalizedAudit != 1 {
		t.Fatalf("rotation audit counts prepared=%d started=%d finalized=%d", preparedAudit, startedAudit, finalizedAudit)
	}
}

func TestManagedBackupRestoresAcrossInstancesWithTargetMasterKey(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	newConfig := func(name string) (Config, masterkey.Key, string) {
		t.Helper()
		instanceRoot := filepath.Join(root, name)
		secrets := filepath.Join(instanceRoot, "secrets")
		if err := os.MkdirAll(secrets, 0o700); err != nil {
			t.Fatal(err)
		}
		masterPath := filepath.Join(secrets, "master.key")
		master, err := masterkey.Generate(masterPath, masterkey.GenerateOptions{Random: rand.Reader})
		if err != nil {
			t.Fatal(err)
		}
		adminPath := filepath.Join(secrets, "admin.token")
		if err := auth.Generate(adminPath, auth.GenerateOptions{Random: rand.Reader}); err != nil {
			t.Fatal(err)
		}
		return Config{
			DataDir: filepath.Join(instanceRoot, "data"), MasterKeyPath: masterPath,
			AdminTokenPath: adminPath, Listen: "127.0.0.1:0", Development: true,
		}, master, adminPath
	}
	sourceConfig, sourceMaster, sourceAdminPath := newConfig("source")
	sourceService, err := Open(ctx, sourceConfig)
	if err != nil {
		t.Fatal(err)
	}
	sourceServer := httptest.NewServer(sourceService.api.Handler())
	singBoxInput := "{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"Portable\",\"server\":\"restore.example\",\"server_port\":443,\"uuid\":\"00000000-0000-4000-8000-000000000001\",\"fixed_test_secret\":\"backup-secret-must-stay-encrypted\"}]}\n"
	created := postJSON(t, sourceServer.URL+"/api/v1/sources", readAdminBearer(t, sourceAdminPath), map[string]interface{}{
		"display_name": "portable source", "type": "inline", "input_format": "sing-box",
		"output_format": "same", "content": singBoxInput,
	})
	worked, err := sourceService.worker.ProcessOne(ctx)
	if err != nil || !worked {
		t.Fatalf("source backup ProcessOne() = %v, %v", worked, err)
	}
	subscriptionPath := requiredString(t, created, "subscription_url")
	sourceServer.Close()
	sourceService.Close()

	backupPath := filepath.Join(root, "portable.plbk")
	passphrase := []byte("cross instance backup passphrase")
	backupInfo, err := CreateManagedBackup(ctx, sourceConfig, backupPath, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if backupInfo.Size == 0 || bytes.Contains(mustReadFile(t, backupPath), []byte("backup-secret-must-stay-encrypted")) {
		t.Fatal("managed backup is empty or leaks plaintext secret")
	}

	targetConfig, targetMaster, _ := newConfig("target")
	targetInitial, err := Open(ctx, targetConfig)
	if err != nil {
		t.Fatal(err)
	}
	targetInitial.Close()
	if _, err := RestoreManagedBackup(ctx, targetConfig, backupPath, []byte("wrong backup passphrase")); err == nil {
		t.Fatal("restore accepted a wrong passphrase")
	}
	targetUnchanged, err := Open(ctx, targetConfig)
	if err != nil {
		t.Fatalf("target changed after failed restore: %v", err)
	}
	var targetSources int
	err = targetUnchanged.sqlite.DB().QueryRow(`SELECT count(*) FROM sources`).Scan(&targetSources)
	if err != nil || targetSources != 0 {
		t.Fatalf("failed restore changed target sources: items=%d err=%v", targetSources, err)
	}
	targetUnchanged.Close()

	restoredInfo, err := RestoreManagedBackup(ctx, targetConfig, backupPath, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if restoredInfo.SourceInstanceID == "" || restoredInfo.RollbackPath == "" {
		t.Fatalf("restore info = %+v", restoredInfo)
	}
	restored, err := Open(ctx, targetConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var activeMasterID string
	if err := restored.sqlite.DB().QueryRow(`SELECT active_master_key_id FROM instances WHERE singleton = 1`).Scan(&activeMasterID); err != nil {
		t.Fatal(err)
	}
	if activeMasterID != targetMaster.ID || activeMasterID == sourceMaster.ID {
		t.Fatalf("restored active master = %s, target=%s source=%s", activeMasterID, targetMaster.ID, sourceMaster.ID)
	}
	restoredServer := httptest.NewServer(restored.api.Handler())
	defer restoredServer.Close()
	response, err := http.Get(restoredServer.URL + subscriptionPath)
	if err != nil {
		t.Fatal(err)
	}
	content, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Equal(content, []byte(singBoxInput)) {
		t.Fatalf("restored publication status=%d content=%s", response.StatusCode, content)
	}
}

func TestBlobDataKeyRotationIsOfflineAndPreservesPublications(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	secrets := filepath.Join(root, "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	masterPath := filepath.Join(secrets, "master.key")
	if _, err := masterkey.Generate(masterPath, masterkey.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	adminPath := filepath.Join(secrets, "admin.token")
	if err := auth.Generate(adminPath, auth.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	config := Config{
		DataDir: filepath.Join(root, "data"), MasterKeyPath: masterPath,
		AdminTokenPath: adminPath, Listen: "127.0.0.1:0", Development: true,
	}
	runtime, err := Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(runtime.api.Handler())
	padding := strings.Repeat("x", 70<<10)
	content := "{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"Rotated\",\"server\":\"rotation.example\",\"server_port\":443,\"uuid\":\"00000000-0000-4000-8000-000000000001\",\"padding\":\"" + padding + "\"}]}\n"
	created := postJSON(t, server.URL+"/api/v1/sources", readAdminBearer(t, adminPath), map[string]interface{}{
		"display_name": "rotation source", "type": "inline", "input_format": "sing-box",
		"output_format": "same", "content": content,
	})
	worked, err := runtime.worker.ProcessOne(ctx)
	if err != nil || !worked {
		t.Fatalf("data rotation ProcessOne() = %v, %v", worked, err)
	}
	var oldKeyID string
	if err := runtime.sqlite.DB().QueryRow(`SELECT id FROM data_keys WHERE purpose = 'blob' AND status = 'active'`).Scan(&oldKeyID); err != nil {
		t.Fatal(err)
	}
	var externalBefore int
	if err := runtime.sqlite.DB().QueryRow(`SELECT count(*) FROM encrypted_blobs WHERE relative_path IS NOT NULL`).Scan(&externalBefore); err != nil {
		t.Fatal(err)
	}
	if externalBefore == 0 {
		t.Fatal("rotation fixture did not create external encrypted blobs")
	}
	if _, err := RotateBlobDataKey(ctx, config); !errors.Is(err, ErrServiceRunning) {
		t.Fatalf("online data key rotation error = %v", err)
	}
	server.Close()
	runtime.Close()

	rotation, err := RotateBlobDataKey(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if rotation.ActiveKeyID == oldKeyID || rotation.BlobCount == 0 {
		t.Fatalf("data key rotation result = %+v old=%s", rotation, oldKeyID)
	}
	restarted, err := Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	var retiredState string
	var oldWrappings, wrongBlobKeys int
	if err := restarted.sqlite.DB().QueryRow(`SELECT status FROM data_keys WHERE id = ?`, oldKeyID).Scan(&retiredState); err != nil {
		t.Fatal(err)
	}
	if err := restarted.sqlite.DB().QueryRow(`SELECT count(*) FROM master_key_wrappings WHERE data_key_id = ?`, oldKeyID).Scan(&oldWrappings); err != nil {
		t.Fatal(err)
	}
	if err := restarted.sqlite.DB().QueryRow(`SELECT count(*) FROM encrypted_blobs WHERE key_id <> ?`, rotation.ActiveKeyID).Scan(&wrongBlobKeys); err != nil {
		t.Fatal(err)
	}
	if retiredState != "retired" || oldWrappings != 0 || wrongBlobKeys != 0 {
		t.Fatalf("rotated key cleanup state=%s wrappings=%d wrong_blob_keys=%d", retiredState, oldWrappings, wrongBlobKeys)
	}
	restartedServer := httptest.NewServer(restarted.api.Handler())
	defer restartedServer.Close()
	response, err := http.Get(restartedServer.URL + requiredString(t, created, "subscription_url"))
	if err != nil {
		t.Fatal(err)
	}
	artifact, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Equal(artifact, []byte(content)) {
		t.Fatalf("publication after data key rotation status=%d bytes=%d", response.StatusCode, len(artifact))
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func activeDataKeyIDs(t *testing.T, database interface {
	Query(string, ...interface{}) (*sql.Rows, error)
}) map[string]string {
	t.Helper()
	rows, err := database.Query(`SELECT purpose, id FROM data_keys WHERE status = 'active' ORDER BY purpose`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var purpose, id string
		if err := rows.Scan(&purpose, &id); err != nil {
			t.Fatal(err)
		}
		result[purpose] = id
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func equalStringMaps(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func TestAdministratorBrowserSessionAndCSRF(t *testing.T) {
	root := t.TempDir()
	secrets := filepath.Join(root, "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	masterPath := filepath.Join(secrets, "master.key")
	if _, err := masterkey.Generate(masterPath, masterkey.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	adminPath := filepath.Join(secrets, "admin.token")
	if err := auth.Generate(adminPath, auth.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	service, err := Open(context.Background(), Config{
		DataDir: filepath.Join(root, "data"), MasterKeyPath: masterPath,
		AdminTokenPath: adminPath, Listen: "127.0.0.1:0", Development: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	server := httptest.NewServer(service.api.Handler())
	defer server.Close()

	setupToken, _, err := service.sessions.CreateSetupToken(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	setupRequest := requestJSON(t, http.MethodPost, server.URL+"/api/v1/setup/admin", map[string]interface{}{
		"username": "administrator", "password": "correct horse battery staple", "timezone": "Asia/Shanghai",
	})
	setupRequest.Header.Set("X-ProxyLoom-Setup-Token", setupToken)
	setupResponse, err := http.DefaultClient.Do(setupRequest)
	if err != nil {
		t.Fatal(err)
	}
	setupBody := decodeResponseJSON(t, setupResponse)
	if setupResponse.StatusCode != http.StatusCreated {
		t.Fatalf("setup status=%d body=%v", setupResponse.StatusCode, setupBody)
	}
	cookies := setupResponse.Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Secure {
		t.Fatalf("setup cookie = %+v", cookies)
	}
	csrf, _ := setupBody["csrf_token"].(string)
	if csrf == "" {
		t.Fatal("setup response omitted CSRF token")
	}

	getSession, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/session", nil)
	getSession.AddCookie(cookies[0])
	getResponse, err := http.DefaultClient.Do(getSession)
	if err != nil {
		t.Fatal(err)
	}
	getBody := decodeResponseJSON(t, getResponse)
	if getResponse.StatusCode != http.StatusOK {
		t.Fatalf("get session status=%d body=%v", getResponse.StatusCode, getBody)
	}
	csrf, _ = getBody["csrf_token"].(string)
	if csrf == "" {
		t.Fatal("session refresh omitted rotated CSRF token")
	}

	createInput := map[string]interface{}{
		"display_name": "browser source", "type": "inline", "input_format": "auto",
		"output_format": "same", "content": "vless://one@example.com:443?encryption=none#One\n",
	}
	noOrigin := requestJSON(t, http.MethodPost, server.URL+"/api/v1/sources", createInput)
	noOrigin.AddCookie(cookies[0])
	noOrigin.Header.Set("X-CSRF-Token", csrf)
	noOriginResponse, err := http.DefaultClient.Do(noOrigin)
	if err != nil {
		t.Fatal(err)
	}
	noOriginResponse.Body.Close()
	if noOriginResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie mutation without origin status=%d", noOriginResponse.StatusCode)
	}

	badCSRF := requestJSON(t, http.MethodPost, server.URL+"/api/v1/sources", createInput)
	badCSRF.AddCookie(cookies[0])
	badCSRF.Header.Set("Origin", server.URL)
	badCSRF.Header.Set("X-CSRF-Token", "plcsrf1_invalid")
	badCSRFResponse, err := http.DefaultClient.Do(badCSRF)
	if err != nil {
		t.Fatal(err)
	}
	badCSRFResponse.Body.Close()
	if badCSRFResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie mutation with bad CSRF status=%d", badCSRFResponse.StatusCode)
	}

	create := requestJSON(t, http.MethodPost, server.URL+"/api/v1/sources", createInput)
	create.AddCookie(cookies[0])
	create.Header.Set("Origin", server.URL)
	create.Header.Set("X-CSRF-Token", csrf)
	createResponse, err := http.DefaultClient.Do(create)
	if err != nil {
		t.Fatal(err)
	}
	createBody := decodeResponseJSON(t, createResponse)
	if createResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("cookie source create status=%d body=%v", createResponse.StatusCode, createBody)
	}
	worked, err := service.worker.ProcessOne(context.Background())
	if err != nil || !worked {
		t.Fatalf("browser source ProcessOne() = %v, %v", worked, err)
	}
	sourceID := requiredString(t, createBody, "source_id")
	jobID := requiredString(t, createBody, "job_id")
	listRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/sources?query=browser", nil)
	listRequest.AddCookie(cookies[0])
	listResponse, err := http.DefaultClient.Do(listRequest)
	if err != nil {
		t.Fatal(err)
	}
	listBody := decodeResponseJSON(t, listResponse)
	items, _ := listBody["items"].([]interface{})
	if listResponse.StatusCode != http.StatusOK || len(items) != 1 {
		t.Fatalf("source list status=%d body=%v", listResponse.StatusCode, listBody)
	}
	detailRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/sources/"+sourceID, nil)
	detailRequest.AddCookie(cookies[0])
	detailResponse, err := http.DefaultClient.Do(detailRequest)
	if err != nil {
		t.Fatal(err)
	}
	detailETag := detailResponse.Header.Get("ETag")
	detailBody := decodeResponseJSON(t, detailResponse)
	if detailResponse.StatusCode != http.StatusOK || detailETag == "" || detailBody["masked_location"] != "inline" {
		t.Fatalf("source detail status=%d etag=%q body=%v", detailResponse.StatusCode, detailETag, detailBody)
	}
	patchRequest := requestJSON(t, http.MethodPatch, server.URL+"/api/v1/sources/"+sourceID, map[string]interface{}{
		"display_name": "renamed browser source",
	})
	patchRequest.AddCookie(cookies[0])
	patchRequest.Header.Set("Origin", server.URL)
	patchRequest.Header.Set("X-CSRF-Token", csrf)
	patchRequest.Header.Set("If-Match", detailETag)
	patchRequest.Header.Set("Content-Type", "application/merge-patch+json")
	patchResponse, err := http.DefaultClient.Do(patchRequest)
	if err != nil {
		t.Fatal(err)
	}
	patchETag := patchResponse.Header.Get("ETag")
	patchBody := decodeResponseJSON(t, patchResponse)
	if patchResponse.StatusCode != http.StatusAccepted || patchETag == "" || patchETag == detailETag || patchBody["display_name"] != "renamed browser source" {
		t.Fatalf("source patch status=%d etag=%q body=%v", patchResponse.StatusCode, patchETag, patchBody)
	}
	worked, err = service.worker.ProcessOne(context.Background())
	if err != nil || !worked {
		t.Fatalf("patched source ProcessOne() = %v, %v", worked, err)
	}
	updatedDetail, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/sources/"+sourceID, nil)
	updatedDetail.AddCookie(cookies[0])
	updatedDetailResponse, err := http.DefaultClient.Do(updatedDetail)
	if err != nil {
		t.Fatal(err)
	}
	updatedDetailResponse.Body.Close()
	detailETag = updatedDetailResponse.Header.Get("ETag")
	if updatedDetailResponse.StatusCode != http.StatusOK || detailETag == "" {
		t.Fatalf("updated source detail status=%d etag=%q", updatedDetailResponse.StatusCode, detailETag)
	}
	for _, history := range []string{"revisions", "refresh-attempts", "snapshots"} {
		historyRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/sources/"+sourceID+"/"+history, nil)
		historyRequest.AddCookie(cookies[0])
		historyResponse, err := http.DefaultClient.Do(historyRequest)
		if err != nil {
			t.Fatal(err)
		}
		historyBody := decodeResponseJSON(t, historyResponse)
		historyItems, _ := historyBody["items"].([]interface{})
		if historyResponse.StatusCode != http.StatusOK || len(historyItems) == 0 {
			t.Fatalf("source %s status=%d body=%v", history, historyResponse.StatusCode, historyBody)
		}
	}
	staleArchive, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/sources/"+sourceID, nil)
	staleArchive.AddCookie(cookies[0])
	staleArchive.Header.Set("Origin", server.URL)
	staleArchive.Header.Set("X-CSRF-Token", csrf)
	staleArchive.Header.Set("If-Match", `"source-stale"`)
	staleArchiveResponse, err := http.DefaultClient.Do(staleArchive)
	if err != nil {
		t.Fatal(err)
	}
	staleArchiveResponse.Body.Close()
	if staleArchiveResponse.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("stale source archive status=%d", staleArchiveResponse.StatusCode)
	}
	archive, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/sources/"+sourceID, nil)
	archive.AddCookie(cookies[0])
	archive.Header.Set("Origin", server.URL)
	archive.Header.Set("X-CSRF-Token", csrf)
	archive.Header.Set("If-Match", detailETag)
	archiveResponse, err := http.DefaultClient.Do(archive)
	if err != nil {
		t.Fatal(err)
	}
	archiveResponse.Body.Close()
	if archiveResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("source archive status=%d", archiveResponse.StatusCode)
	}
	job, err := service.jobs.Get(context.Background(), jobID)
	if err != nil || job.Status != "succeeded" {
		t.Fatalf("archived source completed job = %+v, %v", job, err)
	}

	logout, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/session", nil)
	logout.AddCookie(cookies[0])
	logout.Header.Set("Origin", server.URL)
	logout.Header.Set("X-CSRF-Token", csrf)
	logoutResponse, err := http.DefaultClient.Do(logout)
	if err != nil {
		t.Fatal(err)
	}
	logoutResponse.Body.Close()
	if logoutResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status=%d", logoutResponse.StatusCode)
	}
	afterLogout, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/session", nil)
	afterLogout.AddCookie(cookies[0])
	afterLogoutResponse, err := http.DefaultClient.Do(afterLogout)
	if err != nil {
		t.Fatal(err)
	}
	afterLogoutResponse.Body.Close()
	if afterLogoutResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked session status=%d", afterLogoutResponse.StatusCode)
	}
}

func TestExpiredWorkerLeaseIsRequeued(t *testing.T) {
	root := t.TempDir()
	secrets := filepath.Join(root, "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	masterPath := filepath.Join(secrets, "master.key")
	if _, err := masterkey.Generate(masterPath, masterkey.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	adminPath := filepath.Join(secrets, "admin.token")
	if err := auth.Generate(adminPath, auth.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	service, err := Open(context.Background(), Config{
		DataDir: filepath.Join(root, "data"), MasterKeyPath: masterPath,
		AdminTokenPath: adminPath, Listen: "127.0.0.1:0", Development: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	server := httptest.NewServer(service.api.Handler())
	defer server.Close()
	created := postJSON(t, server.URL+"/api/v1/sources", readAdminBearer(t, adminPath), map[string]interface{}{
		"display_name": "lease", "type": "inline", "content": "ss://fixture@example.com:443#Node\n",
	})
	jobID := requiredString(t, created, "job_id")
	job, exists, err := service.jobs.Claim(context.Background(), "crashed-worker", 30*time.Millisecond)
	if err != nil || !exists || job.ID != jobID {
		t.Fatalf("Claim() = %+v, %v, %v", job, exists, err)
	}
	if _, err := service.jobs.MarkRunning(context.Background(), job.ID, "crashed-worker"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	recovered, err := service.jobs.RecoverExpired(context.Background())
	if err != nil || recovered != 1 {
		t.Fatalf("RecoverExpired() = %d, %v", recovered, err)
	}
	requeued, err := service.jobs.Get(context.Background(), job.ID)
	if err != nil || requeued.Status != "queued" || requeued.Attempt != 1 {
		t.Fatalf("requeued job = %+v, %v", requeued, err)
	}
}

func TestWorkerRecoversLeaseThatExpiresAfterStartup(t *testing.T) {
	root := t.TempDir()
	secrets := filepath.Join(root, "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	masterPath := filepath.Join(secrets, "master.key")
	if _, err := masterkey.Generate(masterPath, masterkey.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	adminPath := filepath.Join(secrets, "admin.token")
	if err := auth.Generate(adminPath, auth.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	service, err := Open(context.Background(), Config{
		DataDir: filepath.Join(root, "data"), MasterKeyPath: masterPath,
		AdminTokenPath: adminPath, Listen: "127.0.0.1:0", Development: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	server := httptest.NewServer(service.api.Handler())
	defer server.Close()
	created := postJSON(t, server.URL+"/api/v1/sources", readAdminBearer(t, adminPath), map[string]interface{}{
		"display_name": "lease after startup", "type": "inline",
		"content": "ss://fixture@example.com:443#Node\n",
	})
	jobID := requiredString(t, created, "job_id")
	job, exists, err := service.jobs.Claim(context.Background(), "crashed-worker", 50*time.Millisecond)
	if err != nil || !exists || job.ID != jobID {
		t.Fatalf("Claim() = %+v, %v, %v", job, exists, err)
	}
	if _, err := service.jobs.MarkRunning(context.Background(), job.ID, "crashed-worker"); err != nil {
		t.Fatal(err)
	}
	worker, err := app.NewWorker(service.manager, service.jobs, app.WorkerOptions{
		Owner: "replacement-worker", PollInterval: 5 * time.Millisecond,
		MaintenanceInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		current, getErr := service.jobs.Get(context.Background(), jobID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if current.Status == "succeeded" {
			cancel()
			if runErr := <-done; runErr != nil {
				t.Fatal(runErr)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatal("worker did not recover and complete the expired job")
}

func TestRefreshSchedulesSupportedAndUnsupportedNodeHealth(t *testing.T) {
	root := t.TempDir()
	secrets := filepath.Join(root, "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	masterPath := filepath.Join(secrets, "master.key")
	if _, err := masterkey.Generate(masterPath, masterkey.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	adminPath := filepath.Join(secrets, "admin.token")
	if err := auth.Generate(adminPath, auth.GenerateOptions{Random: rand.Reader}); err != nil {
		t.Fatal(err)
	}
	executorPath := filepath.Join(root, "sing-box")
	if err := os.WriteFile(executorPath, []byte("#!/bin/sh\nif [ \"$1\" = version ]; then echo 'sing-box version 1.12.25'; exit 0; fi\nif [ \"$1\" = check ]; then exit 0; fi\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	service, err := Open(context.Background(), Config{
		DataDir: filepath.Join(root, "data"), MasterKeyPath: masterPath,
		AdminTokenPath: adminPath, SingBoxPath: executorPath,
		Listen: "127.0.0.1:0", Development: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	server := httptest.NewServer(service.api.Handler())
	defer server.Close()
	input := `{"outbounds":[` +
		`{"type":"vless","tag":"Supported","server":"one.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001"},` +
		`{"type":"ssh","tag":"Unsupported","server":"two.example","server_port":22,"user":"root"}]}`
	created := postJSON(t, server.URL+"/api/v1/sources", readAdminBearer(t, adminPath), map[string]interface{}{
		"display_name": "health scheduling", "type": "inline", "input_format": "sing-box",
		"output_format": "same", "health_filter_enabled": true, "content": input,
	})
	worked, err := service.worker.ProcessOne(context.Background())
	if err != nil || !worked {
		t.Fatalf("ProcessOne() = %v, %v", worked, err)
	}
	job, err := service.jobs.Get(context.Background(), requiredString(t, created, "job_id"))
	if err != nil || job.Status != "succeeded" {
		t.Fatalf("health source job = %+v, %v", job, err)
	}
	var unchecked, unsupported, queued, dormant int
	if err := service.sqlite.DB().QueryRow(`SELECT count(*) FROM node_health_states WHERE state = 'unchecked'`).Scan(&unchecked); err != nil {
		t.Fatal(err)
	}
	if err := service.sqlite.DB().QueryRow(`SELECT count(*) FROM node_health_states WHERE state = 'unsupported'`).Scan(&unsupported); err != nil {
		t.Fatal(err)
	}
	if err := service.sqlite.DB().QueryRow(`SELECT count(*) FROM probe_queue_items WHERE status = 'queued'`).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if err := service.sqlite.DB().QueryRow(`SELECT count(*) FROM probe_queue_items WHERE status = 'dormant'`).Scan(&dormant); err != nil {
		t.Fatal(err)
	}
	if unchecked != 1 || unsupported != 1 || queued != 1 || dormant != 1 {
		t.Fatalf("health state counts unchecked=%d unsupported=%d queued=%d dormant=%d", unchecked, unsupported, queued, dormant)
	}
	item, exists, err := service.healthStore.Claim(context.Background(), "test-health", time.Minute)
	if err != nil || !exists || item.ProtocolID != "vless" {
		t.Fatalf("Claim() = %+v, %v, %v", item, exists, err)
	}
	state, err := service.healthStore.Complete(context.Background(), item, "test-health", healthstore.ProbeResult{
		Class: healthstore.ResultSuccess, Success: true, Total: 100 * time.Millisecond,
		TargetID: "fixture", ExecutorID: "sing-box", ExecutorVersion: "1.12.25",
	})
	if err != nil || state.State != healthstore.StateHealthy {
		t.Fatalf("Complete() = %+v, %v", state, err)
	}
	admin := readAdminBearer(t, adminPath)
	getAdminJSON := func(path string) map[string]interface{} {
		t.Helper()
		request, _ := http.NewRequest(http.MethodGet, server.URL+path, nil)
		request.Header.Set("Authorization", "Bearer "+admin)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body := decodeResponseJSON(t, response)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status=%d body=%v", path, response.StatusCode, body)
		}
		return body
	}
	nodesBody := getAdminJSON("/api/v1/nodes?source_id=" + requiredString(t, created, "source_id"))
	nodeItems, _ := nodesBody["items"].([]interface{})
	if len(nodeItems) != 2 {
		t.Fatalf("node API body = %v", nodesBody)
	}
	recordsBody := getAdminJSON("/api/v1/nodes/" + item.NodeOccurrenceID + "/health-records")
	recordItems, _ := recordsBody["items"].([]interface{})
	if len(recordItems) != 1 {
		t.Fatalf("health record API body = %v", recordsBody)
	}
	record := recordItems[0].(map[string]interface{})
	if record["executor_id"] != "sing-box" || record["executor_version"] != "1.12.25" {
		t.Fatalf("health record executor = %v", record)
	}
	capacityBody := getAdminJSON("/api/v1/health/capacity")
	if capacityBody["queue_total"].(float64) != 2 {
		t.Fatalf("health capacity API body = %v", capacityBody)
	}
	postJSONWithStatus(t, server.URL+"/api/v1/nodes/"+item.NodeOccurrenceID+"/checks", admin, nil, http.StatusAccepted)
	sourceID := requiredString(t, created, "source_id")
	subscriptionURL := server.URL + requiredString(t, created, "subscription_url")
	setHealthState := func(state string, recoveryStep int) {
		t.Helper()
		if _, err := service.sqlite.DB().Exec(`
UPDATE node_health_states SET state = ?, recovery_step = ?, updated_at = ?
WHERE node_occurrence_id = ?`, state, recoveryStep, time.Now().UTC().UnixMilli(), item.NodeOccurrenceID); err != nil {
			t.Fatal(err)
		}
		postJSONWithStatus(t, server.URL+"/api/v1/sources/"+sourceID+"/refresh", admin, nil, http.StatusAccepted)
		worked, err := service.worker.ProcessOne(context.Background())
		if err != nil || !worked {
			t.Fatalf("health-boundary ProcessOne() = %v, %v", worked, err)
		}
	}
	readTags := func() []string {
		t.Helper()
		response, err := http.Get(subscriptionURL)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var document struct {
			Outbounds []struct {
				Tag string `json:"tag"`
			} `json:"outbounds"`
		}
		if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
			t.Fatal(err)
		}
		result := make([]string, len(document.Outbounds))
		for index, outbound := range document.Outbounds {
			result[index] = outbound.Tag
		}
		return result
	}
	setHealthState("unhealthy", 0)
	if tags := readTags(); len(tags) != 1 || tags[0] != "Unsupported" {
		t.Fatalf("unhealthy filtered tags = %v", tags)
	}
	setHealthState("degraded", 1)
	if tags := readTags(); len(tags) != 1 || tags[0] != "Unsupported" {
		t.Fatalf("recovery-pending filtered tags = %v", tags)
	}
	setHealthState("healthy", 0)
	if tags := readTags(); len(tags) != 2 || tags[0] != "Supported" || tags[1] != "Unsupported" {
		t.Fatalf("recovered tags = %v", tags)
	}
}

func requestJSON(t *testing.T, method, url string, input interface{}) *http.Request {
	t.Helper()
	content, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(method, url, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	return request
}

func decodeResponseJSON(t *testing.T, response *http.Response) map[string]interface{} {
	t.Helper()
	defer response.Body.Close()
	var result map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatalf("decode HTTP %d response: %v", response.StatusCode, err)
	}
	return result
}

func postJSON(t *testing.T, url, bearer string, input interface{}) map[string]interface{} {
	t.Helper()
	return postJSONWithStatus(t, url, bearer, input, http.StatusAccepted)
}

func postJSONWithStatus(t *testing.T, url, bearer string, input interface{}, expectedStatus int) map[string]interface{} {
	t.Helper()
	content, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != expectedStatus {
		t.Fatalf("POST %s status=%d body=%s", url, response.StatusCode, body)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func patchJSONWithStatus(t *testing.T, url, bearer string, input interface{}, expectedStatus int) map[string]interface{} {
	t.Helper()
	content, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPatch, url, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	request.Header.Set("Content-Type", "application/merge-patch+json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != expectedStatus {
		t.Fatalf("PATCH %s status=%d body=%s", url, response.StatusCode, body)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func putJSONWithStatus(t *testing.T, url, bearer string, input interface{}, expectedStatus int) map[string]interface{} {
	t.Helper()
	getRequest, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	getRequest.Header.Set("Authorization", "Bearer "+bearer)
	getResponse, err := http.DefaultClient.Do(getRequest)
	if err != nil {
		t.Fatal(err)
	}
	getResponse.Body.Close()
	etag := getResponse.Header.Get("ETag")
	if getResponse.StatusCode != http.StatusOK || etag == "" {
		t.Fatalf("GET %s before PUT status=%d etag=%q", url, getResponse.StatusCode, etag)
	}
	content, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", etag)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != expectedStatus {
		t.Fatalf("PUT %s status=%d body=%s", url, response.StatusCode, body)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func requiredString(t *testing.T, value map[string]interface{}, key string) string {
	t.Helper()
	result, ok := value[key].(string)
	if !ok || result == "" {
		t.Fatalf("missing string %q in %+v", key, value)
	}
	return result
}

func readAdminBearer(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(strings.TrimPrefix(string(content), "plat1:"), "\n")
}
