package singbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	ExecutorID         = "sing-box"
	ProbeConfigVersion = "sing-box-probe-config-v1"
)

type Target struct {
	ID             string
	URL            string
	ExpectedStatus int
}

type ProbeResult struct {
	Class          string
	Success        bool
	HTTPStatus     *int
	Total          time.Duration
	DiagnosticCode string
}

func (v *Validator) Probe(ctx context.Context, canonical []byte, target Target) ProbeResult {
	started := time.Now()
	result := ProbeResult{Class: "executor_crash", DiagnosticCode: "executor_not_started"}
	if v == nil || v.path == "" || target.ID == "" || target.URL == "" || target.ExpectedStatus < 100 || target.ExpectedStatus > 599 {
		return result
	}
	outbounds, finalTag, err := prepareProbeOutbounds(canonical)
	if err != nil {
		result.Class, result.DiagnosticCode = "executor_unsupported", "canonical_node_unsupported"
		return result
	}
	port, err := reserveLoopbackPort()
	if err != nil {
		result.Class, result.DiagnosticCode = "resource_limited", "loopback_port_unavailable"
		return result
	}
	config := map[string]interface{}{
		"log": map[string]interface{}{"level": "error", "timestamp": false},
		"dns": map[string]interface{}{
			"servers": []map[string]interface{}{{"type": "local", "tag": "local"}},
			"final":   "local",
		},
		"inbounds": []map[string]interface{}{{
			"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": port,
		}},
		"outbounds": outbounds,
		"route":     map[string]interface{}{"default_domain_resolver": "local", "final": finalTag},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		result.DiagnosticCode = "probe_config_encode_failed"
		return result
	}
	directory, err := os.MkdirTemp(v.tempRoot, "proxyloom-singbox-probe-")
	if err != nil {
		result.Class, result.DiagnosticCode = "resource_limited", "probe_directory_unavailable"
		return result
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0o700); err != nil {
		result.Class, result.DiagnosticCode = "resource_limited", "probe_directory_insecure"
		return result
	}
	configPath := filepath.Join(directory, "config.json")
	if err := writePrivateFile(configPath, encoded); err != nil {
		result.Class, result.DiagnosticCode = "resource_limited", "probe_config_unavailable"
		return result
	}
	probeContext, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	command := exec.CommandContext(probeContext, v.path, "run", "-c", configPath)
	command.Dir = directory
	command.Env = []string{"HOME=" + directory, "TMPDIR=" + directory, "LANG=C", "LC_ALL=C"}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var diagnostics limitedBuffer
	command.Stdout, command.Stderr = &diagnostics, &diagnostics
	if err := command.Start(); err != nil {
		result.DiagnosticCode = "executor_start_failed"
		return result
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	defer stopProcessGroup(command, done)
	if err := waitLoopback(probeContext, port, 3*time.Second); err != nil {
		if probeContext.Err() != nil {
			result.Class, result.DiagnosticCode = "connect_timeout", "executor_readiness_timeout"
		} else {
			result.Class, result.DiagnosticCode = "protocol_failure", "executor_not_ready"
		}
		result.Total = time.Since(started)
		return result
	}
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
		ForceAttemptHTTP2:   false,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	request, err := http.NewRequestWithContext(probeContext, http.MethodGet, target.URL, nil)
	if err != nil {
		result.Class, result.DiagnosticCode = "target_failure", "invalid_probe_target"
		return result
	}
	request.Header.Set("User-Agent", "Mozilla/5.0")
	request.Header.Set("Accept", "*/*")
	response, err := client.Do(request)
	result.Total = time.Since(started)
	if err != nil {
		result.Class, result.DiagnosticCode = classifyProbeError(err), "proxy_request_failed"
		return result
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1025))
	status := response.StatusCode
	result.HTTPStatus = &status
	if response.StatusCode != target.ExpectedStatus {
		result.Class, result.DiagnosticCode = "unexpected_status", "unexpected_http_status"
		return result
	}
	result.Class, result.Success, result.DiagnosticCode = "success", true, ""
	return result
}

func prepareProbeOutbounds(canonical []byte) ([]map[string]interface{}, string, error) {
	if len(canonical) == 0 || len(canonical) > 4<<20 {
		return nil, "", fmt.Errorf("canonical node is empty or too large")
	}
	var outbounds []map[string]interface{}
	if err := json.Unmarshal(canonical, &outbounds); err != nil || len(outbounds) == 0 || len(outbounds) > 8 {
		return nil, "", fmt.Errorf("canonical node is not an outbound array")
	}
	prefixBytes := make([]byte, 6)
	if _, err := io.ReadFull(rand.Reader, prefixBytes); err != nil {
		return nil, "", err
	}
	prefix := "probe-" + hex.EncodeToString(prefixBytes)
	tags := make(map[string]string, len(outbounds))
	for index, outbound := range outbounds {
		oldTag, _ := outbound["tag"].(string)
		typeName, _ := outbound["type"].(string)
		if oldTag == "" || typeName == "" {
			return nil, "", fmt.Errorf("canonical outbound is missing type or tag")
		}
		newTag := fmt.Sprintf("%s-%d", prefix, index+1)
		tags[oldTag] = newTag
		outbound["tag"] = newTag
	}
	for _, outbound := range outbounds {
		if detour, exists := outbound["detour"].(string); exists {
			mapped, ok := tags[detour]
			if !ok {
				return nil, "", fmt.Errorf("canonical outbound detour is unresolved")
			}
			outbound["detour"] = mapped
		}
	}
	finalTag, _ := outbounds[len(outbounds)-1]["tag"].(string)
	return outbounds, finalTag, nil
}

func reserveLoopbackPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		return 0, err
	}
	return port, nil
}

func waitLoopback(ctx context.Context, port int, maximum time.Duration) error {
	deadline := time.Now().Add(maximum)
	for time.Now().Before(deadline) {
		connection, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = connection.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	return fmt.Errorf("loopback listener did not become ready")
}

func stopProcessGroup(command *exec.Cmd, done <-chan error) {
	if command == nil || command.Process == nil {
		return
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
	select {
	case <-done:
		return
	case <-time.After(500 * time.Millisecond):
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
}

func writePrivateFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func classifyProbeError(err error) string {
	if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
		return "connect_timeout"
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "certificate") || strings.Contains(message, "tls") || strings.Contains(message, "x509") {
		return "tls_failure"
	}
	if strings.Contains(message, "refused") {
		return "connect_refused"
	}
	if strings.Contains(message, "no such host") || strings.Contains(message, "dns") {
		return "dns_failure"
	}
	return "protocol_failure"
}
