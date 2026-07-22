package app

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/doujialong/proxyloom/internal/storage/sourcestore"
)

func TestValidateConfigRemoteHeaders(t *testing.T) {
	valid := normalizeConfig(SourceConfig{
		Type: sourcestore.SourceRemote, URL: "https://example.test/subscription",
		RequestHeaders: map[string]string{"Authorization": "Basic secret", "User-Agent": "Private Client"},
	})
	if err := validateConfig(valid); err != nil {
		t.Fatalf("valid authenticated remote config: %v", err)
	}

	unsafe := valid
	unsafe.RequestHeaders = map[string]string{"Host": "internal.example"}
	if err := validateConfig(unsafe); err == nil {
		t.Fatal("validateConfig accepted a Host override")
	}

	inline := normalizeConfig(SourceConfig{
		Type: sourcestore.SourceInline, InlineContent: "ss://fixture@example.com:443#Node\n",
		RequestHeaders: map[string]string{"Authorization": "Basic secret"},
	})
	if err := validateConfig(inline); err == nil {
		t.Fatal("validateConfig accepted remote headers for inline content")
	}
}

func TestNormalizeConfigPreservesStrictMaximumDropRatio(t *testing.T) {
	config := normalizeConfig(SourceConfig{MaximumDropRatio: 0})
	if config.MaximumDropRatio != 0 {
		t.Fatalf("maximum drop ratio = %v, want strict zero", config.MaximumDropRatio)
	}
}

func TestNormalizeConfigDefaultsRemoteTimeout(t *testing.T) {
	config := normalizeConfig(SourceConfig{Type: sourcestore.SourceRemote})
	if config.TimeoutSeconds != 30 {
		t.Fatalf("remote timeout = %d, want 30", config.TimeoutSeconds)
	}
	inline := normalizeConfig(SourceConfig{Type: sourcestore.SourceInline})
	if inline.TimeoutSeconds != 0 {
		t.Fatalf("inline timeout = %d, want 0", inline.TimeoutSeconds)
	}
	if config.RetryCount != DefaultSourceRetryCount || config.StaleAfterSeconds != DefaultSourceStaleAfterSeconds {
		t.Fatalf("source reliability defaults = retries %d stale %d", config.RetryCount, config.StaleAfterSeconds)
	}
	disabled := normalizeConfig(SourceConfig{RetryCount: 0, RetryCountSet: true})
	if disabled.RetryCount != 0 {
		t.Fatalf("explicit zero retry count = %d", disabled.RetryCount)
	}
}

func TestSourceRetryDelayUsesIncreasingJitteredBackoff(t *testing.T) {
	bases := []time.Duration{time.Minute, 3 * time.Minute, 10 * time.Minute, 30 * time.Minute, time.Hour}
	for failures, base := range bases {
		delay := sourceRetryDelay("00000000-0000-4000-8000-000000000001", failures+1, 0)
		if delay < base*8/10 || delay > base*12/10 {
			t.Fatalf("failure %d delay = %s, base %s", failures+1, delay, base)
		}
	}
	authDelay := sourceRetryDelay("00000000-0000-4000-8000-000000000001", 1, http.StatusUnauthorized)
	if authDelay < 8*time.Minute {
		t.Fatalf("authentication retry delay = %s", authDelay)
	}
}

func TestRetryableRefreshFailureClassification(t *testing.T) {
	if retryableRefreshFailure(&OperationError{Code: "fetch_failed", Err: errors.New("gone"), HTTPStatus: http.StatusGone}) {
		t.Fatal("HTTP 410 was treated as immediately retryable")
	}
	if retryableRefreshFailure(&OperationError{Code: "config_invalid", Err: errors.New("invalid")}) {
		t.Fatal("invalid config was treated as retryable")
	}
	if !retryableRefreshFailure(&OperationError{Code: "fetch_failed", Err: errors.New("temporary"), HTTPStatus: http.StatusServiceUnavailable}) {
		t.Fatal("HTTP 503 was not treated as retryable")
	}
	if staleDuration(DefaultSourceStaleAfterSeconds) != 72*time.Hour {
		t.Fatalf("default stale duration = %s", staleDuration(DefaultSourceStaleAfterSeconds))
	}
}
