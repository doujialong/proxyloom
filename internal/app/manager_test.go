package app

import (
	"testing"

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
}
