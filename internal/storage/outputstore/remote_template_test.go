package outputstore

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestRemoteTemplateContentChecksumSurvivesConfigRoundTrip(t *testing.T) {
	original := []byte("{\n  \"route\": {\"rules\": [{\"domain_suffix\": [\"a.example\"], \"outbound\": \"<proxy&direct>\"}]}\n}\n")
	content, digest, err := NormalizeRemoteTemplateContent(original)
	if err != nil {
		t.Fatalf("normalize content: %v", err)
	}
	if bytes.Equal(content, original) {
		t.Fatal("test fixture did not exercise JSON normalization")
	}
	config := RemoteTemplateConfig{
		SourceType: "remote", TargetFormat: "sing-box", URL: "https://example.test/template.json",
		RefreshIntervalSeconds: 900, Content: content, ContentSHA256: digest, FetchedAt: time.Unix(1, 0).UTC(),
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	var decoded RemoteTemplateConfig
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	if err := validateRemoteTemplateConfig(decoded); err != nil {
		t.Fatalf("validate round-tripped config: %v", err)
	}
	if decoded.ContentSHA256 != digest || !bytes.Equal(decoded.Content, content) {
		t.Fatal("remote template content or checksum changed during config round trip")
	}
}

func TestNormalizeRemoteTemplateConfigRepairsCallerChecksum(t *testing.T) {
	config, err := normalizeRemoteTemplateConfig(RemoteTemplateConfig{
		SourceType: "remote", TargetFormat: "sing-box", URL: "https://example.test/template.json",
		RefreshIntervalSeconds: 900, Content: json.RawMessage("{\n\"outbounds\": []\n}"),
		ContentSHA256: "stale", FetchedAt: time.Unix(1, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("normalize config: %v", err)
	}
	if err := validateRemoteTemplateConfig(config); err != nil {
		t.Fatalf("validate normalized config: %v", err)
	}
}

func TestDecodeRemoteTemplateConfigRepairsLegacyChecksum(t *testing.T) {
	legacy := RemoteTemplateConfig{
		SourceType: "remote", TargetFormat: "sing-box", URL: "https://example.test/template.json",
		RefreshIntervalSeconds: 900, Content: json.RawMessage("{\n\"outbounds\": []\n}"),
		ContentSHA256: "legacy-pre-normalization-checksum", FetchedAt: time.Unix(1, 0).UTC(),
	}
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy config: %v", err)
	}
	decoded, err := decodeRemoteTemplateConfig(encoded)
	if err != nil {
		t.Fatalf("decode legacy config: %v", err)
	}
	if decoded.ContentSHA256 == legacy.ContentSHA256 {
		t.Fatal("legacy checksum was not repaired from authenticated content")
	}
	if err := validateRemoteTemplateConfig(decoded); err != nil {
		t.Fatalf("validate repaired legacy config: %v", err)
	}
}
