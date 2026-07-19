package httpapi

import (
	"strings"
	"testing"

	"github.com/doujialong/proxyloom/internal/app"
)

func TestSourceConfigMaximumDropRatioDefaultsAndPreservesZero(t *testing.T) {
	defaulted := sourceConfigFromRequest(createSourceRequest{})
	if defaulted.MaximumDropRatio != 0.5 {
		t.Fatalf("omitted maximum drop ratio = %v, want 0.5", defaulted.MaximumDropRatio)
	}
	zero := 0.0
	strict := sourceConfigFromRequest(createSourceRequest{MaximumDropRatio: &zero})
	if strict.MaximumDropRatio != 0 {
		t.Fatalf("explicit maximum drop ratio = %v, want 0", strict.MaximumDropRatio)
	}
}

func TestSourceMergePatchMaximumDropRatioNullResetsDefault(t *testing.T) {
	config := app.SourceConfig{MaximumDropRatio: 0.8}
	_, strict, err := applySourceMergePatch(strings.NewReader(`{"maximum_drop_ratio":0}`), "source", config)
	if err != nil {
		t.Fatalf("apply strict merge patch: %v", err)
	}
	if strict.MaximumDropRatio != 0 {
		t.Fatalf("strict merge patch ratio = %v, want 0", strict.MaximumDropRatio)
	}
	_, reset, err := applySourceMergePatch(strings.NewReader(`{"maximum_drop_ratio":null}`), "source", strict)
	if err != nil {
		t.Fatalf("apply reset merge patch: %v", err)
	}
	if reset.MaximumDropRatio != 0.5 {
		t.Fatalf("reset merge patch ratio = %v, want 0.5", reset.MaximumDropRatio)
	}
}

func TestSourceMergePatchCanReplaceAndClearProxy(t *testing.T) {
	config := app.SourceConfig{ProxyURL: "socks5://old.example:1080", TimeoutSeconds: 30}
	_, replaced, err := applySourceMergePatch(strings.NewReader(`{"proxy_url":"socks5h://new.example:1080","timeout_seconds":60}`), "source", config)
	if err != nil {
		t.Fatalf("replace proxy: %v", err)
	}
	if replaced.ProxyURL != "socks5h://new.example:1080" || replaced.TimeoutSeconds != 60 {
		t.Fatalf("replaced config = %#v", replaced)
	}
	_, cleared, err := applySourceMergePatch(strings.NewReader(`{"proxy_url":null}`), "source", replaced)
	if err != nil {
		t.Fatalf("clear proxy: %v", err)
	}
	if cleared.ProxyURL != "" {
		t.Fatalf("cleared proxy = %q", cleared.ProxyURL)
	}
}
