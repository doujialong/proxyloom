package app

import (
	"testing"

	singboxexecutor "github.com/doujialong/proxyloom/internal/executor/singbox"
	"github.com/doujialong/proxyloom/internal/storage/healthstore"
)

func TestNormalizeProbeOutcomeSuppressesSuccessWithoutControls(t *testing.T) {
	class, success, attributable := normalizeProbeOutcome(singboxexecutor.ProbeResult{
		Class: "success", Success: true,
	}, false)
	if class != healthstore.ResultTargetFailure || success || attributable {
		t.Fatalf("outcome = %q, %v, %v", class, success, attributable)
	}

	class, success, attributable = normalizeProbeOutcome(singboxexecutor.ProbeResult{
		Class: "connect_timeout",
	}, true)
	if class != healthstore.ResultConnectTimeout || success || !attributable {
		t.Fatalf("attributable outcome = %q, %v, %v", class, success, attributable)
	}
}
