package aggregate

import (
	"testing"
	"time"
)

func TestTemplateRetryDelayUsesBoundedExponentialBackoff(t *testing.T) {
	previous := time.Duration(0)
	for failures := 1; failures <= 8; failures++ {
		delay := templateRetryDelay("018f4c7a-77c2-7000-8000-000000000001", failures)
		if delay < 24*time.Second || delay > 5*time.Minute {
			t.Fatalf("failure %d delay %s is outside the bounded jitter range", failures, delay)
		}
		if failures <= 4 && delay <= previous {
			t.Fatalf("failure %d delay %s did not increase after %s", failures, delay, previous)
		}
		previous = delay
	}
}
