package occurrence

import (
	"strconv"
	"testing"
	"time"

	"github.com/doujialong/proxyloom/internal/identity"
)

func BenchmarkReconcile20000Candidates(b *testing.B) {
	candidates := make([]Candidate, 20_000)
	for index := range candidates {
		value := strconv.Itoa(index)
		candidates[index] = Candidate{
			Ordinal:        index,
			Fingerprint:    benchmarkFingerprint(value),
			ExtractionPath: "/" + value,
			ProtocolID:     "vless",
			OriginalName:   "Node",
		}
	}
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	initial := reconcileBenchmarkCandidates(b, nil, candidates, now)

	b.Run("new", func(b *testing.B) {
		for iteration := 0; iteration < b.N; iteration++ {
			reconcileBenchmarkCandidates(b, nil, candidates, now)
		}
	})
	b.Run("steady_state", func(b *testing.B) {
		for iteration := 0; iteration < b.N; iteration++ {
			reconcileBenchmarkCandidates(b, initial.Occurrences, candidates, now)
		}
	})

	changed := append([]Candidate(nil), candidates...)
	for index := range changed {
		changed[index].Fingerprint = benchmarkFingerprint("changed-" + strconv.Itoa(index))
	}
	b.Run("connection_change_auxiliary", func(b *testing.B) {
		for iteration := 0; iteration < b.N; iteration++ {
			reconcileBenchmarkCandidates(b, initial.Occurrences, changed, now)
		}
	})
}

func reconcileBenchmarkCandidates(b *testing.B, existing []Occurrence, candidates []Candidate, now time.Time) Result {
	b.Helper()
	nextID := 0
	result, err := Reconcile(existing, candidates, Options{
		Now: now,
		NewID: func() string {
			nextID++
			return "occ-" + strconv.Itoa(nextID)
		},
	})
	if err != nil {
		b.Fatalf("Reconcile() error = %v", err)
	}
	if len(result.Links) != len(candidates) {
		b.Fatalf("link count = %d, want %d", len(result.Links), len(candidates))
	}
	return result
}

func benchmarkFingerprint(digest string) identity.Fingerprint {
	return identity.Fingerprint{
		Kind:              identity.KindSemantic,
		Algorithm:         identity.Algorithm,
		ProjectionVersion: "benchmark-projection-v1",
		KeyID:             "benchmark-key",
		Digest:            digest,
	}
}
