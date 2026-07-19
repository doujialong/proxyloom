package naming

import (
	"strconv"
	"testing"
	"time"
)

func BenchmarkAllocate20000SameNameCandidates(b *testing.B) {
	candidates := make([]Candidate, 20_000)
	for index := range candidates {
		value := strconv.Itoa(index)
		candidates[index] = Candidate{
			OccurrenceID:     "occ-" + value,
			BaseName:         "Same Name",
			StableKey:        "stable-" + leftPad(value, 5),
			CandidateOrdinal: index,
		}
	}
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := Allocate(nil, candidates, Options{Now: now})
		if err != nil {
			b.Fatalf("Allocate() error = %v", err)
		}
		if len(result.Snapshot) != 20_000 {
			b.Fatalf("snapshot count = %d", len(result.Snapshot))
		}
	}
}

func leftPad(value string, width int) string {
	for len(value) < width {
		value = "0" + value
	}
	return value
}
