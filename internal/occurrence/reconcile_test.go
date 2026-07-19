package occurrence

import (
	"fmt"
	"testing"
	"time"

	"github.com/doujialong/proxyloom/internal/identity"
)

func TestReconcileDuplicateLifecycle(t *testing.T) {
	base := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	next := 0
	newID := func() string {
		next++
		return fmt.Sprintf("occ-%d", next)
	}
	fingerprint := testFingerprint("same")

	first, err := Reconcile(nil, []Candidate{
		{Ordinal: 0, Fingerprint: fingerprint, ExtractionPath: "/0", ProtocolID: "vless", OriginalName: "Hong Kong"},
		{Ordinal: 1, Fingerprint: fingerprint, ExtractionPath: "/1", ProtocolID: "vless", OriginalName: "Hong Kong"},
		{Ordinal: 2, Fingerprint: fingerprint, ExtractionPath: "/2", ProtocolID: "vless", OriginalName: "Hong Kong"},
	}, Options{Now: base, NewID: newID})
	if err != nil {
		t.Fatalf("first Reconcile() error = %v", err)
	}
	assertLinkIDs(t, first.Links, []string{"occ-1", "occ-2", "occ-3"})
	for i, occurrence := range first.Occurrences {
		if occurrence.DuplicateSlot != i+1 || occurrence.State != StatePresent {
			t.Fatalf("occurrence[%d] = %+v", i, occurrence)
		}
	}

	second, err := Reconcile(first.Occurrences, []Candidate{
		{Ordinal: 0, Fingerprint: fingerprint, ExtractionPath: "/0", ProtocolID: "vless", OriginalName: "Hong Kong"},
		{Ordinal: 1, Fingerprint: fingerprint, ExtractionPath: "/1", ProtocolID: "vless", OriginalName: "Hong Kong"},
	}, Options{Now: base.Add(24 * time.Hour), NewID: newID})
	if err != nil {
		t.Fatalf("second Reconcile() error = %v", err)
	}
	if second.Occurrences[2].State != StateAbsent || second.Occurrences[2].RetainUntil == nil {
		t.Fatalf("missing duplicate was not retained: %+v", second.Occurrences[2])
	}

	recovered, err := Reconcile(second.Occurrences, []Candidate{
		{Ordinal: 0, Fingerprint: fingerprint, ExtractionPath: "/0", ProtocolID: "vless", OriginalName: "Hong Kong"},
		{Ordinal: 1, Fingerprint: fingerprint, ExtractionPath: "/1", ProtocolID: "vless", OriginalName: "Hong Kong"},
		{Ordinal: 2, Fingerprint: fingerprint, ExtractionPath: "/2", ProtocolID: "vless", OriginalName: "Hong Kong"},
	}, Options{Now: base.Add(10 * 24 * time.Hour), NewID: newID})
	if err != nil {
		t.Fatalf("recovery Reconcile() error = %v", err)
	}
	assertLinkIDs(t, recovered.Links, []string{"occ-1", "occ-2", "occ-3"})
	if recovered.Occurrences[2].State != StatePresent || recovered.Occurrences[2].AbsentSince != nil {
		t.Fatalf("duplicate did not recover: %+v", recovered.Occurrences[2])
	}
}

func TestReconcileExpiredOccurrenceBecomesNew(t *testing.T) {
	base := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	next := 0
	newID := func() string { next++; return fmt.Sprintf("occ-%d", next) }
	candidate := Candidate{Ordinal: 0, Fingerprint: testFingerprint("one"), ExtractionPath: "/0", ProtocolID: "vless", OriginalName: "Node"}

	first, _ := Reconcile(nil, []Candidate{candidate}, Options{Now: base, NewID: newID})
	missing, _ := Reconcile(first.Occurrences, nil, Options{Now: base.Add(time.Hour), NewID: newID})
	returned, err := Reconcile(missing.Occurrences, []Candidate{candidate}, Options{Now: base.Add(31 * 24 * time.Hour), NewID: newID})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if returned.Occurrences[0].State != StateRetired {
		t.Fatalf("old occurrence state = %s, want retired", returned.Occurrences[0].State)
	}
	if returned.Links[0].OccurrenceID != "occ-2" || returned.Links[0].Method != MatchNew {
		t.Fatalf("returned link = %+v", returned.Links[0])
	}
}

func TestReconcileUniqueAuxiliaryMatchSurvivesConnectionChange(t *testing.T) {
	base := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	next := 0
	newID := func() string { next++; return fmt.Sprintf("occ-%d", next) }
	firstCandidate := Candidate{Ordinal: 0, Fingerprint: testFingerprint("old"), ExtractionPath: "/0", ProtocolID: "vless", OriginalName: "Node"}
	first, _ := Reconcile(nil, []Candidate{firstCandidate}, Options{Now: base, NewID: newID})
	changed := firstCandidate
	changed.Fingerprint = testFingerprint("new")

	result, err := Reconcile(first.Occurrences, []Candidate{changed}, Options{Now: base.Add(time.Hour), NewID: newID})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.Links[0].OccurrenceID != "occ-1" || result.Links[0].Method != MatchAuxiliaryUnique {
		t.Fatalf("link = %+v", result.Links[0])
	}
}

func TestReconcileAmbiguousAuxiliaryEvidenceCreatesNewOccurrence(t *testing.T) {
	base := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	existing := []Occurrence{
		{ID: "occ-1", Fingerprint: testFingerprint("old-1"), ExtractionPath: "/0", ProtocolID: "vless", OriginalName: "Node", State: StatePresent, DuplicateSlot: 1, CreatedAt: base, LastSeenAt: base},
		{ID: "occ-2", Fingerprint: testFingerprint("old-2"), ExtractionPath: "/0", ProtocolID: "vless", OriginalName: "Node", State: StatePresent, DuplicateSlot: 1, CreatedAt: base.Add(time.Second), LastSeenAt: base},
	}
	result, err := Reconcile(existing, []Candidate{
		{Ordinal: 0, Fingerprint: testFingerprint("new"), ExtractionPath: "/0", ProtocolID: "vless", OriginalName: "Node"},
	}, Options{Now: base.Add(time.Hour), NewID: func() string { return "occ-3" }})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.Links[0].OccurrenceID != "occ-3" || result.Links[0].Method != MatchAmbiguousNew {
		t.Fatalf("link = %+v", result.Links[0])
	}
	if result.Occurrences[0].State != StateAbsent || result.Occurrences[1].State != StateAbsent {
		t.Fatalf("ambiguous old occurrences were not retained as absent: %+v", result.Occurrences)
	}
}

func testFingerprint(digest string) identity.Fingerprint {
	return identity.Fingerprint{
		Kind:              identity.KindSemantic,
		Algorithm:         identity.Algorithm,
		ProjectionVersion: "test-projection-v1",
		KeyID:             "test-key",
		Digest:            digest,
	}
}

func assertLinkIDs(t *testing.T, links []Link, want []string) {
	t.Helper()
	if len(links) != len(want) {
		t.Fatalf("link count = %d, want %d", len(links), len(want))
	}
	for i := range links {
		if links[i].OccurrenceID != want[i] {
			t.Fatalf("link[%d] = %s, want %s", i, links[i].OccurrenceID, want[i])
		}
	}
}
