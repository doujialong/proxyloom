package naming

import (
	"testing"
	"time"
)

func TestAllocateStableSuffixLifecycle(t *testing.T) {
	base := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	firstCandidates := []Candidate{
		{OccurrenceID: "occ-c", BaseName: "Hong Kong", StableKey: "c", CandidateOrdinal: 0},
		{OccurrenceID: "occ-a", BaseName: "Hong Kong", StableKey: "a", CandidateOrdinal: 1},
		{OccurrenceID: "occ-b", BaseName: "Hong Kong", StableKey: "b", CandidateOrdinal: 2},
	}
	first, err := Allocate(nil, firstCandidates, Options{Now: base})
	if err != nil {
		t.Fatalf("Allocate() error = %v", err)
	}
	assertNames(t, first.Allocations, map[string]string{
		"occ-a": "Hong Kong",
		"occ-b": "Hong Kong #2",
		"occ-c": "Hong Kong #3",
	})

	withoutFirst := []Candidate{
		{OccurrenceID: "occ-b", BaseName: "Hong Kong", StableKey: "b", CandidateOrdinal: 0},
		{OccurrenceID: "occ-c", BaseName: "Hong Kong", StableKey: "c", CandidateOrdinal: 1},
		{OccurrenceID: "occ-d", BaseName: "Hong Kong", StableKey: "d", CandidateOrdinal: 2},
	}
	second, err := Allocate(first.Allocations, withoutFirst, Options{Now: base.Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("second Allocate() error = %v", err)
	}
	assertNames(t, second.Allocations, map[string]string{
		"occ-a": "Hong Kong",
		"occ-b": "Hong Kong #2",
		"occ-c": "Hong Kong #3",
		"occ-d": "Hong Kong #4",
	})
	if allocationByID(second.Allocations, "occ-a").Active {
		t.Fatal("missing allocation remained active")
	}

	recoveredCandidates := append(withoutFirst, Candidate{OccurrenceID: "occ-a", BaseName: "Hong Kong", StableKey: "a", CandidateOrdinal: 3})
	recovered, err := Allocate(second.Allocations, recoveredCandidates, Options{Now: base.Add(10 * 24 * time.Hour)})
	if err != nil {
		t.Fatalf("recovery Allocate() error = %v", err)
	}
	if got := allocationByID(recovered.Allocations, "occ-a"); got.FinalName != "Hong Kong" || !got.Active {
		t.Fatalf("recovered allocation = %+v", got)
	}
}

func TestAllocateReusesSmallestSuffixAfterRetention(t *testing.T) {
	base := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	first, _ := Allocate(nil, []Candidate{
		{OccurrenceID: "occ-a", BaseName: "Node", StableKey: "a", CandidateOrdinal: 0},
		{OccurrenceID: "occ-b", BaseName: "Node", StableKey: "b", CandidateOrdinal: 1},
	}, Options{Now: base})
	missing, _ := Allocate(first.Allocations, []Candidate{
		{OccurrenceID: "occ-b", BaseName: "Node", StableKey: "b", CandidateOrdinal: 0},
	}, Options{Now: base.Add(time.Hour)})
	afterExpiry, err := Allocate(missing.Allocations, []Candidate{
		{OccurrenceID: "occ-b", BaseName: "Node", StableKey: "b", CandidateOrdinal: 0},
		{OccurrenceID: "occ-new", BaseName: "Node", StableKey: "new", CandidateOrdinal: 1},
	}, Options{Now: base.Add(31 * 24 * time.Hour)})
	if err != nil {
		t.Fatalf("Allocate() error = %v", err)
	}
	if got := allocationByID(afterExpiry.Allocations, "occ-new").FinalName; got != "Node" {
		t.Fatalf("new allocation = %q, want Node", got)
	}
	if got := allocationByID(afterExpiry.Allocations, "occ-b").FinalName; got != "Node #2" {
		t.Fatalf("existing allocation changed to %q", got)
	}
}

func TestAllocateAvoidsReservedLogicalNames(t *testing.T) {
	result, err := Allocate(nil, []Candidate{
		{OccurrenceID: "occ-a", BaseName: "proxy", StableKey: "a", CandidateOrdinal: 0},
	}, Options{
		Now:           time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC),
		ReservedNames: []string{"proxy"},
	})
	if err != nil {
		t.Fatalf("Allocate() error = %v", err)
	}
	if result.Snapshot[0].FinalName != "proxy #2" {
		t.Fatalf("final name = %q", result.Snapshot[0].FinalName)
	}
}

func TestAllocateProtectsCandidateBaseNames(t *testing.T) {
	result, err := Allocate(nil, []Candidate{
		{OccurrenceID: "occ-a", BaseName: "Node", StableKey: "a", CandidateOrdinal: 0},
		{OccurrenceID: "occ-b", BaseName: "Node", StableKey: "b", CandidateOrdinal: 1},
		{OccurrenceID: "occ-c", BaseName: "Node #2", StableKey: "c", CandidateOrdinal: 2},
	}, Options{Now: time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("Allocate() error = %v", err)
	}
	assertNames(t, result.Allocations, map[string]string{
		"occ-a": "Node",
		"occ-b": "Node #3",
		"occ-c": "Node #2",
	})
}

func TestAllocateMovesUnlockedNameWhenItBecomesReserved(t *testing.T) {
	base := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	first, err := Allocate(nil, []Candidate{
		{OccurrenceID: "occ-a", BaseName: "proxy", StableKey: "a", CandidateOrdinal: 0},
	}, Options{Now: base})
	if err != nil {
		t.Fatalf("first Allocate() error = %v", err)
	}
	moved, err := Allocate(first.Allocations, []Candidate{
		{OccurrenceID: "occ-a", BaseName: "proxy", StableKey: "a", CandidateOrdinal: 0},
	}, Options{Now: base.Add(time.Hour), ReservedNames: []string{"proxy"}})
	if err != nil {
		t.Fatalf("second Allocate() error = %v", err)
	}
	if got := moved.Snapshot[0].FinalName; got != "proxy #2" {
		t.Fatalf("final name = %q, want proxy #2", got)
	}

	locked := first.Allocations
	locked[0].Locked = true
	if _, err := Allocate(locked, []Candidate{
		{OccurrenceID: "occ-a", BaseName: "proxy", StableKey: "a", CandidateOrdinal: 0},
	}, Options{Now: base.Add(time.Hour), ReservedNames: []string{"proxy"}}); err == nil {
		t.Fatal("locked allocation conflict was accepted")
	}
}

func TestAllocateKeepsActiveLastSeenStable(t *testing.T) {
	firstSeen := time.Date(2026, 7, 18, 8, 0, 0, 0, time.UTC)
	existing := []Allocation{{
		OccurrenceID: "occ-a", BaseName: "Node", FinalName: "Node", Suffix: 1,
		Active: true, LastSeenAt: firstSeen, Version: AlgorithmVersion,
	}}
	result, err := Allocate(existing, []Candidate{{
		OccurrenceID: "occ-a", BaseName: "Node", StableKey: "source/occ-a", CandidateOrdinal: 0,
	}}, Options{Now: firstSeen.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if got := allocationByID(result.Allocations, "occ-a").LastSeenAt; !got.Equal(firstSeen) {
		t.Fatalf("active allocation last seen changed from %s to %s", firstSeen, got)
	}
}

func assertNames(t *testing.T, allocations []Allocation, want map[string]string) {
	t.Helper()
	for id, name := range want {
		if got := allocationByID(allocations, id).FinalName; got != name {
			t.Fatalf("allocation %s = %q, want %q", id, got, name)
		}
	}
}

func allocationByID(allocations []Allocation, id string) Allocation {
	for _, allocation := range allocations {
		if allocation.OccurrenceID == id {
			return allocation
		}
	}
	return Allocation{}
}
