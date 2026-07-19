package build

import (
	"strings"
	"testing"
	"time"

	"github.com/doujialong/proxyloom/internal/format/urilist"
	"github.com/doujialong/proxyloom/internal/protocol"
)

func TestURIListOnlyPatchesConflictingDisplayFragments(t *testing.T) {
	document, err := urilist.Parse([]byte(strings.Join([]string{
		"vless://one@example.test:443?x=%2f#Hong%20Kong",
		"vless://two@example.test:443?x=%2F#Hong%20Kong",
	}, "\n")), protocol.NewRegistry(), urilist.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	result, err := URIList([]URICandidate{
		{OccurrenceID: "occ-one", StableKey: "one", Node: document.Nodes[0], CandidateOrdinal: 0},
		{OccurrenceID: "occ-two", StableKey: "two", Node: document.Nodes[1], CandidateOrdinal: 1},
	}, URIOptions{Now: time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	output := string(result.Artifact)
	if !strings.Contains(output, "?x=%2f#Hong%20Kong\n") {
		t.Fatalf("first URI was unexpectedly normalized: %s", output)
	}
	if !strings.Contains(output, "?x=%2F#Hong%20Kong%20%232\n") {
		t.Fatalf("duplicate URI did not receive a numeric suffix: %s", output)
	}
}

func TestURIListPreservesUniqueRawURI(t *testing.T) {
	raw := []byte("ss://opaque@example.test:443#Only%20One\n")
	document, err := urilist.Parse(raw, protocol.NewRegistry(), urilist.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	result, err := URIList([]URICandidate{{
		OccurrenceID: "occ-one", StableKey: "one", Node: document.Nodes[0], CandidateOrdinal: 0,
	}}, URIOptions{Now: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Artifact) != string(raw) {
		t.Fatalf("artifact = %q, want byte-preserving %q", result.Artifact, raw)
	}
}
