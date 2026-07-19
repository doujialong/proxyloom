package build

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/doujialong/proxyloom/internal/format/singbox"
	"github.com/doujialong/proxyloom/internal/identity"
	"github.com/doujialong/proxyloom/internal/ingest"
	"github.com/doujialong/proxyloom/internal/jsonlossless"
	"github.com/doujialong/proxyloom/internal/protocol"
)

func TestM1GoldenOutbounds(t *testing.T) {
	input := readFixture(t, "testdata/m1-input.json")
	expected := readFixture(t, "testdata/m1-outbounds.golden.json")
	processor := testProcessor(t)
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	nextID := 0
	snapshot, err := processor.Process(input, nil, ingest.Options{
		SourceID: "source-a",
		Now:      now,
		NewOccurrenceID: func() string {
			nextID++
			return fmt.Sprintf("occ-%03d", nextID)
		},
	})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if len(snapshot.Nodes) != 3 || len(snapshot.Document.NonNodes) != 1 {
		t.Fatalf("snapshot nodes = %d, non-nodes = %d", len(snapshot.Nodes), len(snapshot.Document.NonNodes))
	}
	if snapshot.Nodes[0].Fingerprint.MatchKey() != snapshot.Nodes[1].Fingerprint.MatchKey() {
		t.Fatal("identical nodes did not share a fingerprint")
	}
	if snapshot.Nodes[2].Fingerprint.Kind != identity.KindOpaqueStructural {
		t.Fatalf("unknown fingerprint = %+v", snapshot.Nodes[2].Fingerprint)
	}

	candidates := buildCandidates(snapshot)
	result, err := Outbounds(candidates, Options{Now: now})
	if err != nil {
		t.Fatalf("Outbounds() error = %v", err)
	}
	if !bytes.Equal(result.Artifact, expected) {
		t.Fatalf("artifact differs from golden\n--- want\n%s\n--- got\n%s", expected, result.Artifact)
	}
	if len(result.Changes) != 2 {
		t.Fatalf("changes = %d, want 2", len(result.Changes))
	}
	for _, change := range result.Changes {
		if change.Change.Path != "/tag" {
			t.Fatalf("unexpected change = %+v", change)
		}
	}

	replayed, err := Outbounds(candidates, Options{Now: now.Add(time.Hour), Allocations: result.Allocations})
	if err != nil {
		t.Fatalf("replay Outbounds() error = %v", err)
	}
	if !bytes.Equal(replayed.Artifact, result.Artifact) {
		t.Fatal("fixed inputs did not produce byte-identical artifact")
	}
}

func TestRenderSingBoxDocumentKeepsFullConfigAndNonProxyOutbounds(t *testing.T) {
	input := []byte(`{"log":{"level":"warn"},"outbounds":[{"type":"vless","tag":"Node","server":"a","server_port":443},{"type":"vless","tag":"Node","server":"b","server_port":443},{"type":"selector","tag":"Proxy","outbounds":["Node","Node #2"]}],"future":{"ratio":1.2300}}`)
	processor := testProcessor(t)
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	next := 0
	snapshot, err := processor.Process(input, nil, ingest.Options{
		SourceID: "source-full", Now: now,
		NewOccurrenceID: func() string { next++; return fmt.Sprintf("occ-%d", next) },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Outbounds(buildCandidates(snapshot), Options{Now: now, ReservedNames: []string{"Proxy"}})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := RenderSingBoxDocument(snapshot.Document, result.AllocationSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	root, err := jsonlossless.Parse(artifact, jsonlossless.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := root.Member("log"); !exists {
		t.Fatal("full config log section was removed")
	}
	future, exists := root.Member("future")
	if !exists {
		t.Fatal("unknown root member was removed")
	}
	ratio, _ := future.Member("ratio")
	if value, _ := ratio.NumberLexeme(); value != "1.2300" {
		t.Fatalf("future number lexeme = %q", value)
	}
	outbounds, _ := root.Member("outbounds")
	if len(outbounds.Elements) != 3 {
		t.Fatalf("outbound count = %d, want proxy and logical outbounds", len(outbounds.Elements))
	}
	secondTag, _ := outbounds.Elements[1].Member("tag")
	if value, _ := secondTag.StringValue(); value != "Node #2" {
		t.Fatalf("second tag = %q", value)
	}
}

func TestM1ProtocolFixturesPassThroughLosslessly(t *testing.T) {
	input := readFixture(t, "../protocol/testdata/singbox-v1.12.25-canonical.json")
	processor := testProcessor(t)
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	nextID := 0
	snapshot, err := processor.Process(input, nil, ingest.Options{
		SourceID: "source-fixtures",
		Now:      now,
		NewOccurrenceID: func() string {
			nextID++
			return fmt.Sprintf("occ-%02d", nextID)
		},
	})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if len(snapshot.Nodes) != 9 {
		t.Fatalf("node count = %d, want 9", len(snapshot.Nodes))
	}
	result, err := Outbounds(buildCandidates(snapshot), Options{Now: now})
	if err != nil {
		t.Fatalf("Outbounds() error = %v", err)
	}
	if len(result.Changes) != 0 {
		t.Fatalf("unexpected changes = %+v", result.Changes)
	}
	artifact, err := jsonlossless.Parse(result.Artifact, jsonlossless.DefaultLimits())
	if err != nil {
		t.Fatalf("parse artifact: %v", err)
	}
	outbounds, _ := artifact.Member("outbounds")
	for index, node := range snapshot.Nodes {
		original, err := jsonlossless.MarshalCompact(node.Raw.Raw)
		if err != nil {
			t.Fatalf("marshal original %d: %v", index, err)
		}
		rendered, err := jsonlossless.MarshalCompact(outbounds.Elements[index])
		if err != nil {
			t.Fatalf("marshal rendered %d: %v", index, err)
		}
		if !bytes.Equal(original, rendered) {
			t.Fatalf("node %d changed\nwant: %s\n got: %s", index, original, rendered)
		}
	}
}

func TestUnknownProtocolPassesThroughWithoutSemanticConversion(t *testing.T) {
	processor := testProcessor(t)
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	input := []byte(`[{"type":"future-proto","tag":"Unique","nested":{"huge":900719925474099312345,"ratio":1.2300}}]`)
	snapshot, err := processor.Process(input, nil, ingest.Options{SourceID: "source-a", Now: now, NewOccurrenceID: func() string { return "occ-unknown" }})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	result, err := Outbounds(buildCandidates(snapshot), Options{Now: now})
	if err != nil {
		t.Fatalf("Outbounds() error = %v", err)
	}
	artifact, err := jsonlossless.Parse(result.Artifact, jsonlossless.DefaultLimits())
	if err != nil {
		t.Fatalf("parse artifact: %v", err)
	}
	outbounds, _ := artifact.Member("outbounds")
	original, _ := jsonlossless.MarshalCompact(snapshot.Nodes[0].Raw.Raw)
	rendered, _ := jsonlossless.MarshalCompact(outbounds.Elements[0])
	if !bytes.Equal(original, rendered) {
		t.Fatalf("unknown node changed\nwant: %s\n got: %s", original, rendered)
	}
	if len(result.Changes) != 0 {
		t.Fatalf("unexpected changes = %+v", result.Changes)
	}
}

func TestNamingOccursBeforeHealthStyleExclusion(t *testing.T) {
	processor := testProcessor(t)
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	input := []byte(`[
  {"type":"vless","tag":"Node","server":"198.51.100.1","server_port":443},
  {"type":"vless","tag":"Node","server":"198.51.100.2","server_port":443}
]`)
	next := 0
	snapshot, err := processor.Process(input, nil, ingest.Options{SourceID: "source-a", Now: now, NewOccurrenceID: func() string {
		next++
		return fmt.Sprintf("occ-%d", next)
	}})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	candidates := buildCandidates(snapshot)
	candidates[0].Excluded = true
	filtered, err := Outbounds(candidates, Options{Now: now})
	if err != nil {
		t.Fatalf("filtered Outbounds() error = %v", err)
	}
	if filtered.AllocationSnapshot[0].IncludedOrdinal != nil {
		t.Fatal("excluded node has an included ordinal")
	}
	if filtered.AllocationSnapshot[1].FinalName != "Node #2" {
		t.Fatalf("healthy node name = %q, want Node #2", filtered.AllocationSnapshot[1].FinalName)
	}

	recovered, err := Outbounds(buildCandidates(snapshot), Options{Now: now.Add(time.Hour), Allocations: filtered.Allocations})
	if err != nil {
		t.Fatalf("recovered Outbounds() error = %v", err)
	}
	if recovered.AllocationSnapshot[0].FinalName != "Node" || recovered.AllocationSnapshot[1].FinalName != "Node #2" {
		t.Fatalf("recovered names = %+v", recovered.AllocationSnapshot)
	}
}

func TestNodeWithoutTagGetsStableProtocolName(t *testing.T) {
	processor := testProcessor(t)
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	snapshot, err := processor.Process(
		[]byte(`{"type":"vless","server":"198.51.100.1","server_port":443,"uuid":"fixture","future":{"value":1.2300}}`),
		nil,
		ingest.Options{SourceID: "source-a", Now: now, NewOccurrenceID: func() string { return "occ-1" }},
	)
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	result, err := Outbounds(buildCandidates(snapshot), Options{Now: now})
	if err != nil {
		t.Fatalf("Outbounds() error = %v", err)
	}
	if len(result.Changes) != 1 || result.Changes[0].Change.Operation != "add" || result.Changes[0].Change.Origin != "name-required" {
		t.Fatalf("changes = %+v", result.Changes)
	}
	root, err := jsonlossless.Parse(result.Artifact, jsonlossless.DefaultLimits())
	if err != nil {
		t.Fatalf("parse artifact: %v", err)
	}
	outbounds, _ := root.Member("outbounds")
	tag, _ := outbounds.Elements[0].Member("tag")
	if value, _ := tag.StringValue(); value != "vless" {
		t.Fatalf("tag = %q, want vless", value)
	}
	future, _ := outbounds.Elements[0].Member("future")
	encoded, _ := jsonlossless.MarshalCompact(future)
	if string(encoded) != `{"value":1.2300}` {
		t.Fatalf("future field changed: %s", encoded)
	}
}

func TestInitialNamingDoesNotDependOnCollectionOrder(t *testing.T) {
	processor := testProcessor(t)
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	input := []byte(`[
  {"type":"vless","tag":"Node","server":"198.51.100.1","server_port":443},
  {"type":"vless","tag":"Node","server":"198.51.100.2","server_port":443},
  {"type":"future-proto","tag":"Node","server":"198.51.100.3","server_port":443}
]`)
	next := 0
	snapshot, err := processor.Process(input, nil, ingest.Options{SourceID: "source-a", Now: now, NewOccurrenceID: func() string {
		next++
		return fmt.Sprintf("occ-%d", next)
	}})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	forward := buildCandidates(snapshot)
	reverse := make([]Candidate, len(forward))
	for i := range forward {
		reverse[i] = forward[len(forward)-1-i]
		reverse[i].CandidateOrdinal = i
	}
	forwardResult, err := Outbounds(forward, Options{Now: now})
	if err != nil {
		t.Fatalf("forward Outbounds() error = %v", err)
	}
	reverseResult, err := Outbounds(reverse, Options{Now: now})
	if err != nil {
		t.Fatalf("reverse Outbounds() error = %v", err)
	}
	forwardNames := snapshotNames(forwardResult.AllocationSnapshot)
	reverseNames := snapshotNames(reverseResult.AllocationSnapshot)
	if len(forwardNames) != len(reverseNames) {
		t.Fatalf("name counts differ: %v vs %v", forwardNames, reverseNames)
	}
	for occurrenceID, name := range forwardNames {
		if reverseNames[occurrenceID] != name {
			t.Fatalf("occurrence %s changed from %q to %q", occurrenceID, name, reverseNames[occurrenceID])
		}
	}
}

func testProcessor(t *testing.T) *ingest.Processor {
	t.Helper()
	fingerprinter, err := identity.NewFingerprinter(bytes.Repeat([]byte{0x5a}, 32), "fixture-key")
	if err != nil {
		t.Fatalf("NewFingerprinter() error = %v", err)
	}
	processor, err := ingest.NewProcessor(protocol.NewRegistry(), fingerprinter, singbox.DefaultLimits())
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}
	return processor
}

func buildCandidates(snapshot *ingest.Snapshot) []Candidate {
	candidates := make([]Candidate, len(snapshot.Nodes))
	for i, node := range snapshot.Nodes {
		candidates[i] = Candidate{
			OccurrenceID:     node.OccurrenceID,
			StableKey:        node.NamingKey,
			Node:             node.Raw,
			CandidateOrdinal: i,
		}
	}
	return candidates
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	return content
}

func snapshotNames(items []SnapshotItem) map[string]string {
	names := make(map[string]string, len(items))
	for _, item := range items {
		names[item.OccurrenceID] = item.FinalName
	}
	return names
}
