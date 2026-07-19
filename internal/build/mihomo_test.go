package build

import (
	"bytes"
	"testing"
	"time"

	"github.com/doujialong/proxyloom/internal/format/mihomo"
	"github.com/doujialong/proxyloom/internal/protocol"
)

func TestMihomoPreservesExactBytesAndRenamesDuplicates(t *testing.T) {
	input := []byte("# exact bytes\nproxies:\n  - {name: One, type: ss, server: one.example, port: 443}\n")
	document, err := mihomo.Parse(input, protocol.NewRegistry(), mihomo.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	result, err := Mihomo([]MihomoCandidate{{
		OccurrenceID: "occ-one", StableKey: "one", Node: document.Nodes[0], CandidateOrdinal: 0,
	}}, document, MihomoOptions{Now: time.Unix(100, 0), NameRetention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || !bytes.Equal(result.Artifact, input) {
		t.Fatalf("unchanged Mihomo input was rewritten:\n%s", result.Artifact)
	}

	duplicateInput := []byte("proxies:\n  - {name: Same, type: ss, server: one.example, port: 443}\n  - {name: Same, type: vless, server: two.example, port: 443}\n")
	duplicateDocument, err := mihomo.Parse(duplicateInput, protocol.NewRegistry(), mihomo.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	result, err = Mihomo([]MihomoCandidate{
		{OccurrenceID: "occ-one", StableKey: "one", Node: duplicateDocument.Nodes[0], CandidateOrdinal: 0},
		{OccurrenceID: "occ-two", StableKey: "two", Node: duplicateDocument.Nodes[1], CandidateOrdinal: 1},
	}, duplicateDocument, MihomoOptions{Now: time.Unix(100, 0), NameRetention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed {
		t.Fatal("duplicate Mihomo names were not changed")
	}
	rendered, err := mihomo.Parse(result.Artifact, protocol.NewRegistry(), mihomo.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(rendered.Nodes) != 2 || rendered.Nodes[0].DisplayName != "Same" || rendered.Nodes[1].DisplayName != "Same #2" {
		t.Fatalf("rendered names = %q, %q", rendered.Nodes[0].DisplayName, rendered.Nodes[1].DisplayName)
	}
}
