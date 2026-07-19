package build

import (
	"bytes"
	"testing"
	"time"

	"github.com/doujialong/proxyloom/internal/format/clienttext"
	"github.com/doujialong/proxyloom/internal/protocol"
)

func TestClientTextExactPassThroughAndDuplicateRename(t *testing.T) {
	input := []byte("[Proxy]\nOne = vmess, one.example, 443, opaque\n")
	document, err := clienttext.Parse(input, protocol.NewRegistry(), clienttext.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	result, err := ClientText([]ClientTextCandidate{{
		OccurrenceID: "occ-one", StableKey: "one", Node: document.Nodes[0], CandidateOrdinal: 0,
	}}, document, ClientTextOptions{Now: time.Unix(100, 0), NameRetention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || !bytes.Equal(result.Artifact, input) {
		t.Fatalf("unchanged client config was rewritten:\n%s", result.Artifact)
	}

	duplicates := []byte("[Proxy]\nSame = vmess, one.example, 443, opaque\nSame = anytls, two.example, 443, opaque\n")
	duplicateDocument, err := clienttext.Parse(duplicates, protocol.NewRegistry(), clienttext.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	result, err = ClientText([]ClientTextCandidate{
		{OccurrenceID: "occ-one", StableKey: "one", Node: duplicateDocument.Nodes[0], CandidateOrdinal: 0},
		{OccurrenceID: "occ-two", StableKey: "two", Node: duplicateDocument.Nodes[1], CandidateOrdinal: 1},
	}, duplicateDocument, ClientTextOptions{Now: time.Unix(100, 0), NameRetention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || !bytes.Contains(result.Artifact, []byte("Same #2 = anytls")) {
		t.Fatalf("duplicate client names were not renamed:\n%s", result.Artifact)
	}
}
