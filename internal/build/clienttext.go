package build

import (
	"fmt"
	"sort"
	"time"

	"github.com/doujialong/proxyloom/internal/format/clienttext"
	"github.com/doujialong/proxyloom/internal/naming"
)

const ClientTextBuilderVersion = "client-text-builder-v1"

type ClientTextCandidate struct {
	OccurrenceID     string
	StableKey        string
	Node             clienttext.RawNode
	CandidateOrdinal int
	Excluded         bool
}

type ClientTextOptions struct {
	Now           time.Time
	NameRetention time.Duration
	Allocations   []naming.Allocation
}

type ClientTextResult struct {
	Artifact    []byte
	Allocations []naming.Allocation
	Names       map[int]string
	Changed     bool
}

func ClientText(candidates []ClientTextCandidate, document *clienttext.Document, options ClientTextOptions) (ClientTextResult, error) {
	if document == nil || len(candidates) == 0 {
		return ClientTextResult{}, fmt.Errorf("client text document and candidates are required")
	}
	ordered := append([]ClientTextCandidate(nil), candidates...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].CandidateOrdinal < ordered[j].CandidateOrdinal
	})
	namingCandidates := make([]naming.Candidate, len(ordered))
	previousOrdinal := -1
	for index, candidate := range ordered {
		if candidate.OccurrenceID == "" || candidate.StableKey == "" || candidate.Node.DisplayName == "" || candidate.CandidateOrdinal <= previousOrdinal {
			return ClientTextResult{}, fmt.Errorf("invalid client text build candidate at index %d", index)
		}
		previousOrdinal = candidate.CandidateOrdinal
		namingCandidates[index] = naming.Candidate{
			OccurrenceID: candidate.OccurrenceID, BaseName: candidate.Node.DisplayName,
			StableKey: candidate.StableKey, CandidateOrdinal: candidate.CandidateOrdinal,
		}
	}
	allocated, err := naming.Allocate(options.Allocations, namingCandidates, naming.Options{
		Now: options.Now, Retention: options.NameRetention,
	})
	if err != nil {
		return ClientTextResult{}, err
	}
	nameByOccurrence := make(map[string]string, len(allocated.Snapshot))
	for _, item := range allocated.Snapshot {
		nameByOccurrence[item.OccurrenceID] = item.FinalName
	}
	changed := false
	names := make(map[int]string, len(ordered))
	excluded := make(map[int]bool)
	for _, candidate := range ordered {
		finalName := nameByOccurrence[candidate.OccurrenceID]
		if finalName != candidate.Node.DisplayName {
			changed = true
		}
		names[candidate.CandidateOrdinal] = finalName
		if candidate.Excluded {
			excluded[candidate.CandidateOrdinal] = true
			changed = true
		}
	}
	if !changed {
		return ClientTextResult{
			Artifact:    append([]byte(nil), document.Original...),
			Allocations: allocated.Allocations,
			Names:       names,
		}, nil
	}
	artifact, err := clienttext.RenderFiltered(document, names, excluded)
	if err != nil {
		return ClientTextResult{}, err
	}
	return ClientTextResult{Artifact: artifact, Allocations: allocated.Allocations, Names: names, Changed: true}, nil
}
