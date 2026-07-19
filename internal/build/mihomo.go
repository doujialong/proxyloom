package build

import (
	"fmt"
	"sort"
	"time"

	"github.com/doujialong/proxyloom/internal/format/mihomo"
	"github.com/doujialong/proxyloom/internal/naming"
)

const MihomoBuilderVersion = "mihomo-yaml-builder-v1"

type MihomoCandidate struct {
	OccurrenceID     string
	StableKey        string
	Node             mihomo.RawNode
	CandidateOrdinal int
	Excluded         bool
}

type MihomoOptions struct {
	Now           time.Time
	NameRetention time.Duration
	Allocations   []naming.Allocation
}

type MihomoResult struct {
	Artifact    []byte
	Allocations []naming.Allocation
	Names       map[int]string
	Changed     bool
}

func Mihomo(candidates []MihomoCandidate, document *mihomo.Document, options MihomoOptions) (MihomoResult, error) {
	if document == nil || len(candidates) == 0 {
		return MihomoResult{}, fmt.Errorf("Mihomo document and candidates are required")
	}
	ordered := append([]MihomoCandidate(nil), candidates...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].CandidateOrdinal < ordered[j].CandidateOrdinal
	})
	namingCandidates := make([]naming.Candidate, len(ordered))
	previousOrdinal := -1
	for index, candidate := range ordered {
		if candidate.OccurrenceID == "" || candidate.StableKey == "" || candidate.Node.DisplayName == "" || candidate.CandidateOrdinal <= previousOrdinal {
			return MihomoResult{}, fmt.Errorf("invalid Mihomo build candidate at index %d", index)
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
		return MihomoResult{}, err
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
		return MihomoResult{
			Artifact:    append([]byte(nil), document.Original...),
			Allocations: allocated.Allocations,
			Names:       names,
		}, nil
	}
	artifact, err := mihomo.RenderFiltered(document, names, excluded)
	if err != nil {
		return MihomoResult{}, err
	}
	return MihomoResult{Artifact: artifact, Allocations: allocated.Allocations, Names: names, Changed: true}, nil
}
