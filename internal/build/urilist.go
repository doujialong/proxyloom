package build

import (
	"bytes"
	"fmt"
	"net/url"
	"sort"
	"time"

	"github.com/doujialong/proxyloom/internal/format/urilist"
	"github.com/doujialong/proxyloom/internal/naming"
)

const URIBuilderVersion = "uri-list-builder-v1"

type URICandidate struct {
	OccurrenceID     string
	StableKey        string
	Node             urilist.RawNode
	CandidateOrdinal int
	Excluded         bool
}

type URIOptions struct {
	Now           time.Time
	NameRetention time.Duration
	Allocations   []naming.Allocation
}

type URIResult struct {
	Artifact    []byte
	Allocations []naming.Allocation
	Names       map[int]string
	Changed     bool
}

func URIList(candidates []URICandidate, options URIOptions) (URIResult, error) {
	ordered := append([]URICandidate(nil), candidates...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].CandidateOrdinal < ordered[j].CandidateOrdinal
	})
	namingCandidates := make([]naming.Candidate, len(ordered))
	for index, candidate := range ordered {
		baseName := candidate.Node.DisplayName
		if baseName == "" {
			baseName = candidate.Node.RawType
		}
		namingCandidates[index] = naming.Candidate{
			OccurrenceID: candidate.OccurrenceID, BaseName: baseName,
			StableKey: candidate.StableKey, CandidateOrdinal: candidate.CandidateOrdinal,
		}
	}
	allocated, err := naming.Allocate(options.Allocations, namingCandidates, naming.Options{
		Now: options.Now, Retention: options.NameRetention,
	})
	if err != nil {
		return URIResult{}, err
	}
	nameByOccurrence := make(map[string]string, len(allocated.Snapshot))
	for _, item := range allocated.Snapshot {
		nameByOccurrence[item.OccurrenceID] = item.FinalName
	}
	nodes := make([]urilist.RawNode, 0, len(ordered))
	names := make(map[int]string, len(ordered))
	changed := false
	for _, candidate := range ordered {
		node := candidate.Node
		finalName := nameByOccurrence[candidate.OccurrenceID]
		names[candidate.CandidateOrdinal] = finalName
		if node.FragmentIsDisplayName && finalName != node.DisplayName {
			node.Raw = replaceURIFragment(node.Raw, finalName)
			changed = true
		}
		if !candidate.Excluded {
			nodes = append(nodes, node)
		} else {
			changed = true
		}
	}
	artifact, err := urilist.Render(nodes)
	if err != nil {
		return URIResult{}, err
	}
	return URIResult{Artifact: artifact, Allocations: allocated.Allocations, Names: names, Changed: changed}, nil
}

func replaceURIFragment(raw []byte, name string) []byte {
	fragment := []byte(url.PathEscape(name))
	index := bytes.IndexByte(raw, '#')
	if index < 0 {
		result := make([]byte, 0, len(raw)+1+len(fragment))
		result = append(result, raw...)
		result = append(result, '#')
		return append(result, fragment...)
	}
	result := make([]byte, 0, index+1+len(fragment))
	result = append(result, raw[:index+1]...)
	return append(result, fragment...)
}

func validateURICandidate(candidate URICandidate) error {
	if candidate.OccurrenceID == "" || candidate.StableKey == "" || len(candidate.Node.Raw) == 0 {
		return fmt.Errorf("invalid URI build candidate")
	}
	return nil
}
