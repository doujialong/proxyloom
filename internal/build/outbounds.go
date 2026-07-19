package build

import (
	"fmt"
	"sort"
	"time"

	"github.com/doujialong/proxyloom/internal/format/singbox"
	"github.com/doujialong/proxyloom/internal/jsonlossless"
	"github.com/doujialong/proxyloom/internal/naming"
	"github.com/doujialong/proxyloom/internal/patch"
)

const BuilderVersion = "singbox-outbounds-v2"

type Candidate struct {
	OccurrenceID     string
	StableKey        string
	Node             singbox.RawNode
	CandidateOrdinal int
	Excluded         bool
}

type Options struct {
	Now           time.Time
	NameRetention time.Duration
	ReservedNames []string
	Allocations   []naming.Allocation
}

type NodeChange struct {
	OccurrenceID string
	Change       patch.Change
}

type SnapshotItem struct {
	OccurrenceID     string
	FinalName        string
	CandidateOrdinal int
	IncludedOrdinal  *int
}

type Result struct {
	Artifact           []byte
	Allocations        []naming.Allocation
	AllocationSnapshot []SnapshotItem
	Changes            []NodeChange
}

func Outbounds(candidates []Candidate, options Options) (Result, error) {
	ordered := append([]Candidate(nil), candidates...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].CandidateOrdinal < ordered[j].CandidateOrdinal
	})
	nameCandidates := make([]naming.Candidate, len(ordered))
	for i, candidate := range ordered {
		baseName := candidate.Node.DisplayName
		if baseName == "" {
			baseName = candidate.Node.RawType
		}
		nameCandidates[i] = naming.Candidate{
			OccurrenceID:     candidate.OccurrenceID,
			BaseName:         baseName,
			StableKey:        candidate.StableKey,
			CandidateOrdinal: candidate.CandidateOrdinal,
		}
	}
	allocated, err := naming.Allocate(options.Allocations, nameCandidates, naming.Options{
		Now:           options.Now,
		Retention:     options.NameRetention,
		ReservedNames: options.ReservedNames,
	})
	if err != nil {
		return Result{}, err
	}
	nameByOccurrence := make(map[string]string, len(allocated.Snapshot))
	for _, item := range allocated.Snapshot {
		nameByOccurrence[item.OccurrenceID] = item.FinalName
	}

	outboundNodes := make([]*jsonlossless.Node, 0, len(ordered))
	changes := make([]NodeChange, 0)
	snapshot := make([]SnapshotItem, 0, len(ordered))
	for _, candidate := range ordered {
		finalName := nameByOccurrence[candidate.OccurrenceID]
		item := SnapshotItem{
			OccurrenceID:     candidate.OccurrenceID,
			FinalName:        finalName,
			CandidateOrdinal: candidate.CandidateOrdinal,
		}
		if candidate.Excluded {
			snapshot = append(snapshot, item)
			continue
		}

		changeOrigin := "name-conflict"
		if candidate.Node.DisplayName == "" {
			changeOrigin = "name-required"
		}
		patched, change, err := patch.ApplyTag(candidate.Node.Raw, finalName, changeOrigin)
		if err != nil {
			return Result{}, fmt.Errorf("patch occurrence %s: %w", candidate.OccurrenceID, err)
		}
		if change != nil {
			changes = append(changes, NodeChange{OccurrenceID: candidate.OccurrenceID, Change: *change})
		}
		includedOrdinal := len(outboundNodes)
		item.IncludedOrdinal = &includedOrdinal
		snapshot = append(snapshot, item)
		outboundNodes = append(outboundNodes, patched)
	}

	root := jsonlossless.NewObject(jsonlossless.Member{
		Key:    "outbounds",
		KeyRaw: `"outbounds"`,
		Value:  jsonlossless.NewArray(outboundNodes...),
	})
	artifact, err := jsonlossless.MarshalIndent(root, "", "  ")
	if err != nil {
		return Result{}, err
	}
	artifact = append(artifact, '\n')
	return Result{
		Artifact:           artifact,
		Allocations:        allocated.Allocations,
		AllocationSnapshot: snapshot,
		Changes:            changes,
	}, nil
}

func RenderSingBoxDocument(document *singbox.Document, snapshot []SnapshotItem) ([]byte, error) {
	if document == nil || document.Root == nil {
		return nil, fmt.Errorf("sing-box document is required")
	}
	root := document.Root.Clone()
	var outbounds []*jsonlossless.Node
	switch document.Shape {
	case singbox.ShapeSingleNode:
		outbounds = []*jsonlossless.Node{root}
	case singbox.ShapeOutboundArray:
		outbounds = root.Elements
	case singbox.ShapeFullConfig:
		value, exists := root.Member("outbounds")
		if !exists || value.Kind != jsonlossless.KindArray {
			return nil, fmt.Errorf("sing-box full config no longer contains an outbound array")
		}
		outbounds = value.Elements
	default:
		return nil, fmt.Errorf("unsupported sing-box document shape %q", document.Shape)
	}
	for _, item := range snapshot {
		if item.CandidateOrdinal < 0 || item.CandidateOrdinal >= len(outbounds) || item.FinalName == "" {
			return nil, fmt.Errorf("invalid sing-box allocation snapshot ordinal %d", item.CandidateOrdinal)
		}
		patched, _, err := patch.ApplyTag(outbounds[item.CandidateOrdinal], item.FinalName, "name-conflict")
		if err != nil {
			return nil, fmt.Errorf("patch sing-box document ordinal %d: %w", item.CandidateOrdinal, err)
		}
		outbounds[item.CandidateOrdinal] = patched
	}
	excluded := make(map[int]struct{})
	for _, item := range snapshot {
		if item.IncludedOrdinal == nil {
			excluded[item.CandidateOrdinal] = struct{}{}
		}
	}
	if len(excluded) > 0 {
		filtered := make([]*jsonlossless.Node, 0, len(outbounds)-len(excluded))
		for ordinal, outbound := range outbounds {
			if _, remove := excluded[ordinal]; !remove {
				filtered = append(filtered, outbound)
			}
		}
		switch document.Shape {
		case singbox.ShapeSingleNode:
			return nil, fmt.Errorf("health filtering removed the only sing-box outbound")
		case singbox.ShapeOutboundArray:
			root.Elements = filtered
		case singbox.ShapeFullConfig:
			value, _ := root.Member("outbounds")
			value.Elements = filtered
		}
	}
	artifact, err := jsonlossless.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(artifact, '\n'), nil
}
