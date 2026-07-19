package ingest

import (
	"fmt"

	"github.com/doujialong/proxyloom/internal/format/mihomo"
	"github.com/doujialong/proxyloom/internal/identity"
	"github.com/doujialong/proxyloom/internal/occurrence"
	"github.com/doujialong/proxyloom/internal/protocol"
)

const MihomoProcessorVersion = "mihomo-snapshot-v1"

type MihomoProcessor struct {
	registry      *protocol.Registry
	fingerprinter *identity.Fingerprinter
	limits        mihomo.Limits
}

type MihomoNode struct {
	Raw           mihomo.RawNode
	Fingerprint   identity.Fingerprint
	OccurrenceID  string
	DuplicateSlot int
	NamingKey     string
	MatchMethod   occurrence.MatchMethod
}

type MihomoSnapshot struct {
	Document    *mihomo.Document
	Nodes       []MihomoNode
	Occurrences []occurrence.Occurrence
}

func NewMihomoProcessor(registry *protocol.Registry, fingerprinter *identity.Fingerprinter, limits mihomo.Limits) (*MihomoProcessor, error) {
	if fingerprinter == nil {
		return nil, fmt.Errorf("fingerprinter is required")
	}
	if registry == nil {
		registry = protocol.NewRegistry()
	}
	return &MihomoProcessor{registry: registry, fingerprinter: fingerprinter, limits: limits}, nil
}

func (p *MihomoProcessor) Process(data []byte, existing []occurrence.Occurrence, options Options) (*MihomoSnapshot, error) {
	if p == nil || p.fingerprinter == nil {
		return nil, fmt.Errorf("Mihomo snapshot processor is not initialized")
	}
	if options.SourceID == "" {
		return nil, fmt.Errorf("source ID is required")
	}
	document, err := mihomo.Parse(data, p.registry, p.limits)
	if err != nil {
		return nil, err
	}
	fingerprints := make([]identity.Fingerprint, len(document.Nodes))
	candidates := make([]occurrence.Candidate, len(document.Nodes))
	for index, rawNode := range document.Nodes {
		fingerprint, err := p.fingerprinter.SumBytes(identity.ByteProjection{
			Value: rawNode.IdentityBytes, Kind: identity.KindOpaqueStructural,
			Version: "opaque-mihomo-yaml-v1",
		})
		if err != nil {
			return nil, fmt.Errorf("fingerprint %s: %w", rawNode.ExtractionPath, err)
		}
		fingerprints[index] = fingerprint
		candidates[index] = occurrence.Candidate{
			Ordinal: rawNode.Ordinal, Fingerprint: fingerprint,
			ExtractionPath: rawNode.ExtractionPath, ProtocolID: rawNode.ProtocolID,
			OriginalName: rawNode.DisplayName,
		}
	}
	reconciled, err := occurrence.Reconcile(existing, candidates, occurrence.Options{
		Now: options.Now, Retention: options.OccurrenceRetention, NewID: options.NewOccurrenceID,
	})
	if err != nil {
		return nil, err
	}
	links := make(map[int]occurrence.Link, len(reconciled.Links))
	for _, link := range reconciled.Links {
		links[link.CandidateOrdinal] = link
	}
	occurrencesByID := make(map[string]occurrence.Occurrence, len(reconciled.Occurrences))
	for _, item := range reconciled.Occurrences {
		occurrencesByID[item.ID] = item
	}
	nodes := make([]MihomoNode, len(document.Nodes))
	for index, rawNode := range document.Nodes {
		link, exists := links[rawNode.Ordinal]
		if !exists {
			return nil, fmt.Errorf("missing occurrence link for ordinal %d", rawNode.Ordinal)
		}
		matched, exists := occurrencesByID[link.OccurrenceID]
		if !exists {
			return nil, fmt.Errorf("missing occurrence %s", link.OccurrenceID)
		}
		nodes[index] = MihomoNode{
			Raw: rawNode, Fingerprint: fingerprints[index], OccurrenceID: link.OccurrenceID,
			DuplicateSlot: matched.DuplicateSlot,
			NamingKey:     fmt.Sprintf("%s\x00%s\x00%08d\x00%s", options.SourceID, fingerprints[index].MatchKey(), matched.DuplicateSlot, link.OccurrenceID),
			MatchMethod:   link.Method,
		}
	}
	return &MihomoSnapshot{Document: document, Nodes: nodes, Occurrences: reconciled.Occurrences}, nil
}
