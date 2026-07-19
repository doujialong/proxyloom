package ingest

import (
	"fmt"
	"time"

	"github.com/doujialong/proxyloom/internal/format/singbox"
	"github.com/doujialong/proxyloom/internal/identity"
	"github.com/doujialong/proxyloom/internal/occurrence"
	"github.com/doujialong/proxyloom/internal/protocol"
)

const ProcessorVersion = "singbox-snapshot-v2"

type Processor struct {
	registry      *protocol.Registry
	fingerprinter *identity.Fingerprinter
	limits        singbox.Limits
}

func NewProcessor(registry *protocol.Registry, fingerprinter *identity.Fingerprinter, limits singbox.Limits) (*Processor, error) {
	if fingerprinter == nil {
		return nil, fmt.Errorf("fingerprinter is required")
	}
	if registry == nil {
		registry = protocol.NewRegistry()
	}
	return &Processor{registry: registry, fingerprinter: fingerprinter, limits: limits}, nil
}

type Node struct {
	Raw           singbox.RawNode
	Fingerprint   identity.Fingerprint
	OccurrenceID  string
	DuplicateSlot int
	NamingKey     string
	MatchMethod   occurrence.MatchMethod
}

type Snapshot struct {
	Document    *singbox.Document
	Nodes       []Node
	Occurrences []occurrence.Occurrence
}

type Options struct {
	SourceID            string
	Now                 time.Time
	OccurrenceRetention time.Duration
	NewOccurrenceID     func() string
}

func (p *Processor) Process(data []byte, existing []occurrence.Occurrence, options Options) (*Snapshot, error) {
	if p == nil || p.fingerprinter == nil {
		return nil, fmt.Errorf("snapshot processor is not initialized")
	}
	if options.SourceID == "" {
		return nil, fmt.Errorf("source ID is required")
	}
	document, err := singbox.Parse(data, p.registry, p.limits)
	if err != nil {
		return nil, err
	}

	fingerprints := make([]identity.Fingerprint, len(document.Nodes))
	candidates := make([]occurrence.Candidate, len(document.Nodes))
	for i, rawNode := range document.Nodes {
		definition := p.registry.Lookup(singbox.FormatID, rawNode.RawType)
		projection := identity.Projection{
			Node:              rawNode.Raw,
			Kind:              identity.KindOpaqueStructural,
			Version:           identity.OpaqueProjection,
			ExcludeRootMember: "tag",
		}
		if definition.IdentityProjection != "" {
			projected, err := protocol.ProjectIdentity(definition, rawNode.Raw)
			if err != nil {
				return nil, fmt.Errorf("identity projection %s: %w", rawNode.ExtractionPath, err)
			}
			projection = identity.Projection{
				Node:    projected,
				Kind:    identity.KindSemantic,
				Version: definition.IdentityProjection,
			}
		}
		fingerprint, err := p.fingerprinter.Sum(projection)
		if err != nil {
			return nil, fmt.Errorf("fingerprint %s: %w", rawNode.ExtractionPath, err)
		}
		fingerprints[i] = fingerprint
		candidates[i] = occurrence.Candidate{
			Ordinal:        rawNode.Ordinal,
			Fingerprint:    fingerprint,
			ExtractionPath: rawNode.ExtractionPath,
			ProtocolID:     rawNode.ProtocolID,
			OriginalName:   rawNode.DisplayName,
		}
	}

	reconciled, err := occurrence.Reconcile(existing, candidates, occurrence.Options{
		Now:       options.Now,
		Retention: options.OccurrenceRetention,
		NewID:     options.NewOccurrenceID,
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

	nodes := make([]Node, len(document.Nodes))
	for i, rawNode := range document.Nodes {
		link, exists := links[rawNode.Ordinal]
		if !exists {
			return nil, fmt.Errorf("missing occurrence link for ordinal %d", rawNode.Ordinal)
		}
		matchedOccurrence, exists := occurrencesByID[link.OccurrenceID]
		if !exists {
			return nil, fmt.Errorf("missing occurrence %s", link.OccurrenceID)
		}
		nodes[i] = Node{
			Raw:           rawNode,
			Fingerprint:   fingerprints[i],
			OccurrenceID:  link.OccurrenceID,
			DuplicateSlot: matchedOccurrence.DuplicateSlot,
			NamingKey:     fmt.Sprintf("%s\x00%s\x00%08d\x00%s", options.SourceID, fingerprints[i].MatchKey(), matchedOccurrence.DuplicateSlot, link.OccurrenceID),
			MatchMethod:   link.Method,
		}
	}
	return &Snapshot{Document: document, Nodes: nodes, Occurrences: reconciled.Occurrences}, nil
}
