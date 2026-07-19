package singbox

import (
	"fmt"

	"github.com/doujialong/proxyloom/internal/jsonlossless"
	"github.com/doujialong/proxyloom/internal/protocol"
)

const (
	FormatID            = protocol.FormatSingBoxJSON
	AdapterVersion      = "sing-box-json-v2"
	DefaultMaxOutbounds = 20_000
	GlobalMaxOutbounds  = 100_000
)

type Shape string

const (
	ShapeOutboundArray Shape = "outbound_array"
	ShapeFullConfig    Shape = "full_config"
	ShapeSingleNode    Shape = "single_node"
)

type ParseStatus string

const (
	ParseComplete ParseStatus = "complete"
	ParsePartial  ParseStatus = "partial"
	ParseOpaque   ParseStatus = "opaque"
)

type Limits struct {
	JSON         jsonlossless.Limits
	MaxOutbounds int
}

func DefaultLimits() Limits {
	return Limits{JSON: jsonlossless.DefaultLimits(), MaxOutbounds: DefaultMaxOutbounds}
}

type Issue struct {
	Ordinal int
	Path    string
	Code    string
	Detail  string
}

type RawNode struct {
	FormatID       string
	AdapterVersion string
	Ordinal        int
	ExtractionPath string
	RawType        string
	ProtocolID     string
	DefinitionKind protocol.Kind
	DisplayName    string
	ParseStatus    ParseStatus
	Raw            *jsonlossless.Node
	Canonical      protocol.CanonicalNode
}

type Document struct {
	Raw      []byte
	Root     *jsonlossless.Node
	Shape    Shape
	Nodes    []RawNode
	NonNodes []RawNode
	Issues   []Issue
}

func Parse(data []byte, registry *protocol.Registry, limits Limits) (*Document, error) {
	if registry == nil {
		registry = protocol.NewRegistry()
	}
	limits = normalizeLimits(limits)
	root, err := jsonlossless.Parse(data, limits.JSON)
	if err != nil {
		return nil, err
	}

	document := &Document{Raw: append([]byte(nil), data...), Root: root}
	var outbounds []*jsonlossless.Node
	var pathPrefix string
	singleNode := false
	switch root.Kind {
	case jsonlossless.KindArray:
		document.Shape = ShapeOutboundArray
		outbounds = root.Elements
	case jsonlossless.KindObject:
		value, exists := root.Member("outbounds")
		if !exists {
			if _, hasType := root.Member("type"); !hasType {
				return nil, fmt.Errorf("singbox_outbounds_missing: object is neither a node nor a full config with outbounds")
			}
			document.Shape = ShapeSingleNode
			outbounds = []*jsonlossless.Node{root}
			singleNode = true
			break
		}
		document.Shape = ShapeFullConfig
		if value.Kind != jsonlossless.KindArray {
			return nil, fmt.Errorf("singbox_outbounds_invalid: outbounds must be an array")
		}
		outbounds = value.Elements
		pathPrefix = "/outbounds"
	default:
		return nil, fmt.Errorf("singbox_document_invalid: expected an outbound array or full config object")
	}

	if len(outbounds) > limits.MaxOutbounds {
		return nil, fmt.Errorf("singbox_node_limit_exceeded: got %d outbounds, limit is %d", len(outbounds), limits.MaxOutbounds)
	}

	for ordinal, raw := range outbounds {
		path := fmt.Sprintf("%s/%d", pathPrefix, ordinal)
		if singleNode {
			path = ""
		}
		if raw.Kind != jsonlossless.KindObject {
			document.Issues = append(document.Issues, Issue{Ordinal: ordinal, Path: path, Code: "outbound_not_object", Detail: "outbound must be an object"})
			continue
		}

		typeNode, exists := raw.Member("type")
		rawType, validType := typeNode.StringValue()
		if !exists || !validType || rawType == "" {
			document.Issues = append(document.Issues, Issue{Ordinal: ordinal, Path: path, Code: "outbound_type_invalid", Detail: "outbound type must be a non-empty string"})
			continue
		}
		definition := registry.Lookup(FormatID, rawType)
		displayName := ""
		status := ParseComplete
		if tagNode, tagExists := raw.Member("tag"); tagExists {
			displayName, _ = tagNode.StringValue()
		}
		if displayName == "" {
			status = ParsePartial
			document.Issues = append(document.Issues, Issue{Ordinal: ordinal, Path: path, Code: "outbound_tag_missing", Detail: "outbound tag is missing or empty"})
		}
		if definition.Kind == protocol.KindUnknown {
			status = ParseOpaque
		}

		canonical := protocol.Normalize(definition, displayName, raw)
		if status == ParseComplete && canonical.Completeness != protocol.CompletenessComplete {
			status = ParsePartial
		}
		node := RawNode{
			FormatID:       FormatID,
			AdapterVersion: AdapterVersion,
			Ordinal:        ordinal,
			ExtractionPath: path,
			RawType:        rawType,
			ProtocolID:     definition.ID,
			DefinitionKind: definition.Kind,
			DisplayName:    displayName,
			ParseStatus:    status,
			Raw:            raw,
			Canonical:      canonical,
		}
		if definition.Kind == protocol.KindNonProxy {
			document.NonNodes = append(document.NonNodes, node)
			continue
		}
		document.Nodes = append(document.Nodes, node)
	}
	return document, nil
}

func normalizeLimits(limits Limits) Limits {
	if limits.JSON.MaxBytes == 0 && limits.JSON.MaxDepth == 0 && limits.JSON.MaxValues == 0 && limits.JSON.MaxStringBytes == 0 {
		limits.JSON = jsonlossless.DefaultLimits()
	}
	if limits.MaxOutbounds <= 0 {
		limits.MaxOutbounds = DefaultMaxOutbounds
	}
	if limits.MaxOutbounds > GlobalMaxOutbounds {
		limits.MaxOutbounds = GlobalMaxOutbounds
	}
	return limits
}
