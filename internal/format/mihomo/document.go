package mihomo

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/doujialong/proxyloom/internal/protocol"
	"gopkg.in/yaml.v3"
)

const (
	FormatID       = protocol.FormatMihomoYAML
	AdapterVersion = "mihomo-yaml-v1"
	LimitsVersion  = 1

	hardMaxInputBytes  = 50 << 20
	hardMaxDepth       = 128
	hardMaxValues      = 5_000_000
	hardMaxScalarBytes = 4 << 20
	hardMaxProxies     = 100_000
)

var (
	ErrUnrecognized = errors.New("input is not a Mihomo YAML subscription")
	ErrLimit        = errors.New("Mihomo YAML limit exceeded")
)

type Shape string

const (
	ShapeFullConfig Shape = "full_config"
	ShapeProxyArray Shape = "proxy_array"
	ShapeSingleNode Shape = "single_node"
)

type Limits struct {
	MaxInputBytes  int
	MaxDepth       int
	MaxValues      int
	MaxScalarBytes int
	MaxProxies     int
}

func DefaultLimits() Limits {
	return Limits{
		MaxInputBytes: 10 << 20, MaxDepth: 64, MaxValues: 1_000_000,
		MaxScalarBytes: 1 << 20, MaxProxies: 20_000,
	}
}

type RawNode struct {
	Ordinal        int
	ExtractionPath string
	RawType        string
	ProtocolID     string
	DefinitionKind protocol.Kind
	DisplayName    string
	Raw            *yaml.Node
	RawBytes       []byte
	IdentityBytes  []byte
	Warnings       []string
}

type Document struct {
	Original []byte
	Root     *yaml.Node
	Shape    Shape
	Nodes    []RawNode
	NonNodes []RawNode
}

func Parse(input []byte, registry *protocol.Registry, limits Limits) (*Document, error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}
	if len(input) == 0 || !utf8.Valid(input) {
		return nil, ErrUnrecognized
	}
	if len(input) > limits.MaxInputBytes {
		return nil, fmt.Errorf("%w: input exceeds %d bytes", ErrLimit, limits.MaxInputBytes)
	}
	if registry == nil {
		registry = protocol.NewRegistry()
	}

	decoder := yaml.NewDecoder(bytes.NewReader(input))
	var parsed yaml.Node
	if err := decoder.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode Mihomo YAML: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("Mihomo YAML must contain exactly one document")
		}
		return nil, fmt.Errorf("decode trailing Mihomo YAML: %w", err)
	}
	if len(parsed.Content) != 1 {
		return nil, ErrUnrecognized
	}
	root := parsed.Content[0]
	values := 0
	if err := validateNode(root, 1, &values, limits); err != nil {
		return nil, err
	}

	document := &Document{Original: append([]byte(nil), input...), Root: root}
	proxies, prefix, shape, err := locateProxies(root)
	if err != nil {
		return nil, err
	}
	document.Shape = shape
	if len(proxies) > limits.MaxProxies {
		return nil, fmt.Errorf("%w: proxy count exceeds %d", ErrLimit, limits.MaxProxies)
	}
	for ordinal, raw := range proxies {
		if raw.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("proxy %d must be a mapping", ordinal)
		}
		nameNode, hasName := mappingValue(raw, "name")
		typeNode, hasType := mappingValue(raw, "type")
		if !hasName || nameNode.Kind != yaml.ScalarNode || strings.TrimSpace(nameNode.Value) == "" {
			return nil, fmt.Errorf("proxy %d requires a non-empty scalar name", ordinal)
		}
		if !hasType || typeNode.Kind != yaml.ScalarNode || strings.TrimSpace(typeNode.Value) == "" {
			return nil, fmt.Errorf("proxy %d requires a non-empty scalar type", ordinal)
		}
		rawType := strings.ToLower(strings.TrimSpace(typeNode.Value))
		definition := registry.Lookup(FormatID, rawType)
		rawBytes, err := yaml.Marshal(raw)
		if err != nil {
			return nil, fmt.Errorf("marshal proxy %d: %w", ordinal, err)
		}
		identityNode := cloneNode(raw)
		removeMappingMember(identityNode, "name")
		identityBytes, err := yaml.Marshal(identityNode)
		if err != nil {
			return nil, fmt.Errorf("marshal proxy identity %d: %w", ordinal, err)
		}
		warnings := []string(nil)
		if definition.Kind == protocol.KindUnknown {
			warnings = append(warnings, "unknown_protocol")
		}
		node := RawNode{
			Ordinal: ordinal, ExtractionPath: fmt.Sprintf("%s/%d", prefix, ordinal),
			RawType: rawType, ProtocolID: definition.ID, DefinitionKind: definition.Kind,
			DisplayName: nameNode.Value, Raw: raw, RawBytes: rawBytes,
			IdentityBytes: identityBytes, Warnings: warnings,
		}
		if shape == ShapeSingleNode {
			node.ExtractionPath = ""
		}
		if definition.Kind == protocol.KindNonProxy {
			document.NonNodes = append(document.NonNodes, node)
			continue
		}
		document.Nodes = append(document.Nodes, node)
	}
	if len(document.Nodes) == 0 {
		return nil, fmt.Errorf("%w: document contains no proxy nodes", ErrUnrecognized)
	}
	return document, nil
}

func Render(document *Document, names map[int]string) ([]byte, error) {
	return RenderFiltered(document, names, nil)
}

func RenderFiltered(document *Document, names map[int]string, excluded map[int]bool) ([]byte, error) {
	if document == nil || document.Root == nil {
		return nil, fmt.Errorf("Mihomo document is required")
	}
	root := cloneNode(document.Root)
	proxies, _, shape, err := locateProxies(root)
	if err != nil {
		return nil, err
	}
	if shape != document.Shape {
		return nil, fmt.Errorf("Mihomo document shape changed during rendering")
	}
	for ordinal, name := range names {
		if ordinal < 0 || ordinal >= len(proxies) || name == "" {
			return nil, fmt.Errorf("invalid Mihomo name allocation for ordinal %d", ordinal)
		}
		nameNode, exists := mappingValue(proxies[ordinal], "name")
		if !exists || nameNode.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("Mihomo proxy %d no longer has a scalar name", ordinal)
		}
		nameNode.Tag = "!!str"
		nameNode.Value = name
	}
	for ordinal := range excluded {
		if !excluded[ordinal] {
			continue
		}
		if ordinal < 0 || ordinal >= len(proxies) {
			return nil, fmt.Errorf("invalid excluded Mihomo proxy ordinal %d", ordinal)
		}
	}
	if len(excluded) > 0 {
		switch shape {
		case ShapeFullConfig:
			sequence, _ := mappingValue(root, "proxies")
			sequence.Content = filterSequence(sequence.Content, excluded)
		case ShapeProxyArray:
			root.Content = filterSequence(root.Content, excluded)
		case ShapeSingleNode:
			if excluded[0] {
				root = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			}
		}
	}
	return yaml.Marshal(root)
}

func filterSequence(nodes []*yaml.Node, excluded map[int]bool) []*yaml.Node {
	filtered := make([]*yaml.Node, 0, len(nodes))
	for ordinal, node := range nodes {
		if !excluded[ordinal] {
			filtered = append(filtered, node)
		}
	}
	return filtered
}

func locateProxies(root *yaml.Node) ([]*yaml.Node, string, Shape, error) {
	switch root.Kind {
	case yaml.SequenceNode:
		return root.Content, "", ShapeProxyArray, nil
	case yaml.MappingNode:
		if proxies, exists := mappingValue(root, "proxies"); exists {
			if proxies.Kind != yaml.SequenceNode {
				return nil, "", "", fmt.Errorf("Mihomo proxies must be a sequence")
			}
			return proxies.Content, "/proxies", ShapeFullConfig, nil
		}
		_, hasName := mappingValue(root, "name")
		_, hasType := mappingValue(root, "type")
		if hasName && hasType {
			return []*yaml.Node{root}, "", ShapeSingleNode, nil
		}
	}
	return nil, "", "", fmt.Errorf("%w: expected proxies, a proxy array, or one proxy object", ErrUnrecognized)
}

func validateNode(node *yaml.Node, depth int, values *int, limits Limits) error {
	if node == nil {
		return fmt.Errorf("Mihomo YAML contains a nil node")
	}
	if depth > limits.MaxDepth {
		return fmt.Errorf("%w: depth exceeds %d", ErrLimit, limits.MaxDepth)
	}
	*values++
	if *values > limits.MaxValues {
		return fmt.Errorf("%w: value count exceeds %d", ErrLimit, limits.MaxValues)
	}
	if node.Kind == yaml.AliasNode {
		return fmt.Errorf("Mihomo YAML aliases are not allowed")
	}
	if !allowedTag(node.ShortTag()) {
		return fmt.Errorf("Mihomo YAML tag %q is not allowed", node.ShortTag())
	}
	if node.Kind == yaml.ScalarNode && len(node.Value) > limits.MaxScalarBytes {
		return fmt.Errorf("%w: scalar exceeds %d bytes", ErrLimit, limits.MaxScalarBytes)
	}
	if node.Kind == yaml.MappingNode {
		if len(node.Content)%2 != 0 {
			return fmt.Errorf("Mihomo YAML mapping has an odd child count")
		}
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode {
				return fmt.Errorf("Mihomo YAML mapping keys must be scalars")
			}
			identity := key.ShortTag() + "\x00" + key.Value
			if _, exists := seen[identity]; exists {
				return fmt.Errorf("Mihomo YAML contains duplicate mapping key %q", key.Value)
			}
			seen[identity] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if err := validateNode(child, depth+1, values, limits); err != nil {
			return err
		}
	}
	return nil
}

func allowedTag(tag string) bool {
	switch tag {
	case "!!map", "!!seq", "!!str", "!!bool", "!!int", "!!float", "!!null", "!!timestamp", "!!merge":
		return true
	default:
		return false
	}
}

func mappingValue(mapping *yaml.Node, name string) (*yaml.Node, bool) {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil, false
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == name {
			return mapping.Content[index+1], true
		}
	}
	return nil, false
}

func removeMappingMember(mapping *yaml.Node, name string) {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == name {
			mapping.Content = append(mapping.Content[:index], mapping.Content[index+2:]...)
			return
		}
	}
}

func cloneNode(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	cloned := *node
	cloned.Content = make([]*yaml.Node, len(node.Content))
	for index, child := range node.Content {
		cloned.Content[index] = cloneNode(child)
	}
	cloned.Alias = nil
	return &cloned
}

func normalizeLimits(limits Limits) (Limits, error) {
	defaults := DefaultLimits()
	if limits.MaxInputBytes == 0 {
		limits.MaxInputBytes = defaults.MaxInputBytes
	}
	if limits.MaxDepth == 0 {
		limits.MaxDepth = defaults.MaxDepth
	}
	if limits.MaxValues == 0 {
		limits.MaxValues = defaults.MaxValues
	}
	if limits.MaxScalarBytes == 0 {
		limits.MaxScalarBytes = defaults.MaxScalarBytes
	}
	if limits.MaxProxies == 0 {
		limits.MaxProxies = defaults.MaxProxies
	}
	if limits.MaxInputBytes < 1 || limits.MaxInputBytes > hardMaxInputBytes ||
		limits.MaxDepth < 1 || limits.MaxDepth > hardMaxDepth ||
		limits.MaxValues < 1 || limits.MaxValues > hardMaxValues ||
		limits.MaxScalarBytes < 1 || limits.MaxScalarBytes > hardMaxScalarBytes ||
		limits.MaxProxies < 1 || limits.MaxProxies > hardMaxProxies {
		return Limits{}, fmt.Errorf("invalid Mihomo YAML limits")
	}
	return limits, nil
}
