package clienttext

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/doujialong/proxyloom/internal/protocol"
)

const (
	FormatID       = protocol.FormatClientText
	AdapterVersion = "client-text-v1"
	LimitsVersion  = 1

	hardMaxInputBytes = 50 << 20
	hardMaxLineBytes  = 4 << 20
	hardMaxNodes      = 100_000
)

var (
	ErrUnrecognized = errors.New("input is not a supported client text configuration")
	ErrLimit        = errors.New("client text limit exceeded")
)

type Style string

const (
	StyleNamedAssignment Style = "named_assignment"
	StyleQuantumultXTag  Style = "quantumult_x_tag"
)

type Limits struct {
	MaxInputBytes int
	MaxLineBytes  int
	MaxNodes      int
}

func DefaultLimits() Limits {
	return Limits{MaxInputBytes: 10 << 20, MaxLineBytes: 1 << 20, MaxNodes: 20_000}
}

type RawNode struct {
	Ordinal        int
	Line           int
	ExtractionPath string
	RawType        string
	ProtocolID     string
	DisplayName    string
	Style          Style
	Raw            []byte
	IdentityBytes  []byte
	NameStart      int
	NameEnd        int
	Warnings       []string
}

type Document struct {
	Original []byte
	Nodes    []RawNode
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

	document := &Document{Original: append([]byte(nil), input...)}
	section := ""
	lineNumber := 0
	for start := 0; start <= len(input); lineNumber++ {
		endOffset := bytes.IndexByte(input[start:], '\n')
		last := endOffset < 0
		end := len(input)
		if !last {
			end = start + endOffset
		}
		lineEnd := end
		if lineEnd > start && input[lineEnd-1] == '\r' {
			lineEnd--
		}
		line := input[start:lineEnd]
		if len(line) > limits.MaxLineBytes {
			return nil, fmt.Errorf("%w: line %d exceeds %d bytes", ErrLimit, lineNumber+1, limits.MaxLineBytes)
		}
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) >= 2 && trimmed[0] == '[' && trimmed[len(trimmed)-1] == ']' {
			section = strings.ToLower(strings.TrimSpace(string(trimmed[1 : len(trimmed)-1])))
		} else if len(trimmed) != 0 && trimmed[0] != '#' && trimmed[0] != ';' {
			var node RawNode
			var parsed bool
			switch section {
			case "proxy":
				node, parsed = parseNamedAssignment(line, start, lineNumber, len(document.Nodes), registry)
			case "server_local":
				node, parsed = parseQuantumultX(line, start, lineNumber, len(document.Nodes), registry)
			}
			if parsed {
				if len(document.Nodes) >= limits.MaxNodes {
					return nil, fmt.Errorf("%w: node count exceeds %d", ErrLimit, limits.MaxNodes)
				}
				document.Nodes = append(document.Nodes, node)
			}
		}
		if last {
			break
		}
		start = end + 1
	}
	if len(document.Nodes) == 0 {
		return nil, ErrUnrecognized
	}
	return document, nil
}

func Render(document *Document, names map[int]string) ([]byte, error) {
	return RenderFiltered(document, names, nil)
}

func RenderFiltered(document *Document, names map[int]string, excluded map[int]bool) ([]byte, error) {
	if document == nil || len(document.Original) == 0 {
		return nil, fmt.Errorf("client text document is required")
	}
	patches := make([]textPatch, 0, len(names)+len(excluded))
	for ordinal, name := range names {
		if ordinal < 0 || ordinal >= len(document.Nodes) || !validReplacementName(name) {
			return nil, fmt.Errorf("invalid client text name allocation for ordinal %d", ordinal)
		}
		node := document.Nodes[ordinal]
		if node.NameStart < 0 || node.NameStart > node.NameEnd || node.NameEnd > len(document.Original) {
			return nil, fmt.Errorf("invalid client text name span for ordinal %d", ordinal)
		}
		if !excluded[ordinal] {
			patches = append(patches, textPatch{start: node.NameStart, end: node.NameEnd, value: []byte(name)})
		}
	}
	for ordinal := range excluded {
		if !excluded[ordinal] {
			continue
		}
		if ordinal < 0 || ordinal >= len(document.Nodes) {
			return nil, fmt.Errorf("invalid excluded client text node ordinal %d", ordinal)
		}
		node := document.Nodes[ordinal]
		start := bytes.LastIndexByte(document.Original[:node.NameStart], '\n') + 1
		end := len(document.Original)
		if relativeEnd := bytes.IndexByte(document.Original[node.NameEnd:], '\n'); relativeEnd >= 0 {
			end = node.NameEnd + relativeEnd + 1
		}
		patches = append(patches, textPatch{start: start, end: end})
	}
	for index := 1; index < len(patches); index++ {
		for cursor := index; cursor > 0 && patches[cursor].start < patches[cursor-1].start; cursor-- {
			patches[cursor], patches[cursor-1] = patches[cursor-1], patches[cursor]
		}
	}
	var output bytes.Buffer
	position := 0
	for _, patch := range patches {
		if patch.start < position {
			return nil, fmt.Errorf("overlapping client text name patches")
		}
		output.Write(document.Original[position:patch.start])
		output.Write(patch.value)
		position = patch.end
	}
	output.Write(document.Original[position:])
	return output.Bytes(), nil
}

type textPatch struct {
	start int
	end   int
	value []byte
}

func parseNamedAssignment(line []byte, absoluteStart, lineNumber, ordinal int, registry *protocol.Registry) (RawNode, bool) {
	equals := bytes.IndexByte(line, '=')
	if equals <= 0 || equals == len(line)-1 {
		return RawNode{}, false
	}
	left := line[:equals]
	nameStart, nameEnd := trimSpan(left, 0, len(left))
	if nameStart == nameEnd {
		return RawNode{}, false
	}
	rightStart, rightEnd := trimSpan(line, equals+1, len(line))
	if rightStart == rightEnd {
		return RawNode{}, false
	}
	comma := bytes.IndexByte(line[rightStart:rightEnd], ',')
	if comma < 0 {
		return RawNode{}, false
	}
	rawType := strings.ToLower(strings.TrimSpace(string(line[rightStart : rightStart+comma])))
	if rawType == "" {
		return RawNode{}, false
	}
	definition := registry.Lookup(FormatID, rawType)
	warnings := unknownWarnings(definition)
	return RawNode{
		Ordinal: ordinal, Line: lineNumber + 1,
		ExtractionPath: fmt.Sprintf("/sections/proxy/lines/%d", lineNumber),
		RawType:        rawType, ProtocolID: definition.ID, DisplayName: string(line[nameStart:nameEnd]),
		Style: StyleNamedAssignment, Raw: append([]byte(nil), line...),
		IdentityBytes: append([]byte(nil), line[rightStart:rightEnd]...),
		NameStart:     absoluteStart + nameStart, NameEnd: absoluteStart + nameEnd,
		Warnings: warnings,
	}, true
}

func parseQuantumultX(line []byte, absoluteStart, lineNumber, ordinal int, registry *protocol.Registry) (RawNode, bool) {
	spans, ok := commaSeparatedSpans(line)
	if !ok || len(spans) < 2 {
		return RawNode{}, false
	}
	firstStart, firstEnd := trimSpan(line, spans[0][0], spans[0][1])
	equals := bytes.IndexByte(line[firstStart:firstEnd], '=')
	if equals <= 0 {
		return RawNode{}, false
	}
	rawType := strings.ToLower(strings.TrimSpace(string(line[firstStart : firstStart+equals])))
	if rawType == "" {
		return RawNode{}, false
	}
	nameStart, nameEnd := -1, -1
	for _, span := range spans[1:] {
		start, end := trimSpan(line, span[0], span[1])
		fieldEquals := bytes.IndexByte(line[start:end], '=')
		if fieldEquals <= 0 || !strings.EqualFold(strings.TrimSpace(string(line[start:start+fieldEquals])), "tag") {
			continue
		}
		nameStart, nameEnd = trimSpan(line, start+fieldEquals+1, end)
		if nameEnd-nameStart >= 2 && (line[nameStart] == '"' && line[nameEnd-1] == '"' || line[nameStart] == '\'' && line[nameEnd-1] == '\'') {
			nameStart++
			nameEnd--
		}
		break
	}
	if nameStart < 0 || nameStart == nameEnd {
		return RawNode{}, false
	}
	definition := registry.Lookup(FormatID, rawType)
	identity := make([]byte, 0, len(line)-(nameEnd-nameStart))
	identity = append(identity, line[:nameStart]...)
	identity = append(identity, line[nameEnd:]...)
	return RawNode{
		Ordinal: ordinal, Line: lineNumber + 1,
		ExtractionPath: fmt.Sprintf("/sections/server_local/lines/%d", lineNumber),
		RawType:        rawType, ProtocolID: definition.ID, DisplayName: string(line[nameStart:nameEnd]),
		Style: StyleQuantumultXTag, Raw: append([]byte(nil), line...), IdentityBytes: identity,
		NameStart: absoluteStart + nameStart, NameEnd: absoluteStart + nameEnd,
		Warnings: unknownWarnings(definition),
	}, true
}

func commaSeparatedSpans(line []byte) ([][2]int, bool) {
	result := make([][2]int, 0, bytes.Count(line, []byte{','})+1)
	start := 0
	quote := byte(0)
	escaped := false
	for index, value := range line {
		if escaped {
			escaped = false
			continue
		}
		if value == '\\' && quote != 0 {
			escaped = true
			continue
		}
		if quote != 0 {
			if value == quote {
				quote = 0
			}
			continue
		}
		if value == '\'' || value == '"' {
			quote = value
			continue
		}
		if value == ',' {
			result = append(result, [2]int{start, index})
			start = index + 1
		}
	}
	if quote != 0 || escaped {
		return nil, false
	}
	return append(result, [2]int{start, len(line)}), true
}

func trimSpan(value []byte, start, end int) (int, int) {
	for start < end && (value[start] == ' ' || value[start] == '\t') {
		start++
	}
	for end > start && (value[end-1] == ' ' || value[end-1] == '\t') {
		end--
	}
	return start, end
}

func unknownWarnings(definition protocol.Definition) []string {
	if definition.Kind == protocol.KindUnknown {
		return []string{"unknown_protocol"}
	}
	return nil
}

func validReplacementName(value string) bool {
	return value != "" && utf8.ValidString(value) && !strings.ContainsAny(value, "\r\n")
}

func normalizeLimits(limits Limits) (Limits, error) {
	defaults := DefaultLimits()
	if limits.MaxInputBytes == 0 {
		limits.MaxInputBytes = defaults.MaxInputBytes
	}
	if limits.MaxLineBytes == 0 {
		limits.MaxLineBytes = defaults.MaxLineBytes
	}
	if limits.MaxNodes == 0 {
		limits.MaxNodes = defaults.MaxNodes
	}
	if limits.MaxInputBytes < 1 || limits.MaxInputBytes > hardMaxInputBytes ||
		limits.MaxLineBytes < 1 || limits.MaxLineBytes > hardMaxLineBytes ||
		limits.MaxNodes < 1 || limits.MaxNodes > hardMaxNodes {
		return Limits{}, fmt.Errorf("invalid client text limits")
	}
	return limits, nil
}
