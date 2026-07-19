package urilist

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/doujialong/proxyloom/internal/jsonlossless"
	"github.com/doujialong/proxyloom/internal/protocol"
)

const (
	FormatID       = protocol.FormatURIList
	AdapterVersion = "uri-list-v1"
	LimitsVersion  = 1

	hardMaxInputBytes   = 50 << 20
	hardMaxDecodedBytes = 50 << 20
	hardMaxLineBytes    = 4 << 20
	hardMaxNodes        = 100000
)

var (
	ErrUnrecognized = errors.New("input is not a URI subscription")
	ErrLimit        = errors.New("URI subscription limit exceeded")
)

type Encoding string

const (
	EncodingPlain          Encoding = "plain"
	EncodingBase64Standard Encoding = "base64-standard"
	EncodingBase64URL      Encoding = "base64-url"
)

type Limits struct {
	MaxInputBytes   int
	MaxDecodedBytes int
	MaxLineBytes    int
	MaxNodes        int
}

func DefaultLimits() Limits {
	return Limits{
		MaxInputBytes: 10 << 20, MaxDecodedBytes: 10 << 20,
		MaxLineBytes: 1 << 20, MaxNodes: 20000,
	}
}

type RawNode struct {
	Ordinal               int
	Line                  int
	ExtractionPath        string
	Raw                   []byte
	RawType               string
	ProtocolID            string
	DisplayName           string
	FragmentIsDisplayName bool
	IdentityBytes         []byte
	IdentityVersion       string
	Warnings              []string
}

type Document struct {
	Encoding Encoding
	Original []byte
	Decoded  []byte
	Nodes    []RawNode
}

func Render(nodes []RawNode) ([]byte, error) {
	if len(nodes) == 0 {
		return nil, fmt.Errorf("URI list requires at least one node")
	}
	limits := DefaultLimits()
	if len(nodes) > limits.MaxNodes {
		return nil, fmt.Errorf("%w: render node count exceeds %d", ErrLimit, limits.MaxNodes)
	}
	registry := protocol.NewRegistry()
	var output bytes.Buffer
	for index, node := range nodes {
		if len(node.Raw) == 0 || len(node.Raw) > limits.MaxLineBytes || bytes.IndexAny(node.Raw, "\r\n") >= 0 {
			return nil, fmt.Errorf("URI node %d has invalid raw bytes", index)
		}
		if output.Len()+len(node.Raw)+1 > limits.MaxDecodedBytes {
			return nil, fmt.Errorf("%w: rendered URI list exceeds %d bytes", ErrLimit, limits.MaxDecodedBytes)
		}
		if _, err := parseLine(node.Raw, index, index, registry, limits); err != nil {
			return nil, fmt.Errorf("render URI node %d: %w", index, err)
		}
		output.Write(node.Raw)
		output.WriteByte('\n')
	}
	return output.Bytes(), nil
}

func Parse(input []byte, registry *protocol.Registry, limits Limits) (*Document, error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}
	if len(input) == 0 {
		return nil, ErrUnrecognized
	}
	if len(input) > limits.MaxInputBytes {
		return nil, fmt.Errorf("%w: input exceeds %d bytes", ErrLimit, limits.MaxInputBytes)
	}
	if registry == nil {
		registry = protocol.NewRegistry()
	}
	if nodes, parseErr := parseLines(input, registry, limits); parseErr == nil {
		return &Document{
			Encoding: EncodingPlain, Original: append([]byte(nil), input...),
			Decoded: append([]byte(nil), input...), Nodes: nodes,
		}, nil
	} else if bytes.Contains(input, []byte("://")) {
		return nil, parseErr
	}

	decoded, encoding, err := decodeSubscription(input, limits.MaxDecodedBytes)
	if err != nil {
		if errors.Is(err, ErrLimit) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrUnrecognized, err)
	}
	nodes, err := parseLines(decoded, registry, limits)
	if err != nil {
		if errors.Is(err, ErrLimit) {
			return nil, fmt.Errorf("decoded URI subscription: %w", err)
		}
		return nil, fmt.Errorf("%w: decoded content: %v", ErrUnrecognized, err)
	}
	return &Document{
		Encoding: encoding, Original: append([]byte(nil), input...),
		Decoded: decoded, Nodes: nodes,
	}, nil
}

func parseLines(content []byte, registry *protocol.Registry, limits Limits) ([]RawNode, error) {
	if len(content) > limits.MaxDecodedBytes {
		return nil, fmt.Errorf("%w: decoded content exceeds %d bytes", ErrLimit, limits.MaxDecodedBytes)
	}
	if !utf8.Valid(content) {
		return nil, fmt.Errorf("URI subscription must be valid UTF-8")
	}
	nodes := make([]RawNode, 0, minInt(bytes.Count(content, []byte{'\n'})+1, limits.MaxNodes))
	lineIndex := 0
	for start := 0; start <= len(content); lineIndex++ {
		end := bytes.IndexByte(content[start:], '\n')
		lastLine := end < 0
		if lastLine {
			end = len(content)
		} else {
			end += start
		}
		line := content[start:end]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) > limits.MaxLineBytes {
			return nil, fmt.Errorf("%w: line %d exceeds %d bytes", ErrLimit, lineIndex+1, limits.MaxLineBytes)
		}
		if lineIndex == 0 {
			line = bytes.TrimPrefix(line, []byte{0xef, 0xbb, 0xbf})
		}
		line = bytes.Trim(line, " \t")
		if len(line) != 0 && line[0] != '#' {
			if len(nodes) >= limits.MaxNodes {
				return nil, fmt.Errorf("%w: node count exceeds %d", ErrLimit, limits.MaxNodes)
			}
			node, err := parseLine(line, lineIndex, len(nodes), registry, limits)
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, node)
		}
		if lastLine {
			break
		}
		start = end + 1
	}
	if len(nodes) == 0 {
		return nil, ErrUnrecognized
	}
	return nodes, nil
}

func parseLine(line []byte, lineIndex, ordinal int, registry *protocol.Registry, limits Limits) (RawNode, error) {
	for _, value := range line {
		if value < 0x20 || value == 0x7f {
			return RawNode{}, fmt.Errorf("line %d contains a control byte", lineIndex+1)
		}
	}
	raw := string(line)
	separator := strings.Index(raw, "://")
	if separator <= 0 || !validScheme(raw[:separator]) {
		return RawNode{}, fmt.Errorf("line %d does not contain a valid absolute URI scheme", lineIndex+1)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" {
		return RawNode{}, fmt.Errorf("line %d contains an invalid URI", lineIndex+1)
	}
	rawType := strings.ToLower(parsed.Scheme)
	definition := registry.Lookup(FormatID, rawType)
	registered := definition.ID != protocol.UnknownID
	fragmentIsName := registered && fragmentDisplaySchemes[rawType]
	displayName := ""
	warnings := []string(nil)
	identity := append([]byte(nil), line...)
	identityVersion := "opaque-uri-v1"
	vmessProjected := false

	if rawType == "vmess" {
		name, projected, vmessErr := parseVMessPayload(raw[separator+3:], limits)
		if vmessErr == nil {
			displayName = name
			identity = projected
			identityVersion = "opaque-vmess-json-v1"
			vmessProjected = true
		} else {
			warnings = append(warnings, "vmess_payload_opaque")
		}
	}
	if fragmentIsName {
		if displayName == "" && parsed.Fragment != "" {
			if utf8.ValidString(parsed.Fragment) {
				displayName = parsed.Fragment
			} else {
				warnings = append(warnings, "invalid_display_fragment")
			}
		}
		if !vmessProjected {
			marker := bytes.IndexByte(identity, '#')
			if marker >= 0 {
				identity = append([]byte(nil), identity[:marker]...)
			}
		}
	}
	return RawNode{
		Ordinal: ordinal, Line: lineIndex + 1,
		ExtractionPath: fmt.Sprintf("/lines/%d", lineIndex),
		Raw:            append([]byte(nil), line...), RawType: rawType,
		ProtocolID: definition.ID, DisplayName: displayName,
		FragmentIsDisplayName: fragmentIsName,
		IdentityBytes:         identity, IdentityVersion: identityVersion,
		Warnings: warnings,
	}, nil
}

func parseVMessPayload(payload string, limits Limits) (string, []byte, error) {
	if marker := strings.IndexByte(payload, '#'); marker >= 0 {
		payload = payload[:marker]
	}
	decoded, _, err := decodeBase64String(payload, limits.MaxLineBytes)
	if err != nil {
		return "", nil, err
	}
	jsonLimits := jsonlossless.DefaultLimits()
	jsonLimits.MaxBytes = limits.MaxLineBytes
	jsonLimits.MaxStringBytes = limits.MaxLineBytes
	root, err := jsonlossless.Parse(decoded, jsonLimits)
	if err != nil || root.Kind != jsonlossless.KindObject {
		return "", nil, fmt.Errorf("VMess payload is not a JSON object")
	}
	name := ""
	if value, exists := root.Member("ps"); exists {
		name, _ = value.StringValue()
	}
	projection := root.Clone()
	projection.RemoveMember("ps")
	canonical, err := jsonlossless.MarshalOpaqueV1(projection, "")
	if err != nil {
		return "", nil, err
	}
	identity := append([]byte("proxyloom-vmess-json-v1\x00"), canonical...)
	return name, identity, nil
}

func decodeSubscription(input []byte, maxDecoded int) ([]byte, Encoding, error) {
	normalized := make([]byte, 0, len(input))
	for _, value := range input {
		if value == ' ' || value == '\t' || value == '\r' || value == '\n' {
			continue
		}
		normalized = append(normalized, value)
	}
	return decodeBase64String(string(normalized), maxDecoded)
}

func decodeBase64String(value string, maxDecoded int) ([]byte, Encoding, error) {
	if value == "" || len(value)%4 == 1 {
		return nil, "", fmt.Errorf("invalid Base64 length")
	}
	if base64.RawStdEncoding.DecodedLen(len(value)) > maxDecoded+2 {
		return nil, "", fmt.Errorf("%w: decoded Base64 exceeds %d bytes", ErrLimit, maxDecoded)
	}
	decoders := []struct {
		encoding *base64.Encoding
		kind     Encoding
	}{
		{base64.StdEncoding.Strict(), EncodingBase64Standard},
		{base64.RawStdEncoding.Strict(), EncodingBase64Standard},
		{base64.URLEncoding.Strict(), EncodingBase64URL},
		{base64.RawURLEncoding.Strict(), EncodingBase64URL},
	}
	var lastErr error
	for _, decoder := range decoders {
		decoded, err := decoder.encoding.DecodeString(value)
		if err != nil {
			lastErr = err
			continue
		}
		if len(decoded) > maxDecoded {
			return nil, "", fmt.Errorf("%w: decoded Base64 exceeds %d bytes", ErrLimit, maxDecoded)
		}
		return decoded, decoder.kind, nil
	}
	return nil, "", lastErr
}

func normalizeLimits(limits Limits) (Limits, error) {
	defaults := DefaultLimits()
	if limits.MaxInputBytes <= 0 {
		limits.MaxInputBytes = defaults.MaxInputBytes
	}
	if limits.MaxDecodedBytes <= 0 {
		limits.MaxDecodedBytes = defaults.MaxDecodedBytes
	}
	if limits.MaxLineBytes <= 0 {
		limits.MaxLineBytes = defaults.MaxLineBytes
	}
	if limits.MaxNodes <= 0 {
		limits.MaxNodes = defaults.MaxNodes
	}
	if limits.MaxInputBytes > hardMaxInputBytes || limits.MaxDecodedBytes > hardMaxDecodedBytes ||
		limits.MaxLineBytes > hardMaxLineBytes || limits.MaxNodes > hardMaxNodes {
		return Limits{}, fmt.Errorf("%w: configured URI limits exceed hard limits", ErrLimit)
	}
	if limits.MaxLineBytes > limits.MaxDecodedBytes {
		return Limits{}, fmt.Errorf("URI line limit exceeds decoded input limit")
	}
	return limits, nil
}

func validScheme(value string) bool {
	if value == "" || value[0] < 'A' || value[0] > 'Z' && value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || character == '+' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

var fragmentDisplaySchemes = map[string]bool{
	"socks": true, "socks4": true, "socks4a": true, "socks5": true,
	"http": true, "https": true, "ss": true, "vmess": true, "vless": true,
	"trojan": true, "hysteria": true, "hy1": true, "hysteria2": true,
	"hy2": true, "tuic": true, "anytls": true, "ssh": true, "ssr": true,
	"juicity": true,
}
