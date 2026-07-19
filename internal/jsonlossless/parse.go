package jsonlossless

import (
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

const (
	DefaultMaxBytes       = 10 << 20
	DefaultMaxDepth       = 64
	DefaultMaxValues      = 1_000_000
	DefaultMaxStringBytes = 1 << 20
	GlobalMaxBytes        = 50 << 20
	GlobalMaxDepth        = 128
	GlobalMaxValues       = 5_000_000
	GlobalMaxStringBytes  = 4 << 20
)

type Limits struct {
	MaxBytes       int
	MaxDepth       int
	MaxValues      int
	MaxStringBytes int
}

func DefaultLimits() Limits {
	return Limits{
		MaxBytes:       DefaultMaxBytes,
		MaxDepth:       DefaultMaxDepth,
		MaxValues:      DefaultMaxValues,
		MaxStringBytes: DefaultMaxStringBytes,
	}
}

type ParseError struct {
	Code   string
	Offset int
	Detail string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%s at byte %d: %s", e.Code, e.Offset, e.Detail)
}

type parser struct {
	data   []byte
	pos    int
	values int
	limits Limits
}

func Parse(data []byte, limits Limits) (*Node, error) {
	limits = normalizeLimits(limits)
	if len(data) > limits.MaxBytes {
		return nil, &ParseError{Code: "json_limit_exceeded", Offset: 0, Detail: "input exceeds byte limit"}
	}
	if !utf8.Valid(data) {
		return nil, &ParseError{Code: "invalid_json", Offset: 0, Detail: "input is not valid UTF-8"}
	}

	p := &parser{data: data, limits: limits}
	p.skipWhitespace()
	root, err := p.parseValue(1)
	if err != nil {
		return nil, err
	}
	p.skipWhitespace()
	if p.pos != len(p.data) {
		return nil, p.error("invalid_json", "unexpected trailing data")
	}
	return root, nil
}

func normalizeLimits(limits Limits) Limits {
	defaults := DefaultLimits()
	if limits.MaxBytes <= 0 {
		limits.MaxBytes = defaults.MaxBytes
	}
	if limits.MaxDepth <= 0 {
		limits.MaxDepth = defaults.MaxDepth
	}
	if limits.MaxValues <= 0 {
		limits.MaxValues = defaults.MaxValues
	}
	if limits.MaxStringBytes <= 0 {
		limits.MaxStringBytes = defaults.MaxStringBytes
	}
	if limits.MaxBytes > GlobalMaxBytes {
		limits.MaxBytes = GlobalMaxBytes
	}
	if limits.MaxDepth > GlobalMaxDepth {
		limits.MaxDepth = GlobalMaxDepth
	}
	if limits.MaxValues > GlobalMaxValues {
		limits.MaxValues = GlobalMaxValues
	}
	if limits.MaxStringBytes > GlobalMaxStringBytes {
		limits.MaxStringBytes = GlobalMaxStringBytes
	}
	return limits
}

func (p *parser) parseValue(depth int) (*Node, error) {
	if depth > p.limits.MaxDepth {
		return nil, p.error("json_limit_exceeded", "maximum depth exceeded")
	}
	p.values++
	if p.values > p.limits.MaxValues {
		return nil, p.error("json_limit_exceeded", "maximum value count exceeded")
	}
	if p.pos >= len(p.data) {
		return nil, p.error("invalid_json", "expected value")
	}

	switch p.data[p.pos] {
	case '{':
		return p.parseObject(depth)
	case '[':
		return p.parseArray(depth)
	case '"':
		raw, decoded, err := p.parseString()
		if err != nil {
			return nil, err
		}
		return &Node{Kind: KindString, Raw: raw, String: decoded}, nil
	case 't':
		return p.parseLiteral("true", KindBool)
	case 'f':
		return p.parseLiteral("false", KindBool)
	case 'n':
		return p.parseLiteral("null", KindNull)
	default:
		return p.parseNumber()
	}
}

func (p *parser) parseObject(depth int) (*Node, error) {
	p.pos++
	p.skipWhitespace()
	object := NewObject()
	if p.consume('}') {
		return object, nil
	}

	seen := make(map[string]struct{})
	for {
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, p.error("invalid_json", "expected object key")
		}
		keyOffset := p.pos
		keyRaw, key, err := p.parseString()
		if err != nil {
			return nil, err
		}
		if _, exists := seen[key]; exists {
			return nil, &ParseError{Code: "duplicate_json_key", Offset: keyOffset, Detail: fmt.Sprintf("duplicate key %q", key)}
		}
		seen[key] = struct{}{}

		p.skipWhitespace()
		if !p.consume(':') {
			return nil, p.error("invalid_json", "expected colon after object key")
		}
		p.skipWhitespace()
		value, err := p.parseValue(depth + 1)
		if err != nil {
			return nil, err
		}
		object.Members = append(object.Members, Member{Key: key, KeyRaw: keyRaw, Value: value})

		p.skipWhitespace()
		if p.consume('}') {
			return object, nil
		}
		if !p.consume(',') {
			return nil, p.error("invalid_json", "expected comma or closing brace")
		}
		p.skipWhitespace()
	}
}

func (p *parser) parseArray(depth int) (*Node, error) {
	p.pos++
	p.skipWhitespace()
	array := NewArray()
	if p.consume(']') {
		return array, nil
	}

	for {
		value, err := p.parseValue(depth + 1)
		if err != nil {
			return nil, err
		}
		array.Elements = append(array.Elements, value)
		p.skipWhitespace()
		if p.consume(']') {
			return array, nil
		}
		if !p.consume(',') {
			return nil, p.error("invalid_json", "expected comma or closing bracket")
		}
		p.skipWhitespace()
	}
}

func (p *parser) parseString() (string, string, error) {
	start := p.pos
	p.pos++
	for p.pos < len(p.data) {
		current := p.data[p.pos]
		switch current {
		case '"':
			p.pos++
			raw := p.data[start:p.pos]
			if len(raw)-2 > p.limits.MaxStringBytes {
				return "", "", p.errorAt("json_limit_exceeded", start, "string exceeds byte limit")
			}
			if !validUnicodeEscapes(raw) {
				return "", "", p.errorAt("invalid_json", start, "invalid unicode surrogate pair")
			}
			var decoded string
			if err := json.Unmarshal(raw, &decoded); err != nil {
				return "", "", p.errorAt("invalid_json", start, "invalid string")
			}
			if len(decoded) > p.limits.MaxStringBytes {
				return "", "", p.errorAt("json_limit_exceeded", start, "decoded string exceeds byte limit")
			}
			return string(raw), decoded, nil
		case '\\':
			p.pos++
			if p.pos >= len(p.data) {
				return "", "", p.error("invalid_json", "incomplete escape")
			}
			escape := p.data[p.pos]
			if escape == 'u' {
				if p.pos+4 >= len(p.data) {
					return "", "", p.error("invalid_json", "incomplete unicode escape")
				}
				for i := 1; i <= 4; i++ {
					if !isHex(p.data[p.pos+i]) {
						return "", "", p.error("invalid_json", "invalid unicode escape")
					}
				}
				p.pos += 5
				continue
			}
			if !isSimpleEscape(escape) {
				return "", "", p.error("invalid_json", "invalid escape")
			}
			p.pos++
		case 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f:
			return "", "", p.error("invalid_json", "unescaped control character")
		default:
			p.pos++
		}
	}
	return "", "", p.errorAt("invalid_json", start, "unterminated string")
}

func (p *parser) parseLiteral(literal string, kind Kind) (*Node, error) {
	if p.pos+len(literal) > len(p.data) || string(p.data[p.pos:p.pos+len(literal)]) != literal {
		return nil, p.error("invalid_json", "invalid literal")
	}
	p.pos += len(literal)
	return &Node{Kind: kind, Raw: literal}, nil
}

func (p *parser) parseNumber() (*Node, error) {
	start := p.pos
	if p.consume('-') && p.pos >= len(p.data) {
		return nil, p.errorAt("invalid_json", start, "incomplete number")
	}

	if p.consume('0') {
		if p.pos < len(p.data) && isDigit(p.data[p.pos]) {
			return nil, p.errorAt("invalid_json", start, "leading zero in number")
		}
	} else {
		if p.pos >= len(p.data) || p.data[p.pos] < '1' || p.data[p.pos] > '9' {
			return nil, p.errorAt("invalid_json", start, "expected value")
		}
		for p.pos < len(p.data) && isDigit(p.data[p.pos]) {
			p.pos++
		}
	}

	if p.consume('.') {
		if p.pos >= len(p.data) || !isDigit(p.data[p.pos]) {
			return nil, p.errorAt("invalid_json", start, "fraction requires a digit")
		}
		for p.pos < len(p.data) && isDigit(p.data[p.pos]) {
			p.pos++
		}
	}

	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if p.pos >= len(p.data) || !isDigit(p.data[p.pos]) {
			return nil, p.errorAt("invalid_json", start, "exponent requires a digit")
		}
		for p.pos < len(p.data) && isDigit(p.data[p.pos]) {
			p.pos++
		}
	}

	return &Node{Kind: KindNumber, Raw: string(p.data[start:p.pos])}, nil
}

func (p *parser) skipWhitespace() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\r', '\n':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) consume(expected byte) bool {
	if p.pos < len(p.data) && p.data[p.pos] == expected {
		p.pos++
		return true
	}
	return false
}

func (p *parser) error(code, detail string) error {
	return p.errorAt(code, p.pos, detail)
}

func (p *parser) errorAt(code string, offset int, detail string) error {
	return &ParseError{Code: code, Offset: offset, Detail: detail}
}

func isDigit(value byte) bool {
	return value >= '0' && value <= '9'
}

func isHex(value byte) bool {
	return isDigit(value) || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func isSimpleEscape(value byte) bool {
	switch value {
	case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
		return true
	default:
		return false
	}
}

func validUnicodeEscapes(raw []byte) bool {
	for i := 1; i+1 < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		value := decodeHex4(raw[i+1 : i+5])
		i += 4
		switch {
		case value >= 0xd800 && value <= 0xdbff:
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low := decodeHex4(raw[i+3 : i+7])
			if low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		case value >= 0xdc00 && value <= 0xdfff:
			return false
		}
	}
	return true
}

func decodeHex4(value []byte) uint16 {
	var result uint16
	for _, digit := range value {
		result <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			result += uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			result += uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			result += uint16(digit-'A') + 10
		}
	}
	return result
}
