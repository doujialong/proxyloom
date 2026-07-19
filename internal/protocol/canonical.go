package protocol

import (
	"strconv"
	"strings"

	"github.com/doujialong/proxyloom/internal/jsonlossless"
)

type Completeness string

const (
	CompletenessComplete Completeness = "complete"
	CompletenessPartial  Completeness = "partial"
	CompletenessOpaque   Completeness = "opaque"
	AdapterVersion                    = "singbox-canonical-v2"
)

type OptionalBool struct {
	Set   bool
	Value bool
}

type Authentication struct {
	Username string
	Password string
	UUID     string
	Method   string
	Security string
	Flow     string
}

type ECHOptions struct {
	Present                     bool
	Enabled                     OptionalBool
	Config                      []string
	ConfigPath                  string
	PQSignatureSchemesEnabled   OptionalBool
	DynamicRecordSizingDisabled OptionalBool
}

type UTLSOptions struct {
	Present     bool
	Enabled     OptionalBool
	Fingerprint string
}

type RealityOptions struct {
	Present   bool
	Enabled   OptionalBool
	PublicKey string
	ShortID   string
}

type TLSOptions struct {
	Present         bool
	Enabled         OptionalBool
	DisableSNI      OptionalBool
	ServerName      string
	Insecure        OptionalBool
	ALPN            []string
	MinVersion      string
	MaxVersion      string
	CipherSuites    []string
	CertificatePath string
	ECH             ECHOptions
	UTLS            UTLSOptions
	Reality         RealityOptions
}

type TransportOptions struct {
	Present     bool
	Type        string
	Host        []string
	Path        string
	Method      string
	ServiceName string
}

type MultiplexOptions struct {
	Present        bool
	Enabled        OptionalBool
	Protocol       string
	MaxConnections string
	MinStreams     string
	MaxStreams     string
	Padding        OptionalBool
}

type ProtocolOptions struct {
	Version                  string
	Network                  []string
	Plugin                   string
	PluginOptions            string
	PacketEncoding           string
	AlterID                  string
	GlobalPadding            OptionalBool
	AuthenticatedLength      OptionalBool
	ServerPorts              []string
	HopInterval              string
	UpMbps                   string
	DownMbps                 string
	ObfsType                 string
	ObfsPassword             string
	CongestionControl        string
	UDPRelayMode             string
	UDPOverStream            OptionalBool
	ZeroRTTHandshake         OptionalBool
	Heartbeat                string
	IdleSessionCheckInterval string
	IdleSessionTimeout       string
	MinIdleSession           string
}

type FieldIssue struct {
	Path string
	Code string
}

type CanonicalNode struct {
	ProtocolID     string
	DisplayName    string
	Server         string
	ServerPort     uint16
	Authentication Authentication
	TLS            TLSOptions
	Transport      TransportOptions
	Multiplex      MultiplexOptions
	Options        ProtocolOptions
	Completeness   Completeness
	Issues         []FieldIssue
	AdapterVersion string
}

func Normalize(definition Definition, displayName string, raw *jsonlossless.Node) CanonicalNode {
	canonical := CanonicalNode{
		ProtocolID:     definition.ID,
		DisplayName:    displayName,
		Completeness:   CompletenessPartial,
		AdapterVersion: AdapterVersion,
	}
	if definition.Kind == KindUnknown {
		canonical.Completeness = CompletenessOpaque
		return canonical
	}
	if raw == nil || raw.Kind != jsonlossless.KindObject {
		canonical.Issues = append(canonical.Issues, FieldIssue{Path: "", Code: "expected_object"})
		return canonical
	}

	canonical.Server = readString(raw, &canonical.Issues, "server")
	canonical.ServerPort = readPort(raw, &canonical.Issues, "server_port")
	canonical.Authentication = Authentication{
		Username: readString(raw, &canonical.Issues, "username"),
		Password: readString(raw, &canonical.Issues, "password"),
		UUID:     readString(raw, &canonical.Issues, "uuid"),
		Method:   readString(raw, &canonical.Issues, "method"),
		Security: readString(raw, &canonical.Issues, "security"),
		Flow:     readString(raw, &canonical.Issues, "flow"),
	}
	canonical.Options = ProtocolOptions{
		Version:                  readString(raw, &canonical.Issues, "version"),
		Network:                  readStringList(raw, &canonical.Issues, "network"),
		Plugin:                   readString(raw, &canonical.Issues, "plugin"),
		PluginOptions:            readString(raw, &canonical.Issues, "plugin_opts"),
		PacketEncoding:           readString(raw, &canonical.Issues, "packet_encoding"),
		AlterID:                  readNumber(raw, &canonical.Issues, "alter_id"),
		GlobalPadding:            readBool(raw, &canonical.Issues, "global_padding"),
		AuthenticatedLength:      readBool(raw, &canonical.Issues, "authenticated_length"),
		ServerPorts:              readStringList(raw, &canonical.Issues, "server_ports"),
		HopInterval:              readScalarLexeme(raw, &canonical.Issues, "hop_interval"),
		UpMbps:                   readNumber(raw, &canonical.Issues, "up_mbps"),
		DownMbps:                 readNumber(raw, &canonical.Issues, "down_mbps"),
		CongestionControl:        readString(raw, &canonical.Issues, "congestion_control"),
		UDPRelayMode:             readString(raw, &canonical.Issues, "udp_relay_mode"),
		UDPOverStream:            readBool(raw, &canonical.Issues, "udp_over_stream"),
		ZeroRTTHandshake:         readBool(raw, &canonical.Issues, "zero_rtt_handshake"),
		Heartbeat:                readScalarLexeme(raw, &canonical.Issues, "heartbeat"),
		IdleSessionCheckInterval: readScalarLexeme(raw, &canonical.Issues, "idle_session_check_interval"),
		IdleSessionTimeout:       readScalarLexeme(raw, &canonical.Issues, "idle_session_timeout"),
		MinIdleSession:           readNumber(raw, &canonical.Issues, "min_idle_session"),
	}
	canonical.Options.ObfsType = readString(raw, &canonical.Issues, "obfs", "type")
	canonical.Options.ObfsPassword = readString(raw, &canonical.Issues, "obfs", "password")
	canonical.TLS = normalizeTLS(raw, &canonical.Issues)
	canonical.Transport = normalizeTransport(raw, &canonical.Issues)
	canonical.Multiplex = normalizeMultiplex(raw, &canonical.Issues)

	validateRequiredFields(definition, raw, canonical.ServerPort, &canonical.Issues)
	return canonical
}

func normalizeTLS(raw *jsonlossless.Node, issues *[]FieldIssue) TLSOptions {
	tlsNode, exists := raw.Member("tls")
	if !exists {
		return TLSOptions{}
	}
	if tlsNode.Kind != jsonlossless.KindObject {
		*issues = append(*issues, FieldIssue{Path: "/tls", Code: "expected_object"})
		return TLSOptions{Present: true}
	}
	issueStart := len(*issues)
	tls := TLSOptions{
		Present:         true,
		Enabled:         readBool(tlsNode, issues, "enabled"),
		DisableSNI:      readBool(tlsNode, issues, "disable_sni"),
		ServerName:      readString(tlsNode, issues, "server_name"),
		Insecure:        readBool(tlsNode, issues, "insecure"),
		ALPN:            readStringList(tlsNode, issues, "alpn"),
		MinVersion:      readString(tlsNode, issues, "min_version"),
		MaxVersion:      readString(tlsNode, issues, "max_version"),
		CipherSuites:    readStringList(tlsNode, issues, "cipher_suites"),
		CertificatePath: readString(tlsNode, issues, "certificate_path"),
	}
	if echNode, ok := objectMember(tlsNode, issues, "ech"); ok {
		nestedIssueStart := len(*issues)
		tls.ECH = ECHOptions{
			Present:                     true,
			Enabled:                     readBool(echNode, issues, "enabled"),
			Config:                      readStringList(echNode, issues, "config"),
			ConfigPath:                  readString(echNode, issues, "config_path"),
			PQSignatureSchemesEnabled:   readBool(echNode, issues, "pq_signature_schemes_enabled"),
			DynamicRecordSizingDisabled: readBool(echNode, issues, "dynamic_record_sizing_disabled"),
		}
		prefixIssues(*issues, nestedIssueStart, "/ech")
	}
	if utlsNode, ok := objectMember(tlsNode, issues, "utls"); ok {
		nestedIssueStart := len(*issues)
		tls.UTLS = UTLSOptions{
			Present:     true,
			Enabled:     readBool(utlsNode, issues, "enabled"),
			Fingerprint: readString(utlsNode, issues, "fingerprint"),
		}
		prefixIssues(*issues, nestedIssueStart, "/utls")
	}
	if realityNode, ok := objectMember(tlsNode, issues, "reality"); ok {
		nestedIssueStart := len(*issues)
		tls.Reality = RealityOptions{
			Present:   true,
			Enabled:   readBool(realityNode, issues, "enabled"),
			PublicKey: readString(realityNode, issues, "public_key"),
			ShortID:   readString(realityNode, issues, "short_id"),
		}
		prefixIssues(*issues, nestedIssueStart, "/reality")
	}
	prefixIssues(*issues, issueStart, "/tls")
	return tls
}

func normalizeTransport(raw *jsonlossless.Node, issues *[]FieldIssue) TransportOptions {
	transportNode, exists := raw.Member("transport")
	if !exists {
		return TransportOptions{}
	}
	if transportNode.Kind != jsonlossless.KindObject {
		*issues = append(*issues, FieldIssue{Path: "/transport", Code: "expected_object"})
		return TransportOptions{Present: true}
	}
	issueStart := len(*issues)
	transport := TransportOptions{
		Present:     true,
		Type:        readString(transportNode, issues, "type"),
		Host:        readStringList(transportNode, issues, "host"),
		Path:        readString(transportNode, issues, "path"),
		Method:      readString(transportNode, issues, "method"),
		ServiceName: readString(transportNode, issues, "service_name"),
	}
	prefixIssues(*issues, issueStart, "/transport")
	return transport
}

func normalizeMultiplex(raw *jsonlossless.Node, issues *[]FieldIssue) MultiplexOptions {
	multiplexNode, exists := raw.Member("multiplex")
	if !exists {
		return MultiplexOptions{}
	}
	if multiplexNode.Kind != jsonlossless.KindObject {
		*issues = append(*issues, FieldIssue{Path: "/multiplex", Code: "expected_object"})
		return MultiplexOptions{Present: true}
	}
	issueStart := len(*issues)
	multiplex := MultiplexOptions{
		Present:        true,
		Enabled:        readBool(multiplexNode, issues, "enabled"),
		Protocol:       readString(multiplexNode, issues, "protocol"),
		MaxConnections: readNumber(multiplexNode, issues, "max_connections"),
		MinStreams:     readNumber(multiplexNode, issues, "min_streams"),
		MaxStreams:     readNumber(multiplexNode, issues, "max_streams"),
		Padding:        readBool(multiplexNode, issues, "padding"),
	}
	prefixIssues(*issues, issueStart, "/multiplex")
	return multiplex
}

func validateRequiredFields(definition Definition, raw *jsonlossless.Node, serverPort uint16, issues *[]FieldIssue) {
	for _, name := range definition.RequiredString {
		node, exists := raw.Member(name)
		value, valid := node.StringValue()
		if !exists || valid && value == "" {
			*issues = append(*issues, FieldIssue{Path: "/" + name, Code: "required_field_missing"})
		}
	}
	if definition.RequiresServerPort {
		if _, exists := raw.Member("server_port"); !exists {
			*issues = append(*issues, FieldIssue{Path: "/server_port", Code: "required_field_missing"})
		} else if serverPort == 0 {
			// readPort already reports the invalid value with a more specific code.
		}
	}
}

func objectMember(node *jsonlossless.Node, issues *[]FieldIssue, name string) (*jsonlossless.Node, bool) {
	value, exists := node.Member(name)
	if !exists {
		return nil, false
	}
	if value.Kind != jsonlossless.KindObject {
		*issues = append(*issues, FieldIssue{Path: "/" + name, Code: "expected_object"})
		return nil, false
	}
	return value, true
}

func nodeAt(root *jsonlossless.Node, path ...string) (*jsonlossless.Node, bool) {
	current := root
	for _, name := range path {
		if current == nil || current.Kind != jsonlossless.KindObject {
			return nil, false
		}
		var exists bool
		current, exists = current.Member(name)
		if !exists {
			return nil, false
		}
	}
	return current, true
}

func readString(root *jsonlossless.Node, issues *[]FieldIssue, path ...string) string {
	node, exists := nodeAt(root, path...)
	if !exists {
		return ""
	}
	value, valid := node.StringValue()
	if !valid {
		*issues = append(*issues, FieldIssue{Path: jsonPath(path), Code: "expected_string"})
		return ""
	}
	return value
}

func readStringList(root *jsonlossless.Node, issues *[]FieldIssue, path ...string) []string {
	node, exists := nodeAt(root, path...)
	if !exists {
		return nil
	}
	if value, valid := node.StringValue(); valid {
		return []string{value}
	}
	if node.Kind != jsonlossless.KindArray {
		*issues = append(*issues, FieldIssue{Path: jsonPath(path), Code: "expected_string_or_string_array"})
		return nil
	}
	values := make([]string, 0, len(node.Elements))
	for index, item := range node.Elements {
		value, valid := item.StringValue()
		if !valid {
			*issues = append(*issues, FieldIssue{Path: jsonPath(path) + "/" + strconv.Itoa(index), Code: "expected_string"})
			continue
		}
		values = append(values, value)
	}
	return values
}

func readBool(root *jsonlossless.Node, issues *[]FieldIssue, path ...string) OptionalBool {
	node, exists := nodeAt(root, path...)
	if !exists {
		return OptionalBool{}
	}
	value, valid := node.BoolValue()
	if !valid {
		*issues = append(*issues, FieldIssue{Path: jsonPath(path), Code: "expected_bool"})
		return OptionalBool{}
	}
	return OptionalBool{Set: true, Value: value}
}

func readNumber(root *jsonlossless.Node, issues *[]FieldIssue, path ...string) string {
	node, exists := nodeAt(root, path...)
	if !exists {
		return ""
	}
	value, valid := node.NumberLexeme()
	if !valid {
		*issues = append(*issues, FieldIssue{Path: jsonPath(path), Code: "expected_number"})
		return ""
	}
	return value
}

func readScalarLexeme(root *jsonlossless.Node, issues *[]FieldIssue, path ...string) string {
	node, exists := nodeAt(root, path...)
	if !exists {
		return ""
	}
	if value, valid := node.StringValue(); valid {
		return value
	}
	if value, valid := node.NumberLexeme(); valid {
		return value
	}
	*issues = append(*issues, FieldIssue{Path: jsonPath(path), Code: "expected_string_or_number"})
	return ""
}

func readPort(root *jsonlossless.Node, issues *[]FieldIssue, path ...string) uint16 {
	value := readNumber(root, issues, path...)
	if value == "" {
		return 0
	}
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil || port == 0 {
		*issues = append(*issues, FieldIssue{Path: jsonPath(path), Code: "invalid_port"})
		return 0
	}
	return uint16(port)
}

func jsonPath(path []string) string {
	return "/" + strings.Join(path, "/")
}

func prefixIssues(issues []FieldIssue, start int, prefix string) {
	for index := start; index < len(issues); index++ {
		issues[index].Path = prefix + issues[index].Path
	}
}
