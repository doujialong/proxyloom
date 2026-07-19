package singbox

import (
	"fmt"
	"strings"
	"testing"

	"github.com/doujialong/proxyloom/internal/jsonlossless"
	"github.com/doujialong/proxyloom/internal/protocol"
)

func TestParseFullConfigClassifiesOutbounds(t *testing.T) {
	input := []byte(`{
  "dns": {"servers": [{"tag": "dns", "address": "local"}]},
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "vless", "tag": "node", "server": "198.51.100.1", "server_port": 443, "tls": {"enabled": true}},
    {"type": "future-protocol", "tag": "future", "nested": {"x": 1.2300}}
  ]
}`)
	document, err := Parse(input, protocol.NewRegistry(), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if document.Shape != ShapeFullConfig || len(document.Nodes) != 2 || len(document.NonNodes) != 1 {
		t.Fatalf("classification = shape %s, nodes %d, non-nodes %d", document.Shape, len(document.Nodes), len(document.NonNodes))
	}
	if document.Nodes[0].ProtocolID != "vless" || document.Nodes[0].Canonical.Completeness != protocol.CompletenessPartial {
		t.Fatalf("known node = %+v", document.Nodes[0])
	}
	if document.Nodes[1].ProtocolID != protocol.UnknownID || document.Nodes[1].ParseStatus != ParseOpaque {
		t.Fatalf("unknown node = %+v", document.Nodes[1])
	}
	if string(document.Raw) != string(input) {
		t.Fatal("raw document bytes changed")
	}
}

func TestParseRecognizesSingBoxBaselineTypes(t *testing.T) {
	proxyTypes := []string{
		"socks", "http", "shadowsocks", "vmess", "vless", "trojan", "wireguard",
		"hysteria", "shadowtls", "tuic", "hysteria2", "anytls", "tor", "ssh",
	}
	for _, proxyType := range proxyTypes {
		t.Run(proxyType, func(t *testing.T) {
			input := fmt.Sprintf(`[{"type":%q,"tag":"fixture","server":"198.51.100.1","server_port":443}]`, proxyType)
			document, err := Parse([]byte(input), protocol.NewRegistry(), DefaultLimits())
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if len(document.Nodes) != 1 || document.Nodes[0].ProtocolID != proxyType || document.Nodes[0].DefinitionKind != protocol.KindProxy {
				t.Fatalf("node = %+v", document.Nodes)
			}
		})
	}

	document, err := Parse([]byte(`[{"type":"shadowsocksr","tag":"legacy","server":"198.51.100.1","server_port":443}]`), protocol.NewRegistry(), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse(SSR) error = %v", err)
	}
	if len(document.Nodes) != 1 || document.Nodes[0].DefinitionKind != protocol.KindRawOnly {
		t.Fatalf("SSR classification = %+v", document.Nodes)
	}

	for _, nonProxyType := range []string{"direct", "block", "dns", "selector", "urltest"} {
		t.Run("non-proxy-"+nonProxyType, func(t *testing.T) {
			input := fmt.Sprintf(`[{"type":%q,"tag":"fixture"}]`, nonProxyType)
			document, err := Parse([]byte(input), protocol.NewRegistry(), DefaultLimits())
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if len(document.Nodes) != 0 || len(document.NonNodes) != 1 {
				t.Fatalf("classification = nodes %+v, non-nodes %+v", document.Nodes, document.NonNodes)
			}
		})
	}
}

func TestParseEnforcesOutboundLimit(t *testing.T) {
	_, err := Parse([]byte(`[{"type":"vless","tag":"a"},{"type":"vless","tag":"b"}]`), protocol.NewRegistry(), Limits{
		MaxOutbounds: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "singbox_node_limit_exceeded") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseSingleNodeObject(t *testing.T) {
	document, err := Parse([]byte(`{"type":"vless","tag":"Node","server":"198.51.100.1","server_port":443,"uuid":"fixture","future":{"value":1.2300}}`), protocol.NewRegistry(), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if document.Shape != ShapeSingleNode || len(document.Nodes) != 1 {
		t.Fatalf("document = shape %s, nodes %d", document.Shape, len(document.Nodes))
	}
	if document.Nodes[0].ExtractionPath != "" {
		t.Fatalf("extraction path = %q, want root pointer", document.Nodes[0].ExtractionPath)
	}
	encoded, err := jsonlossless.MarshalCompact(document.Nodes[0].Raw)
	if err != nil {
		t.Fatalf("MarshalCompact() error = %v", err)
	}
	if string(encoded) != string(document.Raw) {
		t.Fatalf("single node changed\nwant: %s\n got: %s", document.Raw, encoded)
	}
}

func TestParseRetainsDocumentAndReportsInvalidOutbound(t *testing.T) {
	document, err := Parse([]byte(`[{"tag":"missing type"},{"type":"vless","tag":"ok","server":"host","server_port":443}]`), protocol.NewRegistry(), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(document.Nodes) != 1 || len(document.Issues) != 1 || document.Issues[0].Code != "outbound_type_invalid" {
		t.Fatalf("document = %+v", document)
	}
}
