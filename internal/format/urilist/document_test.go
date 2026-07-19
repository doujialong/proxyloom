package urilist

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/doujialong/proxyloom/internal/protocol"
)

func TestParsePlainURIListPreservesRawAndClassifiesSchemes(t *testing.T) {
	vmessJSON := `{"v":"2","ps":"VMess Node","add":"example.test","port":"443","id":"fixture"}`
	vmess := "vmess://" + base64.RawStdEncoding.EncodeToString([]byte(vmessJSON))
	input := []byte(strings.Join([]string{
		"# provider comment",
		"ss://YWVzLTI1Ni1nY206c2VjcmV0@example.test:443#Hong%20Kong",
		"vless://fixture@example.test:443?security=tls#VLESS%20Node",
		"trojan://secret@example.test:443#Rate%20100%25",
		vmess,
		"future://opaque-payload#connection-fragment",
	}, "\r\n"))
	document, err := Parse(input, protocol.NewRegistry(), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if document.Encoding != EncodingPlain || !bytes.Equal(document.Original, input) || len(document.Nodes) != 5 {
		t.Fatalf("document = %+v", document)
	}
	wantProtocols := []string{"shadowsocks", "vless", "trojan", "vmess", protocol.UnknownID}
	for index, want := range wantProtocols {
		if document.Nodes[index].ProtocolID != want || document.Nodes[index].Ordinal != index {
			t.Fatalf("node %d = %+v", index, document.Nodes[index])
		}
	}
	if document.Nodes[0].DisplayName != "Hong Kong" || document.Nodes[1].DisplayName != "VLESS Node" ||
		document.Nodes[2].DisplayName != "Rate 100%" || document.Nodes[3].DisplayName != "VMess Node" {
		t.Fatalf("display names = %q, %q, %q, %q", document.Nodes[0].DisplayName, document.Nodes[1].DisplayName, document.Nodes[2].DisplayName, document.Nodes[3].DisplayName)
	}
	if bytes.Contains(document.Nodes[1].IdentityBytes, []byte("#VLESS")) {
		t.Fatal("registered display fragment remained in VLESS identity bytes")
	}
	if !bytes.Contains(document.Nodes[4].IdentityBytes, []byte("#connection-fragment")) || document.Nodes[4].DisplayName != "" {
		t.Fatalf("unknown URI identity/display = %+v", document.Nodes[4])
	}
	if string(document.Nodes[1].Raw) != "vless://fixture@example.test:443?security=tls#VLESS%20Node" {
		t.Fatalf("raw VLESS URI = %q", document.Nodes[1].Raw)
	}
}

func TestRenderPreservesEachRawURIIncludingUnknownSchemes(t *testing.T) {
	input := []byte("vless://fixture@example.test:443#Node\nfuture://opaque/%2f#identity-data\n")
	document, err := Parse(input, nil, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := Render(document.Nodes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rendered, input) {
		t.Fatalf("Render() = %q, want %q", rendered, input)
	}
	document.Nodes[0].Raw = []byte("not a URI")
	if _, err := Render(document.Nodes); err == nil {
		t.Fatal("Render() accepted mutated invalid raw bytes")
	}
}

func TestParseStandardAndURLSafeBase64Subscriptions(t *testing.T) {
	plain := []byte("trojan://secret@example.test:443#\u083e\nanytls://secret@example.test:443#Two\n")
	tests := []struct {
		name     string
		encoded  string
		encoding Encoding
	}{
		{name: "standard padded", encoded: base64.StdEncoding.EncodeToString(plain), encoding: EncodingBase64Standard},
		{name: "standard raw", encoded: base64.RawStdEncoding.EncodeToString(plain), encoding: EncodingBase64Standard},
		{name: "URL raw", encoded: base64.RawURLEncoding.EncodeToString(plain), encoding: EncodingBase64URL},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wrapped := " \n" + test.encoded[:len(test.encoded)/2] + "\n" + test.encoded[len(test.encoded)/2:] + "\t"
			document, err := Parse([]byte(wrapped), protocol.NewRegistry(), DefaultLimits())
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if document.Encoding != test.encoding || !bytes.Equal(document.Decoded, plain) || len(document.Nodes) != 2 {
				t.Fatalf("document = %+v", document)
			}
		})
	}
}

func TestParseURIListEnforcesLimitsAndRejectsMalformedLines(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		limits Limits
		is     error
	}{
		{name: "input", input: []byte("vless://fixture"), limits: Limits{MaxInputBytes: 4, MaxDecodedBytes: 64, MaxLineBytes: 64, MaxNodes: 2}, is: ErrLimit},
		{name: "line", input: []byte("vless://fixture"), limits: Limits{MaxInputBytes: 64, MaxDecodedBytes: 64, MaxLineBytes: 4, MaxNodes: 2}, is: ErrLimit},
		{name: "nodes", input: []byte("vless://one\ntrojan://two"), limits: Limits{MaxInputBytes: 64, MaxDecodedBytes: 64, MaxLineBytes: 32, MaxNodes: 1}, is: ErrLimit},
		{name: "malformed URI", input: []byte("vless://host/%zz"), limits: DefaultLimits()},
		{name: "not subscription", input: []byte("not a URI or Base64 subscription"), limits: DefaultLimits(), is: ErrUnrecognized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse(test.input, protocol.NewRegistry(), test.limits)
			if err == nil || test.is != nil && !errors.Is(err, test.is) {
				t.Fatalf("Parse() error = %v", err)
			}
		})
	}
}

func TestVMessIdentityExcludesDisplayNameButRetainsConnectionFields(t *testing.T) {
	makeURI := func(name, host string) string {
		payload := `{"v":"2","ps":"` + name + `","add":"` + host + `","port":"443","id":"fixture"}`
		return "vmess://" + base64.RawStdEncoding.EncodeToString([]byte(payload))
	}
	first, err := Parse([]byte(makeURI("One", "example.test")), nil, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := Parse([]byte(makeURI("Two", "example.test")), nil, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	changed, err := Parse([]byte(makeURI("One", "other.test")), nil, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Nodes[0].IdentityBytes, renamed.Nodes[0].IdentityBytes) {
		t.Fatal("VMess display name changed opaque identity projection")
	}
	if bytes.Equal(first.Nodes[0].IdentityBytes, changed.Nodes[0].IdentityBytes) {
		t.Fatal("VMess connection field did not change opaque identity projection")
	}
}
