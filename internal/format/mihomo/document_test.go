package mihomo

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/doujialong/proxyloom/internal/protocol"
)

func TestParseAndRenderMihomoFullConfig(t *testing.T) {
	input := []byte("# preserved when no edits are needed\nport: 7890\nproxies:\n  - name: Same\n    type: ss\n    server: one.example\n    port: 443\n    cipher: aes-128-gcm\n    password: first\n  - name: Same\n    type: private-future\n    server: two.example\n    port: 8443\n    future: true\nproxy-groups:\n  - name: Select\n    type: select\n    proxies: [Same]\n")
	document, err := Parse(input, protocol.NewRegistry(), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if document.Shape != ShapeFullConfig || len(document.Nodes) != 2 {
		t.Fatalf("document shape=%s nodes=%d", document.Shape, len(document.Nodes))
	}
	if document.Nodes[0].ProtocolID != "shadowsocks" || document.Nodes[1].ProtocolID != protocol.UnknownID {
		t.Fatalf("protocols = %q, %q", document.Nodes[0].ProtocolID, document.Nodes[1].ProtocolID)
	}
	if len(document.Nodes[1].Warnings) != 1 || document.Nodes[1].Warnings[0] != "unknown_protocol" {
		t.Fatalf("unknown protocol warnings = %v", document.Nodes[1].Warnings)
	}

	rendered, err := Render(document, map[int]string{0: "Same", 1: "Same #2"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rendered, []byte("future: true")) || !bytes.Contains(rendered, []byte("proxy-groups:")) {
		t.Fatalf("rendered document lost data:\n%s", rendered)
	}
	reparsed, err := Parse(rendered, protocol.NewRegistry(), DefaultLimits())
	if err != nil {
		t.Fatalf("reparse rendered document: %v", err)
	}
	if reparsed.Nodes[1].DisplayName != "Same #2" {
		t.Fatalf("renamed node = %q", reparsed.Nodes[1].DisplayName)
	}
}

func TestMihomoYAMLSecurityLimits(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "duplicate key", input: "proxies:\n  - name: one\n    name: two\n    type: ss\n"},
		{name: "alias", input: "shared: &node\n  name: one\n  type: ss\nproxies:\n  - *node\n"},
		{name: "custom tag", input: "proxies:\n  - name: one\n    type: !private ss\n"},
		{name: "multiple documents", input: "proxies:\n  - {name: one, type: ss}\n---\nproxies:\n  - {name: two, type: ss}\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Parse([]byte(test.input), protocol.NewRegistry(), DefaultLimits()); err == nil {
				t.Fatal("Parse() accepted unsafe YAML")
			}
		})
	}

	limits := DefaultLimits()
	limits.MaxProxies = 1
	_, err := Parse([]byte("proxies:\n  - {name: one, type: ss}\n  - {name: two, type: ss}\n"), protocol.NewRegistry(), limits)
	if err == nil || !errors.Is(err, ErrLimit) {
		t.Fatalf("proxy limit error = %v", err)
	}

	limits = DefaultLimits()
	limits.MaxScalarBytes = 3
	_, err = Parse([]byte("proxies:\n  - {name: longer, type: ss}\n"), protocol.NewRegistry(), limits)
	if err == nil || !errors.Is(err, ErrLimit) || strings.Contains(err.Error(), "longer") {
		t.Fatalf("scalar limit error = %v", err)
	}
}

func TestRenderFilteredMihomoKeepsUnrelatedConfiguration(t *testing.T) {
	input := []byte("port: 7890\nproxies:\n  - {name: One, type: ss, server: one.example, port: 443}\n  - {name: Two, type: anytls, server: two.example, port: 8443, future: true}\nproxy-groups:\n  - {name: Select, type: select, proxies: [One]}\n")
	document, err := Parse(input, protocol.NewRegistry(), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := RenderFiltered(document, map[int]string{0: "One", 1: "Two"}, map[int]bool{1: true})
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := Parse(rendered, protocol.NewRegistry(), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(reparsed.Nodes) != 1 || reparsed.Nodes[0].DisplayName != "One" {
		t.Fatalf("filtered nodes = %+v", reparsed.Nodes)
	}
	if !bytes.Contains(rendered, []byte("proxy-groups:")) || !bytes.Contains(rendered, []byte("port: 7890")) {
		t.Fatalf("filtered document lost unrelated configuration:\n%s", rendered)
	}
}
