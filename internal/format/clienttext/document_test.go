package clienttext

import (
	"bytes"
	"errors"
	"testing"

	"github.com/doujialong/proxyloom/internal/protocol"
)

func TestParseAndRenderNamedAssignments(t *testing.T) {
	input := []byte("[General]\r\nloglevel = notify\r\n[Proxy]\r\nSame = vmess, one.example, 443, opaque-one\r\nSame = AnyTLS, two.example, 8443, opaque-two\r\n[Proxy Group]\r\nSelect = select, Same\r\n")
	document, err := Parse(input, protocol.NewRegistry(), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Nodes) != 2 || document.Nodes[0].ProtocolID != "vmess" || document.Nodes[1].ProtocolID != "anytls" {
		t.Fatalf("nodes = %+v", document.Nodes)
	}
	rendered, err := Render(document, map[int]string{0: "Same", 1: "Same #2"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rendered, []byte("Same #2 = AnyTLS")) || !bytes.Contains(rendered, []byte("Select = select, Same")) {
		t.Fatalf("rendered config lost or changed unrelated data:\n%s", rendered)
	}
	if bytes.Count(rendered, []byte("\r\n")) != bytes.Count(input, []byte("\r\n")) {
		t.Fatal("render changed CRLF framing")
	}
}

func TestParseAndRenderQuantumultXTags(t *testing.T) {
	input := []byte("[general]\nprofile_img_url=https://example.test/a.png\n[server_local]\nvmess=one.example:443, method=aes-128-gcm, password=secret, obfs=ws, tag=Same\nvless=two.example:443, method=none, password=secret, obfs-uri=\"/path,with,commas\", tag=\"Same\"\n[filter_local]\nfinal, direct\n")
	document, err := Parse(input, protocol.NewRegistry(), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Nodes) != 2 || document.Nodes[0].DisplayName != "Same" || document.Nodes[1].DisplayName != "Same" {
		t.Fatalf("nodes = %+v", document.Nodes)
	}
	rendered, err := Render(document, map[int]string{0: "Same", 1: "Same #2"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rendered, []byte(`obfs-uri="/path,with,commas", tag="Same #2"`)) || !bytes.Contains(rendered, []byte("final, direct")) {
		t.Fatalf("rendered Quantumult X config lost data:\n%s", rendered)
	}
}

func TestClientTextUnknownProtocolAndLimits(t *testing.T) {
	input := []byte("[Proxy]\nFuture = private-future, host.example, 443, opaque\n")
	document, err := Parse(input, protocol.NewRegistry(), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if document.Nodes[0].ProtocolID != protocol.UnknownID || len(document.Nodes[0].Warnings) != 1 {
		t.Fatalf("unknown node = %+v", document.Nodes[0])
	}
	limits := DefaultLimits()
	limits.MaxNodes = 1
	_, err = Parse([]byte("[Proxy]\nOne = ss, one, 1, x\nTwo = ss, two, 2, y\n"), protocol.NewRegistry(), limits)
	if err == nil || !errors.Is(err, ErrLimit) {
		t.Fatalf("node limit error = %v", err)
	}
	if _, err := Parse([]byte("[Rule]\nFINAL,DIRECT\n"), protocol.NewRegistry(), DefaultLimits()); !errors.Is(err, ErrUnrecognized) {
		t.Fatalf("non-proxy config error = %v", err)
	}
}

func TestRenderFilteredClientTextPreservesFramingAndOtherSections(t *testing.T) {
	input := []byte("[General]\r\nloglevel = notify\r\n[Proxy]\r\nOne = vmess, one.example, 443, opaque-one\r\nTwo = AnyTLS, two.example, 8443, opaque-two\r\n[Proxy Group]\r\nSelect = select, One\r\n")
	document, err := Parse(input, protocol.NewRegistry(), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := RenderFiltered(document, map[int]string{0: "One", 1: "Two"}, map[int]bool{0: true})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rendered, []byte("one.example")) || !bytes.Contains(rendered, []byte("two.example")) || !bytes.Contains(rendered, []byte("Select = select, One")) {
		t.Fatalf("filtered client config is wrong:\n%s", rendered)
	}
	if bytes.Count(rendered, []byte("\r\n")) != bytes.Count(input, []byte("\r\n"))-1 {
		t.Fatal("filtered render changed unrelated line framing")
	}
}
