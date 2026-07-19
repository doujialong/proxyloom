package protocol

import (
	"bytes"
	"os"
	"testing"

	"github.com/doujialong/proxyloom/internal/jsonlossless"
)

func TestM1IdentityProjectionFixturesCoverDeclaredFields(t *testing.T) {
	content, err := os.ReadFile("testdata/singbox-v1.12.25-canonical.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	root, err := jsonlossless.Parse(content, jsonlossless.DefaultLimits())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	protocolIDs := []string{"socks", "http", "shadowsocks", "vmess", "vless", "trojan", "hysteria2", "tuic", "anytls"}
	registry := NewRegistry()
	for index, protocolID := range protocolIDs {
		t.Run(protocolID, func(t *testing.T) {
			raw := root.Elements[index]
			projection, err := ProjectIdentity(registry.Lookup(FormatSingBoxJSON, protocolID), raw)
			if err != nil {
				t.Fatalf("ProjectIdentity() error = %v", err)
			}
			got, err := jsonlossless.MarshalOpaqueV1(projection, "")
			if err != nil {
				t.Fatalf("marshal projection: %v", err)
			}
			want, err := jsonlossless.MarshalOpaqueV1(raw, "tag")
			if err != nil {
				t.Fatalf("marshal fixture: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("fixture contains an undeclared identity field\nwant: %s\n got: %s", want, got)
			}
		})
	}
}

func TestIdentityProjectionExcludesUndeclaredRootAndNestedFields(t *testing.T) {
	raw := parseCanonicalFixture(t, `{
  "type":"vless",
  "tag":"Node",
  "server":"198.51.100.1",
  "server_port":443,
  "uuid":"fixture",
  "future_metadata":{"region":"test"},
  "tls":{"enabled":true,"server_name":"example.test","future_tls_metadata":1},
  "transport":{"type":"grpc","service_name":"service","future_transport_metadata":2}
}`)
	projection, err := ProjectIdentity(NewRegistry().Lookup(FormatSingBoxJSON, "vless"), raw)
	if err != nil {
		t.Fatalf("ProjectIdentity() error = %v", err)
	}
	encoded, err := jsonlossless.MarshalOpaqueV1(projection, "")
	if err != nil {
		t.Fatalf("MarshalOpaqueV1() error = %v", err)
	}
	want := `{"server":"198.51.100.1","server_port":443,"tls":{"enabled":true,"server_name":"example.test"},"transport":{"service_name":"service","type":"grpc"},"type":"vless","uuid":"fixture"}`
	if string(encoded) != want {
		t.Fatalf("projection\nwant: %s\n got: %s", want, encoded)
	}
}
