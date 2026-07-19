package protocol

import (
	"os"
	"reflect"
	"testing"

	"github.com/doujialong/proxyloom/internal/jsonlossless"
)

func TestNormalizeM1ProtocolFixtures(t *testing.T) {
	content, err := os.ReadFile("testdata/singbox-v1.12.25-canonical.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	root, err := jsonlossless.Parse(content, jsonlossless.DefaultLimits())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	expectedProtocols := []string{"socks", "http", "shadowsocks", "vmess", "vless", "trojan", "hysteria2", "tuic", "anytls"}
	if len(root.Elements) != len(expectedProtocols) {
		t.Fatalf("fixture count = %d, want %d", len(root.Elements), len(expectedProtocols))
	}
	registry := NewRegistry()
	canonical := make(map[string]CanonicalNode, len(expectedProtocols))
	for index, raw := range root.Elements {
		protocolID := expectedProtocols[index]
		node := Normalize(registry.Lookup(FormatSingBoxJSON, protocolID), protocolID+"-fixture", raw)
		if node.Completeness != CompletenessPartial || len(node.Issues) != 0 {
			t.Errorf("%s canonical = %+v", protocolID, node)
		}
		if node.Server == "" || node.ServerPort == 0 {
			t.Errorf("%s missing server metadata: %+v", protocolID, node)
		}
		canonical[protocolID] = node
	}

	if socks := canonical["socks"]; socks.Options.Version != "5" || socks.Authentication.Username != "fixture-user" || !reflect.DeepEqual(socks.Options.Network, []string{"tcp", "udp"}) {
		t.Fatalf("SOCKS canonical = %+v", socks)
	}
	if http := canonical["http"]; !http.TLS.Enabled.Value || !http.TLS.ECH.Enabled.Value || http.TLS.UTLS.Fingerprint != "chrome" || http.TLS.Reality.PublicKey != "fixture-public-key" {
		t.Fatalf("HTTP TLS canonical = %+v", http.TLS)
	}
	if shadowsocks := canonical["shadowsocks"]; shadowsocks.Authentication.Method == "" || shadowsocks.Options.PluginOptions != "obfs=http" || !shadowsocks.Multiplex.Enabled.Value {
		t.Fatalf("Shadowsocks canonical = %+v", shadowsocks)
	}
	if vmess := canonical["vmess"]; vmess.Authentication.Security != "auto" || vmess.Options.AlterID != "0" || vmess.Transport.Type != "ws" {
		t.Fatalf("VMess canonical = %+v", vmess)
	}
	if vless := canonical["vless"]; vless.Authentication.Flow != "xtls-rprx-vision" || vless.Transport.ServiceName != "fixture-service" {
		t.Fatalf("VLESS canonical = %+v", vless)
	}
	if trojan := canonical["trojan"]; trojan.Authentication.Password == "" || trojan.Transport.Type != "httpupgrade" {
		t.Fatalf("Trojan canonical = %+v", trojan)
	}
	if hysteria2 := canonical["hysteria2"]; hysteria2.Options.ObfsType != "salamander" || hysteria2.Options.UpMbps != "100" || len(hysteria2.Options.ServerPorts) != 2 {
		t.Fatalf("Hysteria2 canonical = %+v", hysteria2)
	}
	if tuic := canonical["tuic"]; tuic.Options.CongestionControl != "bbr" || !tuic.Options.UDPOverStream.Value || tuic.Options.Heartbeat != "10s" {
		t.Fatalf("TUIC canonical = %+v", tuic)
	}
	if anytls := canonical["anytls"]; anytls.Options.IdleSessionTimeout != "60s" || anytls.Options.MinIdleSession != "2" {
		t.Fatalf("AnyTLS canonical = %+v", anytls)
	}
}

func TestNormalizeReportsFullNestedPathsAndKeepsRawUsable(t *testing.T) {
	raw := parseCanonicalFixture(t, `{
  "type":"vless",
  "tag":"Node",
  "server":"198.51.100.1",
  "server_port":443,
  "uuid":"00000000-0000-0000-0000-000000000001",
  "tls":{"ech":{"config":[1]}},
  "transport":{"type":false}
}`)
	canonical := Normalize(NewRegistry().Lookup(FormatSingBoxJSON, "vless"), "Node", raw)
	if canonical.Completeness != CompletenessPartial {
		t.Fatalf("completeness = %s", canonical.Completeness)
	}
	wantIssues := []FieldIssue{
		{Path: "/tls/ech/config/0", Code: "expected_string"},
		{Path: "/transport/type", Code: "expected_string"},
	}
	if !reflect.DeepEqual(canonical.Issues, wantIssues) {
		t.Fatalf("issues = %+v, want %+v", canonical.Issues, wantIssues)
	}
	if _, err := jsonlossless.MarshalCompact(raw); err != nil {
		t.Fatalf("raw node became unusable: %v", err)
	}
}

func TestNormalizeFuturePhaseRemainsPartial(t *testing.T) {
	raw := parseCanonicalFixture(t, `{"type":"wireguard","tag":"Node","server":"host","server_port":443}`)
	canonical := Normalize(NewRegistry().Lookup(FormatSingBoxJSON, "wireguard"), "Node", raw)
	if canonical.Completeness != CompletenessPartial {
		t.Fatalf("wireguard completeness = %s", canonical.Completeness)
	}
}

func TestNormalizeUnknownRemainsOpaque(t *testing.T) {
	raw := parseCanonicalFixture(t, `{"type":"future","tag":"Node","server":"host","server_port":443}`)
	canonical := Normalize(NewRegistry().Lookup(FormatSingBoxJSON, "future"), "Node", raw)
	if canonical.ProtocolID != UnknownID || canonical.Completeness != CompletenessOpaque {
		t.Fatalf("canonical = %+v", canonical)
	}
}

func TestNormalizeDoesNotCoerceInvalidPort(t *testing.T) {
	raw := parseCanonicalFixture(t, `{"type":"vless","tag":"Node","server":"host","server_port":1.5,"uuid":"fixture"}`)
	canonical := Normalize(NewRegistry().Lookup(FormatSingBoxJSON, "vless"), "Node", raw)
	if canonical.ServerPort != 0 || canonical.Completeness != CompletenessPartial {
		t.Fatalf("canonical = %+v", canonical)
	}
}

func TestNormalizeReportsMissingRequiredFields(t *testing.T) {
	raw := parseCanonicalFixture(t, `{"type":"vless","tag":"Node","server":""}`)
	canonical := Normalize(NewRegistry().Lookup(FormatSingBoxJSON, "vless"), "Node", raw)
	want := []FieldIssue{
		{Path: "/server", Code: "required_field_missing"},
		{Path: "/uuid", Code: "required_field_missing"},
		{Path: "/server_port", Code: "required_field_missing"},
	}
	if !reflect.DeepEqual(canonical.Issues, want) {
		t.Fatalf("issues = %+v, want %+v", canonical.Issues, want)
	}
}

func parseCanonicalFixture(t *testing.T, input string) *jsonlossless.Node {
	t.Helper()
	node, err := jsonlossless.Parse([]byte(input), jsonlossless.DefaultLimits())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return node
}
