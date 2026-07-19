package identity

import (
	"bytes"
	"strings"
	"testing"

	"github.com/doujialong/proxyloom/internal/jsonlossless"
	"github.com/doujialong/proxyloom/internal/protocol"
)

func TestFingerprintIgnoresDisplayTag(t *testing.T) {
	fingerprinter, err := NewFingerprinter(bytes.Repeat([]byte{0x42}, 32), "test-key")
	if err != nil {
		t.Fatalf("NewFingerprinter() error = %v", err)
	}
	first := mustParse(t, `{"type":"vless","tag":"one","server":"example.com","server_port":443,"uuid":"fixture","future_metadata":1.2300}`)
	second := mustParse(t, `{"future_metadata":9.9900,"uuid":"fixture","server_port":443,"server":"example.com","tag":"two","type":"vless"}`)
	firstFingerprint, err := fingerprinter.Sum(semanticProjection(t, first, "vless"))
	if err != nil {
		t.Fatalf("Sum(first) error = %v", err)
	}
	secondFingerprint, err := fingerprinter.Sum(semanticProjection(t, second, "vless"))
	if err != nil {
		t.Fatalf("Sum(second) error = %v", err)
	}
	if firstFingerprint.MatchKey() != secondFingerprint.MatchKey() {
		t.Fatalf("tag/order changed fingerprint\nfirst:  %+v\nsecond: %+v", firstFingerprint, secondFingerprint)
	}
}

func TestOpaqueFingerprintPreservesNumberLexeme(t *testing.T) {
	fingerprinter, _ := NewFingerprinter(bytes.Repeat([]byte{0x24}, 32), "test-key")
	first, _ := fingerprinter.Sum(opaqueProjection(mustParse(t, `{"type":"future","tag":"one","value":1.0}`)))
	second, _ := fingerprinter.Sum(opaqueProjection(mustParse(t, `{"type":"future","tag":"one","value":1.00}`)))
	if first.Digest == second.Digest {
		t.Fatal("opaque fingerprint collapsed distinct number lexemes")
	}
	if first.Kind != KindOpaqueStructural || first.ProjectionVersion != OpaqueProjection {
		t.Fatalf("opaque fingerprint metadata = %+v", first)
	}
}

func TestRegisteredProjectionCoversConnectionDimensions(t *testing.T) {
	fingerprinter, _ := NewFingerprinter(bytes.Repeat([]byte{0x17}, 32), "test-key")
	base := `{
  "type":"vless",
  "tag":"display",
  "server":"198.51.100.1",
  "server_port":443,
  "uuid":"00000000-0000-0000-0000-000000000001",
  "tls":{
    "enabled":true,
    "server_name":"example.test",
    "ech":{"enabled":true,"config":["AA=="]},
    "utls":{"enabled":true,"fingerprint":"chrome"},
    "reality":{"enabled":true,"public_key":"key-one","short_id":"0123456789abcdef"}
  },
  "transport":{"type":"grpc","service_name":"service-one"},
  "multiplex":{"enabled":true,"padding":true},
  "detour":"upstream-one"
}`
	baseFingerprint, err := fingerprinter.Sum(semanticProjection(t, mustParse(t, base), "vless"))
	if err != nil {
		t.Fatalf("Sum(base) error = %v", err)
	}
	variants := map[string]string{
		"server":          strings.Replace(base, "198.51.100.1", "198.51.100.2", 1),
		"server_port":     strings.Replace(base, "443", "8443", 1),
		"authentication":  strings.Replace(base, "000000000001", "000000000002", 1),
		"tls_server_name": strings.Replace(base, "example.test", "other.test", 1),
		"ech":             strings.Replace(base, "AA==", "BB==", 1),
		"utls":            strings.Replace(base, "chrome", "firefox", 1),
		"reality":         strings.Replace(base, "key-one", "key-two", 1),
		"transport":       strings.Replace(base, "service-one", "service-two", 1),
		"multiplex":       strings.Replace(base, `"padding":true`, `"padding":false`, 1),
		"detour":          strings.Replace(base, "upstream-one", "upstream-two", 1),
	}
	for name, variant := range variants {
		t.Run(name, func(t *testing.T) {
			fingerprint, err := fingerprinter.Sum(semanticProjection(t, mustParse(t, variant), "vless"))
			if err != nil {
				t.Fatalf("Sum() error = %v", err)
			}
			if fingerprint.Digest == baseFingerprint.Digest {
				t.Fatalf("%s change did not affect fingerprint", name)
			}
		})
	}
}

func TestProtocolWithoutDeclaredIdentityProjectionIsOpaque(t *testing.T) {
	fingerprinter, _ := NewFingerprinter(bytes.Repeat([]byte{0x33}, 32), "test-key")
	fingerprint, err := fingerprinter.Sum(opaqueProjection(
		mustParse(t, `{"type":"wireguard","tag":"Node","server":"198.51.100.1","server_port":443}`),
	))
	if err != nil {
		t.Fatalf("Sum() error = %v", err)
	}
	if fingerprint.Kind != KindOpaqueStructural || fingerprint.ProjectionVersion != OpaqueProjection {
		t.Fatalf("fingerprint = %+v", fingerprint)
	}
}

func TestByteProjectionIsVersionedAndExact(t *testing.T) {
	fingerprinter, _ := NewFingerprinter(bytes.Repeat([]byte{0x55}, 32), "test-key")
	first, err := fingerprinter.SumBytes(ByteProjection{
		Value: []byte("vless://first"), Kind: KindOpaqueStructural, Version: OpaqueURIProjection,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, _ := fingerprinter.SumBytes(ByteProjection{
		Value: []byte("vless://second"), Kind: KindOpaqueStructural, Version: OpaqueURIProjection,
	})
	otherVersion, _ := fingerprinter.SumBytes(ByteProjection{
		Value: []byte("vless://first"), Kind: KindOpaqueStructural, Version: "opaque-uri-v2",
	})
	if first.Digest == second.Digest || first.Digest == otherVersion.Digest {
		t.Fatal("byte fingerprint did not bind exact bytes and projection version")
	}
	if first.ProjectionVersion != OpaqueURIProjection || first.Kind != KindOpaqueStructural {
		t.Fatalf("fingerprint = %+v", first)
	}
}

func semanticProjection(t *testing.T, raw *jsonlossless.Node, protocolID string) Projection {
	t.Helper()
	definition := protocol.NewRegistry().Lookup(protocol.FormatSingBoxJSON, protocolID)
	projected, err := protocol.ProjectIdentity(definition, raw)
	if err != nil {
		t.Fatalf("ProjectIdentity() error = %v", err)
	}
	return Projection{Node: projected, Kind: KindSemantic, Version: definition.IdentityProjection}
}

func opaqueProjection(raw *jsonlossless.Node) Projection {
	return Projection{
		Node:              raw,
		Kind:              KindOpaqueStructural,
		Version:           OpaqueProjection,
		ExcludeRootMember: "tag",
	}
}

func mustParse(t *testing.T, input string) *jsonlossless.Node {
	t.Helper()
	node, err := jsonlossless.Parse([]byte(input), jsonlossless.DefaultLimits())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return node
}
